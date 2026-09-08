from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest


TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent

import sys

sys.path.insert(0, str(TOOLS))

import macos_release_contract as contract  # noqa: E402
import release_open_gates  # noqa: E402


class MacReleaseContractTests(unittest.TestCase):
    @staticmethod
    def write_json(path: Path, payload: object) -> None:
        path.write_bytes(contract._canonical_bytes(payload))

    @staticmethod
    def thin_macho(cpu: int, subtype: int = 0) -> bytes:
        return b"\xcf\xfa\xed\xfe" + struct.pack("<II", cpu, subtype) + b"\x00" * 64

    @staticmethod
    def fat_macho(architectures: list[tuple[int, int]]) -> bytes:
        header = b"\xca\xfe\xba\xbe" + struct.pack(">I", len(architectures))
        entries = b"".join(
            struct.pack(">IIIII", cpu, subtype, 4096 + index * 4096, 64, 12)
            for index, (cpu, subtype) in enumerate(architectures)
        )
        return header + entries + b"\x00" * 64

    @staticmethod
    def approved_policy(files: list[dict]) -> dict:
        files = sorted(copy.deepcopy(files), key=lambda item: item["path"])
        return {
            "schemaVersion": 1,
            "target": "macos-arm64",
            "status": "approved",
            "hashAlgorithm": "SHA-256",
            "approvedInventorySha256": contract.inventory_digest(files),
            "bundleTarget": "SupertonicVox.app",
            "entries": [
                {
                    "path": item["path"],
                    "origin": "first-party",
                    "type": item["type"],
                    "action": "owner-sign" if item["type"] == "macho" else "hash-only-resource",
                    "preSignSha256": item["sha256"],
                    "sizeBytes": item["sizeBytes"],
                    "architectures": item["architectures"],
                    "entitlementsProfile": "none" if item["type"] == "macho" else None,
                    "approvalId": None,
                }
                for item in files
            ],
        }

    @staticmethod
    def inventory(files: list[dict]) -> dict:
        files = sorted(copy.deepcopy(files), key=lambda item: item["path"])
        return {
            "schemaVersion": 1,
            "target": "macos-arm64",
            "hashAlgorithm": "SHA-256",
            "files": files,
            "inventorySha256": contract.inventory_digest(files),
        }

    def test_committed_contract_is_staging_only_and_entitlements_are_exact(self) -> None:
        payload = contract.load_contract()
        self.assertEqual("staging-placeholder", payload["identity"]["status"])
        self.assertEqual(["arm64"], payload["architecture"]["finalArchitectures"])
        self.assertIn(["arm64", "arm64e", "x86_64"], payload["architecture"]["acceptedInputSets"])
        self.assertEqual(
            hashlib.sha256((ROOT / "packaging/macos/SupertonicVox.entitlements").read_bytes()).hexdigest(),
            payload["signing"]["entitlementsSha256"],
        )
        with self.assertRaisesRegex(contract.MacReleaseContractError, "identity-not-approved"):
            contract.load_contract(production=True)

    def test_capture_required_policy_fails_production(self) -> None:
        self.assertEqual("capture-required", contract.load_policy()["status"])
        with self.assertRaisesRegex(contract.MacReleaseContractError, "policy-not-approved"):
            contract.load_policy(production=True)

    def test_macho_parser_distinguishes_arm64_arm64e_x86_and_fat(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            arm = root / "arm"
            arm.write_bytes(self.thin_macho(0x0100000C))
            arm64e = root / "arm64e"
            arm64e.write_bytes(self.thin_macho(0x0100000C, 2))
            fat = root / "fat"
            fat.write_bytes(self.fat_macho([
                (0x01000007, 3),
                (0x0100000C, 0),
                (0x0100000C, 2),
            ]))
            self.assertEqual(["arm64"], contract.macho_architectures(arm))
            self.assertEqual(["arm64e"], contract.macho_architectures(arm64e))
            self.assertEqual(["arm64", "arm64e", "x86_64"], contract.macho_architectures(fat))

    def test_inventory_rejects_links_unknown_architecture_and_final_universal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            app = root / "app"
            app.mkdir()
            thin = app / "main"
            thin.write_bytes(self.thin_macho(0x0100000C))
            (app / "notice.txt").write_text("notice", encoding="utf-8")
            captured = contract.capture_inventory(app, require_arm64_only=True)
            self.assertEqual(2, len(captured["files"]))
            universal = app / "universal"
            universal.write_bytes(self.fat_macho([(0x01000007, 3), (0x0100000C, 0)]))
            with self.assertRaisesRegex(contract.MacReleaseContractError, "final-architecture"):
                contract.capture_inventory(app, require_arm64_only=True)
            universal.unlink()
            unknown = app / "unknown"
            unknown.write_bytes(self.thin_macho(0x12345678))
            with self.assertRaisesRegex(contract.MacReleaseContractError, "input-architecture"):
                contract.capture_inventory(app)
            unknown.unlink()
            hardlink = app / "notice-copy.txt"
            try:
                os.link(app / "notice.txt", hardlink)
            except OSError:
                self.skipTest("hardlinks unavailable")
            with self.assertRaisesRegex(contract.MacReleaseContractError, "file-invalid"):
                contract.capture_inventory(app)

    def test_policy_candidate_requires_human_review(self) -> None:
        files = [{
            "path": "Contents/MacOS/App",
            "sha256": "a" * 64,
            "sizeBytes": 10,
            "type": "macho",
            "architectures": ["arm64"],
        }]
        candidate = contract.create_policy_candidate(self.inventory(files))
        self.assertEqual("review-required", candidate["status"])
        self.assertEqual("REVIEW-REQUIRED", candidate["entries"][0]["action"])

    def test_approved_policy_and_signing_transition_bind_every_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files = [
                {"path": "Contents/MacOS/App", "sha256": "a" * 64, "sizeBytes": 10, "type": "macho", "architectures": ["arm64"]},
                {"path": "Contents/Info.plist", "sha256": "b" * 64, "sizeBytes": 20, "type": "resource", "architectures": []},
            ]
            policy = self.approved_policy(files)
            path = root / "policy.json"
            self.write_json(path, policy)
            loaded = contract.load_policy(path, production=True)
            contract.verify_signing_transition(loaded, self.inventory(files), "pre-sign")
            signed_files = copy.deepcopy(files)
            executable = next(item for item in signed_files if item["type"] == "macho")
            executable["sha256"] = "c" * 64
            executable["sizeBytes"] = 11
            signed_files.append({
                "path": "Contents/_CodeSignature/CodeResources",
                "sha256": "e" * 64,
                "sizeBytes": 30,
                "type": "resource",
                "architectures": [],
            })
            decisions = contract.verify_signing_transition(loaded, self.inventory(signed_files), "signed")
            owner_decision = next(item for item in decisions if item["action"] == "owner-sign")
            self.assertTrue(owner_decision["changedByOwnerSigning"])
            forged = copy.deepcopy(signed_files)
            next(item for item in forged if item["path"] == "Contents/Info.plist")["sha256"] = "d" * 64
            with self.assertRaisesRegex(contract.MacReleaseContractError, "change-invalid"):
                contract.verify_signing_transition(loaded, self.inventory(forged), "signed")

    def test_evidence_binds_normalization_signing_staple_and_dual_notary(self) -> None:
        files = [
            {"path": "Contents/MacOS/App", "sha256": "a" * 64, "sizeBytes": 10, "type": "macho", "architectures": ["arm64"]},
            {"path": "Contents/Info.plist", "sha256": "b" * 64, "sizeBytes": 20, "type": "resource", "architectures": []},
        ]
        policy = self.approved_policy(files)
        owner = contract.load_contract()
        owner["identity"] = {
            "status": "owner-approved",
            "certificateKind": "Developer ID Application",
            "leafCertificateSha256": "d" * 64,
            "subject": "CN=Release Owner",
            "teamId": "ABCDE12345",
            "approvalId": "MAC-OWNER-1",
        }
        normalized = self.inventory(files)
        signed_files = copy.deepcopy(files)
        executable = next(item for item in signed_files if item["type"] == "macho")
        executable["sha256"] = "c" * 64
        executable["sizeBytes"] = 11
        signed_files.append({
            "path": "Contents/_CodeSignature/CodeResources",
            "sha256": "0" * 64,
            "sizeBytes": 25,
            "type": "resource",
            "architectures": [],
        })
        signed = self.inventory(signed_files)
        stapled_files = copy.deepcopy(signed_files) + [{
            "path": "Contents/CodeResources",
            "sha256": "e" * 64,
            "sizeBytes": 30,
            "type": "resource",
            "architectures": [],
        }]
        stapled_files.sort(key=lambda item: item["path"])
        stapled = self.inventory(stapled_files)
        file_identity = lambda name, digest: {"name": name, "sha256": digest, "sizeBytes": 1}
        entitlements_path = ROOT / "packaging/macos/SupertonicVox.entitlements"
        evidence = {
            "schemaVersion": 2,
            "releaseEligible": False,
            "sourceCommit": "f" * 40,
            "packageVersion": "0.1.0",
            "contractSha256": hashlib.sha256(contract._canonical_bytes(owner)).hexdigest(),
            "signingPolicySha256": hashlib.sha256(contract._canonical_bytes(policy)).hexdigest(),
            "identityMode": "owner-approved",
            "preNormalizationInventory": normalized,
            "normalizationDecisions": [{
                "path": "Contents/MacOS/App",
                "originalArchitectures": ["arm64"],
                "originalSha256": "a" * 64,
                "originalSizeBytes": 10,
                "normalizedArchitectures": ["arm64"],
                "normalizedSha256": "a" * 64,
                "normalizedSizeBytes": 10,
                "changedByArm64Thinning": False,
            }],
            "normalizedInventory": normalized,
            "signingDecisions": contract.verify_signing_transition(policy, signed, "signed"),
            "signedInventory": signed,
            "stapledInventory": stapled,
            "appStages": {
                "normalizedInventorySha256": normalized["inventorySha256"],
                "signedInventorySha256": signed["inventorySha256"],
                "submissionZip": file_identity("SupertonicVox.app.zip", "1" * 64),
                "stapledInventorySha256": stapled["inventorySha256"],
            },
            "dmgStages": {
                "unsigned": file_identity("unsigned.dmg", "2" * 64),
                "signed": file_identity("signed.dmg", "3" * 64),
                "stapled": file_identity("stapled.dmg", "4" * 64),
            },
            "signers": {
                "app": {
                    "leafCertificateSha256": "d" * 64,
                    "subject": "CN=Release Owner",
                    "teamId": "ABCDE12345",
                    "secureTimestamp": True,
                    "certificateKind": "Developer ID Application",
                },
                "dmg": {
                    "leafCertificateSha256": "d" * 64,
                    "subject": "CN=Release Owner",
                    "teamId": "ABCDE12345",
                    "secureTimestamp": True,
                    "certificateKind": "Developer ID Application",
                },
            },
            "entitlements": {
                "file": {
                    "name": entitlements_path.name,
                    "sha256": hashlib.sha256(entitlements_path.read_bytes()).hexdigest(),
                    "sizeBytes": entitlements_path.stat().st_size,
                },
                "extracted": True,
                "allowedKeys": ["com.apple.security.cs.allow-jit"],
            },
            "notarization": {
                "app": {"submissionId": "00000000-0000-4000-8000-000000000001", "status": "Accepted", "logFile": file_identity("app-notary.json", "5" * 64)},
                "dmg": {"submissionId": "00000000-0000-4000-8000-000000000002", "status": "Accepted", "logFile": file_identity("dmg-notary.json", "6" * 64)},
            },
            "verifications": {
                "signedAppCodesignStrict": True,
                "stapledAppCodesignStrict": True,
                "appStaplerValidate": True,
                "signedDmgCodesign": True,
                "dmgStaplerValidate": True,
                "mountedAppCodesignStrict": True,
                "mountedAppGatekeeper": True,
                "dmgGatekeeperPrimarySignature": True,
            },
            "privacyEvidence": [file_identity("mounted.json", "7" * 64), file_identity("dmg.json", "8" * 64)],
            "externalApprovals": {
                "sourceLicense": file_identity("source.json", "9" * 64),
                "modelRedistribution": file_identity("model.json", "a" * 64),
                "productionCatalogVerification": file_identity("catalog.json", "b" * 64),
            },
            "toolchain": {
                "dotnetSdkVersion": "10.0.302",
                "macosVersion": "15.0",
                "xcodeVersion": "Xcode 17",
                "codesignExecutableSha256": "c" * 64,
                "notarytoolVersion": "notarytool-1",
            },
            "nativeChecks": {
                "quarantineApplied": "missing",
                "cleanAccountFirstLaunch": "missing",
                "offlineSynthesis": "missing",
                "saveRestart": "missing",
                "uninstall": "missing",
                "userDataPreserved": "missing",
                "noOrphanProcesses": "missing",
                "upgrade": "not-applicable-first-release",
                "priorBaselineSha256": None,
            },
            "openGates": release_open_gates.load_contract()["requiredOpenGateIds"],
        }
        contract.validate_evidence(evidence, owner, policy)
        forged = copy.deepcopy(evidence)
        forged["signedInventory"]["files"][0]["sha256"] = "0" * 64
        with self.assertRaises(contract.MacReleaseContractError):
            contract.validate_evidence(forged, owner, policy)
        forbidden_staple = copy.deepcopy(evidence)
        next(
            item for item in forbidden_staple["stapledInventory"]["files"]
            if item["path"] == "Contents/Info.plist"
        )["sha256"] = "0" * 64
        forbidden_staple["stapledInventory"]["inventorySha256"] = contract.inventory_digest(
            forbidden_staple["stapledInventory"]["files"]
        )
        forbidden_staple["appStages"]["stapledInventorySha256"] = forbidden_staple["stapledInventory"]["inventorySha256"]
        with self.assertRaisesRegex(contract.MacReleaseContractError, "staple-change"):
            contract.validate_evidence(forbidden_staple, owner, policy)
        reused_submission = copy.deepcopy(evidence)
        reused_submission["notarization"]["dmg"]["submissionId"] = (
            reused_submission["notarization"]["app"]["submissionId"]
        )
        with self.assertRaisesRegex(contract.MacReleaseContractError, "not-distinct"):
            contract.validate_evidence(reused_submission, owner, policy)
        invented_input = copy.deepcopy(evidence)
        invented_input["normalizationDecisions"][0].update({
            "originalArchitectures": ["arm64", "x86_64"],
            "originalSha256": "f" * 64,
            "originalSizeBytes": 100,
            "changedByArm64Thinning": True,
        })
        with self.assertRaisesRegex(contract.MacReleaseContractError, "normalization-binding"):
            contract.validate_evidence(invented_input, owner, policy)
        removed_signed_file = copy.deepcopy(evidence)
        removed_signed_file["stapledInventory"]["files"] = [
            item for item in removed_signed_file["stapledInventory"]["files"]
            if item["path"] != "Contents/Info.plist"
        ]
        removed_signed_file["stapledInventory"]["inventorySha256"] = contract.inventory_digest(
            removed_signed_file["stapledInventory"]["files"]
        )
        removed_signed_file["appStages"]["stapledInventorySha256"] = (
            removed_signed_file["stapledInventory"]["inventorySha256"]
        )
        with self.assertRaisesRegex(contract.MacReleaseContractError, "staple-removed"):
            contract.validate_evidence(removed_signed_file, owner, policy)

    def test_scripts_encode_dual_notary_order_keychain_and_no_publish(self) -> None:
        script = (ROOT / "packaging/build-macos-signed-release.sh").read_text(encoding="utf-8")
        workflow = (ROOT / ".github/workflows/macos-release.yml").read_text(encoding="utf-8")
        app_sign = script.index('codesign --force --sign "$CERTIFICATE_SHA1" --keychain "$NOTARY_KEYCHAIN" --options runtime --timestamp --entitlements')
        app_notary = script.index('notarytool submit "$APP_ZIP"')
        app_staple = script.index('stapler staple "$APP_DIR"')
        dmg_create = script.index("hdiutil create", app_staple)
        dmg_sign = script.index('codesign --force --sign "$CERTIFICATE_SHA1" --keychain "$NOTARY_KEYCHAIN" --timestamp "$DMG_PATH"')
        dmg_notary = script.index('notarytool submit "$DMG_PATH"')
        dmg_staple = script.index('stapler staple "$DMG_PATH"')
        self.assertLess(app_sign, app_notary)
        self.assertLess(app_notary, app_staple)
        self.assertLess(app_staple, dmg_create)
        self.assertLess(dmg_create, dmg_sign)
        self.assertLess(dmg_sign, dmg_notary)
        self.assertLess(dmg_notary, dmg_staple)
        self.assertNotIn("codesign --deep", script)
        self.assertIn('--extract-certificates="$prefix"', script)
        self.assertNotIn('codesign --version', script)
        self.assertIn('"mode":"macos-signing-policy-capture"', script)
        self.assertIn('"sourceCommit":sys.argv[2]', script)
        self.assertIn("--context context:primary-signature", script)
        self.assertIn("--keychain \"$NOTARY_KEYCHAIN\"", script)
        self.assertIn("release-gate-traceability.json", script)
        self.assertIn("final-release-signing-policy.json", script)
        self.assertIn("validate-traceability", script)
        self.assertIn("store-credentials", workflow)
        self.assertIn("--keychain \"$KEYCHAIN_PATH\"", workflow)
        self.assertIn("if: always()", workflow)
        self.assertNotIn("actions/upload-artifact", workflow)
        self.assertNotIn("gh release", workflow.casefold())

    def test_clean_account_checklist_requires_quarantine(self) -> None:
        checklist = (ROOT / "MACOS_RELEASE_CHECKLIST.md").read_text(encoding="utf-8")
        self.assertIn("com.apple.quarantine", checklist)
        self.assertIn("xattr", checklist)


if __name__ == "__main__":
    unittest.main()

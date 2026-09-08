from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
import uuid
import xml.etree.ElementTree as ET


TOOLS = Path(__file__).resolve().parent

import sys

sys.path.insert(0, str(TOOLS))

import release_open_gates  # noqa: E402
import windows_msi_contract as contract  # noqa: E402


class WindowsMsiContractTests(unittest.TestCase):
    @staticmethod
    def write_json(path: Path, payload: dict) -> None:
        path.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n", encoding="ascii")

    @staticmethod
    def make_pe(path: Path) -> None:
        payload = bytearray(256)
        payload[:2] = b"MZ"
        payload[0x3C:0x40] = (0x80).to_bytes(4, "little")
        payload[0x80:0x84] = b"PE\x00\x00"
        path.write_bytes(payload)

    def test_committed_contract_is_staging_only_and_product_codes_are_versioned(self) -> None:
        payload = contract.load_contract()
        self.assertEqual(contract.STAGING_UPGRADE_CODE, payload["identity"]["upgradeCode"])
        first = contract.derive_product_code(payload, "0.1.0")
        second = contract.derive_product_code(payload, "0.2.0")
        self.assertRegex(first, contract.GUID)
        self.assertNotEqual(first, second)
        with self.assertRaisesRegex(contract.WindowsMsiContractError, "production-identity"):
            contract.load_contract(production=True)
        with self.assertRaisesRegex(contract.WindowsMsiContractError, "refuses-staging"):
            contract.derive_product_code(payload, "0.1.0", production=True)

    def test_msi_version_rejects_prerelease_and_field_overflow(self) -> None:
        self.assertEqual((255, 255, 65535), contract.parse_version("255.255.65535"))
        for value in ("1.2.3-beta", "1.2", "256.0.0", "1.256.0", "1.2.65536", "01.2.3"):
            with self.subTest(value=value), self.assertRaises(contract.WindowsMsiContractError):
                contract.parse_version(value)

    def test_contract_rejects_noncanonical_duplicate_and_staging_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = contract.load_contract()
            noncanonical = root / "noncanonical.json"
            noncanonical.write_text(json.dumps(original), encoding="ascii")
            duplicate = root / "duplicate.json"
            duplicate.write_text('{"schemaVersion":1,"schemaVersion":1}', encoding="ascii")
            drift = copy.deepcopy(original)
            drift["identity"]["manufacturer"] = "Looks Production"
            drift_path = root / "drift.json"
            self.write_json(drift_path, drift)
            for path in (noncanonical, duplicate, drift_path):
                with self.subTest(path=path.name), self.assertRaises(contract.WindowsMsiContractError):
                    contract.load_contract(path)

    def test_capture_required_policy_fails_production(self) -> None:
        policy = contract.load_policy()
        self.assertEqual("capture-required", policy["status"])
        with self.assertRaisesRegex(contract.WindowsMsiContractError, "not-approved"):
            contract.load_policy(production=True)

    def test_policy_candidate_is_explicitly_review_required(self) -> None:
        inventory = {
            "schemaVersion": 1,
            "target": "win-x64",
            "hashAlgorithm": "SHA-256",
            "files": [{"path": "app.exe", "sha256": "a" * 64, "sizeBytes": 10, "type": "pe"}],
            "inventorySha256": contract.inventory_digest(
                [{"path": "app.exe", "sha256": "a" * 64, "sizeBytes": 10, "type": "pe"}]
            ),
        }
        candidate = contract.create_policy_candidate(inventory)
        self.assertEqual("review-required", candidate["status"])
        self.assertEqual("REVIEW-REQUIRED", candidate["entries"][0]["origin"])
        self.assertEqual("REVIEW-REQUIRED", candidate["entries"][0]["action"])

    def test_approved_policy_binds_every_file_action_and_expected_signer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files = [
                {"path": "app.exe", "sha256": "a" * 64, "sizeBytes": 10, "type": "pe"},
                {"path": "runtime.dll", "sha256": "b" * 64, "sizeBytes": 20, "type": "pe"},
                {"path": "notice.txt", "sha256": "c" * 64, "sizeBytes": 30, "type": "non-pe"},
            ]
            entries = [
                {
                    "path": "app.exe",
                    "origin": "first-party",
                    "type": "pe",
                    "action": "owner-sign",
                    "preSignSha256": "a" * 64,
                    "sizeBytes": 10,
                    "approvalId": None,
                    "allowedSigners": [],
                },
                {
                    "path": "notice.txt",
                    "origin": "first-party",
                    "type": "non-pe",
                    "action": "hash-only-non-pe",
                    "preSignSha256": "c" * 64,
                    "sizeBytes": 30,
                    "approvalId": None,
                    "allowedSigners": [],
                },
                {
                    "path": "runtime.dll",
                    "origin": "microsoft",
                    "type": "pe",
                    "action": "verify-existing-authenticode",
                    "preSignSha256": "b" * 64,
                    "sizeBytes": 20,
                    "approvalId": None,
                    "allowedSigners": [
                        {"leafCertificateSha256": "d" * 64, "subject": "CN=Microsoft Corporation"}
                    ],
                },
            ]
            policy = {
                "schemaVersion": 1,
                "target": "win-x64",
                "status": "approved",
                "hashAlgorithm": "SHA-256",
                "approvedInventorySha256": contract.inventory_digest(
                    sorted(files, key=lambda item: item["path"])
                ),
                "ownerCertificate": {
                    "leafCertificateSha256": "e" * 64,
                    "subject": "CN=Release Owner",
                    "approvalId": "OWNER-CERT-1",
                },
                "entries": entries,
            }
            path = root / "policy.json"
            self.write_json(path, policy)
            self.assertEqual("approved", contract.load_policy(path, production=True)["status"])

            unsigned = copy.deepcopy(policy)
            unsigned["entries"][2]["action"] = "approved-unsigned-pe"
            unsigned["entries"][2]["approvalId"] = None
            unsigned["entries"][2]["allowedSigners"] = []
            unsigned_path = root / "unsigned.json"
            self.write_json(unsigned_path, unsigned)
            with self.assertRaisesRegex(contract.WindowsMsiContractError, "unsigned-pe-approval"):
                contract.load_policy(unsigned_path)

            wrong_signer = copy.deepcopy(policy)
            wrong_signer["entries"][2]["allowedSigners"] = []
            wrong_path = root / "wrong-signer.json"
            self.write_json(wrong_path, wrong_signer)
            with self.assertRaisesRegex(contract.WindowsMsiContractError, "expected-signer"):
                contract.load_policy(wrong_path)

            loaded = contract.load_policy(path, production=True)
            pre_inventory = {
                "schemaVersion": 1,
                "target": "win-x64",
                "hashAlgorithm": "SHA-256",
                "files": sorted(files, key=lambda item: item["path"]),
                "inventorySha256": contract.inventory_digest(
                    sorted(files, key=lambda item: item["path"])
                ),
            }
            self.assertEqual(
                3,
                len(contract.verify_inventory_transition(loaded, pre_inventory, "pre-sign")),
            )
            final_inventory = copy.deepcopy(pre_inventory)
            final_inventory["files"][0]["sha256"] = "f" * 64
            final_inventory["files"][0]["sizeBytes"] = 11
            final_inventory["inventorySha256"] = contract.inventory_digest(final_inventory["files"])
            decisions = contract.verify_inventory_transition(loaded, final_inventory, "final")
            self.assertTrue(decisions[0]["changedByApprovedOwnerSigning"])
            unchanged = copy.deepcopy(pre_inventory)
            with self.assertRaisesRegex(contract.WindowsMsiContractError, "transition-missing"):
                contract.verify_inventory_transition(loaded, unchanged, "final")

    def test_inventory_capture_detects_pe_and_rejects_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = root / "payload"
            payload.mkdir()
            self.make_pe(payload / "app.exe")
            (payload / "notice.txt").write_text("notice", encoding="utf-8")
            inventory = contract.capture_inventory(payload)
            self.assertEqual(["app.exe", "notice.txt"], [item["path"] for item in inventory["files"]])
            self.assertEqual("pe", inventory["files"][0]["type"])
            self.assertEqual("non-pe", inventory["files"][1]["type"])

            hardlink = payload / "notice-copy.txt"
            try:
                os.link(payload / "notice.txt", hardlink)
            except (NotImplementedError, OSError):
                self.skipTest("hardlinks unavailable")
            with self.assertRaisesRegex(contract.WindowsMsiContractError, "inventory-file-invalid"):
                contract.capture_inventory(payload)

    def test_generated_wix_components_match_inventory_and_avoid_user_data(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            committed = contract.load_contract()
            files = []
            for index, path in enumerate(committed["requiredPayloadSubset"]):
                files.append(
                    {
                        "path": path,
                        "sha256": f"{index + 1:064x}",
                        "sizeBytes": index + 1,
                        "type": "non-pe",
                    }
                )
            inventory = {
                "schemaVersion": 1,
                "target": "win-x64",
                "hashAlgorithm": "SHA-256",
                "files": files,
                "inventorySha256": contract.inventory_digest(files),
            }
            output = root / "GeneratedComponents.wxs"
            contract.generate_components(committed, inventory, output)
            tree = ET.parse(output)
            namespace = {"w": "http://wixtoolset.org/schemas/v4/wxs"}
            self.assertEqual(len(files), len(tree.findall(".//w:Component", namespace)))
            text = output.read_text(encoding="utf-8")
            self.assertNotIn("LOCALAPPDATA", text.upper())
            self.assertNotIn("DOCUMENTS\\SUPERTONICVOX", text.upper())

    def test_noneligible_evidence_requires_canonical_open_gates_and_msi_hash_binding(self) -> None:
        committed = contract.load_contract()
        policy_file = {
            "path": "notice.txt",
            "sha256": "a" * 64,
            "sizeBytes": 1,
            "type": "non-pe",
        }
        policy = {
            "schemaVersion": 1,
            "target": "win-x64",
            "status": "approved",
            "hashAlgorithm": "SHA-256",
            "approvedInventorySha256": contract.inventory_digest([policy_file]),
            "ownerCertificate": None,
            "entries": [{
                "path": policy_file["path"],
                "origin": "first-party",
                "type": policy_file["type"],
                "action": "hash-only-non-pe",
                "preSignSha256": policy_file["sha256"],
                "sizeBytes": policy_file["sizeBytes"],
                "approvalId": None,
                "allowedSigners": [],
            }],
        }
        product_code = contract.derive_product_code(committed, "0.1.0")
        digest = "a" * 64
        final_inventory = {
            "schemaVersion": 1,
            "target": "win-x64",
            "hashAlgorithm": "SHA-256",
            "files": [policy_file],
            "inventorySha256": policy["approvedInventorySha256"],
        }
        evidence = {
            "schemaVersion": 2,
            "releaseEligible": False,
            "sourceCommit": "b" * 40,
            "packageVersion": "0.1.0",
            "identityMode": "staging-placeholder",
            "upgradeCode": contract.STAGING_UPGRADE_CODE,
            "productCode": product_code,
            "packageCode": str(uuid.uuid4()).upper(),
            "contractSha256": hashlib.sha256(contract._canonical_bytes(committed)).hexdigest(),
            "signingPolicySha256": hashlib.sha256(contract._canonical_bytes(policy)).hexdigest(),
            "preSignInventorySha256": policy["approvedInventorySha256"],
            "finalInventorySha256": policy["approvedInventorySha256"],
            "payloadManifestSha256": hashlib.sha256(
                contract._canonical_bytes(final_inventory)
            ).hexdigest(),
            "unsignedMsiSha256": digest,
            "iceValidatedUnsignedMsiSha256": digest,
            "signedMsiSha256": None,
            "msiSigner": None,
            "timestamp": None,
            "toolchain": {
                "dotnetSdkVersion": "10.0.302",
                "wixSdkVersion": "7.0.0",
                "powerShellVersion": "5.1.0",
                "windowsVersion": "Windows fixture",
                "signToolVersion": None,
            },
            "signingDecisions": [{
                "path": "notice.txt",
                "action": "hash-only-non-pe",
                "type": "non-pe",
                "preSignSha256": digest,
                "finalSha256": digest,
                "finalSizeBytes": 1,
                "changedByApprovedOwnerSigning": False,
            }],
            "iceValidation": {"status": "passed", "unsignedMsiSha256": digest, "suppressions": []},
            "privacyEvidence": [{"name": "privacy.json", "sha256": digest, "sizeBytes": 1}],
            "externalApprovals": {
                "sourceLicense": None,
                "modelRedistribution": None,
                "productionCatalogVerification": None,
            },
            "nativeChecks": {
                "firstRelease": True,
                "cleanInstall": "missing",
                "offlineSynthesis": "missing",
                "saveRestart": "missing",
                "uninstall": "missing",
                "noOrphanProcesses": "missing",
                "upgrade": "not-applicable-first-release",
                "downgradePrevention": "not-applicable-first-release",
                "priorSignedMsiSha256": None,
            },
            "openGates": release_open_gates.load_contract()["requiredOpenGateIds"],
        }
        contract.validate_evidence(evidence, committed, policy)
        incomplete = copy.deepcopy(evidence)
        incomplete["openGates"] = incomplete["openGates"][:-1]
        with self.assertRaisesRegex(contract.WindowsMsiContractError, "preflight-open-gates"):
            contract.validate_evidence(incomplete, committed, policy)
        wrong_ice = copy.deepcopy(evidence)
        wrong_ice["iceValidatedUnsignedMsiSha256"] = "c" * 64
        with self.assertRaisesRegex(contract.WindowsMsiContractError, "ice-unsigned"):
            contract.validate_evidence(wrong_ice, committed, policy)

    def test_owner_identity_requires_approved_policy_and_complete_bound_decisions(self) -> None:
        committed = contract.load_contract()
        committed["identity"] = {
            "status": "owner-approved",
            "upgradeCode": "8A9ED2C7-7AEC-4B9C-80AC-93B500EB6C76",
            "stagingUpgradeCode": contract.STAGING_UPGRADE_CODE,
            "manufacturer": "Release Owner",
            "stagingManufacturer": contract.STAGING_MANUFACTURER,
            "ownerApprovalId": "OWNER-IDENTITY-1",
        }
        capture_required = contract.load_policy()
        digest = "a" * 64
        approvals = {
            key: {"name": f"{key}.json", "sha256": digest, "sizeBytes": 1}
            for key in ("sourceLicense", "modelRedistribution", "productionCatalogVerification")
        }
        evidence = {
            "schemaVersion": 2,
            "releaseEligible": False,
            "sourceCommit": "b" * 40,
            "packageVersion": "0.1.0",
            "identityMode": "owner-approved",
            "upgradeCode": committed["identity"]["upgradeCode"],
            "productCode": contract.derive_product_code(committed, "0.1.0"),
            "packageCode": str(uuid.uuid4()).upper(),
            "contractSha256": hashlib.sha256(contract._canonical_bytes(committed)).hexdigest(),
            "signingPolicySha256": hashlib.sha256(
                contract._canonical_bytes(capture_required)
            ).hexdigest(),
            "preSignInventorySha256": digest,
            "finalInventorySha256": digest,
            "payloadManifestSha256": digest,
            "unsignedMsiSha256": digest,
            "iceValidatedUnsignedMsiSha256": digest,
            "signedMsiSha256": "c" * 64,
            "msiSigner": {
                "leafCertificateSha256": "d" * 64,
                "subject": "CN=Release Owner",
                "serialNumber": "01",
                "codeSigningEku": True,
                "timestampVerified": True,
                "timestampAuthoritySubject": "CN=Timestamp Authority",
            },
            "timestamp": {
                "url": committed["signing"]["timestampUrl"],
                "digestAlgorithm": "SHA-256",
                "authoritySubject": "CN=Timestamp Authority",
                "verified": True,
            },
            "toolchain": {
                "dotnetSdkVersion": "10.0.302",
                "wixSdkVersion": "7.0.0",
                "powerShellVersion": "5.1.0",
                "windowsVersion": "Windows fixture",
                "signToolVersion": "10.0",
            },
            "signingDecisions": [],
            "iceValidation": {"status": "passed", "unsignedMsiSha256": digest, "suppressions": []},
            "privacyEvidence": [{"name": "privacy.json", "sha256": digest, "sizeBytes": 1}],
            "externalApprovals": approvals,
            "nativeChecks": {
                "firstRelease": True,
                "cleanInstall": "missing",
                "offlineSynthesis": "missing",
                "saveRestart": "missing",
                "uninstall": "missing",
                "noOrphanProcesses": "missing",
                "upgrade": "not-applicable-first-release",
                "downgradePrevention": "not-applicable-first-release",
                "priorSignedMsiSha256": None,
            },
            "openGates": release_open_gates.load_contract()["requiredOpenGateIds"],
        }
        with self.assertRaisesRegex(contract.WindowsMsiContractError, "signing-policy-not-approved"):
            contract.validate_evidence(evidence, committed, capture_required)

        approved = {
            "schemaVersion": 1,
            "target": "win-x64",
            "status": "approved",
            "hashAlgorithm": "SHA-256",
            "approvedInventorySha256": contract.inventory_digest(
                [{"path": "app.exe", "sha256": digest, "sizeBytes": 10, "type": "pe"}]
            ),
            "ownerCertificate": {
                "leafCertificateSha256": "d" * 64,
                "subject": "CN=Release Owner",
                "approvalId": "OWNER-CERT-1",
            },
            "entries": [{
                "path": "app.exe",
                "origin": "first-party",
                "type": "pe",
                "action": "owner-sign",
                "preSignSha256": digest,
                "sizeBytes": 10,
                "approvalId": None,
                "allowedSigners": [],
            }],
        }
        evidence["signingPolicySha256"] = hashlib.sha256(
            contract._canonical_bytes(approved)
        ).hexdigest()
        evidence["preSignInventorySha256"] = approved["approvedInventorySha256"]
        with self.assertRaisesRegex(contract.WindowsMsiContractError, "decisions-incomplete"):
            contract.validate_evidence(evidence, committed, approved)
        evidence["signingDecisions"] = [{
            "path": "app.exe",
            "action": "owner-sign",
            "type": "pe",
            "preSignSha256": digest,
            "finalSha256": "e" * 64,
            "finalSizeBytes": 11,
            "changedByApprovedOwnerSigning": True,
        }]
        final_files = [{"path": "app.exe", "sha256": "e" * 64, "sizeBytes": 11, "type": "pe"}]
        evidence["finalInventorySha256"] = contract.inventory_digest(final_files)
        evidence["payloadManifestSha256"] = hashlib.sha256(contract._canonical_bytes({
            "schemaVersion": 1,
            "target": "win-x64",
            "hashAlgorithm": "SHA-256",
            "files": final_files,
            "inventorySha256": evidence["finalInventorySha256"],
        })).hexdigest()
        contract.validate_evidence(evidence, committed, approved)
        forged = copy.deepcopy(evidence)
        forged["signingDecisions"][0]["finalSha256"] = "f" * 64
        with self.assertRaisesRegex(contract.WindowsMsiContractError, "final-inventory-binding"):
            contract.validate_evidence(forged, committed, approved)

    def test_wix_contract_pins_sdk_major_upgrade_and_no_user_data_paths(self) -> None:
        project = (TOOLS.parent / "packaging" / "windows" / "SupertonicVox.wixproj").read_text(
            encoding="utf-8"
        )
        product = (TOOLS.parent / "packaging" / "windows" / "Product.wxs").read_text(
            encoding="utf-8"
        )
        self.assertIn('Sdk="WixToolset.Sdk/7.0.0"', project)
        self.assertIn('<EnableDefaultItems>false</EnableDefaultItems>', project)
        self.assertIn('AllowDowngrades="no"', product)
        self.assertIn('AllowSameVersionUpgrades="no"', product)
        self.assertIn('ProgramFiles64Folder', product)
        self.assertNotIn("LocalAppDataFolder", product)
        self.assertNotIn("PersonalFolder", product)

    def test_powershell_and_workflow_preserve_signing_order_and_never_publish(self) -> None:
        script = (TOOLS.parent / "packaging" / "build-windows-msi.ps1").read_text(
            encoding="utf-8"
        )
        workflow = (TOOLS.parent / ".github" / "workflows" / "windows-release.yml").read_text(
            encoding="utf-8"
        )
        lower = script.casefold()
        self.assertNotIn(".pfx", lower)
        self.assertNotIn("pfxpassword", lower)
        self.assertNotIn("-password", lower)
        self.assertIn("Get-AuthenticodeSignature", script)
        self.assertIn("CatalogReleaseVerifier", script)
        self.assertIn("approved-unsigned-pe", script)
        self.assertIn("--untracked-files=all -- @CommitBoundInputs", script)
        self.assertIn("git cat-file -e", script)
        self.assertIn("Prior signed MSI UpgradeCode", script)
        self.assertIn("Prior signed MSI version must be lower", script)
        self.assertIn("Get-VerifiedSignature -Path $PriorSignedMsi", script)
        self.assertIn("release-gate-traceability.json", script)
        self.assertIn("final-release-signing-policy.json", script)
        self.assertIn("validate-traceability", script)
        self.assertNotIn("SVX_PRODUCTION_INSTALLER_CONTRACT", workflow)
        self.assertNotIn("SVX_WINDOWS_SIGNING_POLICY", workflow)
        unsigned = script.index("$UnsignedMsiIdentity = Get-FileIdentity")
        ice = script.index("wix-ice-validation.txt")
        sign = script.index("msi-sign.txt")
        verify = script.index("msi-signature-verify.txt")
        self.assertLess(unsigned, ice)
        self.assertLess(ice, sign)
        self.assertLess(sign, verify)
        self.assertIn("runs-on: [self-hosted, windows, x64, supertonic-release]", workflow)
        self.assertIn("environment: production-release", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertNotIn("actions/upload-artifact", workflow)
        self.assertNotIn("gh release", workflow.casefold())

    def test_public_staging_includes_the_complete_windows_msi_contract(self) -> None:
        script = (TOOLS.parent / "packaging" / "create-public-release-staging.sh").read_text(
            encoding="utf-8"
        )
        required = (
            ".config/dotnet-tools.json",
            ".github/workflows/windows-release.yml",
            "tools/windows_msi_contract.py",
            "tools/test_windows_msi_contract.py",
            "packaging/build-windows-msi.ps1",
            "packaging/windows-installer-contract.json",
            "packaging/windows-signing-policy.json",
            "packaging/windows-msi-evidence.schema.json",
            "packaging/windows",
        )
        for path in required:
            with self.subTest(path=path):
                self.assertIn(path, script)
        git_add = script.split('git -C "$TREE" add -- \\\n', 1)[1].split("SOURCE_DATE=", 1)[0]
        self.assertIn("  .config \\\n", git_add)


if __name__ == "__main__":
    unittest.main()

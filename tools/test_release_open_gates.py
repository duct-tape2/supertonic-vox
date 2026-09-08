from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest


TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))

import release_open_gates as gates  # noqa: E402


class ReleaseOpenGateTests(unittest.TestCase):
    def test_canonical_contract_is_sorted_unique_and_identified(self) -> None:
        payload = gates.load_contract()
        self.assertEqual(payload["requiredOpenGateIds"], sorted(payload["requiredOpenGateIds"]))
        self.assertEqual(len(payload["requiredOpenGateIds"]), len(set(payload["requiredOpenGateIds"])))
        identity = gates.contract_identity()
        self.assertEqual(64, len(str(identity["sha256"])))

    def test_duplicate_and_noncanonical_contract_gates_fail(self) -> None:
        base = gates.load_contract()
        fixtures = (
            {**base, "requiredOpenGateIds": base["requiredOpenGateIds"] + [base["requiredOpenGateIds"][0]]},
            {**base, "requiredOpenGateIds": list(reversed(base["requiredOpenGateIds"]))},
        )
        with tempfile.TemporaryDirectory() as temporary:
            for index, payload in enumerate(fixtures):
                with self.subTest(index=index):
                    path = Path(temporary) / f"contract-{index}.json"
                    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="ascii")
                    with self.assertRaises(gates.ReleaseOpenGateError):
                        gates.load_contract(path)

    def test_evidence_requires_the_complete_canonical_gate_list(self) -> None:
        required = gates.load_contract()["requiredOpenGateIds"]
        gates.validate_evidence({"releaseEligible": False, "openGates": required})
        for value in (required[:-1], required + ["unexpected-gate"], list(reversed(required))):
            with self.subTest(value=value), self.assertRaisesRegex(
                gates.ReleaseOpenGateError,
                "evidence-open-gates-invalid",
            ):
                gates.validate_evidence({"releaseEligible": False, "openGates": value})
        with self.assertRaisesRegex(gates.ReleaseOpenGateError, "evidence-release-state-invalid"):
            gates.validate_evidence({"releaseEligible": True, "openGates": required})

    def test_traceability_maps_every_gate_and_required_review_exactly_once(self) -> None:
        contract = gates.load_contract()
        payload = gates.load_traceability()
        self.assertEqual(
            contract["requiredOpenGateIds"],
            [item["gateId"] for item in payload["mappings"]],
        )
        self.assertEqual(
            list(gates.REQUIRED_REVIEW_IDS),
            [item["reviewId"] for item in payload["reviewRequirements"]],
        )
        identity = gates.traceability_identity()
        self.assertEqual(64, len(str(identity["sha256"])))

    def test_traceability_rejects_gate_contract_and_review_policy_drift(self) -> None:
        payload = gates.load_traceability()
        fixtures = []

        missing_gate = json.loads(json.dumps(payload))
        missing_gate["mappings"].pop()
        fixtures.append((missing_gate, "traceability-mappings-invalid"))

        wrong_contract = json.loads(json.dumps(payload))
        wrong_contract["gateContractSha256"] = "0" * 64
        fixtures.append((wrong_contract, "traceability-contract-identity-invalid"))

        review_waiver = json.loads(json.dumps(payload))
        review_waiver["reviewRequirements"][0]["allowedOutcomes"] = [
            "owner-approved-waiver",
            "pass",
        ]
        fixtures.append((review_waiver, "traceability-review-policy-invalid"))

        unsafe_path = json.loads(json.dumps(payload))
        unsafe_path["mappings"][0]["evidenceArtifact"] = "evidence/../escape.json"
        fixtures.append((unsafe_path, "traceability-mapping-invalid"))

        with tempfile.TemporaryDirectory() as temporary:
            for index, (fixture, expected) in enumerate(fixtures):
                with self.subTest(index=index):
                    path = Path(temporary) / f"traceability-{index}.json"
                    path.write_bytes(gates.canonical_traceability_bytes(fixture))
                    with self.assertRaisesRegex(gates.ReleaseOpenGateError, expected):
                        gates.load_traceability(path)

    def test_traceability_rejects_noncanonical_bytes(self) -> None:
        payload = gates.load_traceability()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "traceability.json"
            path.write_text(json.dumps(payload) + "\n", encoding="ascii")
            with self.assertRaisesRegex(
                gates.ReleaseOpenGateError,
                "traceability-not-canonical",
            ):
                gates.load_traceability(path)

    def test_all_prerelease_evidence_writers_use_the_canonical_contract(self) -> None:
        root = TOOLS.parent
        for relative in (
            "packaging/build-macos-release.sh",
            "packaging/build-windows-release.ps1",
            "packaging/create-public-release-staging.sh",
        ):
            with self.subTest(relative=relative):
                text = (root / relative).read_text(encoding="utf-8")
                self.assertIn("release-open-gates.json", text)
                self.assertIn("release-gate-traceability.json", text)
                self.assertIn("release_open_gates.py", text)
                self.assertIn("validate-traceability", text)


if __name__ == "__main__":
    unittest.main()

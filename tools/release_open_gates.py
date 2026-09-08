#!/usr/bin/env python3
"""Canonical release-blocker contract shared by every pre-release evidence writer."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re


DEFAULT_CONTRACT = Path(__file__).resolve().parents[1] / "packaging" / "release-open-gates.json"
DEFAULT_TRACEABILITY = (
    Path(__file__).resolve().parents[1] / "packaging" / "release-gate-traceability.json"
)
GATE_ID = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*\Z")
REVIEW_ID = re.compile(r"[a-z0-9][a-z0-9.-]*\Z")
OWNER_STEP = re.compile(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*\Z")
EVIDENCE_PATH = re.compile(r"evidence/[a-z0-9][a-z0-9./-]*\.json\Z")
REQUIRED_REVIEW_IDS = ("fable-readiness", "gpt-5.6-pro-web", "terra-code")
REQUIRED_OWNER_STEPS = (
    "LEGAL_APPROVAL",
    "MAC_NATIVE_RELEASE",
    "REAL_ENGINE_BENCHMARKS",
    "REMOTE_PROVENANCE",
    "TRUST_AND_RUNTIME_ARTIFACTS",
    "WINDOWS_NATIVE_RELEASE",
)


class ReleaseOpenGateError(RuntimeError):
    pass


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseOpenGateError(f"contract-duplicate-key:{key}")
        result[key] = value
    return result


def canonical_contract_bytes(payload: dict) -> bytes:
    ordered = {
        "schemaVersion": payload["schemaVersion"],
        "requiredOpenGateIds": payload["requiredOpenGateIds"],
    }
    return (json.dumps(ordered, ensure_ascii=True, indent=2) + "\n").encode("ascii")


def canonical_traceability_bytes(payload: dict) -> bytes:
    ordered = {
        "schemaVersion": payload["schemaVersion"],
        "gateContractSha256": payload["gateContractSha256"],
        "mappings": [
            {
                "gateId": item["gateId"],
                "ownerStep": item["ownerStep"],
                "evidenceArtifact": item["evidenceArtifact"],
                "verifierId": item["verifierId"],
            }
            for item in payload["mappings"]
        ],
        "reviewRequirements": [
            {
                "reviewId": item["reviewId"],
                "evidenceArtifact": item["evidenceArtifact"],
                "allowedOutcomes": item["allowedOutcomes"],
            }
            for item in payload["reviewRequirements"]
        ],
    }
    return (json.dumps(ordered, ensure_ascii=True, indent=2) + "\n").encode("ascii")


def load_contract(path: Path = DEFAULT_CONTRACT) -> dict:
    try:
        raw = path.read_bytes()
        payload = json.loads(raw.decode("ascii"), object_pairs_hook=_reject_duplicates)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseOpenGateError("contract-unavailable") from exc
    if not isinstance(payload, dict) or tuple(payload) != (
        "schemaVersion",
        "requiredOpenGateIds",
    ):
        raise ReleaseOpenGateError("contract-shape-invalid")
    if (
        not isinstance(payload["schemaVersion"], int)
        or isinstance(payload["schemaVersion"], bool)
        or payload["schemaVersion"] != 1
    ):
        raise ReleaseOpenGateError("contract-version-invalid")
    gates = payload["requiredOpenGateIds"]
    if (
        not isinstance(gates, list)
        or not gates
        or not all(isinstance(value, str) and GATE_ID.fullmatch(value) for value in gates)
        or gates != sorted(gates)
        or len(gates) != len(set(gates))
    ):
        raise ReleaseOpenGateError("contract-gates-invalid")
    if canonical_contract_bytes(payload) != raw:
        raise ReleaseOpenGateError("contract-not-canonical")
    return payload


def contract_identity(path: Path = DEFAULT_CONTRACT) -> dict[str, object]:
    payload = load_contract(path)
    raw = canonical_contract_bytes(payload)
    return {
        "name": path.name,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "sizeBytes": len(raw),
    }


def _is_safe_evidence_path(value: object) -> bool:
    if not isinstance(value, str) or not EVIDENCE_PATH.fullmatch(value):
        return False
    path = PurePosixPath(value)
    return not path.is_absolute() and all(part not in ("", ".", "..") for part in path.parts)


def load_traceability(
    path: Path = DEFAULT_TRACEABILITY,
    contract_path: Path = DEFAULT_CONTRACT,
) -> dict:
    try:
        raw = path.read_bytes()
        payload = json.loads(raw.decode("ascii"), object_pairs_hook=_reject_duplicates)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseOpenGateError("traceability-unavailable") from exc
    if not isinstance(payload, dict) or tuple(payload) != (
        "schemaVersion",
        "gateContractSha256",
        "mappings",
        "reviewRequirements",
    ):
        raise ReleaseOpenGateError("traceability-shape-invalid")
    if (
        not isinstance(payload["schemaVersion"], int)
        or isinstance(payload["schemaVersion"], bool)
        or payload["schemaVersion"] != 1
    ):
        raise ReleaseOpenGateError("traceability-version-invalid")
    expected_contract_sha = contract_identity(contract_path)["sha256"]
    if payload["gateContractSha256"] != expected_contract_sha:
        raise ReleaseOpenGateError("traceability-contract-identity-invalid")

    mappings = payload["mappings"]
    required_gates = load_contract(contract_path)["requiredOpenGateIds"]
    if not isinstance(mappings, list) or len(mappings) != len(required_gates):
        raise ReleaseOpenGateError("traceability-mappings-invalid")
    mapped_gate_ids: list[str] = []
    observed_owner_steps: set[str] = set()
    for item in mappings:
        if not isinstance(item, dict) or tuple(item) != (
            "gateId",
            "ownerStep",
            "evidenceArtifact",
            "verifierId",
        ):
            raise ReleaseOpenGateError("traceability-mapping-shape-invalid")
        gate_id = item["gateId"]
        mapped_gate_ids.append(gate_id)
        owner_step = item["ownerStep"]
        observed_owner_steps.add(owner_step)
        if (
            not isinstance(gate_id, str)
            or not GATE_ID.fullmatch(gate_id)
            or not isinstance(owner_step, str)
            or not OWNER_STEP.fullmatch(owner_step)
            or owner_step not in REQUIRED_OWNER_STEPS
            or not _is_safe_evidence_path(item["evidenceArtifact"])
            or item["evidenceArtifact"] != f"evidence/gates/{gate_id}.json"
            or not isinstance(item["verifierId"], str)
            or not GATE_ID.fullmatch(item["verifierId"])
        ):
            raise ReleaseOpenGateError("traceability-mapping-invalid")
    if mapped_gate_ids != required_gates:
        raise ReleaseOpenGateError("traceability-gate-coverage-invalid")
    if tuple(sorted(observed_owner_steps)) != REQUIRED_OWNER_STEPS:
        raise ReleaseOpenGateError("traceability-owner-step-coverage-invalid")

    review_requirements = payload["reviewRequirements"]
    if not isinstance(review_requirements, list):
        raise ReleaseOpenGateError("traceability-reviews-invalid")
    review_ids: list[str] = []
    for item in review_requirements:
        if not isinstance(item, dict) or tuple(item) != (
            "reviewId",
            "evidenceArtifact",
            "allowedOutcomes",
        ):
            raise ReleaseOpenGateError("traceability-review-shape-invalid")
        review_id = item["reviewId"]
        outcomes = item["allowedOutcomes"]
        review_ids.append(review_id)
        if (
            not isinstance(review_id, str)
            or not REVIEW_ID.fullmatch(review_id)
            or not _is_safe_evidence_path(item["evidenceArtifact"])
            or item["evidenceArtifact"] != f"evidence/reviews/{review_id}.json"
            or not isinstance(outcomes, list)
            or not outcomes
            or outcomes != sorted(outcomes)
            or len(outcomes) != len(set(outcomes))
            or not all(value in ("owner-approved-waiver", "pass") for value in outcomes)
        ):
            raise ReleaseOpenGateError("traceability-review-invalid")
        expected = (
            ["owner-approved-waiver", "pass"]
            if review_id == "gpt-5.6-pro-web"
            else ["pass"]
        )
        if outcomes != expected:
            raise ReleaseOpenGateError("traceability-review-policy-invalid")
    if tuple(review_ids) != REQUIRED_REVIEW_IDS:
        raise ReleaseOpenGateError("traceability-review-coverage-invalid")
    if canonical_traceability_bytes(payload) != raw:
        raise ReleaseOpenGateError("traceability-not-canonical")
    return payload


def traceability_identity(
    path: Path = DEFAULT_TRACEABILITY,
    contract_path: Path = DEFAULT_CONTRACT,
) -> dict[str, object]:
    payload = load_traceability(path, contract_path)
    raw = canonical_traceability_bytes(payload)
    return {
        "name": path.name,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "sizeBytes": len(raw),
    }


def validate_evidence(payload: dict, path: Path = DEFAULT_CONTRACT) -> None:
    required = load_contract(path)["requiredOpenGateIds"]
    if payload.get("releaseEligible") is not False:
        raise ReleaseOpenGateError("evidence-release-state-invalid")
    gates = payload.get("openGates")
    if not isinstance(gates, list) or gates != required:
        raise ReleaseOpenGateError("evidence-open-gates-invalid")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        choices=("validate-contract", "validate-traceability", "validate-evidence"),
    )
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--traceability", type=Path, default=DEFAULT_TRACEABILITY)
    parser.add_argument("--evidence", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "validate-contract":
            print(json.dumps(contract_identity(args.contract), sort_keys=True))
        elif args.command == "validate-traceability":
            print(
                json.dumps(
                    traceability_identity(args.traceability, args.contract),
                    sort_keys=True,
                )
            )
        else:
            if args.evidence is None:
                raise ReleaseOpenGateError("evidence-required")
            payload = json.loads(args.evidence.read_text(encoding="utf-8"))
            validate_evidence(payload, args.contract)
            print(json.dumps({"releaseOpenGates": "pass"}, sort_keys=True))
        return 0
    except (OSError, UnicodeError, json.JSONDecodeError, ReleaseOpenGateError) as exc:
        print(json.dumps({"releaseOpenGateError": str(exc)}, sort_keys=True))
        return 4


if __name__ == "__main__":
    raise SystemExit(main())

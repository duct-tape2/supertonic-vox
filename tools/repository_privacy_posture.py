#!/usr/bin/env python3
"""Require either the exact recovery custody history or a zero-finding public history."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

import release_history_audit as audit


TOOLS = Path(__file__).resolve().parent
RECOVERY_MARKER = "AI_START_HERE.md"
EXPECTED = TOOLS / "recovery_history_expected_findings.json"


class PostureError(RuntimeError):
    pass


def canonical_findings(findings: list[dict[str, str]]) -> list[dict[str, str]]:
    required = {"category", "object", "path"}
    normalized: list[dict[str, str]] = []
    for finding in findings:
        if not isinstance(finding, dict) or set(finding) != required or not all(
            isinstance(finding[key], str) and finding[key] for key in required
        ):
            raise PostureError("history-finding-shape-invalid")
        normalized.append({key: finding[key] for key in sorted(required)})
    return sorted(
        normalized,
        key=lambda item: (item["category"], item["path"], item["object"]),
    )


def finding_set_sha256(findings: list[dict[str, str]]) -> str:
    payload = json.dumps(
        canonical_findings(findings),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def load_expected(path: Path) -> list[dict[str, str]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PostureError("recovery-ledger-unavailable") from exc
    if set(payload) != {"schemaVersion", "findings"} or payload["schemaVersion"] != 1:
        raise PostureError("recovery-ledger-shape-invalid")
    if not isinstance(payload["findings"], list) or not payload["findings"]:
        raise PostureError("recovery-ledger-empty")
    return canonical_findings(payload["findings"])


def evaluate(repo: Path) -> dict[str, object]:
    repo = repo.resolve(strict=True)
    privacy_rules = audit.privacy.load_rules(TOOLS / "release_privacy_rules.json")
    history_rules = audit.load_history_rules(TOOLS / "release_history_rules.json")
    raw = audit.audit_repository(repo, privacy_rules, history_rules)
    recovery_mode = (repo / RECOVERY_MARKER).is_file()
    if recovery_mode:
        expected = load_expected(EXPECTED)
        actual = canonical_findings(raw["findings"])
        if raw["status"] != "fail" or actual != expected:
            raise PostureError("recovery-history-drift")
        mode = "recovery-expected-custody-history"
    else:
        if raw["status"] != "pass" or raw["findingCount"] != 0:
            raise PostureError("public-history-not-clean")
        actual = canonical_findings(raw["findings"])
        mode = "public-clean-history"
    return {
        "schemaVersion": 1,
        "status": "pass",
        "mode": mode,
        "head": raw["head"],
        "rawStatus": raw["status"],
        "findingCount": raw["findingCount"],
        "findingSetSha256": finding_set_sha256(actual),
        "objectScope": raw["objectScope"],
        "localObjectCount": raw["localObjectCount"],
    }


def write_json_atomic(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{hashlib.sha256(str(path).encode()).hexdigest()[:12]}.tmp")
    try:
        temporary.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        result = evaluate(args.repo)
        if args.report:
            write_json_atomic(args.report.resolve(), result)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (PostureError, audit.HistoryAuditError, OSError, ValueError) as exc:
        print(json.dumps({"repositoryPrivacyPostureError": str(exc)}), file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())

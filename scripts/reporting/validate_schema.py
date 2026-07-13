#!/usr/bin/env python3
"""Validate SecureInfra public normalized-report.json files.

This command is intentionally dependency-free. It validates analyzer output
against the local public JSON schemas and performs lightweight contract checks
that are useful before a normalized report is consumed by downstream
tooling.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any


# Allow this helper to run from the repository root without requiring callers
# to set PYTHONPATH. The secureinfra package lives under SecureInfra_AI.
REPO_ROOT = Path(__file__).resolve().parents[2]
SECUREINFRA_REPORTING_ROOT = REPO_ROOT / "SecureInfra_AI" / "scripts" / "reporting"
if str(SECUREINFRA_REPORTING_ROOT) not in sys.path:
    sys.path.insert(0, str(SECUREINFRA_REPORTING_ROOT))

from secureinfra.validators.schema_validator import SchemaValidationError, validate_normalized_report


ALLOWED_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}
SAFETY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("customer project folder name", re.compile(r"customer-projects", re.IGNORECASE)),
    ("input bundle implementation label", re.compile(r"bundle_input", re.IGNORECASE)),
    ("private input bundle folder", re.compile(r"03-input-bundles", re.IGNORECASE)),
    ("private prompt label", re.compile(r"private\s+prompts?", re.IGNORECASE)),
    ("environment file name", re.compile(r"(?:^|[\\/])\.env(?:$|[\\/])", re.IGNORECASE)),
)
WINDOWS_DRIVE_PATTERN = re.compile(r"\b[A-Za-z]:\\")


class ContractValidationError(ValueError):
    """Raised when a normalized report violates public contract checks."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__("Normalized report contract validation failed:\n- " + "\n- ".join(errors))


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate a SecureInfra normalized-report.json file against the public schema contract.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s --input reports/output/normalized-report.json
  %(prog)s --input reports/output
  %(prog)s --input reports/output/normalized-report.json --strict-safety
""",
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to normalized-report.json or a directory containing normalized-report.json.",
    )
    parser.add_argument(
        "--schema-dir",
        help="Optional schema directory. Defaults to SecureInfra_AI/schemas.",
    )
    parser.add_argument(
        "--strict-safety",
        action="store_true",
        help=(
            "Fail if local/internal paths or non-public prompt markers appear anywhere in the report. "
            "Use this for release or handoff validation."
        ),
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Only print validation errors.",
    )
    return parser.parse_args(argv)


def resolve_input_path(raw_input: str | Path) -> Path:
    input_path = Path(raw_input)
    if input_path.is_dir():
        input_path = input_path / "normalized-report.json"
    return input_path


def load_report(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Normalized report not found: {path}")
    if not path.is_file():
        raise ValueError(f"Input must be a file or report directory: {path}")
    with path.open("r", encoding="utf-8-sig") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("Normalized report JSON root must be an object")
    return data


def validate_report_contract(report: dict[str, Any], *, strict_safety: bool = False) -> None:
    errors: list[str] = []
    findings = report.get("findings")
    if not isinstance(findings, list):
        errors.append("$.findings: expected array")
    else:
        validate_findings_contract(findings, errors)
        validate_summary_consistency(report, findings, errors)

    if strict_safety:
        validate_no_private_leaks(report, errors)

    if errors:
        raise ContractValidationError(errors)


def validate_findings_contract(findings: list[Any], errors: list[str]) -> None:
    finding_ids: list[str] = []
    for index, item in enumerate(findings):
        path = f"$.findings[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{path}: expected object")
            continue

        finding_id = item.get("finding_id")
        if isinstance(finding_id, str) and finding_id:
            finding_ids.append(finding_id)

        severity = item.get("severity")
        if severity not in ALLOWED_SEVERITIES:
            errors.append(f"{path}.severity: unsupported value {severity!r}")

        evidence = item.get("evidence")
        if isinstance(evidence, dict):
            for key in ("summary", "details", "confidence"):
                if key not in evidence:
                    errors.append(f"{path}.evidence.{key}: evidence contract field is missing")
        else:
            errors.append(f"{path}.evidence: expected object")

        if item.get("safe_to_auto_remediate") is True:
            reason = str(item.get("not_safe_for_auto_remediation_reason") or "").strip()
            if reason:
                errors.append(
                    f"{path}.safe_to_auto_remediate: true conflicts with not_safe_for_auto_remediation_reason"
                )

    duplicate_ids = sorted(identifier for identifier, count in Counter(finding_ids).items() if count > 1)
    for finding_id in duplicate_ids:
        errors.append(f"$.findings: duplicate finding_id {finding_id!r}")


def validate_summary_consistency(report: dict[str, Any], findings: list[Any], errors: list[str]) -> None:
    summary = report.get("summary")
    if not isinstance(summary, dict):
        return

    finding_count = len([item for item in findings if isinstance(item, dict)])
    for key in ("normalized_finding_count", "total_findings"):
        value = summary.get(key)
        if isinstance(value, int) and value != finding_count:
            errors.append(f"$.summary.{key}: expected {finding_count}, got {value}")

    severity_counts = summary.get("severity_counts")
    if isinstance(severity_counts, dict):
        actual_counts = Counter(
            item.get("severity") for item in findings if isinstance(item, dict) and item.get("severity") in ALLOWED_SEVERITIES
        )
        for severity, expected_count in severity_counts.items():
            if severity not in ALLOWED_SEVERITIES:
                errors.append(f"$.summary.severity_counts.{severity}: unsupported severity bucket")
                continue
            if isinstance(expected_count, int) and expected_count != actual_counts.get(severity, 0):
                errors.append(
                    f"$.summary.severity_counts.{severity}: expected {actual_counts.get(severity, 0)}, got {expected_count}"
                )


def validate_no_private_leaks(report: dict[str, Any], errors: list[str]) -> None:
    for path, value in iter_strings(report):
        for label, pattern in SAFETY_PATTERNS:
            if pattern.search(value):
                errors.append(f"{path}: contains {label}")
        if WINDOWS_DRIVE_PATTERN.search(value):
            errors.append(f"{path}: contains local Windows drive path")


def iter_strings(value: Any, path: str = "$") -> list[tuple[str, str]]:
    if isinstance(value, str):
        return [(path, value)]
    if isinstance(value, dict):
        results: list[tuple[str, str]] = []
        for key, child in value.items():
            safe_key = str(key).replace("~", "~0").replace("/", "~1")
            results.extend(iter_strings(child, f"{path}/{safe_key}"))
        return results
    if isinstance(value, list):
        results = []
        for index, child in enumerate(value):
            results.extend(iter_strings(child, f"{path}/{index}"))
        return results
    return []


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    input_path = resolve_input_path(args.input)
    try:
        report = load_report(input_path)
        validate_normalized_report(report, schema_dir=args.schema_dir)
        validate_report_contract(report, strict_safety=args.strict_safety)
    except (OSError, json.JSONDecodeError, ValueError, SchemaValidationError, ContractValidationError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if not args.quiet:
        findings = report.get("findings") if isinstance(report.get("findings"), list) else []
        strict_label = " with strict safety checks" if args.strict_safety else ""
        print(f"Normalized report validation passed{strict_label}: {input_path}")
        print(f"Findings validated: {len(findings)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

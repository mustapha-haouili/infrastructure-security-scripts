"""Compare normalized SecureInfra AI reports across runs."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from secureinfra.risk_engine.rules import SEVERITY_RANK


VALID_SEVERITIES = set(SEVERITY_RANK)


def add_history_comparison(
    current_report: dict[str, Any],
    previous_report: dict[str, Any],
    previous_source_file: str | Path | None = None,
) -> dict[str, Any]:
    """Attach deterministic history comparison data to a normalized report."""
    comparison = build_history_comparison(current_report, previous_report, previous_source_file)
    current_report["history_comparison"] = comparison
    current_report.setdefault("summary", {})["new_finding_count"] = comparison["new_count"]
    current_report.setdefault("summary", {})["persistent_finding_count"] = comparison["persistent_count"]
    current_report.setdefault("summary", {})["resolved_finding_count"] = comparison["resolved_count"]
    return current_report


def build_history_comparison(
    current_report: dict[str, Any],
    previous_report: dict[str, Any],
    previous_source_file: str | Path | None = None,
) -> dict[str, Any]:
    current_findings = finding_map(current_report)
    previous_findings = finding_map(previous_report)
    current_ids = set(current_findings)
    previous_ids = set(previous_findings)

    new_ids = sort_ids(current_ids - previous_ids, current_findings)
    persistent_ids = sort_ids(current_ids & previous_ids, current_findings)
    resolved_ids = sort_ids(previous_ids - current_ids, previous_findings)

    current_report_id = string_value(current_report.get("report_id")) or "current-report"
    previous_report_id = string_value(previous_report.get("report_id")) or "previous-report"

    return {
        "comparison_id": f"secureinfra-history-{current_report_id}",
        "current_report_id": current_report_id,
        "previous_report_id": previous_report_id,
        "previous_source_file": string_value(previous_source_file),
        "current_generated_at_utc": string_value(current_report.get("generated_at_utc")),
        "previous_generated_at_utc": string_value(previous_report.get("generated_at_utc")),
        "matched_on": "finding_id",
        "new_finding_ids": new_ids,
        "persistent_finding_ids": persistent_ids,
        "resolved_finding_ids": resolved_ids,
        "new_count": len(new_ids),
        "persistent_count": len(persistent_ids),
        "resolved_count": len(resolved_ids),
        "resolved_findings": [finding_summary(previous_findings[finding_id]) for finding_id in resolved_ids],
        "notes": [
            "Comparison is deterministic and based on finding_id.",
            "Resolved findings are present in the previous report but not in the current report.",
        ],
    }


def finding_map(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    findings = report.get("findings", [])
    if not isinstance(findings, list):
        return {}

    mapped: dict[str, dict[str, Any]] = {}
    for item in findings:
        if not isinstance(item, dict):
            continue
        finding_id = string_value(item.get("finding_id"))
        if finding_id and finding_id not in mapped:
            mapped[finding_id] = item
    return mapped


def finding_summary(finding: dict[str, Any]) -> dict[str, str]:
    return {
        "finding_id": string_value(finding.get("finding_id")),
        "title": string_value(finding.get("title")) or "Previous finding",
        "severity": normalize_severity(finding.get("severity")),
        "affected_object": string_value(finding.get("affected_object")),
        "source_script": string_value(finding.get("source_script")),
    }


def sort_ids(finding_ids: set[str], findings: dict[str, dict[str, Any]]) -> list[str]:
    return sorted(
        finding_ids,
        key=lambda finding_id: (
            SEVERITY_RANK.get(normalize_severity(findings.get(finding_id, {}).get("severity")), 99),
            finding_id,
        ),
    )


def normalize_severity(value: Any) -> str:
    severity = string_value(value)
    return severity if severity in VALID_SEVERITIES else "Info"


def string_value(value: Any) -> str:
    return "" if value is None else str(value)

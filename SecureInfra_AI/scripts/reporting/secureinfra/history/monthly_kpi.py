"""Deterministic monthly KPI summaries for normalized reports."""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from typing import Any

from secureinfra.risk_engine.rules import SEVERITY_RANK


SEVERITIES = ["Critical", "High", "Medium", "Low", "Info", "Hold"]
TREND_WEIGHTS = {
    "Critical": {"resolved": 25, "new": -25, "persistent": -10},
    "High": {"resolved": 10, "new": -10, "persistent": -4},
}


def add_monthly_kpi_summary(
    current_report: dict[str, Any],
    previous_report: dict[str, Any] | None = None,
    previous_source_file: str | Path | None = None,
) -> dict[str, Any]:
    """Attach a deterministic monthly KPI summary to a normalized report."""
    monthly_summary = build_monthly_kpi_summary(current_report, previous_report, previous_source_file)
    current_report["monthly_kpi_summary"] = monthly_summary
    current_report.setdefault("summary", {})["monthly_risk_reduction_score"] = monthly_summary["risk_reduction_score"]
    return current_report


def build_monthly_kpi_summary(
    current_report: dict[str, Any],
    previous_report: dict[str, Any] | None = None,
    previous_source_file: str | Path | None = None,
) -> dict[str, Any]:
    current_findings = normalized_findings(current_report)
    previous_findings = normalized_findings(previous_report or {})
    severity_counts = Counter(normalize_severity(item.get("severity")) for item in current_findings)

    if previous_report:
        match_result = match_findings(current_findings, previous_findings)
        new_findings = [current_findings[index] for index in sorted(match_result["new_current_indexes"])]
        persistent_findings = [
            with_match_metadata(current_findings[current_index], matched_on, confidence)
            for current_index, _previous_index, matched_on, confidence in match_result["matches"]
        ]
        resolved_findings = [previous_findings[index] for index in sorted(match_result["resolved_previous_indexes"])]
        comparison_mode = "comparison"
    else:
        match_result = empty_match_result(current_findings)
        new_findings = []
        persistent_findings = []
        resolved_findings = []
        comparison_mode = "baseline"

    risk_score, score_components = risk_reduction_score(new_findings, persistent_findings, resolved_findings, previous_report is not None)
    limitations = build_limitations(comparison_mode, match_result)

    return {
        "schema_version": "1.0",
        "comparison_mode": comparison_mode,
        "current_report_id": text_value(current_report.get("report_id")) or "current-report",
        "previous_report_id": text_value((previous_report or {}).get("report_id")) if previous_report else "",
        "previous_source_file": text_value(previous_source_file),
        "generated_at_utc": text_value(current_report.get("generated_at_utc")),
        "total_findings": len(current_findings),
        "critical_count": severity_counts.get("Critical", 0),
        "high_count": severity_counts.get("High", 0),
        "medium_count": severity_counts.get("Medium", 0),
        "low_count": severity_counts.get("Low", 0),
        "info_count": severity_counts.get("Info", 0),
        "hold_count": severity_counts.get("Hold", 0),
        "new_findings": [finding_summary(item) for item in sorted_findings(new_findings)],
        "persistent_findings": [finding_summary(item) for item in sorted_findings(persistent_findings)],
        "resolved_findings": [finding_summary(item) for item in sorted_findings(resolved_findings)],
        "risk_reduction_score": risk_score,
        "risk_reduction_score_components": score_components,
        "risk_reduction_explanation": (
            "Simple deterministic trend indicator: resolved Critical/High findings add points; "
            "new Critical/High findings subtract points; persistent Critical/High findings subtract smaller points. "
            "It is not a formal risk score."
        ),
        "top_5_current_risks": [finding_summary(item) for item in sorted_findings(current_findings)[:5]],
        "top_5_recommended_actions": recommended_actions(sorted_findings(current_findings)),
        "coverage_summary": coverage_summary(current_report, current_findings),
        "evidence_gaps": evidence_gaps(current_report),
        "limitations": limitations,
        "matching_summary": {
            "matched_by_finding_id": match_result["matched_by_finding_id"],
            "matched_by_fallback_fingerprint": match_result["matched_by_fallback_fingerprint"],
            "new_count": len(new_findings),
            "persistent_count": len(persistent_findings),
            "resolved_count": len(resolved_findings),
            "ambiguous_fallback_fingerprint_count": match_result["ambiguous_fallback_fingerprint_count"],
            "unmatched_current_count": len(match_result["new_current_indexes"]),
            "unmatched_previous_count": len(match_result["resolved_previous_indexes"]),
        },
    }


def match_findings(current_findings: list[dict[str, Any]], previous_findings: list[dict[str, Any]]) -> dict[str, Any]:
    current_unmatched = set(range(len(current_findings)))
    previous_unmatched = set(range(len(previous_findings)))
    matches: list[tuple[int, int, str, str]] = []

    current_ids = unique_key_map(current_findings, finding_id_key)
    previous_ids = unique_key_map(previous_findings, finding_id_key)

    for finding_id in sorted(set(current_ids) & set(previous_ids)):
        current_index = current_ids[finding_id]
        previous_index = previous_ids[finding_id]
        matches.append((current_index, previous_index, "finding_id", "high"))
        current_unmatched.discard(current_index)
        previous_unmatched.discard(previous_index)

    current_fingerprints = unique_key_map(current_findings, fallback_fingerprint, current_unmatched)
    previous_fingerprints = unique_key_map(previous_findings, fallback_fingerprint, previous_unmatched)

    fallback_matches = 0
    for fingerprint in sorted(set(current_fingerprints) & set(previous_fingerprints)):
        current_index = current_fingerprints[fingerprint]
        previous_index = previous_fingerprints[fingerprint]
        matches.append((current_index, previous_index, "fallback_fingerprint", "medium"))
        fallback_matches += 1
        current_unmatched.discard(current_index)
        previous_unmatched.discard(previous_index)

    return {
        "matches": sorted(matches, key=lambda item: (item[0], item[1])),
        "new_current_indexes": current_unmatched,
        "resolved_previous_indexes": previous_unmatched,
        "matched_by_finding_id": len([item for item in matches if item[2] == "finding_id"]),
        "matched_by_fallback_fingerprint": fallback_matches,
        "ambiguous_fallback_fingerprint_count": ambiguous_fingerprint_count(current_findings, previous_findings),
    }


def empty_match_result(current_findings: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "matches": [],
        "new_current_indexes": set(),
        "resolved_previous_indexes": set(),
        "matched_by_finding_id": 0,
        "matched_by_fallback_fingerprint": 0,
        "ambiguous_fallback_fingerprint_count": 0,
        "baseline_current_count": len(current_findings),
    }


def unique_key_map(
    findings: list[dict[str, Any]],
    key_func: Any,
    allowed_indexes: set[int] | None = None,
) -> dict[str, int]:
    grouped: dict[str, list[int]] = {}
    indexes = allowed_indexes if allowed_indexes is not None else set(range(len(findings)))
    for index in indexes:
        key = key_func(findings[index])
        if key:
            grouped.setdefault(key, []).append(index)
    return {key: indexes[0] for key, indexes in grouped.items() if len(indexes) == 1}


def ambiguous_fingerprint_count(current_findings: list[dict[str, Any]], previous_findings: list[dict[str, Any]]) -> int:
    total = 0
    for findings in (current_findings, previous_findings):
        grouped: dict[str, int] = {}
        for finding in findings:
            key = fallback_fingerprint(finding)
            if key:
                grouped[key] = grouped.get(key, 0) + 1
        total += sum(count for count in grouped.values() if count > 1)
    return total


def risk_reduction_score(
    new_findings: list[dict[str, Any]],
    persistent_findings: list[dict[str, Any]],
    resolved_findings: list[dict[str, Any]],
    has_previous_report: bool,
) -> tuple[int, dict[str, int]]:
    if not has_previous_report:
        return 0, {
            "resolved_critical_high_points": 0,
            "new_critical_high_points": 0,
            "persistent_critical_high_points": 0,
        }

    resolved_points = weighted_points(resolved_findings, "resolved")
    new_points = weighted_points(new_findings, "new")
    persistent_points = weighted_points(persistent_findings, "persistent")
    return resolved_points + new_points + persistent_points, {
        "resolved_critical_high_points": resolved_points,
        "new_critical_high_points": new_points,
        "persistent_critical_high_points": persistent_points,
    }


def weighted_points(findings: list[dict[str, Any]], trend: str) -> int:
    total = 0
    for finding in findings:
        severity = normalize_severity(finding.get("severity"))
        total += TREND_WEIGHTS.get(severity, {}).get(trend, 0)
    return total


def coverage_summary(report: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    report_type = text_value(report.get("report_type")) or "unknown"
    metadata = report.get("metadata") if isinstance(report.get("metadata"), dict) else {}
    report_type_metadata = report.get("report_type_metadata") if isinstance(report.get("report_type_metadata"), dict) else {}
    analyzer_type = (
        text_value(metadata.get("normalizer"))
        or text_value(report_type_metadata.get("report_type"))
        or text_value(report.get("tool_name"))
        or "unknown"
    )

    source_script_counts: Counter[str] = Counter()
    report_type_counts: Counter[str] = Counter()
    analyzer_type_counts: Counter[str] = Counter()
    host_counts: Counter[str] = Counter()

    for finding in findings:
        evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
        source_script_counts[text_value(finding.get("source_script")) or "Not provided"] += 1
        report_type_counts[text_value(evidence.get("source_report_type")) or report_type] += 1
        analyzer_type_counts[analyzer_type] += 1
        host_counts[source_host_for(finding, report)] += 1

    return {
        "source_file_count": len([item for item in report.get("source_files", []) if item]) if isinstance(report.get("source_files"), list) else 0,
        "by_source_script": count_rows(source_script_counts, "source_script"),
        "by_report_type": count_rows(report_type_counts, "report_type"),
        "by_analyzer_type": count_rows(analyzer_type_counts, "analyzer_type"),
        "by_source_host": count_rows(host_counts, "source_host"),
    }


def evidence_gaps(report: dict[str, Any]) -> list[str]:
    gaps: list[str] = []
    metadata_sources = [
        report.get("metadata") if isinstance(report.get("metadata"), dict) else {},
        report.get("report_type_metadata") if isinstance(report.get("report_type_metadata"), dict) else {},
    ]

    if not report.get("source_files"):
        gaps.append("No source files were listed in the normalized report.")

    for metadata in metadata_sources:
        missing_files = metadata.get("missing_files")
        if isinstance(missing_files, list):
            for item in missing_files:
                gaps.append(f"Missing optional evidence file: {text_value(item)}")

        failed_files = metadata.get("failed_files")
        if isinstance(failed_files, dict):
            for key, value in sorted(failed_files.items()):
                gaps.append(f"Failed evidence file: {text_value(key)} ({text_value(value)})")

        failed_bundles = metadata.get("failed_bundles")
        if isinstance(failed_bundles, list):
            for item in failed_bundles:
                if isinstance(item, dict):
                    gaps.append(f"Failed bundle: {text_value(item.get('input'))} ({text_value(item.get('error'))})")

        coverage_matrix = metadata.get("coverage_matrix")
        if isinstance(coverage_matrix, list):
            for row in coverage_matrix:
                if not isinstance(row, dict):
                    continue
                status = text_value(row.get("status"))
                missing = row.get("required_missing") if isinstance(row.get("required_missing"), list) else []
                if status in {"Needs rerun", "Failed", "Partial"} or missing:
                    detail = ", ".join(text_value(item) for item in missing) if missing else status
                    gaps.append(
                        f"Coverage gap for {text_value(row.get('machine_name')) or 'unknown host'} "
                        f"{text_value(row.get('scope')) or 'unknown scope'}: {detail}"
                    )

    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    if int_value(summary.get("failed_file_count")) > 0:
        gaps.append(f"Failed file count reported by analyzer: {int_value(summary.get('failed_file_count'))}")
    if int_value(summary.get("missing_optional_file_count")) > 0:
        gaps.append(f"Missing optional file count reported by analyzer: {int_value(summary.get('missing_optional_file_count'))}")

    return unique(gaps) or ["No evidence gaps were identified in the supplied normalized report metadata."]


def build_limitations(comparison_mode: str, match_result: dict[str, Any]) -> list[str]:
    limitations = [
        "Monthly KPI output is deterministic, local, and based only on supplied normalized reports.",
        "Risk reduction score is a simple trend indicator, not a formal risk score.",
        "This summary does not claim compliance, certification, audit attestation, or official audit status.",
    ]
    if comparison_mode == "baseline":
        limitations.append("No previous normalized report was supplied; trend fields are baseline-only.")
    else:
        limitations.append("Findings are matched by stable finding_id first, then by a conservative unique fallback fingerprint.")
    if match_result.get("matched_by_fallback_fingerprint", 0):
        limitations.append(
            f"Fallback fingerprint matching was used for {match_result['matched_by_fallback_fingerprint']} finding(s); review those trend matches before treating them as exact continuations."
        )
    if match_result.get("ambiguous_fallback_fingerprint_count", 0):
        limitations.append(
            f"{match_result['ambiguous_fallback_fingerprint_count']} finding entries had ambiguous fallback fingerprints and were not overmatched."
        )
    return limitations


def recommended_actions(findings: list[dict[str, Any]]) -> list[dict[str, str]]:
    actions = []
    seen: set[str] = set()
    for finding in findings:
        action = text_value(finding.get("recommendation"))
        if not action or action in seen:
            continue
        seen.add(action)
        actions.append(
            {
                "finding_id": text_value(finding.get("finding_id")),
                "severity": normalize_severity(finding.get("severity")),
                "affected_object": text_value(finding.get("affected_object")),
                "action": action,
            }
        )
        if len(actions) == 5:
            break
    return actions


def finding_summary(finding: dict[str, Any]) -> dict[str, str]:
    summary = {
        "finding_id": text_value(finding.get("finding_id")),
        "title": text_value(finding.get("title")) or "Finding requires review",
        "category": text_value(finding.get("category")),
        "severity": normalize_severity(finding.get("severity")),
        "affected_object": text_value(finding.get("affected_object")),
        "source_script": text_value(finding.get("source_script")),
        "recommendation": text_value(finding.get("recommendation")),
    }
    if finding.get("matched_on"):
        summary["matched_on"] = text_value(finding.get("matched_on"))
    if finding.get("match_confidence"):
        summary["match_confidence"] = text_value(finding.get("match_confidence"))
    return summary


def sorted_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        findings,
        key=lambda item: (
            SEVERITY_RANK.get(normalize_severity(item.get("severity")), 99),
            text_value(item.get("finding_id")),
            text_value(item.get("title")),
        ),
    )


def normalized_findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    findings = report.get("findings", [])
    return [item for item in findings if isinstance(item, dict)] if isinstance(findings, list) else []


def finding_id_key(finding: dict[str, Any]) -> str:
    return normalize_key(finding.get("finding_id"))


def fallback_fingerprint(finding: dict[str, Any]) -> str:
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    category = normalize_key(finding.get("category"))
    title = normalize_key(finding.get("title"))
    affected_object = normalize_key(finding.get("affected_object"))
    source = normalize_key(finding.get("source_script") or evidence.get("source_report_type"))
    if not category or not title:
        return ""
    if not affected_object or not source:
        return ""
    return "|".join([category, title, affected_object, source])


def with_match_metadata(finding: dict[str, Any], matched_on: str, confidence: str) -> dict[str, Any]:
    output = dict(finding)
    output["matched_on"] = matched_on
    output["match_confidence"] = confidence
    return output


def source_host_for(finding: dict[str, Any], report: dict[str, Any]) -> str:
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    environment = report.get("environment_summary") if isinstance(report.get("environment_summary"), dict) else {}
    for key in ["machine_name", "computer_name", "source_host", "host_name", "hostname"]:
        value = text_value(evidence.get(key))
        if value:
            return value
    return text_value(environment.get("computer_name")) or "Not provided"


def count_rows(counter: Counter[str], label: str) -> list[dict[str, Any]]:
    return [{label: key, "finding_count": counter[key]} for key in sorted(counter)]


def normalize_severity(value: Any) -> str:
    severity = text_value(value)
    return severity if severity in SEVERITIES else "Info"


def normalize_key(value: Any) -> str:
    text = text_value(value).lower()
    text = re.sub(r"[^a-z0-9_.-]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def text_value(value: Any) -> str:
    return "" if value is None else str(value).strip()


def int_value(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def unique(values: list[str]) -> list[str]:
    output = []
    seen = set()
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output

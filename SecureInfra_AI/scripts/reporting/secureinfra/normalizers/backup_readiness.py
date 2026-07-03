"""Normalize backup readiness audit reports."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from secureinfra.normalizers.ad_common import build_common_finding, normalize_source_severity, severity_counts, utc_now
from secureinfra.normalizers.evidence_contract import normalize_report_evidence_contract


def normalize_backup_readiness(data: dict[str, Any], source_file: str | Path) -> dict[str, Any]:
    """Normalize Windows or Linux backup readiness collector JSON."""
    if not isinstance(data, dict):
        raise ValueError("backup-readiness input must be a JSON object")

    rows = data.get("Findings") or data.get("findings") or []
    if not isinstance(rows, list):
        raise ValueError("backup-readiness input must contain a Findings list")

    source_path = Path(source_file)
    timestamp_utc = generated_at_utc(data)
    source_script_name = source_script(data)
    platform = str(first_value(data, ["Platform", "platform"], "") or "").lower()
    host_name = host_name_for(data)
    findings = [
        normalize_backup_finding(row, index, data, source_path, source_script_name, timestamp_utc)
        for index, row in enumerate(rows, start=1)
        if isinstance(row, dict)
    ]
    source_summary = as_dict(data.get("Summary") or data.get("summary"))
    evidence_summary = summarize_backup_evidence(data)

    return normalize_report_evidence_contract(
        {
            "report_id": f"secureinfra-ai-backup-readiness-{timestamp_utc.replace(':', '').replace('-', '')}",
            "report_type": "backup-readiness",
            "tool_name": "SecureInfra AI Backup Readiness Analyzer",
            "source_files": [str(source_path)],
            "generated_at_utc": timestamp_utc,
            "environment_summary": {
                "company": "",
                "domain": str(first_value(data, ["Domain", "DomainName"], "")),
                "computer_name": host_name,
                "source_host": host_name,
                "platform": platform,
                "scope": "Backup",
                "source_script": source_script_name,
                "source_report_type": str(first_value(data, ["ReportType", "report_type"], "backup-readiness")),
                "input_finding_count": len(rows),
            },
            "summary": {
                "total_findings": len(findings),
                "normalized_finding_count": len(findings),
                "severity_counts": severity_counts(findings),
                "source_summary": source_summary,
                "backup_evidence_summary": evidence_summary,
            },
            "report_type_metadata": {
                "report_type": "backup-readiness",
                "scope": "Backup",
                "platform": platform,
                "source_file": str(source_path),
                "source_script": source_script_name,
                "source_report_type": str(first_value(data, ["ReportType", "report_type"], "backup-readiness")),
                "source_summary": source_summary,
                "backup_evidence_summary": evidence_summary,
                "normalizer_status": "beta",
            },
            "findings": findings,
            "metadata": {
                "normalizer": "backup_readiness",
                "normalizer_version": "0.1.0",
                "risk_engine": "source-priority-mapping",
                "ai_required": False,
                "scope": "Backup",
                "source_report_type": "backup-readiness",
                "schema": "backup-readiness.schema.json",
            },
            "notes": [
                "This beta backup readiness normalizer is report-only and does not change backup systems.",
                "Backup readiness evidence is metadata-only and does not include backup contents.",
                "Service, tool, timer, or path presence is not proof of successful or recoverable backups.",
                "Restore testing and backup monitoring require owner-provided evidence.",
            ],
        }
    )


def normalize_backup_finding(
    row: dict[str, Any],
    index: int,
    data: dict[str, Any],
    source_file: Path,
    source_script_name: str,
    timestamp_utc: str,
) -> dict[str, Any]:
    finding_type = str(first_value(row, ["FindingType", "finding_type", "Id", "id"], "BackupReadinessReview"))
    severity = conservative_backup_severity(finding_type, first_value(row, ["Severity", "severity"], "Info"))
    affected_object = str(first_value(row, ["AffectedObject", "affected_object", "Path", "path", "Name", "name"], host_name_for(data)))
    title = str(first_value(row, ["Title", "title"], title_for_type(finding_type)))
    recommendation = str(first_value(row, ["Recommendation", "recommendation"], recommendation_for_type(finding_type)))
    evidence_text = str(first_value(row, ["Evidence", "evidence"], "Backup readiness evidence requires owner review."))
    evidence = compact_source_facts(row)
    evidence.update(
        {
            "scope": "Backup",
            "platform": str(first_value(data, ["Platform", "platform"], "") or "").lower(),
            "computer_name": host_name_for(data),
            "source_file": str(source_file),
            "backup_evidence_source": str(first_value(row, ["BackupEvidenceSource", "backup_evidence_source"], "")),
            "backup_evidence_confidence": str(first_value(row, ["BackupEvidenceConfidence", "backup_evidence_confidence"], "low")),
            "last_backup_evidence_timestamp": str(
                first_value(row, ["LastBackupEvidenceTimestamp", "last_backup_evidence_timestamp"], "")
            ),
            "restore_test_evidence_status": str(
                first_value(row, ["RestoreTestEvidenceStatus", "restore_test_evidence_status"], "")
            ),
            "monitoring_evidence_status": str(
                first_value(row, ["MonitoringEvidenceStatus", "monitoring_evidence_status"], "")
            ),
            "limitations": list_values(first_value(row, ["Limitations", "limitations"], [])),
        }
    )

    return build_common_finding(
        finding_id=backup_finding_id(finding_type, index),
        title=title,
        category="Backup Readiness",
        severity=severity,
        affected_object=affected_object,
        object_type=object_type_for(finding_type),
        source_script_name=source_script_name,
        evidence=evidence,
        risk_factors=risk_factors_for(row, finding_type),
        business_impact=business_impact_for(finding_type),
        technical_impact=technical_impact_for(finding_type, evidence_text),
        recommendation=recommendation,
        timestamp_utc=timestamp_utc,
        safety_reason="Backup remediation, restore operations, and backup configuration changes require owner review and approved change control.",
    )


def conservative_backup_severity(finding_type: str, source_severity: Any) -> str:
    normalized = normalize_source_severity(source_severity)
    lower_type = finding_type.lower()
    if normalized == "Critical" and "critical" not in lower_type and "severe" not in lower_type:
        return "High"
    if lower_type in {"expectedbackuppathmissing", "expectedbackuppathstale"}:
        return "High"
    if lower_type in {"restoretestevidencemissing", "backupmonitoringevidencemissing", "backupconfigurationreviewrequired"}:
        return "Medium" if normalized in {"Critical", "High", "Medium", "Info"} else normalized
    if lower_type in {"backupevidenceunavailable", "backupservicepresenthealthunverified"}:
        return "Info"
    return normalized


def backup_finding_id(finding_type: str, index: int) -> str:
    sanitized = sanitize_id(finding_type)
    if sanitized:
        return f"BACKUP-READINESS-{sanitized}-{index:04d}"
    return f"BACKUP-READINESS-{index:04d}"


def title_for_type(finding_type: str) -> str:
    return {
        "BackupEvidenceUnavailable": "Backup readiness evidence is unavailable or incomplete",
        "NoRecentBackupEvidenceFound": "No recent backup evidence was found",
        "BackupServicePresentHealthUnverified": "Backup-related service is present but health is unverified",
        "ExpectedBackupPathMissing": "Expected backup path is missing",
        "ExpectedBackupPathStale": "Expected backup path is stale",
        "RestoreTestEvidenceMissing": "Restore test evidence was not provided",
        "BackupMonitoringEvidenceMissing": "Backup monitoring evidence was not provided",
        "BackupConfigurationReviewRequired": "Backup configuration review is required",
    }.get(finding_type, "Backup readiness evidence requires review")


def recommendation_for_type(finding_type: str) -> str:
    return {
        "BackupEvidenceUnavailable": "Provide approved backup job history, monitoring evidence, or expected backup path metadata for review.",
        "NoRecentBackupEvidenceFound": "Confirm the most recent successful backup with the owner and collect authoritative job history.",
        "BackupServicePresentHealthUnverified": "Validate backup job history, alerts, and restore test evidence before relying on service presence.",
        "ExpectedBackupPathMissing": "Confirm the backup target, mount state, permissions, and expected backup job ownership.",
        "ExpectedBackupPathStale": "Validate the backup schedule, storage target, and monitoring alerts before relying on this backup evidence.",
        "RestoreTestEvidenceMissing": "Confirm the date, scope, and result of the latest approved restore test.",
        "BackupMonitoringEvidenceMissing": "Confirm backup monitoring ownership, alert routing, and failure escalation procedures.",
        "BackupConfigurationReviewRequired": "Confirm backup tool installation, job ownership, and monitoring with the system owner.",
    }.get(finding_type, "Review backup readiness evidence with the system owner.")


def object_type_for(finding_type: str) -> str:
    lower_type = finding_type.lower()
    if "path" in lower_type:
        return "Backup evidence path"
    if "service" in lower_type or "software" in lower_type:
        return "Backup service or tool signal"
    if "restore" in lower_type:
        return "Restore test evidence"
    if "monitoring" in lower_type:
        return "Backup monitoring evidence"
    return "Backup readiness evidence"


def risk_factors_for(row: dict[str, Any], finding_type: str) -> list[str]:
    factors = ["Backup readiness", finding_type]
    for key in ["BackupEvidenceSource", "BackupEvidenceConfidence", "RestoreTestEvidenceStatus", "MonitoringEvidenceStatus", "Severity"]:
        value = first_value(row, [key], "")
        if value not in (None, ""):
            factors.append(str(value))
    return list(dict.fromkeys(factors))


def business_impact_for(finding_type: str) -> str:
    lower_type = finding_type.lower()
    if "missing" in lower_type or "stale" in lower_type or "recent" in lower_type:
        return "Incomplete or stale backup evidence can reduce confidence in recovery readiness during an outage or incident."
    if "service" in lower_type:
        return "Visible backup services help identify backup tooling, but do not prove that recovery objectives can be met."
    return "Backup readiness gaps can make recovery planning less predictable until owners provide authoritative evidence."


def technical_impact_for(finding_type: str, evidence_text: str) -> str:
    lower_type = finding_type.lower()
    if "restore" in lower_type:
        return "The source evidence did not include proof that backups have been restored successfully in an approved test."
    if "monitoring" in lower_type:
        return "The source evidence did not include proof that backup failures are monitored and escalated."
    if "service" in lower_type:
        return "The source evidence identified backup-related services or tools, but job status and restoreability remain unverified."
    return evidence_text


def summarize_backup_evidence(data: dict[str, Any]) -> dict[str, Any]:
    summary = as_dict(data.get("Summary") or data.get("summary"))
    evidence = as_dict(data.get("BackupEvidence") or data.get("backup_evidence"))
    return {
        "backup_health_status": str(summary.get("BackupHealthStatus") or summary.get("backup_health_status") or "Unverified"),
        "backup_evidence_source_count": len(evidence),
        "last_backup_evidence_timestamp": str(
            summary.get("LastBackupEvidenceTimestamp") or summary.get("last_backup_evidence_timestamp") or ""
        ),
        "restore_test_evidence_status": str(
            summary.get("RestoreTestEvidenceStatus") or summary.get("restore_test_evidence_status") or ""
        ),
        "monitoring_evidence_status": str(
            summary.get("MonitoringEvidenceStatus") or summary.get("monitoring_evidence_status") or ""
        ),
    }


def generated_at_utc(data: dict[str, Any]) -> str:
    return str(first_value(data, ["GeneratedAtUtc", "generated_at_utc"], "") or utc_now())


def source_script(data: dict[str, Any]) -> str:
    return str(first_value(data, ["ToolName", "tool_name", "SourceScript", "source_script"], "backup-readiness-audit"))


def host_name_for(data: dict[str, Any]) -> str:
    return str(first_value(data, ["ComputerName", "HostName", "hostname", "host"], "backup-readiness-target"))


def first_value(data: dict[str, Any], keys: list[str], default: Any = None) -> Any:
    lower_map = {key.lower(): key for key in data}
    for key in keys:
        actual = lower_map.get(key.lower())
        if actual is not None and data.get(actual) not in (None, ""):
            return data[actual]
    return default


def compact_source_facts(row: dict[str, Any]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in row.items():
        if value in (None, ""):
            continue
        if isinstance(value, list) and not value:
            continue
        output[to_snake_case(key)] = value
    return output


def list_values(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    if value in (None, ""):
        return []
    return [str(value)]


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def sanitize_id(value: Any) -> str:
    text = str(value or "").strip().upper()
    if not text:
        return ""
    return "".join(char if char.isalnum() else "-" for char in text).strip("-")[:48]


def to_snake_case(value: str) -> str:
    output = []
    for index, char in enumerate(str(value)):
        if char.isupper() and index > 0 and output[-1] != "_":
            output.append("_")
        if char in {" ", "-", "."}:
            output.append("_")
        else:
            output.append(char.lower())
    return "".join(output).strip("_")

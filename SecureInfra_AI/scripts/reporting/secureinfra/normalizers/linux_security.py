"""Linux host security audit normalizer."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from secureinfra.normalizers.ad_common import (
    build_common_finding,
    normalize_source_severity,
    severity_counts,
    utc_now,
)
from secureinfra.normalizers.evidence_contract import normalize_report_evidence_contract


LINUX_SECURITY_SOURCE_SCRIPT = "linux-security-audit.sh"


def normalize_linux_security_audit(data: dict[str, Any], source_file: Path) -> dict[str, Any]:
    """Normalize linux-security-audit.sh summary JSON output."""
    findings = normalize_linux_security_findings(data, source_file)
    generated_at = generated_at_utc(data)
    return normalize_report_evidence_contract(
        {
            "report_id": f"secureinfra-ai-linux-security-{generated_at.replace(':', '').replace('-', '')}",
            "report_type": "linux-security-audit",
            "tool_name": "SecureInfra AI Linux Security Normalizer",
            "source_files": [str(source_file)],
            "generated_at_utc": generated_at,
            "environment_summary": {
                "host": host_name_for(data),
                "platform": "linux",
                "source_script": LINUX_SECURITY_SOURCE_SCRIPT,
                "root_context": data.get("root_context"),
                "quick_mode": data.get("quick_mode"),
                "input_record_count": len(source_findings(data)),
            },
            "summary": {
                "total_findings": len(findings),
                "normalized_finding_count": len(findings),
                "severity_counts": severity_counts(findings),
                "source_summary": {
                    "finding_counts": data.get("finding_counts", {}),
                    "root_context": data.get("root_context"),
                    "quick_mode": data.get("quick_mode"),
                },
            },
            "findings": findings,
            "metadata": {
                "normalizer": "linux_security",
                "normalizer_version": "0.1.0",
                "risk_engine": "source-priority-mapping",
                "ai_required": False,
                "scope": "Linux",
                "source_report_type": "linux-security-audit-summary",
            },
            "notes": [
                "Linux security findings are derived from linux-security-audit.sh summary JSON evidence.",
                "The collector is read-only. Remediation remains owner-reviewed and change-controlled.",
                "Missing evidence remains a coverage limitation and is not converted to false or zero.",
            ],
        }
    )


def normalize_linux_security_findings(
    data: dict[str, Any],
    source_file: Path,
    source_script_name: str | None = None,
) -> list[dict[str, Any]]:
    rows = source_findings(data)
    timestamp = generated_at_utc(data)
    findings: list[dict[str, Any]] = []
    script_name = source_script_name or linux_source_script_name(data, source_file)
    for index, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            continue
        findings.append(normalize_linux_security_finding(row, index, data, source_file, timestamp, script_name))
    return findings


def linux_source_script_name(data: dict[str, Any], source_file: Path) -> str:
    explicit = data.get("source_script") or data.get("SourceScript")
    if explicit:
        return str(explicit)
    name = source_file.name.lower()
    if "network" in name:
        return "linux-network-exposure-audit.sh"
    if "log" in name:
        return "linux-log-audit.sh"
    return LINUX_SECURITY_SOURCE_SCRIPT


def source_findings(data: dict[str, Any]) -> list[dict[str, Any]]:
    rows = data.get("findings") or data.get("Findings") or []
    return rows if isinstance(rows, list) else []


def normalize_linux_security_finding(
    row: dict[str, Any],
    index: int,
    data: dict[str, Any],
    source_file: Path,
    timestamp_utc: str,
    source_script_name: str = LINUX_SECURITY_SOURCE_SCRIPT,
) -> dict[str, Any]:
    source_id = str(first_value(row, ["id", "Id", "finding_id", "FindingId"], f"LINUX-SECURITY-{index:04d}"))
    severity = normalize_source_severity(first_value(row, ["severity", "Severity"], "Info"))
    title = str(first_value(row, ["title", "Title"], "Linux security evidence requires review"))
    recommendation = str(
        first_value(
            row,
            ["recommendation", "Recommendation", "recommended_action", "RecommendedAction"],
            "Review the Linux security evidence with the system owner before remediation.",
        )
    )
    evidence_text = str(first_value(row, ["evidence", "Evidence", "details", "Details"], "Linux audit evidence requires review."))
    host_name = host_name_for(data)
    evidence = {
        "scope": "Linux",
        "platform": "linux",
        "computer_name": host_name,
        "host": host_name,
        "source_file": str(source_file),
        "source_id": source_id,
        "linux_control_family": linux_control_family(source_id),
        "collector_type": data.get("collector_type"),
        "source_script": source_script_name,
        "root_context": data.get("root_context"),
        "quick_mode": data.get("quick_mode"),
        "source_evidence": evidence_text,
        "finding_counts": data.get("finding_counts", {}),
    }
    for structured_key in [
        "protocol",
        "port",
        "service_name",
        "bind_scope",
        "local_address",
        "process_name",
        "user",
        "package_name",
    ]:
        value = first_value(row, [structured_key, structured_key.title().replace("_", "")], "")
        if value not in (None, ""):
            evidence[structured_key] = value
    if not data.get("root_context", False):
        evidence["audit_coverage_limitation"] = "The audit was not run as root, so shadow, service, and package evidence may be incomplete."
    if data.get("quick_mode", False):
        evidence["audit_mode_limitation"] = "Quick mode skipped slower filesystem checks."

    return build_common_finding(
        finding_id=linux_finding_id(source_id, index),
        title=title,
        category=category_for_linux_control(source_id),
        severity=severity,
        affected_object=affected_object_for(row, host_name, source_id),
        object_type=object_type_for_linux_control(source_id),
        source_script_name=source_script_name,
        evidence=evidence,
        risk_factors=risk_factors_for(row, source_id, data),
        business_impact=business_impact_for_linux_control(source_id),
        technical_impact=technical_impact_for_linux_control(source_id, evidence_text),
        recommendation=recommendation,
        timestamp_utc=timestamp_utc,
        safety_reason="Linux host remediation can affect access, services, authentication, or routing and requires owner review and approved change control.",
    )


def generated_at_utc(data: dict[str, Any]) -> str:
    value = data.get("generated_at_utc") or data.get("GeneratedAtUtc")
    return str(value) if value else utc_now()


def host_name_for(data: dict[str, Any]) -> str:
    return str(data.get("host") or data.get("hostname") or data.get("Host") or data.get("ComputerName") or "Unknown Linux host")


def first_value(row: dict[str, Any], keys: list[str], default: Any = None) -> Any:
    lower_map = {str(key).lower(): key for key in row}
    for key in keys:
        actual = lower_map.get(key.lower())
        if actual is not None and row.get(actual) not in (None, ""):
            return row.get(actual)
    return default


def linux_finding_id(source_id: str, index: int) -> str:
    token = sanitize_id(source_id)
    if token:
        if token.startswith("LINUX-"):
            return token
        return f"LINUX-SECURITY-{token}"
    return f"LINUX-SECURITY-{index:04d}"


def sanitize_id(value: Any) -> str:
    text = "".join(ch if ch.isalnum() else "-" for ch in str(value or "").upper())
    text = "-".join(part for part in text.split("-") if part)
    return text[:80]


def linux_control_family(source_id: str) -> str:
    token = sanitize_id(source_id)
    parts = token.split("-")
    if len(parts) >= 2 and parts[0] == "LINUX":
        return parts[1]
    return "GENERAL"


def category_for_linux_control(source_id: str) -> str:
    family = linux_control_family(source_id)
    return {
        "AUDIT": "Linux Audit Coverage",
        "IDENTITY": "Linux Identity and Privilege",
        "SUDO": "Linux Identity and Privilege",
        "SSH": "Linux SSH Configuration",
        "FIREWALL": "Linux Network Security",
        "NETWORK": "Linux Network Security",
        "LOG": "Linux Logging and Audit",
        "PACKAGE": "Linux Patch Management",
        "FILESYSTEM": "Linux Filesystem Permissions",
        "KERNEL": "Linux Kernel Hardening",
    }.get(family, "Linux Host Security")


def object_type_for_linux_control(source_id: str) -> str:
    family = linux_control_family(source_id)
    return {
        "AUDIT": "Linux audit coverage evidence",
        "IDENTITY": "Linux local identity control",
        "SUDO": "Linux privilege configuration",
        "SSH": "Linux SSH daemon setting",
        "FIREWALL": "Linux host firewall evidence",
        "NETWORK": "Linux listening service evidence",
        "LOG": "Linux logging or audit control",
        "PACKAGE": "Linux package management evidence",
        "FILESYSTEM": "Linux filesystem permission evidence",
        "KERNEL": "Linux kernel security setting",
    }.get(family, "Linux host security control")


def affected_object_for(row: dict[str, Any], host_name: str, source_id: str) -> str:
    explicit = first_value(row, ["affected_object", "AffectedObject", "object", "Object"], "")
    if explicit:
        return str(explicit)
    family = linux_control_family(source_id)
    if family == "SSH":
        return f"{host_name}: sshd configuration"
    if family == "KERNEL":
        evidence = str(first_value(row, ["evidence", "Evidence"], ""))
        key = evidence.split("=", 1)[0].strip()
        return key if key.startswith("net.") or key.startswith("kernel.") else f"{host_name}: kernel setting"
    if family == "FIREWALL":
        return f"{host_name}: host firewall"
    if family == "NETWORK":
        protocol = str(first_value(row, ["protocol", "Protocol"], "TCP") or "TCP").upper()
        port = first_value(row, ["port", "Port"], "")
        service = first_value(row, ["service_name", "ServiceName", "service", "Service"], "")
        if port:
            suffix = f" / {service}" if service else ""
            return f"{protocol} {port}{suffix}"
        evidence = str(first_value(row, ["evidence", "Evidence"], ""))
        if "TCP " in evidence or "UDP " in evidence:
            return evidence.split(";", 1)[0].strip()
        return f"{host_name}: listening service"
    if family == "LOG":
        return f"{host_name}: logging and audit coverage"
    if family == "PACKAGE":
        return f"{host_name}: package management"
    if family == "FILESYSTEM":
        return f"{host_name}: filesystem permissions"
    if family in {"IDENTITY", "SUDO"}:
        return f"{host_name}: local privilege configuration"
    return host_name


def risk_factors_for(row: dict[str, Any], source_id: str, data: dict[str, Any]) -> list[str]:
    factors = ["Linux", linux_control_family(source_id), source_id]
    severity = first_value(row, ["severity", "Severity"], "")
    if severity:
        factors.append(str(severity))
    if not data.get("root_context", False):
        factors.append("Audit coverage limited: not root")
    if data.get("quick_mode", False):
        factors.append("Quick audit mode")
    return list(dict.fromkeys(factors))


def business_impact_for_linux_control(source_id: str) -> str:
    family = linux_control_family(source_id)
    if family in {"IDENTITY", "SUDO"}:
        return "Local identity or sudo misconfiguration can increase the impact of a compromised Linux account."
    if family == "SSH":
        return "SSH configuration weaknesses can increase remote administration risk if network access is available."
    if family == "FIREWALL":
        return "Incomplete firewall evidence can reduce confidence that host-level network controls are enforced."
    if family == "NETWORK":
        return "Linux listening service evidence helps the customer validate exposed administration, database, file-sharing, and application services."
    if family == "LOG":
        return "Incomplete Linux logging or audit coverage can reduce investigation and accountability capability."
    if family == "PACKAGE":
        return "Linux patch management evidence helps the customer prioritize maintenance windows and vulnerability reduction."
    if family == "FILESYSTEM":
        return "Unsafe filesystem permissions can increase the impact of local compromise or unauthorized configuration changes."
    if family == "KERNEL":
        return "Kernel security settings influence routing behavior and baseline hardening of the Linux host."
    if family == "AUDIT":
        return "Incomplete audit coverage can hide relevant Linux security evidence from the assessment."
    return "Linux host security evidence requires owner review to assess operational risk."


def technical_impact_for_linux_control(source_id: str, evidence_text: str) -> str:
    family = linux_control_family(source_id)
    if family == "SSH":
        return f"The Linux audit reported SSH configuration evidence: {evidence_text}"
    if family == "KERNEL":
        return f"The Linux audit reported kernel or sysctl evidence: {evidence_text}"
    if family in {"IDENTITY", "SUDO"}:
        return f"The Linux audit reported local privilege evidence: {evidence_text}"
    if family == "NETWORK":
        return f"The Linux audit reported listening service evidence: {evidence_text}"
    if family == "LOG":
        return f"The Linux audit reported logging or audit coverage evidence: {evidence_text}"
    if family == "PACKAGE":
        return f"The Linux audit reported package management evidence: {evidence_text}"
    if family == "FILESYSTEM":
        return f"The Linux audit reported filesystem permission evidence: {evidence_text}"
    return evidence_text

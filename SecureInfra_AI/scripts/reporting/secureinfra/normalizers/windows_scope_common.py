"""Standalone Windows scope normalizers for SecureInfra AI."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from secureinfra.bundles.client_bundle import (
    CLIENT_FILE_DEFINITIONS,
    normalize_client_source_file,
    source_script_for,
    source_timestamp,
)
from secureinfra.normalizers.ad_common import severity_counts


WINDOWS_SCOPE_DEFINITIONS: dict[str, dict[str, str]] = {
    "windows-host-audit": {
        "scope": "Host",
        "client_source_key": "host_windows_security_audit",
        "tool_name": "SecureInfra AI Windows Host Audit Analyzer",
        "normalizer": "windows_host_audit",
        "source_report_type": "windows-security-audit",
        "schema": "windows-host-audit-normalized-report.schema.json",
    },
    "windows-server-audit": {
        "scope": "Server",
        "client_source_key": "server_windows_server_security",
        "tool_name": "SecureInfra AI Windows Server Audit Analyzer",
        "normalizer": "windows_server_audit",
        "source_report_type": "windows-server-security-inventory",
        "schema": "windows-server-audit-normalized-report.schema.json",
    },
    "windows-workstation-audit": {
        "scope": "Workstation",
        "client_source_key": "workstation_windows_workstation_security",
        "tool_name": "SecureInfra AI Windows Workstation Audit Analyzer",
        "normalizer": "windows_workstation_audit",
        "source_report_type": "windows-workstation-security-inventory",
        "schema": "windows-workstation-audit-normalized-report.schema.json",
    },
    "windows-network-exposure": {
        "scope": "Network",
        "client_source_key": "network_windows_network_exposure",
        "tool_name": "SecureInfra AI Windows Network Exposure Analyzer",
        "normalizer": "windows_network_exposure",
        "source_report_type": "windows-network-exposure",
        "schema": "windows-network-exposure-normalized-report.schema.json",
    },
}


def normalize_windows_scope_report(data: dict[str, Any], source_file: str | Path, report_type: str) -> dict[str, Any]:
    """Normalize one Windows JSON report into the shared finding contract."""
    if report_type not in WINDOWS_SCOPE_DEFINITIONS:
        raise ValueError(f"Unsupported Windows standalone report type: {report_type}")
    if not isinstance(data, dict):
        raise ValueError(f"{report_type} input must be a JSON object")

    rows = data.get("Findings")
    if not isinstance(rows, list):
        raise ValueError(f"{report_type} input must contain a Findings list")

    definition = WINDOWS_SCOPE_DEFINITIONS[report_type]
    source_path = Path(source_file)
    source_key = definition["client_source_key"]
    source_script_name = source_script_for(source_key, data, source_path)
    timestamp_utc = source_timestamp(data)
    findings = normalize_client_source_file(source_key, data, source_path)
    source_summary = data.get("Summary") if isinstance(data.get("Summary"), dict) else {}
    source_report_type = detected_source_report_type(data, definition["source_report_type"])

    return {
        "report_id": f"secureinfra-ai-{report_type}-{timestamp_utc.replace(':', '').replace('-', '')}",
        "report_type": report_type,
        "tool_name": definition["tool_name"],
        "source_files": [str(source_path)],
        "generated_at_utc": timestamp_utc,
        "environment_summary": {
            "company": "",
            "domain": detected_domain(data),
            "computer_name": detected_computer_name(data),
            "scope": definition["scope"],
            "source_script": source_script_name,
            "source_report_type": source_report_type,
            "input_finding_count": len(rows),
        },
        "summary": {
            "total_findings": len(findings),
            "normalized_finding_count": len(findings),
            "severity_counts": severity_counts(findings),
            "source_summary": source_summary,
        },
        "report_type_metadata": {
            "report_type": report_type,
            "scope": definition["scope"],
            "source_file": str(source_path),
            "source_script": source_script_name,
            "source_report_type": source_report_type,
            "source_summary": source_summary,
            "normalizer_status": "beta",
        },
        "findings": findings,
        "metadata": {
            "normalizer": definition["normalizer"],
            "normalizer_version": "0.1.0",
            "risk_engine": "source-priority-mapping",
            "ai_required": False,
            "scope": definition["scope"],
            "source_report_type": source_report_type,
            "schema": definition["schema"],
        },
        "notes": [
            "This beta standalone normalizer is report-only and does not change Windows systems.",
            "Findings are based only on supplied JSON evidence from the source audit script.",
            "Human owner review and approved change control are required before remediation.",
        ],
    }


def detected_source_report_type(data: dict[str, Any], default: str) -> str:
    metadata = data.get("ReportMetadata") if isinstance(data.get("ReportMetadata"), dict) else {}
    return str(data.get("ReportType") or metadata.get("ReportType") or default)


def detected_computer_name(data: dict[str, Any]) -> str:
    metadata = data.get("ReportMetadata") if isinstance(data.get("ReportMetadata"), dict) else {}
    return str(data.get("ComputerName") or metadata.get("ComputerName") or "")


def detected_domain(data: dict[str, Any]) -> str:
    operating_system = data.get("OperatingSystem") if isinstance(data.get("OperatingSystem"), dict) else {}
    return str(data.get("Domain") or operating_system.get("Domain") or "")


def supported_windows_source_paths() -> dict[str, str]:
    return {
        report_type: CLIENT_FILE_DEFINITIONS[definition["client_source_key"]]["path"]
        for report_type, definition in WINDOWS_SCOPE_DEFINITIONS.items()
    }

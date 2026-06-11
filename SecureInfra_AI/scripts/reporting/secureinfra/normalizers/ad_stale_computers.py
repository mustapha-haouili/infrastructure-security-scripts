"""Normalize AD stale computer reports."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from secureinfra.normalizers.ad_common import (
    ad_safety_reason,
    base_normalized_report,
    build_common_finding,
    generated_at_utc,
    normalize_source_severity,
    row_identifier,
    source_script,
    split_text_or_list,
)
from secureinfra.risk_engine.rules import as_bool, as_int


def build_evidence(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": str(row.get("Name") or ""),
        "dns_host_name": str(row.get("DNSHostName") or ""),
        "enabled": as_bool(row.get("Enabled")),
        "inactive_days": as_int(row.get("InactiveDays"), 0),
        "computer_category": str(row.get("ComputerCategory") or ""),
        "lifecycle_stage": str(row.get("LifecycleStage") or ""),
        "cleanup_readiness": str(row.get("CleanupReadiness") or ""),
        "can_delete_now": as_bool(row.get("CanDeleteNow")),
        "potential_cleanup_candidate": as_bool(row.get("PotentialCleanupCandidate")),
        "is_domain_controller": as_bool(row.get("IsDomainController")),
        "is_server_os": as_bool(row.get("IsServerOS")),
        "has_spn": as_bool(row.get("HasSPN")),
        "spn_count": as_int(row.get("SPNCount"), 0),
        "privileged_group_count": as_int(row.get("PrivilegedGroupCount"), 0),
        "privileged_groups": split_text_or_list(row.get("PrivilegedGroups") or row.get("PrivilegedGroupsText")),
        "risk_flags": split_text_or_list(row.get("RiskFlags") or row.get("RiskFlagsText")),
        "review_reasons": split_text_or_list(row.get("ReviewReasons") or row.get("ReviewReasonsText")),
        "cleanup_guidance": str(row.get("CleanupGuidance") or ""),
        "distinguished_name": str(row.get("DistinguishedName") or ""),
    }


def normalize_stale_computers(data: dict[str, Any], source_file: str | Path) -> dict[str, Any]:
    rows = data.get("StaleComputers")
    if not isinstance(rows, list):
        raise ValueError("Stale computer report must contain a StaleComputers list")

    timestamp_utc = generated_at_utc(data)
    script_name = source_script(data, "Get-ADStaleComputerReport.ps1")
    findings = []
    for index, row in enumerate(rows, start=1):
        severity = normalize_source_severity(row.get("ReviewPriority"))
        affected_object = row_identifier(row, f"stale-computer-{index}")
        findings.append(
            build_common_finding(
                finding_id=f"AD-COMP-{index:04d}",
                title="Stale computer account requires lifecycle review",
                category="Active Directory Security",
                severity=severity,
                affected_object=affected_object,
                object_type="Active Directory computer",
                source_script_name=script_name,
                evidence=build_evidence(row),
                risk_factors=split_text_or_list(row.get("RiskFlags") or row.get("RiskFlagsText")),
                business_impact="Stale computer objects can affect inventory accuracy and may retain trust relationships or service dependencies.",
                technical_impact="The source report identified stale computer account evidence and cleanup-readiness indicators.",
                recommendation=str(row.get("RecommendedAction") or "Confirm owner, device status, dependencies, and staged cleanup plan before any change."),
                timestamp_utc=timestamp_utc,
                safety_reason=ad_safety_reason(row, "Computer account"),
            )
        )

    return base_normalized_report(
        report_type="ad-stale-computers",
        tool_name="SecureInfra AI Stale Computer Analyzer",
        source_file=source_file,
        data=data,
        findings=findings,
        source_script_name=script_name,
        input_count=len(rows),
        normalizer_name="ad_stale_computers",
    )

"""Normalize AD privileged group change reports."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from secureinfra.normalizers.ad_common import (
    base_normalized_report,
    build_common_finding,
    generated_at_utc,
    normalize_source_severity,
    row_identifier,
    source_script,
    split_text_or_list,
)


def build_evidence(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "change_type": str(row.get("ChangeType") or row.get("FindingType") or ""),
        "action_priority": str(row.get("ActionPriority") or ""),
        "group_name": str(row.get("GroupName") or ""),
        "group_sid": str(row.get("GroupSID") or ""),
        "group_tier": str(row.get("GroupTier") or ""),
        "member_name": str(row.get("MemberName") or row.get("Subject") or ""),
        "member_sam_account_name": str(row.get("MemberSamAccountName") or ""),
        "member_object_class": str(row.get("MemberObjectClass") or ""),
        "member_sid": str(row.get("MemberSID") or ""),
        "member_dn": str(row.get("MemberDN") or ""),
        "risk_flags": split_text_or_list(row.get("RiskFlags") or row.get("RiskFlagsText")),
        "admin_action": str(row.get("AdminAction") or ""),
        "verification_step": str(row.get("VerificationStep") or ""),
        "evidence": str(row.get("Evidence") or ""),
    }


def finding_title(row: dict[str, Any]) -> str:
    change_type = str(row.get("ChangeType") or row.get("FindingType") or "").strip()
    if change_type == "Added":
        return "Privileged group membership addition requires review"
    if change_type == "Removed":
        return "Privileged group membership removal requires review"
    if change_type == "NestedGroupPresent":
        return "Nested privileged group membership requires review"
    if change_type == "ForeignSecurityPrincipalPresent":
        return "Foreign principal in privileged group requires review"
    if change_type == "ComputerAccountPresent":
        return "Computer account in privileged group requires review"
    return "Privileged group change or finding requires review"


def risk_factors_for(row: dict[str, Any]) -> list[str]:
    factors = split_text_or_list(row.get("RiskFlags") or row.get("RiskFlagsText"))
    change_type = str(row.get("ChangeType") or row.get("FindingType") or "").strip()
    if change_type:
        factors.insert(0, change_type)
    return factors


def normalize_privileged_groups(data: dict[str, Any], source_file: str | Path) -> dict[str, Any]:
    rows = data.get("Changes")
    if not isinstance(rows, list):
        rows = data.get("Findings")
    if not isinstance(rows, list):
        raise ValueError("Privileged group report must contain a Changes list")

    timestamp_utc = generated_at_utc(data)
    script_name = source_script(data, "Watch-ADPrivilegedGroupChanges.ps1")
    findings = []
    for index, row in enumerate(rows, start=1):
        severity = normalize_source_severity(row.get("Severity") or row.get("ReviewPriority") or row.get("ActionPriority"))
        affected_object = row_identifier(row, f"privileged-group-change-{index}")
        findings.append(
            build_common_finding(
                finding_id=f"AD-PGROUP-{index:04d}",
                title=finding_title(row),
                category="Active Directory Security",
                severity=severity,
                affected_object=affected_object,
                object_type="Active Directory privileged group membership",
                source_script_name=script_name,
                evidence=build_evidence(row),
                risk_factors=risk_factors_for(row),
                business_impact="Privileged group membership changes can materially change administrative access and should be reconciled against owner approval.",
                technical_impact="The source report identified privileged group membership changes or risky current membership patterns.",
                recommendation=str(row.get("AdminAction") or "Validate group owner, business justification, and change ticket before changing privileged membership."),
                timestamp_utc=timestamp_utc,
                safety_reason="Privileged group membership changes require owner validation, approved change control, and post-change verification.",
            )
        )

    return base_normalized_report(
        report_type="ad-privileged-groups",
        tool_name="SecureInfra AI Privileged Group Analyzer",
        source_file=source_file,
        data=data,
        findings=findings,
        source_script_name=script_name,
        input_count=len(rows),
        normalizer_name="ad_privileged_groups",
    )

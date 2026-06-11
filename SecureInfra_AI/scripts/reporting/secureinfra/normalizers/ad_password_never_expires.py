"""Normalize AD PasswordNeverExpires reports."""

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
        "sam_account_name": str(row.get("SamAccountName") or ""),
        "enabled": as_bool(row.get("Enabled")),
        "account_category": str(row.get("AccountCategory") or ""),
        "rotation_readiness": str(row.get("RotationReadiness") or ""),
        "password_never_expires": as_bool(row.get("PasswordNeverExpires")),
        "password_age_days": as_int(row.get("PasswordAgeDays"), 0),
        "inactive_days": as_int(row.get("InactiveDays"), 0),
        "has_spn": as_bool(row.get("HasSPN")),
        "spn_count": as_int(row.get("SPNCount"), 0),
        "privileged_group_count": as_int(row.get("PrivilegedGroupCount"), 0),
        "privileged_groups": split_text_or_list(row.get("PrivilegedGroups") or row.get("PrivilegedGroupsText")),
        "owner_evidence_missing": as_bool(row.get("OwnerEvidenceMissing")),
        "exception_required": as_bool(row.get("ExceptionRequired")),
        "risk_flags": split_text_or_list(row.get("RiskFlags") or row.get("RiskFlagsText")),
        "review_reasons": split_text_or_list(row.get("ReviewReasons") or row.get("ReviewReasonsText")),
        "distinguished_name": str(row.get("DistinguishedName") or ""),
    }


def normalize_password_never_expires(data: dict[str, Any], source_file: str | Path) -> dict[str, Any]:
    rows = data.get("PasswordNeverExpiresAccounts")
    if not isinstance(rows, list):
        raise ValueError("PasswordNeverExpires report must contain a PasswordNeverExpiresAccounts list")

    timestamp_utc = generated_at_utc(data)
    script_name = source_script(data, "Get-ADPasswordNeverExpiresReport.ps1")
    findings = []
    for index, row in enumerate(rows, start=1):
        severity = normalize_source_severity(row.get("ReviewPriority"))
        affected_object = row_identifier(row, f"password-never-expires-{index}")
        risk_factors = split_text_or_list(row.get("RiskFlags") or row.get("RiskFlagsText"))
        findings.append(
            build_common_finding(
                finding_id=f"AD-PNE-{index:04d}",
                title="PasswordNeverExpires account requires exception review",
                category="Active Directory Security",
                severity=severity,
                affected_object=affected_object,
                object_type="Active Directory user",
                source_script_name=script_name,
                evidence=build_evidence(row),
                risk_factors=risk_factors,
                business_impact="Accounts with non-expiring passwords can increase identity exposure if ownership, exception status, and rotation plan are unclear.",
                technical_impact="The source report identified an account with PasswordNeverExpires and related review indicators.",
                recommendation=str(row.get("RecommendedAction") or "Validate owner, exception status, and rotation plan before any account change."),
                timestamp_utc=timestamp_utc,
                safety_reason=ad_safety_reason(row, "Account"),
            )
        )

    return base_normalized_report(
        report_type="ad-password-never-expires",
        tool_name="SecureInfra AI PasswordNeverExpires Analyzer",
        source_file=source_file,
        data=data,
        findings=findings,
        source_script_name=script_name,
        input_count=len(rows),
        normalizer_name="ad_password_never_expires",
    )

"""Normalize AD PasswordNeverExpires reports."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from secureinfra.normalizers.ad_common import (
    activity_evidence_context,
    account_review_recommendation,
    account_risk_flags,
    ad_safety_reason,
    base_normalized_report,
    build_common_finding,
    generated_at_utc,
    normalize_source_severity,
    optional_bool,
    optional_int,
    row_identifier,
    service_account_classification,
    source_script,
    split_text_or_list,
)


def build_evidence(row: dict[str, Any]) -> dict[str, Any]:
    classification = service_account_classification(row)
    return {
        "sam_account_name": str(row.get("SamAccountName") or ""),
        "enabled": optional_bool(row.get("Enabled")),
        "account_category": str(row.get("AccountCategory") or ""),
        "rotation_readiness": str(row.get("RotationReadiness") or ""),
        "password_never_expires": optional_bool(row.get("PasswordNeverExpires")),
        "password_age_days": optional_int(row.get("PasswordAgeDays")),
        "inactive_days": optional_int(row.get("InactiveDays")),
        "has_spn": optional_bool(row.get("HasSPN")),
        "spn_count": optional_int(row.get("SPNCount")),
        "admin_count": optional_int(row.get("AdminCount")),
        "privileged_group_count": optional_int(row.get("PrivilegedGroupCount")),
        "privileged_groups": split_text_or_list(row.get("PrivilegedGroups") or row.get("PrivilegedGroupsText")),
        "owner_evidence_missing": optional_bool(row.get("OwnerEvidenceMissing")),
        "exception_required": optional_bool(row.get("ExceptionRequired")),
        "risk_flags": account_risk_flags(row),
        "review_reasons": split_text_or_list(row.get("ReviewReasons") or row.get("ReviewReasonsText")),
        "distinguished_name": str(row.get("DistinguishedName") or ""),
        **activity_evidence_context(row),
        **classification,
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
        classification = service_account_classification(row)["classification"]
        risk_factors = account_risk_flags(row)
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
                recommendation=account_review_recommendation(
                    row,
                    classification,
                    "Validate owner, exception status, and rotation plan before any account change.",
                ),
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

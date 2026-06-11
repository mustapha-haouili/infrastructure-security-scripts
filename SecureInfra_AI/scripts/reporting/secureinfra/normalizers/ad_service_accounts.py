"""Normalize AD service account audit reports."""

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
        "account_type": str(row.get("AccountType") or ""),
        "object_class": str(row.get("ObjectClass") or ""),
        "has_spn": as_bool(row.get("HasSPN")),
        "spn_count": as_int(row.get("SPNCount"), 0),
        "password_never_expires": as_bool(row.get("PasswordNeverExpires")),
        "password_age_days": as_int(row.get("PasswordAgeDays"), 0),
        "inactive_days": as_int(row.get("InactiveDays"), 0),
        "admin_count": as_int(row.get("AdminCount"), 0),
        "privileged_group_count": as_int(row.get("PrivilegedGroupCount"), 0),
        "privileged_groups": split_text_or_list(row.get("PrivilegedGroups") or row.get("PrivilegedGroupsText")),
        "does_not_require_pre_auth": as_bool(row.get("DoesNotRequirePreAuth")),
        "trusted_for_delegation": as_bool(row.get("TrustedForDelegation")),
        "trusted_to_auth_for_delegation": as_bool(row.get("TrustedToAuthForDelegation")),
        "owner_evidence_missing": as_bool(row.get("OwnerEvidenceMissing")),
        "risk_flags": split_text_or_list(row.get("RiskFlags") or row.get("RiskFlagsText")),
        "review_reasons": split_text_or_list(row.get("ReviewReasons") or row.get("ReviewReasonsText")),
        "distinguished_name": str(row.get("DistinguishedName") or ""),
    }


def normalize_service_accounts(data: dict[str, Any], source_file: str | Path) -> dict[str, Any]:
    rows = data.get("ServiceAccounts")
    if not isinstance(rows, list):
        raise ValueError("Service account report must contain a ServiceAccounts list")

    timestamp_utc = generated_at_utc(data)
    script_name = source_script(data, "Get-ADServiceAccountAudit.ps1")
    findings = []
    for index, row in enumerate(rows, start=1):
        severity = normalize_source_severity(row.get("ReviewPriority"))
        affected_object = row_identifier(row, f"service-account-{index}")
        findings.append(
            build_common_finding(
                finding_id=f"AD-SVC-{index:04d}",
                title="Service account requires owner and dependency review",
                category="Active Directory Security",
                severity=severity,
                affected_object=affected_object,
                object_type="Active Directory service account",
                source_script_name=script_name,
                evidence=build_evidence(row),
                risk_factors=split_text_or_list(row.get("RiskFlags") or row.get("RiskFlagsText")),
                business_impact="Service account changes can disrupt applications, but unmanaged or stale service accounts increase identity exposure.",
                technical_impact="The source report identified service account risk indicators such as SPNs, old passwords, delegation, privilege, or missing ownership.",
                recommendation=str(row.get("RecommendedAction") or "Confirm service owner, dependency, rotation plan, and maintenance window before any change."),
                timestamp_utc=timestamp_utc,
                safety_reason=ad_safety_reason(row, "Service account"),
            )
        )

    return base_normalized_report(
        report_type="ad-service-accounts",
        tool_name="SecureInfra AI Service Account Analyzer",
        source_file=source_file,
        data=data,
        findings=findings,
        source_script_name=script_name,
        input_count=len(rows),
        normalizer_name="ad_service_accounts",
    )

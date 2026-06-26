"""Normalize AD service account audit reports."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from secureinfra.normalizers.ad_common import (
    activity_evidence_context,
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
        "account_type": str(row.get("AccountType") or ""),
        "object_class": str(row.get("ObjectClass") or ""),
        "has_spn": optional_bool(row.get("HasSPN")),
        "spn_count": optional_int(row.get("SPNCount")),
        "password_never_expires": optional_bool(row.get("PasswordNeverExpires")),
        "password_age_days": optional_int(row.get("PasswordAgeDays")),
        "inactive_days": optional_int(row.get("InactiveDays")),
        "admin_count": optional_int(row.get("AdminCount")),
        "privileged_group_count": optional_int(row.get("PrivilegedGroupCount")),
        "privileged_groups": split_text_or_list(row.get("PrivilegedGroups") or row.get("PrivilegedGroupsText")),
        "does_not_require_pre_auth": optional_bool(row.get("DoesNotRequirePreAuth")),
        "trusted_for_delegation": optional_bool(row.get("TrustedForDelegation")),
        "trusted_to_auth_for_delegation": optional_bool(row.get("TrustedToAuthForDelegation")),
        "owner_evidence_missing": optional_bool(row.get("OwnerEvidenceMissing")),
        "risk_flags": split_text_or_list(row.get("RiskFlags") or row.get("RiskFlagsText")),
        "review_reasons": split_text_or_list(row.get("ReviewReasons") or row.get("ReviewReasonsText")),
        "distinguished_name": str(row.get("DistinguishedName") or ""),
        **activity_evidence_context(row),
        **classification,
    }


def title_for(classification: str) -> str:
    return {
        "Strict Service Accounts": "Strict service account requires owner and dependency review",
        "Service Account Candidates": "Service account candidate requires validation",
        "Privileged Residue Candidates": "Privileged residue candidate requires ownership review",
        "Password Exception Reviews": "Password exception requires owner review",
        "Missing Owner Reviews": "Missing owner evidence requires account review",
    }.get(classification, "Account review candidate requires validation")


def object_type_for(classification: str) -> str:
    if classification == "Strict Service Accounts":
        return "Active Directory service account"
    if classification == "Service Account Candidates":
        return "Active Directory service account candidate"
    return "Active Directory account review candidate"


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
        classification = service_account_classification(row)["classification"]
        findings.append(
            build_common_finding(
                finding_id=f"AD-SVC-{index:04d}",
                title=title_for(classification),
                category="Active Directory Security",
                severity=severity,
                affected_object=affected_object,
                object_type=object_type_for(classification),
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

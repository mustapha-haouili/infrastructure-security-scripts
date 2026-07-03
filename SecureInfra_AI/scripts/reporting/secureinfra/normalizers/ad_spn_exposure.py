"""Normalize AD SPN exposure reports."""

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
        "spn_count": optional_int(row.get("SPNCount")),
        "service_principal_names": split_text_or_list(row.get("ServicePrincipalNames") or row.get("ServicePrincipalNamesText")),
        "has_spn": True,
        "password_never_expires": optional_bool(row.get("PasswordNeverExpires")),
        "password_age_days": optional_int(row.get("PasswordAgeDays")),
        "inactive_days": optional_int(row.get("InactiveDays")),
        "admin_count": optional_int(row.get("AdminCount")),
        "privileged_group_count": optional_int(row.get("PrivilegedGroupCount")),
        "privileged_groups": split_text_or_list(row.get("PrivilegedGroups") or row.get("PrivilegedGroupsText")),
        "does_not_require_pre_auth": optional_bool(row.get("DoesNotRequirePreAuth")),
        "trusted_for_delegation": optional_bool(row.get("TrustedForDelegation")),
        "trusted_to_auth_for_delegation": optional_bool(row.get("TrustedToAuthForDelegation")),
        "encryption_risk": str(row.get("EncryptionRisk") or ""),
        "encryption_evidence": str(row.get("EncryptionEvidence") or ""),
        "risk_flags": account_risk_flags(row),
        "review_reasons": split_text_or_list(row.get("ReviewReasons") or row.get("ReviewReasonsText")),
        "distinguished_name": str(row.get("DistinguishedName") or ""),
        **activity_evidence_context(row),
        **classification,
    }


def normalize_spn_exposure(data: dict[str, Any], source_file: str | Path) -> dict[str, Any]:
    rows = data.get("SPNAccounts")
    if not isinstance(rows, list):
        raise ValueError("SPN exposure report must contain an SPNAccounts list")

    timestamp_utc = generated_at_utc(data)
    script_name = source_script(data, "Get-ADSPNExposureAudit.ps1")
    findings = []
    for index, row in enumerate(rows, start=1):
        severity = normalize_source_severity(row.get("ExposurePriority") or row.get("ReviewPriority"))
        affected_object = row_identifier(row, f"spn-account-{index}")
        classification = service_account_classification(row)["classification"]
        findings.append(
            build_common_finding(
                finding_id=f"AD-SPN-{index:04d}",
                title="SPN-bearing account requires exposure review",
                category="Active Directory Security",
                severity=severity,
                affected_object=affected_object,
                object_type="Active Directory SPN account",
                source_script_name=script_name,
                evidence=build_evidence(row),
                risk_factors=account_risk_flags(row),
                business_impact="SPN-bearing accounts can represent important application dependencies and require controlled ownership and rotation review.",
                technical_impact="The source report identified SPN exposure indicators. This is defensive dependency and configuration evidence, not exploitation guidance.",
                recommendation=account_review_recommendation(
                    row,
                    classification,
                    "Confirm application owner, SPN requirement, credential rotation plan, and delegation posture before any change.",
                ),
                timestamp_utc=timestamp_utc,
                safety_reason=ad_safety_reason(row, "SPN-bearing account"),
            )
        )

    return base_normalized_report(
        report_type="ad-spn-exposure",
        tool_name="SecureInfra AI SPN Exposure Analyzer",
        source_file=source_file,
        data=data,
        findings=findings,
        source_script_name=script_name,
        input_count=len(rows),
        normalizer_name="ad_spn_exposure",
    )

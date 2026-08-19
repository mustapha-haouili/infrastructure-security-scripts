"""Normalize AD privileged identity protection reports."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from secureinfra.normalizers.ad_common import (
    activity_evidence_context,
    account_review_recommendation,
    account_risk_flags,
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
        "finding_type": str(row.get("FindingType") or ""),
        "action_priority": str(row.get("ActionPriority") or ""),
        "subject": str(row.get("Subject") or row.get("SamAccountName") or ""),
        "sam_account_name": str(row.get("SamAccountName") or row.get("Subject") or ""),
        "user_principal_name": str(row.get("UserPrincipalName") or ""),
        "sid": str(row.get("SID") or ""),
        "group_name": str(row.get("GroupName") or row.get("EffectivePrivilegedGroupsText") or ""),
        "direct_privileged_groups": split_text_or_list(row.get("DirectPrivilegedGroups") or row.get("DirectPrivilegedGroupsText")),
        "effective_privileged_groups": split_text_or_list(row.get("EffectivePrivilegedGroups") or row.get("EffectivePrivilegedGroupsText") or row.get("GroupName")),
        "privileged_groups": split_text_or_list(row.get("EffectivePrivilegedGroups") or row.get("EffectivePrivilegedGroupsText") or row.get("GroupName")),
        "identity_category": str(row.get("IdentityCategory") or ""),
        "enabled": optional_bool(row.get("Enabled")),
        "critical_group_member": optional_bool(row.get("CriticalGroupMember")),
        "nested_privileged_access": optional_bool(row.get("NestedPrivilegedAccess")),
        "protected_users_member": optional_bool(row.get("ProtectedUsersMember")),
        "smartcard_logon_required": optional_bool(row.get("SmartcardLogonRequired")),
        "account_not_delegated": optional_bool(row.get("AccountNotDelegated")),
        "password_never_expires": optional_bool(row.get("PasswordNeverExpires")),
        "password_age_days": optional_int(row.get("PasswordAgeDays")),
        "inactive_days": optional_int(row.get("InactiveDays")),
        "does_not_require_pre_auth": optional_bool(row.get("DoesNotRequirePreAuth")),
        "trusted_for_delegation": optional_bool(row.get("TrustedForDelegation")),
        "trusted_to_auth_for_delegation": optional_bool(row.get("TrustedToAuthForDelegation")),
        "has_spn": optional_bool(row.get("HasSPN")),
        "spn_count": optional_int(row.get("SPNCount")),
        "admin_count": optional_int(row.get("AdminCount")),
        "owner_evidence_missing": optional_bool(row.get("OwnerEvidenceMissing")),
        "mfa_conditional_access_status": str(row.get("MFAConditionalAccessStatus") or ""),
        "risk_flags": account_risk_flags(row),
        "review_reasons": split_text_or_list(row.get("ReviewReasons") or row.get("ReviewReasonsText")),
        "evidence": str(row.get("Evidence") or ""),
        "admin_action": str(row.get("AdminAction") or row.get("RecommendedAction") or ""),
        "verification_step": str(row.get("VerificationStep") or row.get("NextReviewStep") or ""),
        "distinguished_name": str(row.get("DistinguishedName") or ""),
        **activity_evidence_context(row),
        **classification,
    }


def title_for(row: dict[str, Any]) -> str:
    finding_type = str(row.get("FindingType") or "").strip()
    if finding_type == "PrivilegedIdentityProtectionGap":
        return "Privileged identity protection gap requires review"
    if finding_type == "NestedPrivilegedGroup":
        return "Nested privileged access requires review"
    if finding_type == "NonUserPrivilegedPrincipal":
        return "Non-user privileged principal requires review"
    if finding_type == "GroupQueryIssue":
        return "Privileged group query issue requires review"
    return "Privileged identity requires protection review"


def risk_factors_for(row: dict[str, Any]) -> list[str]:
    factors = account_risk_flags(row)
    factors.extend(split_text_or_list(row.get("ReviewReasons") or row.get("ReviewReasonsText")))
    finding_type = str(row.get("FindingType") or "").strip()
    if finding_type:
        factors.insert(0, finding_type)
    return factors


def _account_key(value: Any) -> str:
    text = str(value or "").strip().lower()
    if "\\" in text:
        text = text.rsplit("\\", 1)[-1]
    if "@" in text:
        text = text.split("@", 1)[0]
    return text.rstrip("$")


def source_rows(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Return finding rows enriched with authoritative identity details when available.

    The PowerShell report intentionally has two views: ``Findings`` contains compact
    alert rows, while ``PrivilegedIdentities`` contains the richer account evidence
    (SID, groups, password state, activity, etc.).  Normalizing only the compact row
    loses the very context needed for correlation and safe remediation.
    """
    findings = data.get("Findings")
    identities = data.get("PrivilegedIdentities")

    if isinstance(findings, list) and findings:
        identity_by_key: dict[str, dict[str, Any]] = {}
        if isinstance(identities, list):
            for identity in identities:
                if not isinstance(identity, dict):
                    continue
                for candidate in (identity.get("SamAccountName"), identity.get("Name"), identity.get("UserPrincipalName")):
                    key = _account_key(candidate)
                    if key and key not in identity_by_key:
                        identity_by_key[key] = identity

        enriched: list[dict[str, Any]] = []
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            row = dict(finding)
            if str(finding.get("FindingType") or "").strip() == "PrivilegedIdentityProtectionGap":
                key = _account_key(finding.get("Subject") or finding.get("SamAccountName"))
                identity = identity_by_key.get(key)
                if identity:
                    # Rich identity evidence is the base; compact finding fields keep
                    # their finding-specific severity/action/verification semantics.
                    row = dict(identity)
                    row.update(finding)
            enriched.append(row)
        return enriched

    if isinstance(identities, list):
        return [row for row in identities if isinstance(row, dict)]
    raise ValueError("Privileged identity report must contain a Findings or PrivilegedIdentities list")


def normalize_privileged_identity(data: dict[str, Any], source_file: str | Path) -> dict[str, Any]:
    rows = source_rows(data)
    timestamp_utc = generated_at_utc(data)
    script_name = source_script(data, "Get-PrivilegedIdentityProtectionAudit.ps1")
    findings = []
    for index, row in enumerate(rows, start=1):
        severity = normalize_source_severity(row.get("Severity") or row.get("ReviewPriority") or row.get("ActionPriority"))
        affected_object = row_identifier(row, f"privileged-identity-{index}")
        classification = service_account_classification(row)["classification"]
        findings.append(
            build_common_finding(
                finding_id=f"AD-PID-{index:04d}",
                title=title_for(row),
                category="Active Directory Security",
                severity=severity,
                affected_object=affected_object,
                object_type="Active Directory privileged identity",
                source_script_name=script_name,
                evidence=build_evidence(row),
                risk_factors=risk_factors_for(row),
                business_impact="Privileged identities can change administrative control over the domain and require strong ownership and protection evidence.",
                technical_impact="The source report identified privileged identity protection gaps, structural privileged access issues, or review blockers.",
                recommendation=account_review_recommendation(
                    row,
                    classification,
                    "Validate privileged access requirement, owner evidence, and protection controls before changing the account.",
                ),
                timestamp_utc=timestamp_utc,
                safety_reason="Privileged identity changes require identity owner validation, access approval, and controlled verification before remediation.",
            )
        )

    return base_normalized_report(
        report_type="ad-privileged-identity",
        tool_name="SecureInfra AI Privileged Identity Analyzer",
        source_file=source_file,
        data=data,
        findings=findings,
        source_script_name=script_name,
        input_count=len(rows),
        normalizer_name="ad_privileged_identity",
    )

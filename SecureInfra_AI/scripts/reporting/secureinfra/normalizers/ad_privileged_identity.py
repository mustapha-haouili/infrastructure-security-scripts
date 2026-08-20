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
        "sid": str(row.get("SID") or row.get("MemberSID") or ""),
        "object_sid": str(row.get("SID") or row.get("MemberSID") or ""),
        "object_class": str(row.get("ObjectClass") or row.get("MemberObjectClass") or ""),
        "group_name": str(row.get("GroupName") or row.get("EffectivePrivilegedGroupsText") or ""),
        "member_name": str(row.get("MemberName") or row.get("Subject") or ""),
        "member_sam_account_name": str(row.get("MemberSamAccountName") or row.get("SamAccountName") or row.get("Subject") or ""),
        "member_object_class": str(row.get("MemberObjectClass") or row.get("ObjectClass") or ""),
        "member_sid": str(row.get("MemberSID") or row.get("SID") or ""),
        "member_dn": str(row.get("MemberDN") or row.get("DistinguishedName") or ""),
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


def _nonempty(value: Any) -> bool:
    return value not in (None, "", [], {})


def _membership_key(value: Any) -> str:
    return _account_key(value)


def _enrich_structural_finding_from_memberships(
    finding: dict[str, Any], memberships: list[dict[str, Any]]
) -> dict[str, Any]:
    """Attach object-class/SID/DN evidence to compact group/computer principal findings.

    ``NestedPrivilegedGroup`` and ``NonUserPrivilegedPrincipal`` rows are emitted as
    compact alerts, while the report's ``Memberships`` section carries the authoritative
    MemberObjectClass/MemberSID/MemberDN fields.  Without this enrichment a nested group
    can be misclassified as a user and a computer principal cannot correlate with AD-COMP.
    """
    finding_type = str(finding.get("FindingType") or "").strip()
    if finding_type not in {"NestedPrivilegedGroup", "NonUserPrivilegedPrincipal"}:
        return dict(finding)

    subject_key = _membership_key(finding.get("Subject") or finding.get("SamAccountName"))
    group_key = str(finding.get("GroupName") or "").strip().casefold()
    candidates: list[dict[str, Any]] = []
    for membership in memberships:
        if not isinstance(membership, dict):
            continue
        member_keys = {
            _membership_key(membership.get("MemberSamAccountName")),
            _membership_key(membership.get("MemberName")),
        }
        member_keys.discard("")
        if subject_key and subject_key not in member_keys:
            continue
        membership_group = str(membership.get("GroupName") or "").strip().casefold()
        if group_key and membership_group and membership_group != group_key:
            continue
        candidates.append(membership)

    if not candidates:
        return dict(finding)

    # Direct membership is the strongest structural match; then choose deterministically.
    candidates.sort(
        key=lambda item: (
            0 if str(item.get("MembershipType") or "").strip().casefold() == "direct" else 1,
            str(item.get("GroupName") or "").casefold(),
            str(item.get("MemberSID") or "").casefold(),
        )
    )
    membership = candidates[0]
    row = dict(finding)
    mapped = {
        "SamAccountName": membership.get("MemberSamAccountName"),
        "SID": membership.get("MemberSID"),
        "DistinguishedName": membership.get("MemberDN"),
        "ObjectClass": membership.get("MemberObjectClass"),
        "MemberName": membership.get("MemberName"),
        "MemberSamAccountName": membership.get("MemberSamAccountName"),
        "MemberObjectClass": membership.get("MemberObjectClass"),
        "MemberSID": membership.get("MemberSID"),
        "MemberDN": membership.get("MemberDN"),
        "MembershipType": membership.get("MembershipType"),
    }
    for key, value in mapped.items():
        if _nonempty(value) and not _nonempty(row.get(key)):
            row[key] = value
    return row


def source_rows(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Return compact findings enriched from authoritative identity/membership views.

    The PowerShell report intentionally has three complementary views:
    ``Findings`` contains compact alert rows, ``PrivilegedIdentities`` carries rich
    user-account evidence, and ``Memberships`` carries authoritative structural
    identity evidence for nested groups and non-user principals.  Correlation must
    retain the object class/SID rather than guessing from a name.
    """
    findings = data.get("Findings")
    identities = data.get("PrivilegedIdentities")
    memberships_raw = data.get("Memberships")
    memberships = [row for row in memberships_raw if isinstance(row, dict)] if isinstance(memberships_raw, list) else []

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
            finding_type = str(finding.get("FindingType") or "").strip()
            row = dict(finding)
            if finding_type == "PrivilegedIdentityProtectionGap":
                key = _account_key(finding.get("Subject") or finding.get("SamAccountName"))
                identity = identity_by_key.get(key)
                if identity:
                    # Rich identity evidence is the base; compact finding fields keep
                    # their finding-specific severity/action/verification semantics.
                    row = dict(identity)
                    row.update(finding)
            elif finding_type in {"NestedPrivilegedGroup", "NonUserPrivilegedPrincipal"}:
                row = _enrich_structural_finding_from_memberships(finding, memberships)
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

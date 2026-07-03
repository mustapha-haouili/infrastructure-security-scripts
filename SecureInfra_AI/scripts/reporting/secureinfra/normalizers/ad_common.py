"""Shared Active Directory normalizer helpers."""

from __future__ import annotations

import re
import time
from collections import Counter
from pathlib import Path
from typing import Any

from secureinfra.normalizers.evidence_contract import normalize_report_evidence_contract
from secureinfra.risk_engine.rules import as_bool, as_int, as_list, remediation_priority_for


SEVERITIES = ["Critical", "High", "Medium", "Low", "Info", "Hold"]


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def first_present(data: dict[str, Any], names: list[str], default: Any = None) -> Any:
    lower_map = {key.lower(): key for key in data}
    for name in names:
        key = lower_map.get(name.lower())
        if key is not None and data.get(key) not in (None, ""):
            return data.get(key)
    return default


def optional_bool(value: Any) -> bool | None:
    """Return a boolean only when the source value explicitly provides one."""
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1", "enabled"}:
            return True
        if lowered in {"false", "no", "0", "disabled"}:
            return False
    return None


def optional_int(value: Any) -> int | None:
    """Return an integer only when the source value explicitly provides one."""
    if value in (None, "") or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def optional_text(value: Any) -> str | None:
    if value in (None, ""):
        return None
    return str(value)


def activity_evidence_context(row: dict[str, Any]) -> dict[str, Any]:
    inactive_days = optional_int(first_present(row, ["InactiveDays", "DaysInactive"], None))
    never_logged_on = optional_bool(first_present(row, ["NeverLoggedOn"], None))
    source = optional_text(
        first_present(
            row,
            ["ActivityEvidenceSource", "LastLogonEvidence", "LastLogonDateUtc", "LastLogonTimestampUtc"],
            None,
        )
    )
    if source is None and (inactive_days is not None or never_logged_on is not None):
        source = "LastLogonDate / lastLogonTimestamp"
    if source is None:
        return {
            "activity_evidence_source": "Not collected",
            "activity_evidence_confidence": "Needs Corroboration",
            "activity_validation_required": True,
        }
    return {
        "activity_evidence_source": source,
        "activity_evidence_confidence": "Medium",
        "activity_validation_required": True,
    }


ADMIN_GOVERNANCE_CLASSIFICATIONS = {
    "Built-in Administrator Governance Review",
    "Built-in Privileged Account Review",
    "Privileged Administrator Governance Review",
    "Break-glass Account Governance Review",
    "Daily Administrator Governance Review",
}


def service_account_classification(row: dict[str, Any]) -> dict[str, str]:
    """Classify account evidence with admin/governance precedence before service signals."""
    account_type = str(first_present(row, ["AccountType", "AccountCategory", "classification"], "")).strip()
    object_class = str(first_present(row, ["ObjectClass"], "")).strip()
    reason_text = " ".join(
        split_text_or_list(first_present(row, ["RiskFlags", "RiskFlagsText"], []))
        + split_text_or_list(first_present(row, ["ReviewReasons", "ReviewReasonsText"], []))
        + split_text_or_list(first_present(row, ["DependencySignals", "DependencySignalsText"], []))
    ).lower()
    name_text = " ".join(
        str(first_present(row, [name], "") or "")
        for name in ["SamAccountName", "Name", "Description", "DistinguishedName"]
    ).lower()
    has_spn = optional_bool(first_present(row, ["HasSPN"], None)) is True or (optional_int(first_present(row, ["SPNCount"], None)) or 0) > 0
    admin_count = optional_int(first_present(row, ["AdminCount"], None))
    privileged_group_count = optional_int(first_present(row, ["PrivilegedGroupCount"], None)) or 0
    password_never_expires = optional_bool(first_present(row, ["PasswordNeverExpires"], None)) is True
    owner_missing = optional_bool(first_present(row, ["OwnerEvidenceMissing", "MissingOwner"], None)) is True
    admin_review = admin_governance_classification(row)

    if admin_review:
        return admin_review

    managed_service = "managedserviceaccount" in object_class.lower() or "managedserviceaccount" in account_type.lower()
    explicit_service = normalized_account_type(account_type) in {
        "userspnserviceaccount",
        "spnserviceaccount",
        "groupmanagedserviceaccount",
        "standalonemanagedserviceaccount",
        "managedserviceaccount",
        "userserviceaccount",
        "serviceaccount",
    }
    service_dependency = has_explicit_service_dependency(row)
    service_pattern = (
        account_type == "UserServiceAccountCandidate"
        or "servicenamepattern" in reason_text
        or "service account" in reason_text
        or "ou=service accounts" in name_text
        or bool(re.search(r"(^|[^a-z0-9])(svc|gmsa|msa)[-_]", name_text))
    )
    strong_service_evidence = managed_service or explicit_service or service_dependency or (has_spn and service_pattern)

    if strong_service_evidence:
        return {
            "classification": "Strict Service Accounts",
            "classification_reason": "Strong service-account evidence was present, such as explicit service account type, managed service account class, service dependency evidence, or SPN plus service-specific naming/OU evidence.",
            "service_account_confidence": "High",
            "account_review_reason": "Validate owner, dependency, credential handling, and monitoring before changes.",
        }
    if service_pattern:
        return {
            "classification": "Service Account Candidates",
            "classification_reason": "Service naming, OU, or description pattern suggests a possible service account.",
            "service_account_confidence": "Medium",
            "account_review_reason": "Confirm whether this account is used by a service before changes.",
        }
    if admin_count == 1 or privileged_group_count > 0 or "privilegedaccess" in reason_text:
        return {
            "classification": "Privileged Residue Candidates",
            "classification_reason": "Privileged indicators are present, but no strong service-account indicator was found.",
            "service_account_confidence": "Low",
            "account_review_reason": "Review current and former privileged access, ownership, and AdminCount/ACL residue.",
        }
    if password_never_expires:
        return {
            "classification": "Password Exception Reviews",
            "classification_reason": "PasswordNeverExpires is present without strong service-account evidence.",
            "service_account_confidence": "Low",
            "account_review_reason": "Validate owner and approved password exception.",
        }
    if owner_missing:
        return {
            "classification": "Missing Owner Reviews",
            "classification_reason": "Ownership evidence is missing without strong service-account evidence.",
            "service_account_confidence": "Low",
            "account_review_reason": "Assign or confirm an owner before any remediation.",
        }
    return {
        "classification": "Account Review Candidates",
        "classification_reason": "The source did not provide enough evidence for a stricter account classification.",
        "service_account_confidence": "Low",
        "account_review_reason": "Validate account purpose and owner.",
    }


def normalized_account_type(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def account_identity_text(row: dict[str, Any]) -> str:
    values = []
    for key in [
        "AccountType",
        "AccountCategory",
        "IdentityCategory",
        "classification",
        "SamAccountName",
        "Name",
        "Description",
        "DistinguishedName",
        "RiskFlags",
        "RiskFlagsText",
        "ReviewReasons",
        "ReviewReasonsText",
    ]:
        value = row.get(key)
        if isinstance(value, list):
            values.extend(str(item) for item in value)
        elif value not in (None, ""):
            values.append(str(value))
    return " ".join(values).lower()


def is_built_in_administrator_account(row: dict[str, Any]) -> bool:
    sam = str(first_present(row, ["SamAccountName", "Subject", "Name"], "") or "").strip().lower()
    sid = str(first_present(row, ["ObjectSid", "SID", "SubjectSID"], "") or "")
    text = account_identity_text(row)
    return (
        sam == "administrator"
        or "builtinadministrator" in normalized_account_type(text)
        or "built-in administrator" in text
        or sid.endswith("-500")
    )


def explicit_category_present(row: dict[str, Any], categories: set[str]) -> bool:
    for key in ["AccountType", "AccountCategory", "IdentityCategory", "classification"]:
        if normalized_account_type(row.get(key)) in categories:
            return True
    text = normalized_account_type(account_identity_text(row))
    return any(category in text for category in categories)


def admin_governance_classification(row: dict[str, Any]) -> dict[str, str] | None:
    if is_built_in_administrator_account(row):
        return admin_classification(
            "Built-in Administrator Governance Review",
            "Built-in Administrator evidence takes precedence over SPN, AdminCount, privileged membership, PasswordNeverExpires, and service-candidate signals.",
            "Validate owner, break-glass purpose, password custody, monitoring, SPN/dependency exposure, and change approval before any account change.",
            row,
            "built-in administrator account",
        )
    if explicit_category_present(row, {"builtinprivilegedaccount", "builtinprivileged"}):
        return admin_classification(
            "Built-in Privileged Account Review",
            "Built-in privileged-account evidence takes precedence over service-account indicators.",
            "Validate owner, privileged purpose, monitoring, credential custody, and change approval before any account change.",
            row,
            "built-in privileged account",
        )
    if explicit_category_present(row, {"privilegedadministrator", "privilegedadmin"}):
        return admin_classification(
            "Privileged Administrator Governance Review",
            "Explicit privileged-administrator evidence takes precedence over service-account indicators.",
            "Validate owner, administrative purpose, monitoring, credential controls, SPN/dependency exposure, and change approval before any account change.",
            row,
            "privileged administrator account",
        )
    if explicit_category_present(row, {"breakglasscandidate", "breakglassaccount"}):
        return admin_classification(
            "Break-glass Account Governance Review",
            "Explicit break-glass evidence takes precedence over service-account indicators.",
            "Validate break-glass purpose, owner, password custody, activation process, monitoring, and review schedule before any account change.",
            row,
            "break-glass account candidate",
        )
    if explicit_category_present(row, {"dailyadmincandidate", "dailyadministrator"}):
        return admin_classification(
            "Daily Administrator Governance Review",
            "Explicit daily-administrator evidence takes precedence over service-account indicators.",
            "Validate owner, administrative purpose, current usage evidence, monitoring, and change approval before any account change.",
            row,
            "daily administrator account candidate",
        )
    return None


def admin_classification(
    classification: str,
    reason: str,
    review_reason: str,
    row: dict[str, Any],
    summary_label: str,
) -> dict[str, str]:
    return {
        "classification": classification,
        "classification_reason": reason,
        "service_account_confidence": "NotApplicable",
        "account_review_reason": review_reason,
        "summary": account_governance_summary(row, summary_label),
    }


def account_governance_summary(row: dict[str, Any], label: str) -> str:
    parts = [label]
    enabled = optional_bool(first_present(row, ["Enabled"], None))
    inactive_days = optional_int(first_present(row, ["InactiveDays", "DaysInactive"], None))
    admin_count = optional_int(first_present(row, ["AdminCount"], None))
    privileged_group_count = optional_int(first_present(row, ["PrivilegedGroupCount"], None))
    password_never_expires = optional_bool(first_present(row, ["PasswordNeverExpires"], None))
    has_spn = optional_bool(first_present(row, ["HasSPN"], None)) is True or (optional_int(first_present(row, ["SPNCount"], None)) or 0) > 0

    if enabled is not None:
        parts.append(f"enabled: {str(enabled).lower()}")
    if inactive_days is not None:
        parts.append(f"inactivity evidence: {inactive_days} days")
    privileged_indicators = []
    if admin_count is not None:
        privileged_indicators.append(f"AdminCount={admin_count}")
    if privileged_group_count:
        privileged_indicators.append(f"privileged_group_count={privileged_group_count}")
    groups = split_text_or_list(first_present(row, ["PrivilegedGroups", "PrivilegedGroupsText"], []))
    if groups:
        privileged_indicators.append("privileged groups: " + ", ".join(groups))
    if privileged_indicators:
        parts.append("privileged indicators: " + ", ".join(privileged_indicators))
    if password_never_expires is not None:
        parts.append(f"PasswordNeverExpires: {str(password_never_expires).lower()}")
    if has_spn:
        parts.append("SPN/dependency review required")
    return "; ".join(parts)


def has_explicit_service_dependency(row: dict[str, Any]) -> bool:
    values = []
    for key in [
        "DependencySignals",
        "DependencySignalsText",
        "ServiceDependencies",
        "ServiceDependencyEvidence",
        "ServiceEvidence",
        "ServiceName",
        "ServiceOwner",
        "ServicePrincipalNames",
        "ServicePrincipalNamesText",
        "ReviewReasons",
        "ReviewReasonsText",
    ]:
        value = row.get(key)
        if isinstance(value, list):
            values.extend(str(item) for item in value)
        elif value not in (None, ""):
            values.append(str(value))
    text = " ".join(values).lower()
    if not text:
        return False
    if re.search(r"\b(service|application|app|scheduled task|runs as|dependency|database|mssql|http/|ldap/|cifs/)\b", text):
        return True
    return False


def account_risk_flags(row: dict[str, Any]) -> list[str]:
    flags = split_text_or_list(row.get("RiskFlags") or row.get("RiskFlagsText"))
    if is_built_in_administrator_account(row) and not has_explicit_service_dependency(row):
        return [
            flag
            for flag in flags
            if normalized_account_type(flag) not in {"serviceaccountcandidate", "serviceaccount"}
        ]
    return flags


def account_review_recommendation(row: dict[str, Any], classification: str, default: str) -> str:
    supplied = row.get("RecommendedAction") or row.get("AdminAction")
    if classification in ADMIN_GOVERNANCE_CLASSIFICATIONS:
        base = str(supplied) if supplied else (
            "Validate owner, break-glass or administrative purpose, password custody, monitoring, "
            "SPN/dependency exposure, and change approval before any account change."
        )
        if "do not delete" not in base.lower():
            base = f"{base} Do not delete built-in or privileged administrator accounts."
        return base
    if supplied:
        return str(supplied)
    return default


def report_metadata(data: dict[str, Any]) -> dict[str, Any]:
    metadata = data.get("ReportMetadata") or data.get("report_metadata") or data.get("metadata")
    return metadata if isinstance(metadata, dict) else {}


def generated_at_utc(data: dict[str, Any]) -> str:
    metadata = report_metadata(data)
    return str(
        first_present(data, ["GeneratedAtUtc", "generated_at_utc"], None)
        or first_present(metadata, ["GeneratedAtUtc", "generated_at_utc"], None)
        or utc_now()
    )


def source_script(data: dict[str, Any], default: str) -> str:
    metadata = report_metadata(data)
    return str(
        first_present(data, ["SourceScript", "source_script"], None)
        or first_present(metadata, ["ScriptName", "SourceScript", "source_script"], None)
        or default
    )


def environment_summary(data: dict[str, Any], source_script_name: str, input_count: int) -> dict[str, Any]:
    metadata = report_metadata(data)
    domain = data.get("Domain") or data.get("DomainName") or metadata.get("Domain") or metadata.get("DomainName") or ""
    company = data.get("Company") or metadata.get("Company") or ""
    return {
        "company": str(company),
        "domain": str(domain),
        "source_script": source_script_name,
        "input_record_count": input_count,
    }


def summary_from_report(data: dict[str, Any]) -> dict[str, Any]:
    summary = data.get("Summary") or data.get("summary")
    return summary if isinstance(summary, dict) else {}


def severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(str(item.get("severity") or "Info") for item in findings)
    return {severity: counts.get(severity, 0) for severity in SEVERITIES}


def normalize_source_severity(value: Any) -> str:
    raw = str(value or "").strip()
    if raw in SEVERITIES:
        return raw
    lowered = raw.lower()
    if lowered in {"critical", "p1"} or lowered.startswith("p1"):
        return "Critical"
    if lowered in {"high", "p2"} or lowered.startswith("p2"):
        return "High"
    if lowered in {"medium", "moderate", "p3"} or lowered.startswith("p3"):
        return "Medium"
    if lowered in {"low", "p4"} or lowered.startswith("p4"):
        return "Low"
    if lowered in {"hold", "system managed"}:
        return "Hold"
    if lowered in {"info", "informational", "p5"} or lowered.startswith("p5"):
        return "Info"
    return "Info"


def split_text_or_list(value: Any) -> list[str]:
    values = as_list(value)
    if len(values) == 1 and ";" in values[0]:
        return [part.strip() for part in values[0].split(";") if part.strip()]
    return values


def row_identifier(row: dict[str, Any], fallback: str) -> str:
    for key in ["SamAccountName", "Subject", "Name", "DNSHostName", "DisplayName", "MemberSamAccountName", "MemberName", "GroupName", "GpoName", "TargetPath"]:
        value = row.get(key)
        if value not in (None, ""):
            return str(value)
    return fallback


def ad_safety_reason(row: dict[str, Any], object_label: str) -> str:
    if normalize_source_severity(row.get("ReviewPriority") or row.get("ExposurePriority")) == "Hold":
        return f"{object_label} is on hold or system-managed; do not remediate without product owner approval."
    if as_bool(row.get("IsDomainController")):
        return "Domain controller computer objects must not be cleaned up automatically."
    if as_int(row.get("PrivilegedGroupCount"), 0) > 0 or split_text_or_list(row.get("PrivilegedGroups")):
        return f"Privileged {object_label.lower()} changes require owner validation and approved change control."
    if as_bool(row.get("HasSPN")) or as_int(row.get("SPNCount"), 0) > 0:
        return f"SPN-bearing {object_label.lower()} may represent service dependencies and requires owner review."
    if as_bool(row.get("PasswordNeverExpires")):
        return f"{object_label} with PasswordNeverExpires requires exception and owner review."
    return f"{object_label} lifecycle changes require owner review and approved change control."


def build_common_finding(
    *,
    finding_id: str,
    title: str,
    category: str,
    severity: str,
    affected_object: str,
    object_type: str,
    source_script_name: str,
    evidence: dict[str, Any],
    risk_factors: list[str],
    business_impact: str,
    technical_impact: str,
    recommendation: str,
    timestamp_utc: str,
    safety_reason: str,
) -> dict[str, Any]:
    return {
        "finding_id": finding_id,
        "title": title,
        "category": category,
        "severity": severity,
        "affected_object": affected_object,
        "object_type": object_type,
        "source_script": source_script_name,
        "evidence": evidence,
        "risk_factors": risk_factors,
        "business_impact": business_impact,
        "technical_impact": technical_impact,
        "recommendation": recommendation,
        "remediation_priority": remediation_priority_for(severity),
        "requires_owner_review": True,
        "requires_change_approval": severity in {"Critical", "High", "Medium", "Hold"},
        "safe_to_auto_remediate": False,
        "not_safe_for_auto_remediation_reason": safety_reason,
        "status": "Hold" if severity == "Hold" else "Open",
        "timestamp_utc": timestamp_utc,
    }


def base_normalized_report(
    *,
    report_type: str,
    tool_name: str,
    source_file: str | Path,
    data: dict[str, Any],
    findings: list[dict[str, Any]],
    source_script_name: str,
    input_count: int,
    normalizer_name: str,
) -> dict[str, Any]:
    timestamp_utc = generated_at_utc(data)
    return normalize_report_evidence_contract(
        {
            "report_id": f"secureinfra-ai-{report_type}-{timestamp_utc.replace(':', '').replace('-', '')}",
            "report_type": report_type,
            "tool_name": tool_name,
            "source_files": [str(source_file)],
            "generated_at_utc": timestamp_utc,
            "environment_summary": environment_summary(data, source_script_name, input_count),
            "summary": {
                "total_findings": len(findings),
                "normalized_finding_count": len(findings),
                "severity_counts": severity_counts(findings),
                "source_summary": summary_from_report(data),
            },
            "findings": findings,
            "metadata": {
                "normalizer": normalizer_name,
                "normalizer_version": "0.1.0",
                "risk_engine": "source-priority-mapping",
                "ai_required": False,
            },
            "notes": [
                "AI is not required for analysis.",
                "Findings are based only on supplied JSON evidence and source script priorities.",
                "Human owner review and approved change control are required before remediation.",
            ],
        }
    )

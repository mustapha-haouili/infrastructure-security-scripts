"""Rule-based Active Directory risk classification.

These rules are deterministic and defensive. They do not rely on AI and do not
authorize remediation.
"""

from __future__ import annotations

from typing import Any


SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info", "Hold"]
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITY_ORDER)}


def as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "1", "enabled"}
    return False


def as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def as_optional_bool(value: Any) -> bool | None:
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


def as_optional_int(value: Any) -> int | None:
    if value in (None, "") or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    if isinstance(value, str):
        if not value.strip():
            return []
        if "," in value:
            return [part.strip() for part in value.split(",") if part.strip()]
        return [value.strip()]
    return [str(value)]


def lower_text(value: Any) -> str:
    return str(value or "").strip().lower()


def is_health_mailbox(user: dict[str, Any]) -> bool:
    sam = lower_text(user.get("SamAccountName"))
    category = lower_text(user.get("AccountCategory"))
    signals = " ".join(as_list(user.get("DependencySignals"))).lower()
    return sam.startswith("healthmailbox") or "healthmailbox" in category or "health mailbox" in signals


def is_system_managed(user: dict[str, Any]) -> bool:
    category = lower_text(user.get("AccountCategory"))
    risk_flags = " ".join(as_list(user.get("RiskFlags"))).lower()
    lifecycle = lower_text(user.get("LifecycleStage"))
    return is_health_mailbox(user) or "systemmanaged" in risk_flags or "system managed" in category or "system managed" in lifecycle


def is_built_in_administrator(user: dict[str, Any]) -> bool:
    sam = lower_text(user.get("SamAccountName"))
    category = lower_text(user.get("AccountCategory"))
    risk_flags = " ".join(as_list(user.get("RiskFlags"))).lower()
    sid = str(user.get("ObjectSid") or "")
    return (
        sam == "administrator"
        or "builtinadministrator" in category
        or "built-in administrator" in category
        or "builtinadministrator" in risk_flags
        or sid.endswith("-500")
    )


def has_mail_review_signal(user: dict[str, Any]) -> bool:
    signals = " ".join(as_list(user.get("DependencySignals")) + as_list(user.get("RiskFlags"))).lower()
    return "mail" in signals or as_bool(user.get("HasMailAttributes")) or as_bool(user.get("MailEnabled"))


def is_service_account_candidate(user: dict[str, Any]) -> bool:
    sam = lower_text(user.get("SamAccountName"))
    category = lower_text(user.get("AccountCategory"))
    reasons = " ".join(as_list(user.get("ReviewReasons"))).lower()
    return "service" in category or sam.startswith("svc") or "service account" in reasons


def has_explicit_service_dependency(user: dict[str, Any]) -> bool:
    signals = " ".join(
        as_list(user.get("DependencySignals"))
        + as_list(user.get("ReviewReasons"))
        + as_list(user.get("ServiceDependencies"))
        + as_list(user.get("ServiceEvidence"))
        + as_list(user.get("ServicePrincipalNames"))
    ).lower()
    return any(
        needle in signals
        for needle in ["service dependency", "runs as", "windows service", "scheduled task", "application dependency", "database", "mssql"]
    )


def remediation_priority_for(severity: str) -> str:
    return {
        "Critical": "Immediate Review",
        "High": "High Priority",
        "Medium": "Planned Remediation",
        "Low": "Monitor",
        "Info": "Monitor",
        "Hold": "Hold",
    }.get(severity, "Monitor")


def base_risk_factors(user: dict[str, Any]) -> list[str]:
    factors = as_list(user.get("RiskFlags"))
    if is_built_in_administrator(user) and not has_explicit_service_dependency(user):
        factors = [
            item
            for item in factors
            if item.strip().lower().replace(" ", "").replace("-", "") not in {"serviceaccountcandidate", "serviceaccount"}
        ]
    if as_bool(user.get("PasswordNeverExpires")) and "PasswordNeverExpires" not in factors:
        factors.append("PasswordNeverExpires")
    if as_bool(user.get("HasSPN")) and "SPN present" not in factors:
        factors.append("SPN present")
    if as_list(user.get("PrivilegedGroups")) and "Privileged group membership" not in factors:
        factors.append("Privileged group membership")
    if is_built_in_administrator(user) and "Built-in Administrator" not in factors:
        factors.append("Built-in Administrator")
    if is_system_managed(user) and "System-managed account" not in factors:
        factors.append("System-managed account")
    return factors


def safety_reason(user: dict[str, Any], severity: str) -> str:
    if is_health_mailbox(user) or is_system_managed(user):
        return "System-managed account. Do not remediate without product owner approval."
    if is_built_in_administrator(user):
        return "Built-in Administrator must not be deleted; requires break-glass policy review."
    if as_list(user.get("PrivilegedGroups")):
        return "Privileged account changes require owner validation and approved change control."
    if as_bool(user.get("HasSPN")):
        return "SPN-bearing accounts may represent service dependencies and require application owner review."
    if severity in {"Critical", "High", "Medium"}:
        return "Active Directory account lifecycle changes require owner review and approved change control."
    return "No automatic remediation is approved by this analyzer."


def classify_ad_inactive_user(user: dict[str, Any]) -> dict[str, Any]:
    """Classify one inactive AD user record with deterministic rules."""
    enabled_value = as_optional_bool(user.get("Enabled"))
    enabled = enabled_value is True
    inactive_days = as_optional_int(user.get("InactiveDays", user.get("DaysInactive")))
    high_inactivity = inactive_days is not None and inactive_days > 90
    privileged_groups = as_list(user.get("PrivilegedGroups"))
    has_spn = as_bool(user.get("HasSPN"))
    password_never_expires = as_bool(user.get("PasswordNeverExpires"))
    built_in_admin = is_built_in_administrator(user)
    system_managed = is_system_managed(user)

    title = "Inactive account requires review"
    severity = "Low"
    business_impact = "Inactive accounts can increase identity hygiene risk if ownership and purpose are unclear."
    technical_impact = "The account appears in inactive user audit evidence and requires validation."
    recommendation = str(user.get("RecommendedAction") or "Validate owner, purpose, and dependency before any change.")

    if system_managed:
        title = "System-managed account on hold"
        severity = "Hold"
        business_impact = "System-managed accounts can be required for platform health and should not be handled as normal cleanup."
        technical_impact = "The account has system-managed or Exchange HealthMailbox indicators."
        recommendation = "Keep on hold unless the product owner approves a specific action."
    elif built_in_admin and enabled and high_inactivity:
        title = "Built-in Administrator enabled and inactive"
        severity = "Critical"
        business_impact = "Break-glass access requires strict governance, monitoring, and documented ownership."
        technical_impact = "The built-in Administrator account is enabled and inactive in the audit evidence."
        recommendation = "Validate owner, break-glass purpose, password custody, monitoring, and change approval. Do not delete the built-in account."
    elif enabled and high_inactivity and privileged_groups and has_spn:
        title = "Enabled inactive privileged account with SPN detected"
        severity = "Critical"
        business_impact = "Privileged inactive accounts with service indicators can create elevated identity exposure and operational dependency risk."
        technical_impact = "The enabled inactive account has privileged group membership and SPN evidence."
        recommendation = "Validate owner, privileged access need, and service dependency before any change."
    elif enabled and high_inactivity and privileged_groups:
        title = "Enabled inactive privileged account detected"
        severity = "Critical"
        business_impact = "Inactive privileged accounts can retain administrative capability after role or ownership changes."
        technical_impact = "The enabled inactive account has privileged group membership."
        recommendation = "Validate owner, approval record, and need for privileged access."
    elif enabled and high_inactivity and is_service_account_candidate(user):
        title = "Enabled stale service account candidate detected"
        severity = "High"
        business_impact = "Changing service accounts without dependency review can disrupt applications, but stale service accounts also increase exposure."
        technical_impact = "The enabled inactive account has service account indicators."
        recommendation = "Confirm service owner and dependency before any change."
    elif enabled and high_inactivity and password_never_expires:
        title = "Enabled inactive account with PasswordNeverExpires detected"
        severity = "High"
        business_impact = "Long-lived credentials on inactive accounts increase identity exposure."
        technical_impact = "The enabled inactive account has PasswordNeverExpires set."
        recommendation = "Validate owner and exception status before changing password policy or disabling the account."
    elif enabled and high_inactivity and has_spn:
        title = "Inactive account with SPN requires owner review"
        severity = "High"
        business_impact = "SPN-bearing accounts may represent application dependencies and require careful owner validation."
        technical_impact = "The inactive account has SPN evidence. This is a service dependency risk indicator, not exploitation guidance."
        recommendation = "Review application owner and SPN requirement before any change."
    elif enabled_value is False and (high_inactivity or as_bool(user.get("PotentialDeletionCandidate"))):
        title = "Disabled inactive account requires owner review"
        severity = "Medium"
        business_impact = "Disabled inactive accounts may still have mailbox, retention, or dependency requirements."
        technical_impact = "The account is disabled but still requires owner and retention validation."
        recommendation = "Confirm owner, retention, and dependency requirements before cleanup."
    elif has_mail_review_signal(user):
        title = "Mail-enabled inactive account requires mailbox review"
        severity = "Medium"
        business_impact = "Mailbox or data retention requirements can affect account cleanup timing."
        technical_impact = "The inactive account has mail-related review indicators."
        recommendation = "Confirm mailbox ownership and retention requirements."
    elif enabled and high_inactivity:
        title = "Enabled inactive account requires lifecycle review"
        severity = "Medium"
        business_impact = "Enabled inactive accounts can retain access after role or employment changes."
        technical_impact = "The account is enabled and older than the inactivity threshold."
        recommendation = "Validate owner and disable only after approval."

    return {
        "title": title,
        "severity": severity,
        "remediation_priority": remediation_priority_for(severity),
        "risk_factors": base_risk_factors(user),
        "business_impact": business_impact,
        "technical_impact": technical_impact,
        "recommendation": recommendation,
        "requires_owner_review": True,
        "requires_change_approval": severity in {"Critical", "High", "Medium", "Hold"} or enabled,
        "safe_to_auto_remediate": False,
        "not_safe_for_auto_remediation_reason": safety_reason(user, severity),
        "status": "Hold" if severity == "Hold" else "Open",
    }

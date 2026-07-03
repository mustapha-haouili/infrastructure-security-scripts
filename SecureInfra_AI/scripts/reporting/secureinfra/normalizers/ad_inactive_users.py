"""Normalize Active Directory inactive user reports."""

from __future__ import annotations

import time
from collections import Counter
from pathlib import Path
from typing import Any

from secureinfra.normalizers.ad_common import (
    activity_evidence_context,
    account_risk_flags,
    optional_bool,
    optional_int,
    service_account_classification,
)
from secureinfra.normalizers.evidence_contract import normalize_report_evidence_contract
from secureinfra.risk_engine.rules import as_list, classify_ad_inactive_user


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def first_present(data: dict[str, Any], names: list[str], default: Any = None) -> Any:
    lower_map = {key.lower(): key for key in data}
    for name in names:
        key = lower_map.get(name.lower())
        if key is not None and data.get(key) not in (None, ""):
            return data.get(key)
    return default


def build_evidence(user: dict[str, Any]) -> dict[str, Any]:
    classification = service_account_classification(user)
    evidence = {
        "sam_account_name": str(user.get("SamAccountName") or ""),
        "enabled": optional_bool(user.get("Enabled")),
        "inactive_days": optional_int(user.get("InactiveDays", user.get("DaysInactive"))),
        "review_priority": str(user.get("ReviewPriority") or ""),
        "account_category": str(user.get("AccountCategory") or ""),
        "lifecycle_stage": str(user.get("LifecycleStage") or ""),
        "deletion_readiness": str(user.get("DeletionReadiness") or ""),
        "can_delete_now": optional_bool(user.get("CanDeleteNow")),
        "potential_deletion_candidate": optional_bool(user.get("PotentialDeletionCandidate")),
        "password_never_expires": optional_bool(user.get("PasswordNeverExpires")),
        "admin_count": optional_int(user.get("AdminCount")),
        "has_spn": optional_bool(user.get("HasSPN")),
        "privileged_groups": as_list(user.get("PrivilegedGroups")),
        "dependency_signals": as_list(user.get("DependencySignals")),
        "risk_flags": account_risk_flags(user),
        "review_reasons": as_list(user.get("ReviewReasons")),
        "distinguished_name": str(user.get("DistinguishedName") or ""),
        "object_sid": str(user.get("ObjectSid") or ""),
        "deletion_guidance": str(user.get("DeletionGuidance") or ""),
        **activity_evidence_context(user),
        **classification,
    }
    return evidence


def normalize_user(user: dict[str, Any], index: int, source_script: str, timestamp_utc: str) -> dict[str, Any]:
    risk = classify_ad_inactive_user(user)
    sam_account_name = str(user.get("SamAccountName") or f"unknown-user-{index}")
    return {
        "finding_id": f"AD-INACTIVE-{index:04d}",
        "title": risk["title"],
        "category": "Active Directory Security",
        "severity": risk["severity"],
        "affected_object": sam_account_name,
        "object_type": "Active Directory user",
        "source_script": source_script,
        "evidence": build_evidence(user),
        "risk_factors": risk["risk_factors"],
        "business_impact": risk["business_impact"],
        "technical_impact": risk["technical_impact"],
        "recommendation": risk["recommendation"],
        "remediation_priority": risk["remediation_priority"],
        "requires_owner_review": risk["requires_owner_review"],
        "requires_change_approval": risk["requires_change_approval"],
        "safe_to_auto_remediate": risk["safe_to_auto_remediate"],
        "not_safe_for_auto_remediation_reason": risk["not_safe_for_auto_remediation_reason"],
        "status": risk["status"],
        "timestamp_utc": timestamp_utc,
    }


def severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(str(item.get("severity") or "Info") for item in findings)
    return {severity: counts.get(severity, 0) for severity in ["Critical", "High", "Medium", "Low", "Info", "Hold"]}


def normalize_ad_inactive_users(data: dict[str, Any], source_file: str | Path) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ValueError("AD inactive users input must be a JSON object")

    users = data.get("InactiveUsers")
    if not isinstance(users, list):
        raise ValueError("AD inactive users input must contain an InactiveUsers list")

    timestamp_utc = str(first_present(data, ["GeneratedAtUtc", "generated_at_utc"], utc_now()))
    source_script = str(first_present(data, ["SourceScript", "source_script"], "Get-ADInactiveUserReport.ps1"))
    source_path = str(source_file)
    findings = [normalize_user(user, index, source_script, timestamp_utc) for index, user in enumerate(users, start=1)]
    counts = severity_counts(findings)
    summary = data.get("Summary") if isinstance(data.get("Summary"), dict) else {}

    return normalize_report_evidence_contract(
        {
            "report_id": f"secureinfra-ai-ad-inactive-users-{timestamp_utc.replace(':', '').replace('-', '')}",
            "report_type": "ad-inactive-users",
            "tool_name": "SecureInfra AI AD Inactive Users Analyzer",
            "source_files": [source_path],
            "generated_at_utc": timestamp_utc,
            "environment_summary": {
                "company": str(data.get("Company") or ""),
                "domain": str(data.get("Domain") or ""),
                "source_script": source_script,
                "input_user_count": len(users),
            },
            "summary": {
                "total_findings": len(findings),
                "normalized_finding_count": len(findings),
                "severity_counts": counts,
                "source_summary": summary,
            },
            "findings": findings,
            "metadata": {
                "normalizer": "ad_inactive_users",
                "normalizer_version": "0.1.0",
                "risk_engine": "deterministic-rules",
                "ai_required": False,
            },
            "notes": [
                "AI is not required for Phase 1 analysis.",
                "Findings are based only on supplied JSON evidence.",
                "Human owner review and approved change control are required before remediation.",
            ],
        }
    )

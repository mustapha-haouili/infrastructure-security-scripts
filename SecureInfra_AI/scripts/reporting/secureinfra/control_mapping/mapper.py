"""Attach broad deterministic control references to normalized reports."""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

from secureinfra.control_mapping.catalog import CONTROL_CATALOG, THEME_ORDER, ControlReference


def add_control_mappings(report: dict[str, Any]) -> dict[str, Any]:
    """Add control mapping metadata without mutating normalized findings."""
    findings = report.get("findings", [])
    if not isinstance(findings, list):
        findings = []

    references_by_finding_id: dict[str, list[ControlReference]] = {}
    summary: Counter[str] = Counter()

    for finding in findings:
        if not isinstance(finding, dict):
            continue
        finding_id = str(finding.get("finding_id") or "").strip()
        if not finding_id:
            continue
        references = control_references_for_finding(finding)
        if not references:
            continue
        references_by_finding_id[finding_id] = references
        for reference in references:
            summary[f"{reference['framework']}:{reference['control_id']}"] += 1

    metadata = report.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
        report["metadata"] = metadata
    metadata["control_references_by_finding_id"] = references_by_finding_id
    metadata["control_mapping_summary"] = {key: summary[key] for key in sorted(summary)}
    return report


def control_references_for_finding(finding: dict[str, Any]) -> list[ControlReference]:
    themes = matched_themes(finding)
    references: list[ControlReference] = []
    seen: set[tuple[str, str]] = set()
    for theme in THEME_ORDER:
        if theme not in themes:
            continue
        for reference in CONTROL_CATALOG[theme]:
            key = (str(reference["framework"]), str(reference["control_id"]))
            if key in seen:
                continue
            seen.add(key)
            references.append(dict(reference))
    return references


def matched_themes(finding: dict[str, Any]) -> set[str]:
    text = finding_search_text(finding)
    finding_id = normalized_text(finding.get("finding_id"))
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    original_id = normalized_text(evidence.get("original_finding_id")) if isinstance(evidence, dict) else ""
    source_id_text = f"{finding_id} {original_id}"
    themes: set[str] = set()

    if "ad-inactive" in source_id_text or contains_any(text, ["inactive user", "inactive account", "inactive_days"]):
        themes.add("account_management_access_review")

    if "ad-comp" in source_id_text or contains_any(text, ["stale computer", "computer account", "dns_host_name", "asset inventory"]):
        themes.add("asset_inventory_attack_surface")

    if "ad-pne" in source_id_text or contains_any(text, ["passwordneverexpires", "password_never_expires", "non-expiring password"]):
        themes.add("account_management_authentication")

    if (
        "ad-pgroup" in source_id_text
        or "ad-pid" in source_id_text
        or contains_any(text, ["privileged group", "privileged identity", "local administrator", "administrators group", "admin_count"])
    ):
        themes.add("privileged_access_management")

    if (
        "ad-svc" in source_id_text
        or "ad-spn" in source_id_text
        or contains_any(text, ["service account", "spn", "service_principal_names", "credential hygiene", "delegation"])
    ):
        themes.add("service_account_credential_hygiene")

    if "gpo-health" in source_id_text or contains_any(text, ["group policy", "gpo", "sysvol", "secure configuration"]):
        themes.add("secure_configuration_management")

    if contains_any(text, ["firewall", "rdp", "remote desktop", "smb", "network exposure", "listening port", "remote access"]):
        themes.add("network_exposure_secure_configuration")

    if contains_any(text, ["linux", "ssh", "sshd", "sudo", "sudoers", "uid0", "uid 0", "permitrootlogin"]):
        themes.add("linux_account_secure_configuration")

    if contains_any(text, ["docker", "container", "kubernetes", "kubectl", "pod", "rbac", "workload"]):
        themes.add("workload_hardening")

    if contains_any(text, ["secret", "token", "credential", "private key", "api_key", "apikey", "password exposed"]):
        themes.add("secret_management")

    if contains_any(text, ["backup", "recovery", "restore", "resilience"]):
        themes.add("resilience_recovery_readiness")

    if "backup-readiness" in source_id_text or contains_any(
        text,
        [
            "backup readiness",
            "expected backup path",
            "restore test evidence",
            "backup monitoring",
            "backup evidence",
            "operational continuity",
        ],
    ):
        themes.add("backup_readiness_operational_continuity")

    if contains_any(text, ["patch", "updates", "update management", "vulnerability", "cve", "outdated package"]):
        themes.add("vulnerability_update_management")

    if is_windows_configuration_finding(text, source_id_text):
        themes.add("secure_configuration_management")

    return themes


def is_windows_configuration_finding(text: str, source_id_text: str) -> bool:
    if contains_any(source_id_text, ["host-win", "server-security", "workstation-security", "network-exposure"]):
        return True
    return contains_any(text, ["windows host security control", "windows server security control", "windows workstation security control"])


def finding_search_text(finding: dict[str, Any]) -> str:
    values: list[str] = []
    for key in [
        "finding_id",
        "title",
        "category",
        "object_type",
        "source_script",
        "business_impact",
        "technical_impact",
        "recommendation",
        "not_safe_for_auto_remediation_reason",
    ]:
        values.append(str(finding.get(key) or ""))

    risk_factors = finding.get("risk_factors")
    if isinstance(risk_factors, list):
        values.extend(str(item) for item in risk_factors)

    evidence = finding.get("evidence")
    if isinstance(evidence, dict):
        values.extend(flatten_evidence(evidence))

    return normalized_text(" ".join(values))


def flatten_evidence(value: Any) -> list[str]:
    if isinstance(value, dict):
        output: list[str] = []
        for key, item in value.items():
            output.append(str(key))
            output.extend(flatten_evidence(item))
        return output
    if isinstance(value, list):
        output = []
        for item in value:
            output.extend(flatten_evidence(item))
        return output
    return [str(value)]


def contains_any(text: str, needles: list[str]) -> bool:
    return any(normalized_text(needle) in text for needle in needles)


def normalized_text(value: Any) -> str:
    text = str(value or "").lower()
    text = re.sub(r"[^a-z0-9_.-]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()

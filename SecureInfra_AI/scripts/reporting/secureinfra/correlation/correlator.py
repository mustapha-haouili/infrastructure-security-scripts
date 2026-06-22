"""Build deterministic cross-source finding correlations."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from secureinfra.risk_engine.rules import SEVERITY_RANK


RELATIONSHIP_FIELDS = {
    "affected_object",
    "sam_account_name",
    "subject",
    "name",
    "dns_host_name",
    "member_sam_account_name",
    "member_name",
    "group_name",
    "gpo_name",
    "target_path",
    "service_principal_names",
    "privileged_groups",
    "object_sid",
    "sid",
}
IGNORED_RELATIONSHIP_FIELDS = {
    "bundle_input",
    "collection_id",
    "computer_name",
    "machine_id",
    "machine_name",
    "source_file",
    "source_report_type",
}
GENERIC_KEYS = {
    "true",
    "false",
    "critical",
    "high",
    "medium",
    "low",
    "info",
    "hold",
    "open",
    "user",
    "group",
    "computer",
}


def add_correlations(report: dict[str, Any]) -> dict[str, Any]:
    """Attach correlation groups to a normalized report and return it."""
    findings = report.get("findings", [])
    if not isinstance(findings, list):
        report["correlations"] = []
        return report
    report["correlations"] = build_correlations(findings)
    report.setdefault("summary", {})["correlation_count"] = len(report["correlations"])
    return report


def build_correlations(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    display_keys: dict[str, str] = {}

    for finding in findings:
        for display_key, normalized_key in relationship_keys(finding):
            groups[normalized_key].append(finding)
            display_keys.setdefault(normalized_key, display_key)

    candidates = []
    for key, items in groups.items():
        unique_by_id = {str(item.get("finding_id") or ""): item for item in items if item.get("finding_id")}
        unique_items = list(unique_by_id.values())
        if len(unique_items) < 2:
            continue
        source_scripts = sorted({str(item.get("source_script") or "") for item in unique_items if item.get("source_script")})
        candidates.append(
            {
                "key": key,
                "display_key": display_keys.get(key, key),
                "items": unique_items,
                "source_scripts": source_scripts,
                "cross_source": len(source_scripts) > 1,
            }
        )

    candidates.sort(
        key=lambda item: (
            severity_rank(highest_severity(item["items"])),
            -len(item["items"]),
            0 if item["cross_source"] else 1,
            item["display_key"].lower(),
        )
    )

    correlations = []
    for index, candidate in enumerate(candidates, start=1):
        items = sorted(candidate["items"], key=lambda item: str(item.get("finding_id") or ""))
        severity = highest_severity(items)
        source_scripts = candidate["source_scripts"]
        correlation_type = "cross-source-object" if candidate["cross_source"] else "shared-object"
        correlations.append(
            {
                "correlation_id": f"CORR-{index:04d}",
                "correlation_type": correlation_type,
                "key": candidate["display_key"],
                "normalized_key": candidate["key"],
                "title": f"Related findings for {candidate['display_key']}",
                "severity": severity,
                "finding_ids": [str(item.get("finding_id")) for item in items],
                "finding_count": len(items),
                "source_scripts": source_scripts,
                "affected_objects": sorted({str(item.get("affected_object") or "") for item in items if item.get("affected_object")}),
                "rationale": correlation_rationale(candidate["display_key"], source_scripts),
                "recommended_review": "Review these findings together before remediation so ownership, dependencies, and change approval are validated once.",
            }
        )
    return correlations


def relationship_keys(finding: dict[str, Any]) -> list[tuple[str, str]]:
    keys: list[tuple[str, str]] = []

    def add(value: Any) -> None:
        if value is None:
            return
        if isinstance(value, list):
            for item in value:
                add(item)
            return
        if isinstance(value, dict):
            for child_key, child_value in value.items():
                if is_relationship_field(child_key):
                    add(child_value)
            return

        text = str(value).strip()
        if not text:
            return
        for part in split_relationship_text(text):
            normalized = normalize_key(part)
            if normalized and normalized not in GENERIC_KEYS:
                keys.append((part.strip(), normalized))

    add(finding.get("affected_object"))
    evidence = finding.get("evidence")
    if isinstance(evidence, dict):
        add(evidence)

    seen = set()
    unique_keys = []
    for display, normalized in keys:
        if normalized in seen:
            continue
        seen.add(normalized)
        unique_keys.append((display, normalized))
    return unique_keys[:32]


def is_relationship_field(key: str) -> bool:
    normalized = to_snake_case(key)
    if normalized in IGNORED_RELATIONSHIP_FIELDS:
        return False
    return any(field in normalized for field in RELATIONSHIP_FIELDS)


def split_relationship_text(value: str) -> list[str]:
    return [part.strip() for part in re.split(r"[;,]", value) if part.strip()]


def normalize_key(value: str) -> str:
    clean = re.sub(r"^CN=", "", value, flags=re.IGNORECASE)
    clean = re.sub(r"\s+", " ", clean).strip().lower()
    if len(clean) < 3 or len(clean) > 160:
        return ""
    return clean


def to_snake_case(value: str) -> str:
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(value))
    return re.sub(r"[\s-]+", "_", value).lower()


def severity_rank(severity: str) -> int:
    return SEVERITY_RANK.get(severity, 99)


def highest_severity(findings: list[dict[str, Any]]) -> str:
    severities = [str(item.get("severity") or "Info") for item in findings]
    return sorted(severities, key=severity_rank)[0] if severities else "Info"


def correlation_rationale(key: str, source_scripts: list[str]) -> str:
    if len(source_scripts) > 1:
        return f"Multiple source scripts reference {key}, indicating the findings should be reviewed together."
    return f"Multiple findings reference {key}, indicating shared ownership or dependency evidence."

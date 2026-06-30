"""SecureInfra multi-bundle fleet support."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from secureinfra.bundles.client_bundle import CLIENT_FILE_DEFINITIONS, SUPPORTED_SCOPES, normalize_client_bundle
from secureinfra.normalizers.ad_common import severity_counts, utc_now


def normalize_multi_bundle(input_dir: str | Path) -> dict[str, Any]:
    """Normalize a directory containing many SecureInfra client collections."""
    root = Path(input_dir)
    if not root.exists():
        raise FileNotFoundError(f"Multi-bundle input directory not found: {root}")
    if not root.is_dir():
        raise ValueError("multi-bundle input must be a directory containing client bundle folders or .zip archives")

    bundle_inputs = discover_bundle_inputs(root)
    generated_at = utc_now()
    source_files: list[str] = []
    findings: list[dict[str, Any]] = []
    machine_inventory: list[dict[str, Any]] = []
    coverage_matrix: list[dict[str, Any]] = []
    failed_bundles: list[dict[str, str]] = []
    skipped_bundles: list[dict[str, str]] = []
    scope_counts = {scope: 0 for scope in SUPPORTED_SCOPES}
    seen_machine_ids: dict[str, int] = {}
    seen_collection_keys: set[str] = set()

    for bundle_index, bundle_input in enumerate(bundle_inputs, start=1):
        source_label = str(bundle_input)
        try:
            client_report = normalize_client_bundle(bundle_input)
        except Exception as exc:
            failed_bundles.append({"input": source_label, "error": str(exc)})
            continue

        collection_key = collection_key_for(client_report, bundle_input)
        if collection_key in seen_collection_keys:
            skipped_bundles.append({"input": source_label, "reason": f"duplicate collection: {collection_key}"})
            continue
        seen_collection_keys.add(collection_key)

        machine_name = machine_name_for(client_report, bundle_input, bundle_index)
        machine_id = unique_machine_id(machine_name, seen_machine_ids, bundle_index)
        child_findings = client_report.get("findings", [])
        if not isinstance(child_findings, list):
            child_findings = []

        for finding_index, finding in enumerate(child_findings, start=1):
            if not isinstance(finding, dict):
                continue
            fleet_finding = fleet_scoped_finding(finding, machine_name, machine_id, source_label, finding_index)
            findings.append(fleet_finding)

        source_files.extend(str(item) for item in client_report.get("source_files", []) if item)
        child_summary = as_dict(client_report.get("summary"))
        child_scope_counts = as_scope_counts(child_summary.get("scope_finding_counts"))
        for scope, count in child_scope_counts.items():
            scope_counts[scope] += count

        rows = bundle_coverage_rows(client_report, machine_name, machine_id, source_label)
        coverage_matrix.extend(rows)
        machine_inventory.append(machine_record(client_report, machine_name, machine_id, source_label, rows))

    counts = severity_counts(findings)
    top_machines = top_risky_machines(machine_inventory)
    fleet_status = fleet_coverage_status(machine_inventory, failed_bundles)

    return {
        "report_id": f"secureinfra-ai-multi-bundle-{generated_at.replace(':', '').replace('-', '')}",
        "report_type": "multi-bundle",
        "tool_name": "SecureInfra AI Multi-Bundle Fleet Analyzer",
        "source_files": unique_sorted(source_files),
        "generated_at_utc": generated_at,
        "environment_summary": {
            "company": "",
            "domain": common_domain(machine_inventory),
            "input_directory": str(root),
            "detected_bundle_count": len(bundle_inputs),
            "loaded_bundle_count": len(machine_inventory),
            "skipped_bundle_count": len(skipped_bundles),
            "failed_bundle_count": len(failed_bundles),
            "machine_count": len(machine_inventory),
            "coverage_status": fleet_status,
        },
        "summary": {
            "total_findings": len(findings),
            "normalized_finding_count": len(findings),
            "severity_counts": counts,
            "detected_bundle_count": len(bundle_inputs),
            "loaded_bundle_count": len(machine_inventory),
            "skipped_bundle_count": len(skipped_bundles),
            "failed_bundle_count": len(failed_bundles),
            "machine_count": len(machine_inventory),
            "scope_finding_counts": scope_counts,
            "machine_finding_counts": {item["machine_id"]: item["finding_count"] for item in machine_inventory},
            "coverage_status_counts": coverage_status_counts(machine_inventory, failed_bundles),
            "top_risky_machines": top_machines,
        },
        "report_type_metadata": {
            "report_type": "multi-bundle",
            "input_directory": str(root),
            "detected_bundles": [str(item) for item in bundle_inputs],
            "loaded_bundles": {item["machine_id"]: item["input"] for item in machine_inventory},
            "skipped_bundles": skipped_bundles,
            "failed_bundles": failed_bundles,
            "machine_inventory": machine_inventory,
            "coverage_matrix": coverage_matrix,
            "supported_scopes": SUPPORTED_SCOPES,
        },
        "findings": findings,
        "metadata": {
            "normalizer": "multi_bundle",
            "normalizer_version": "0.1.0",
            "risk_engine": "fleet-aggregation",
            "ai_required": False,
            "detected_bundles": [str(item) for item in bundle_inputs],
            "loaded_bundles": {item["machine_id"]: item["input"] for item in machine_inventory},
            "skipped_bundles": skipped_bundles,
            "failed_bundles": failed_bundles,
            "machine_inventory": machine_inventory,
            "coverage_matrix": coverage_matrix,
            "scope_finding_counts": scope_counts,
            "normalized_finding_count": len(findings),
        },
        "notes": [
            "Multi-bundle analysis combines many SecureInfra client collection bundles into one fleet-level normalized report.",
            "Finding IDs are prefixed with the machine identifier to keep IDs unique across hosts.",
            "Duplicate collection IDs are skipped so a zip and its extracted folder are not counted twice.",
            "Machine inventory and coverage_matrix metadata show which scopes were collected, missing, or failed per host.",
            "Human owner review and approved change control are required before remediation.",
        ],
    }


def discover_bundle_inputs(root: Path) -> list[Path]:
    if looks_like_client_bundle(root):
        return [root]

    candidates: list[Path] = []
    seen: set[str] = set()
    for zip_path in sorted(root.rglob("*.zip"), key=lambda item: str(item).lower()):
        add_candidate(candidates, seen, zip_path)

    bundle_dirs: list[Path] = []
    marker_names = ("manifest.json", "client-info.json", "collection-summary.json")
    for marker_name in marker_names:
        for marker_path in sorted(root.rglob(marker_name), key=lambda item: str(item).lower()):
            candidate = marker_path.parent
            if not is_inside_any(candidate, bundle_dirs):
                bundle_dirs.append(candidate)

    for ad_shared_dir in sorted(root.rglob("ad-shared"), key=lambda item: str(item).lower()):
        if ad_shared_dir.is_dir():
            candidate = ad_shared_dir.parent
            if not is_inside_any(candidate, bundle_dirs):
                bundle_dirs.append(candidate)

    for bundle_dir in sorted(bundle_dirs, key=lambda item: str(item).lower()):
        add_candidate(candidates, seen, bundle_dir)

    return candidates


def looks_like_client_bundle(path: Path) -> bool:
    if not path.is_dir():
        return False
    return (
        (path / "manifest.json").is_file()
        or (path / "client-info.json").is_file()
        or (path / "collection-summary.json").is_file()
        or (path / "ad-shared").is_dir()
    )


def add_candidate(candidates: list[Path], seen: set[str], path: Path) -> None:
    key = str(path.resolve()).lower()
    if key in seen:
        return
    seen.add(key)
    candidates.append(path)


def is_inside_any(candidate: Path, parents: list[Path]) -> bool:
    resolved = candidate.resolve()
    for parent in parents:
        parent_resolved = parent.resolve()
        if resolved == parent_resolved or parent_resolved in resolved.parents:
            return True
    return False


def fleet_scoped_finding(
    finding: dict[str, Any],
    machine_name: str,
    machine_id: str,
    bundle_input: str,
    finding_index: int,
) -> dict[str, Any]:
    fleet_finding = copy.deepcopy(finding)
    original_id = str(fleet_finding.get("finding_id") or f"finding-{finding_index}")
    fleet_finding["finding_id"] = f"FLEET-{machine_id}-{sanitize_id(original_id) or finding_index:0>4}"
    evidence = fleet_finding.get("evidence")
    if not isinstance(evidence, dict):
        evidence = {}
        fleet_finding["evidence"] = evidence
    evidence.setdefault("original_finding_id", original_id)
    evidence["machine_name"] = machine_name
    evidence["machine_id"] = machine_id
    evidence["bundle_input"] = bundle_input
    evidence["source_report_type"] = "client-bundle"
    return fleet_finding


def machine_record(
    report: dict[str, Any],
    machine_name: str,
    machine_id: str,
    source_label: str,
    rows: list[dict[str, Any]],
) -> dict[str, Any]:
    summary = as_dict(report.get("summary"))
    metadata = as_dict(report.get("report_type_metadata")) or as_dict(report.get("metadata"))
    environment = as_dict(report.get("environment_summary"))
    finding_count = int(summary.get("normalized_finding_count") or len(report.get("findings", [])))
    counts = severity_counts([item for item in report.get("findings", []) if isinstance(item, dict)])
    return {
        "machine_id": machine_id,
        "machine_name": machine_name,
        "collection_id": str(environment.get("collection_id") or ""),
        "domain": str(environment.get("domain") or ""),
        "os_caption": str(environment.get("os_caption") or ""),
        "input": source_label,
        "report_id": str(report.get("report_id") or ""),
        "finding_count": finding_count,
        "severity_counts": counts,
        "scope_finding_counts": as_scope_counts(summary.get("scope_finding_counts")),
        "scope_file_counts": as_dict(summary.get("scope_file_counts")),
        "coverage_status": coverage_status(rows, object_entries(metadata.get("failed_files"))).get("label"),
        "coverage_status_class": coverage_status(rows, object_entries(metadata.get("failed_files"))).get("className"),
        "missing_files": as_string_list(metadata.get("missing_files")),
        "failed_files": as_dict(metadata.get("failed_files")),
    }


def bundle_coverage_rows(report: dict[str, Any], machine_name: str, machine_id: str, source_label: str) -> list[dict[str, Any]]:
    metadata = as_dict(report.get("report_type_metadata")) or as_dict(report.get("metadata"))
    summary = as_dict(report.get("summary"))
    environment = as_dict(report.get("environment_summary"))
    loaded_files = object_entries(metadata.get("loaded_files"))
    detected_files = object_entries(metadata.get("detected_files"))
    failed_files = object_entries(metadata.get("failed_files"))
    missing_files = as_string_list(metadata.get("missing_files"))
    requested_scopes = normalize_scopes(environment.get("scope_resolved"))
    scope_finding_counts = as_scope_counts(summary.get("scope_finding_counts"))
    scope_file_counts = as_dict(summary.get("scope_file_counts"))
    rows = []
    for scope in SUPPORTED_SCOPES:
        selected = scope in requested_scopes if requested_scopes else scope_file_count(scope, scope_file_counts, loaded_files, detected_files) > 0
        required_missing = [item for item in required_files_for_scope(scope) if selected and item in missing_files]
        failed = any(scope_for_client_file_key(item["key"]) == scope for item in failed_files)
        file_count = int(scope_file_counts.get(scope, scope_file_count(scope, scope_file_counts, loaded_files, detected_files)) or 0)
        finding_count = int(scope_finding_counts.get(scope, 0) or 0)
        status = "Collected"
        status_class = "complete"
        if not selected:
            status = "Not collected"
            status_class = "partial"
        elif failed:
            status = "Failed"
            status_class = "failed"
        elif required_missing:
            status = "Needs rerun"
            status_class = "rerun"
        elif file_count == 0:
            status = "Partial"
            status_class = "partial"
        rows.append(
            {
                "machine_id": machine_id,
                "machine_name": machine_name,
                "input": source_label,
                "scope": scope,
                "selected": selected,
                "finding_count": finding_count,
                "file_count": file_count,
                "required_missing": required_missing,
                "status": status,
                "status_class": status_class,
            }
        )
    return rows


def coverage_status(rows: list[dict[str, Any]], failed_files: list[dict[str, str]]) -> dict[str, str]:
    if failed_files:
        return {"label": "Failed", "className": "failed"}
    if any(row.get("status") == "Needs rerun" for row in rows):
        return {"label": "Needs rerun", "className": "rerun"}
    if any(row.get("status") in {"Not collected", "Partial"} for row in rows):
        return {"label": "Partial", "className": "partial"}
    return {"label": "Complete", "className": "complete"}


def fleet_coverage_status(machine_inventory: list[dict[str, Any]], failed_bundles: list[dict[str, str]]) -> str:
    if failed_bundles or any(item.get("coverage_status") == "Failed" for item in machine_inventory):
        return "Failed"
    if any(item.get("coverage_status") == "Needs rerun" for item in machine_inventory):
        return "Needs rerun"
    if any(item.get("coverage_status") == "Partial" for item in machine_inventory):
        return "Partial"
    return "Complete" if machine_inventory else "No bundles"


def coverage_status_counts(machine_inventory: list[dict[str, Any]], failed_bundles: list[dict[str, str]]) -> dict[str, int]:
    counts = {"Complete": 0, "Partial": 0, "Needs rerun": 0, "Failed": len(failed_bundles)}
    for item in machine_inventory:
        status = str(item.get("coverage_status") or "Partial")
        counts[status] = counts.get(status, 0) + 1
    return counts


def top_risky_machines(machine_inventory: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ranked = []
    for machine in machine_inventory:
        counts = as_dict(machine.get("severity_counts"))
        score = (
            int(counts.get("Critical", 0) or 0) * 100
            + int(counts.get("High", 0) or 0) * 25
            + int(counts.get("Medium", 0) or 0) * 5
            + int(counts.get("Low", 0) or 0)
        )
        ranked.append(
            {
                "machine_id": str(machine.get("machine_id") or ""),
                "machine_name": str(machine.get("machine_name") or ""),
                "finding_count": int(machine.get("finding_count") or 0),
                "critical": int(counts.get("Critical", 0) or 0),
                "high": int(counts.get("High", 0) or 0),
                "risk_score": score,
            }
        )
    return sorted(ranked, key=lambda item: (-item["risk_score"], item["machine_name"].lower()))[:10]


def machine_name_for(report: dict[str, Any], bundle_input: Path, bundle_index: int) -> str:
    environment = as_dict(report.get("environment_summary"))
    for key in ("computer_name", "collection_id"):
        value = str(environment.get(key) or "").strip()
        if value:
            return value
    stem = bundle_input.stem if bundle_input.suffix.lower() == ".zip" else bundle_input.name
    return stem or f"bundle-{bundle_index}"


def collection_key_for(report: dict[str, Any], bundle_input: Path) -> str:
    environment = as_dict(report.get("environment_summary"))
    for key in ("collection_id", "computer_name"):
        value = str(environment.get(key) or "").strip().lower()
        if value:
            return f"{key}:{value}"
    report_id = str(report.get("report_id") or "").strip().lower()
    if report_id:
        return f"report:{report_id}"
    return f"input:{str(bundle_input.resolve()).lower()}"


def unique_machine_id(machine_name: str, seen_machine_ids: dict[str, int], bundle_index: int) -> str:
    base = sanitize_id(machine_name) or f"BUNDLE-{bundle_index:04d}"
    count = seen_machine_ids.get(base, 0) + 1
    seen_machine_ids[base] = count
    return base if count == 1 else f"{base}-{count}"


def common_domain(machine_inventory: list[dict[str, Any]]) -> str:
    domains = sorted({str(item.get("domain") or "") for item in machine_inventory if item.get("domain")})
    return domains[0] if len(domains) == 1 else ""


def as_scope_counts(value: Any) -> dict[str, int]:
    data = as_dict(value)
    return {scope: int(data.get(scope, 0) or 0) for scope in SUPPORTED_SCOPES}


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    if value in (None, ""):
        return []
    return [str(value)]


def object_entries(value: Any) -> list[dict[str, str]]:
    return [{"key": str(key), "value": str(val)} for key, val in as_dict(value).items()]


def normalize_scopes(value: Any) -> list[str]:
    values = as_string_list(value)
    normalized = []
    for item in values:
        text = item.strip().lower()
        if text == "ad" or "active directory" in text or "gpo" in text:
            normalized.append("AD")
        elif text == "host" or "windows host" in text:
            normalized.append("Host")
        elif text == "server" or "terminal server" in text:
            normalized.append("Server")
        elif text == "workstation" or "endpoint" in text:
            normalized.append("Workstation")
        elif text == "network" or "network exposure" in text:
            normalized.append("Network")
        elif text == "backup" or "backup readiness" in text:
            normalized.append("Backup")
    return list(dict.fromkeys(scope for scope in normalized if scope in SUPPORTED_SCOPES))


def required_files_for_scope(scope: str) -> list[str]:
    return {
        "AD": ["ad-shared/"],
        "Host": ["host/windows-security-audit.json"],
        "Server": ["server/windows-server-security.json", "server/windows-local-admins.json", "server/windows-rdp-exposure.json"],
        "Workstation": [
            "workstation/windows-workstation-security.json",
            "workstation/windows-local-admins.json",
            "workstation/windows-rdp-exposure.json",
        ],
        "Network": ["network/windows-network-exposure.json"],
        "Backup": ["backup/backup-readiness.json"],
    }.get(scope, [])


def scope_file_count(
    scope: str,
    scope_file_counts: dict[str, Any],
    loaded_files: list[dict[str, str]],
    detected_files: list[dict[str, str]],
) -> int:
    if scope in scope_file_counts:
        return int(scope_file_counts.get(scope) or 0)
    keys = [item["key"] for item in loaded_files] + [item["key"] for item in detected_files]
    return len([key for key in keys if scope_for_client_file_key(key) == scope])


def scope_for_client_file_key(key: str) -> str:
    if key == "ad_shared" or key.startswith("ad_"):
        return "AD"
    if key.startswith("workstation_"):
        return "Workstation"
    if key.startswith("server_"):
        return "Server"
    if key.startswith("host_"):
        return "Host"
    if key.startswith("backup_"):
        return "Backup"
    definition = CLIENT_FILE_DEFINITIONS.get(key)
    return str(definition.get("scope") or "") if definition else ""


def sanitize_id(value: Any) -> str:
    text = str(value or "").strip().upper()
    if not text:
        return ""
    return "".join(char if char.isalnum() else "-" for char in text).strip("-")[:64]


def unique_sorted(values: list[str]) -> list[str]:
    return sorted(dict.fromkeys(values), key=lambda item: item.lower())

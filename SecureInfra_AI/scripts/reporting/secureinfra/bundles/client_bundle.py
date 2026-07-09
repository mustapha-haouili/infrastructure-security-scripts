"""SecureInfra client collection bundle support."""

from __future__ import annotations

import hashlib
import re
import tempfile
import zipfile
import shutil
from contextlib import contextmanager
from pathlib import Path, PureWindowsPath
from typing import Any, Iterator

from secureinfra.bundles.ad_shared_bundle import normalize_ad_shared_bundle
from secureinfra.loaders.json_loader import load_json_file
from secureinfra.network_context.port_catalog import lookup_port_context
from secureinfra.normalizers.ad_common import build_common_finding, normalize_source_severity, severity_counts, utc_now
from secureinfra.normalizers.evidence_contract import normalize_report_evidence_contract
from secureinfra.normalizers.linux_security import normalize_linux_security_findings


CLIENT_FILE_DEFINITIONS: dict[str, dict[str, str]] = {
    "client_info": {"scope": "Client", "path": "client-info.json"},
    "collection_summary": {"scope": "Client", "path": "collection-summary.json"},
    "manifest": {"scope": "Client", "path": "manifest.json"},
    "bundle_manifest": {"scope": "Client", "path": "bundle-manifest.json"},
    "host_windows_security_audit": {"scope": "Host", "path": "host/windows-security-audit.json"},
    "host_windows_events_summary": {"scope": "Host", "path": "host/windows-events/summary.json"},
    "host_windows_remediation_plan": {"scope": "Host", "path": "host/windows-remediation-plan.json"},
    "host_windows_hardening_preview": {"scope": "Host", "path": "host/windows-hardening-preview.json"},
    "network_windows_network_exposure": {"scope": "Network", "path": "network/windows-network-exposure.json"},
    "server_windows_server_security": {"scope": "Server", "path": "server/windows-server-security.json"},
    "server_windows_local_admins": {"scope": "Server", "path": "server/windows-local-admins.json"},
    "server_windows_rdp_exposure": {"scope": "Server", "path": "server/windows-rdp-exposure.json"},
    "server_rdp_profile_cache_cleanup": {"scope": "Server", "path": "server/rdp-profile-cache-cleanup.json"},
    "workstation_windows_workstation_security": {"scope": "Workstation", "path": "workstation/windows-workstation-security.json"},
    "workstation_windows_local_admins": {"scope": "Workstation", "path": "workstation/windows-local-admins.json"},
    "workstation_windows_rdp_exposure": {"scope": "Workstation", "path": "workstation/windows-rdp-exposure.json"},
    "backup_backup_readiness": {"scope": "Backup", "path": "backup/backup-readiness.json"},
    "linux_security_summary": {"scope": "Linux", "path": "linux/linux-security-summary.json"},
    "linux_network_exposure_summary": {"scope": "Linux", "path": "linux/linux-network-exposure-summary.json"},
    "linux_log_audit_summary": {"scope": "Linux", "path": "linux/linux-log-audit-summary.json"},
    "linux_service_inventory_summary": {"scope": "Linux", "path": "linux/linux-service-inventory-summary.json"},
    "linux_inventory": {"scope": "Linux", "path": "linux/linux-inventory.json"},
}
FINDING_SOURCE_KEYS = {
    "host_windows_security_audit",
    "host_windows_events_summary",
    "network_windows_network_exposure",
    "server_windows_server_security",
    "server_windows_local_admins",
    "server_windows_rdp_exposure",
    "server_rdp_profile_cache_cleanup",
    "workstation_windows_workstation_security",
    "workstation_windows_local_admins",
    "workstation_windows_rdp_exposure",
    "backup_backup_readiness",
    "linux_security_summary",
    "linux_network_exposure_summary",
    "linux_log_audit_summary",
    "linux_service_inventory_summary",
}
SUPPORTED_SCOPES = ["AD", "Host", "Server", "Workstation", "Network", "Backup", "Linux"]
DISPLAY_NAME_BY_KEY = {
    "host_windows_security_audit": "Windows security audit",
    "host_windows_events_summary": "Windows event security summary",
    "host_windows_remediation_plan": "Windows remediation plan",
    "host_windows_hardening_preview": "Windows hardening preview",
    "network_windows_network_exposure": "Windows network exposure",
    "server_windows_server_security": "Server security inventory",
    "server_windows_local_admins": "Server local administrators",
    "server_windows_rdp_exposure": "Server RDP exposure",
    "server_rdp_profile_cache_cleanup": "Server RDP profile cache cleanup",
    "workstation_windows_workstation_security": "Workstation security inventory",
    "workstation_windows_local_admins": "Workstation local administrators",
    "workstation_windows_rdp_exposure": "Workstation RDP exposure",
    "backup_backup_readiness": "Backup readiness audit",
    "linux_security_summary": "Linux security audit summary",
    "linux_network_exposure_summary": "Linux network exposure audit summary",
    "linux_log_audit_summary": "Linux log and audit coverage summary",
    "linux_service_inventory_summary": "Linux service inventory summary",
    "linux_inventory": "Linux host inventory",
}
PREFIX_BY_KEY = {
    "host_windows_security_audit": "HOST-WIN",
    "host_windows_events_summary": "HOST-EVENT",
    "network_windows_network_exposure": "NETWORK-EXPOSURE",
    "server_windows_server_security": "SERVER-SECURITY",
    "server_windows_local_admins": "SERVER-LADMIN",
    "server_windows_rdp_exposure": "SERVER-RDP",
    "server_rdp_profile_cache_cleanup": "SERVER-RDP-CACHE",
    "workstation_windows_workstation_security": "WORKSTATION-SECURITY",
    "workstation_windows_local_admins": "WORKSTATION-LADMIN",
    "workstation_windows_rdp_exposure": "WORKSTATION-RDP",
    "backup_backup_readiness": "BACKUP-READINESS",
    "linux_security_summary": "LINUX-SECURITY",
}
OBJECT_TYPE_BY_KEY = {
    "host_windows_security_audit": "Windows host security control",
    "host_windows_events_summary": "Windows security event indicator",
    "network_windows_network_exposure": "Windows network exposure",
    "server_windows_server_security": "Windows server security control",
    "server_windows_local_admins": "Windows local administrator principal",
    "server_windows_rdp_exposure": "Windows RDP exposure",
    "server_rdp_profile_cache_cleanup": "RDP profile cache candidate",
    "workstation_windows_workstation_security": "Windows workstation security control",
    "workstation_windows_local_admins": "Windows local administrator principal",
    "workstation_windows_rdp_exposure": "Windows RDP exposure",
    "backup_backup_readiness": "Backup readiness evidence",
    "linux_security_summary": "Linux host security control",
}
CATEGORY_BY_KEY = {
    "host_windows_security_audit": "Host Security Baseline",
    "host_windows_events_summary": "Host Security Events",
    "network_windows_network_exposure": "Network Exposure",
    "server_windows_server_security": "Server Security Inventory",
    "server_windows_local_admins": "Server Local Administration",
    "server_windows_rdp_exposure": "Server Remote Access",
    "server_rdp_profile_cache_cleanup": "Server Operations",
    "workstation_windows_workstation_security": "Workstation Security Inventory",
    "workstation_windows_local_admins": "Workstation Local Administration",
    "workstation_windows_rdp_exposure": "Workstation Remote Access",
    "backup_backup_readiness": "Backup Readiness",
    "linux_security_summary": "Linux Host Security",
}

# Client bundles are report-only evidence packages. Keep limits conservative
# enough for normal collector output while rejecting archive bombs and non-report
# content before anything is extracted.
MAX_ZIP_ENTRIES = 512
MAX_ZIP_MEMBER_SIZE_BYTES = 25 * 1024 * 1024
ALLOWED_ZIP_EXTENSIONS = {".json", ".csv", ".md", ".txt", ".log"}
ALLOWED_ZIP_ROOT_FILES = {"client-info.json", "collection-summary.json", "manifest.json", "bundle-manifest.json"}
ALLOWED_ZIP_TOP_LEVEL_DIRS = {"ad-shared", "host", "server", "workstation", "network", "backup", "linux", "devsecops", "docker", "kubernetes", "logs"}
ALL_INTERFACES_BIND_SCOPE_EXPLANATION = (
    "Listening on all interfaces means the service binds to all local interfaces. "
    "Actual reachability depends on firewall rules, routing, segmentation, and allowed source networks."
)


@contextmanager
def prepared_client_bundle_path(input_path: str | Path) -> Iterator[tuple[Path, str]]:
    """Yield a collection root from either a directory or zip archive."""
    source_path = Path(input_path)
    if source_path.is_dir():
        yield source_path, str(source_path)
        return

    if not source_path.is_file() or source_path.suffix.lower() != ".zip":
        raise ValueError("client-bundle input must be a collection directory or .zip archive")

    with tempfile.TemporaryDirectory(prefix="secureinfra-client-bundle-") as temp_root:
        extract_root = Path(temp_root)
        with zipfile.ZipFile(source_path) as archive:
            safe_extract_zip(archive, extract_root)
        yield find_collection_root(extract_root), str(source_path)


def safe_extract_zip(archive: zipfile.ZipFile, target_dir: Path) -> None:
    target_root = target_dir.resolve()
    members = archive.infolist()
    if len(members) > MAX_ZIP_ENTRIES:
        raise ValueError(f"Unsafe zip archive: too many entries ({len(members)} > {MAX_ZIP_ENTRIES})")

    validated_members = []
    for member in members:
        parts = validate_zip_member(member)
        destination = (target_dir / Path(*parts)).resolve()
        if target_root != destination and target_root not in destination.parents:
            raise ValueError(f"Unsafe zip entry path: {member.filename}")
        validated_members.append((member, destination))

    for member, destination in validated_members:
        if member.is_dir():
            destination.mkdir(parents=True, exist_ok=True)
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        with archive.open(member) as source, destination.open("wb") as output:
            shutil.copyfileobj(source, output)


def validate_zip_member(member: zipfile.ZipInfo) -> list[str]:
    raw_name = member.filename
    normalized_name = raw_name.replace("\\", "/")
    windows_path = PureWindowsPath(raw_name)
    if raw_name.startswith(("/", "\\")) or windows_path.is_absolute() or windows_path.drive:
        raise ValueError(f"Unsafe zip entry absolute path: {raw_name}")

    parts = [part for part in normalized_name.split("/") if part and part != "."]
    if not parts or any(part == ".." for part in parts):
        raise ValueError(f"Unsafe zip entry path: {raw_name}")

    if member.file_size > MAX_ZIP_MEMBER_SIZE_BYTES:
        raise ValueError(
            f"Unsafe zip entry too large: {raw_name} ({member.file_size} > {MAX_ZIP_MEMBER_SIZE_BYTES} bytes)"
        )

    if member.is_dir():
        if not is_allowed_zip_relative_path(parts, is_directory=True):
            raise ValueError(f"Unsafe zip entry path is not allowed: {raw_name}")
        return parts

    suffix = Path(parts[-1]).suffix.lower()
    if suffix not in ALLOWED_ZIP_EXTENSIONS:
        raise ValueError(f"Unsafe zip entry extension: {raw_name}")
    if not is_allowed_zip_relative_path(parts, is_directory=False):
        raise ValueError(f"Unsafe zip entry path is not allowed: {raw_name}")
    return parts


def is_allowed_zip_relative_path(parts: list[str], is_directory: bool) -> bool:
    if not parts:
        return False
    if is_directory and len(parts) == 1:
        return True
    if is_allowed_zip_path_without_wrapper(parts, is_directory):
        return True
    if len(parts) > 1:
        return is_allowed_zip_path_without_wrapper(parts[1:], is_directory)
    return False


def is_allowed_zip_path_without_wrapper(parts: list[str], is_directory: bool) -> bool:
    first = parts[0].lower()
    if is_directory:
        return first in ALLOWED_ZIP_TOP_LEVEL_DIRS
    if len(parts) == 1:
        return first in ALLOWED_ZIP_ROOT_FILES
    return first in ALLOWED_ZIP_TOP_LEVEL_DIRS


def find_collection_root(root: Path) -> Path:
    if (root / "manifest.json").is_file() or (root / "client-info.json").is_file():
        return root
    children = [item for item in root.iterdir() if item.is_dir()]
    for child in children:
        if (child / "manifest.json").is_file() or (child / "client-info.json").is_file():
            return child
    return root


def discover_client_bundle(input_dir: str | Path) -> dict[str, Path]:
    bundle_dir = Path(input_dir)
    if not bundle_dir.exists():
        raise FileNotFoundError(f"Client bundle input directory not found: {bundle_dir}")
    if not bundle_dir.is_dir():
        raise ValueError(f"Client bundle input must be a directory: {bundle_dir}")

    detected = {
        key: bundle_dir / definition["path"]
        for key, definition in CLIENT_FILE_DEFINITIONS.items()
        if (bundle_dir / definition["path"]).is_file()
    }
    ad_shared_dir = bundle_dir / "ad-shared"
    if ad_shared_dir.is_dir():
        detected["ad_shared"] = ad_shared_dir

    linux_dir = bundle_dir / "linux"
    if linux_dir.is_dir():
        if "linux_security_summary" not in detected:
            summary_candidates = sorted(
                linux_dir.glob("linux-security-audit-*.summary.json")
            ) + sorted(linux_dir.glob("*linux-security*.summary.json"))
            if summary_candidates:
                detected["linux_security_summary"] = summary_candidates[0]
        if "linux_network_exposure_summary" not in detected:
            network_candidates = sorted(linux_dir.glob("linux-network-exposure-audit-*.summary.json")) + sorted(linux_dir.glob("*linux-network*.summary.json"))
            if network_candidates:
                detected["linux_network_exposure_summary"] = network_candidates[0]
        if "linux_log_audit_summary" not in detected:
            log_candidates = sorted(linux_dir.glob("linux-log-audit-*.summary.json")) + sorted(linux_dir.glob("*linux-log*.summary.json"))
            if log_candidates:
                detected["linux_log_audit_summary"] = log_candidates[0]
        if "linux_service_inventory_summary" not in detected:
            service_candidates = sorted(linux_dir.glob("linux-service-inventory-audit-*.summary.json")) + sorted(linux_dir.glob("*linux-service*.summary.json"))
            if service_candidates:
                detected["linux_service_inventory_summary"] = service_candidates[0]
        if "linux_inventory" not in detected:
            inventory_candidates = sorted(linux_dir.glob("linux-inventory-*.json"))
            if inventory_candidates:
                detected["linux_inventory"] = inventory_candidates[0]
    return detected


def missing_client_files(detected_files: dict[str, Path]) -> list[str]:
    missing = [
        definition["path"]
        for key, definition in CLIENT_FILE_DEFINITIONS.items()
        if key not in detected_files and key != "bundle_manifest" and definition["scope"] in SUPPORTED_SCOPES + ["Client"] and definition["scope"] not in {"Backup", "Linux"}
    ]
    if "ad_shared" not in detected_files:
        missing.append("ad-shared/")
    return missing


def normalize_client_bundle(input_path: str | Path) -> dict[str, Any]:
    """Normalize a full SecureInfra client collection directory or zip."""
    with prepared_client_bundle_path(input_path) as (bundle_dir, source_label):
        return normalize_prepared_client_bundle(bundle_dir, source_label)


def normalize_prepared_client_bundle(bundle_dir: Path, source_label: str) -> dict[str, Any]:
    detected_paths = discover_client_bundle(bundle_dir)
    missing_files = missing_client_files(detected_paths)
    loaded_files: dict[str, str] = {}
    loaded_summaries: dict[str, dict[str, Any]] = {}
    failed_files: dict[str, str] = {}
    scope_counts = {scope: 0 for scope in SUPPORTED_SCOPES}
    normalized_source_counts: dict[str, int] = {}
    findings: list[dict[str, Any]] = []
    notes = [
        "Client bundle analysis combines supported AD, host, server, workstation, network, and optional backup evidence into one normalized report.",
        "Remediation plans and hardening previews are loaded as coverage metadata; they are not counted as separate findings.",
        "Human owner review and approved change control are required before remediation.",
    ]

    client_info = load_optional_json(detected_paths, "client_info", loaded_files, loaded_summaries, failed_files, bundle_dir, source_label)
    collection_summary = load_optional_json(
        detected_paths, "collection_summary", loaded_files, loaded_summaries, failed_files, bundle_dir, source_label
    )
    manifest = load_optional_json(detected_paths, "manifest", loaded_files, loaded_summaries, failed_files, bundle_dir, source_label)
    bundle_manifest = load_optional_json(detected_paths, "bundle_manifest", loaded_files, loaded_summaries, failed_files, bundle_dir, source_label)
    if manifest is None and bundle_manifest is not None:
        manifest = bundle_manifest

    if "ad_shared" in detected_paths:
        try:
            ad_report = normalize_ad_shared_bundle(detected_paths["ad_shared"])
            ad_findings = ad_report.get("findings", [])
            if isinstance(ad_findings, list):
                for finding in ad_findings:
                    if isinstance(finding, dict):
                        finding.setdefault("evidence", {})["scope"] = "AD"
                        findings.append(finding)
                scope_counts["AD"] = len(ad_findings)
                normalized_source_counts["ad_shared"] = len(ad_findings)
            loaded_files["ad_shared"] = display_path(bundle_dir, detected_paths["ad_shared"], source_label)
            loaded_summaries["ad_shared"] = {
                "normalized_finding_count": ad_report.get("summary", {}).get("normalized_finding_count", 0),
                "detected_file_count": ad_report.get("summary", {}).get("detected_file_count", 0),
                "missing_optional_file_count": ad_report.get("summary", {}).get("missing_optional_file_count", 0),
            }
            notes.append("ad-shared was normalized with the existing AD/GPO bundle analyzer.")
        except Exception as exc:
            failed_files["ad_shared"] = str(exc)
            notes.append(f"ad-shared could not be normalized: {exc}")

    for key in FINDING_SOURCE_KEYS:
        data = load_optional_json(detected_paths, key, loaded_files, loaded_summaries, failed_files, bundle_dir, source_label)
        if data is None:
            continue
        source_findings = normalize_client_source_file(key, data, detected_paths[key])
        findings.extend(source_findings)
        scope = CLIENT_FILE_DEFINITIONS[key]["scope"]
        scope_counts[scope] += len(source_findings)
        normalized_source_counts[key] = len(source_findings)

    for metadata_key in ("host_windows_remediation_plan", "host_windows_hardening_preview", "linux_inventory"):
        load_optional_json(detected_paths, metadata_key, loaded_files, loaded_summaries, failed_files, bundle_dir, source_label)

    generated_at = collection_generated_at(collection_summary, manifest)
    source_files = list(loaded_files.values())
    counts = severity_counts(findings)
    environment_summary = build_environment_summary(client_info, collection_summary, manifest, bundle_dir, source_label)
    loaded_scope_counts = scope_file_counts(detected_paths)

    return normalize_report_evidence_contract(
        {
            "report_id": f"secureinfra-ai-client-bundle-{generated_at.replace(':', '').replace('-', '')}",
            "report_type": "client-bundle",
            "tool_name": "SecureInfra AI Client Bundle Analyzer",
            "source_files": source_files,
            "generated_at_utc": generated_at,
            "environment_summary": environment_summary,
            "summary": {
                "total_findings": len(findings),
                "normalized_finding_count": len(findings),
                "severity_counts": counts,
                "detected_file_count": len(detected_paths),
                "loaded_file_count": len(loaded_files),
                "failed_file_count": len(failed_files),
                "missing_optional_file_count": len(missing_files),
                "scope_finding_counts": scope_counts,
                "scope_file_counts": loaded_scope_counts,
            },
            "report_type_metadata": {
                "report_type": "client-bundle",
                "input": source_label,
                "bundle_directory": str(bundle_dir),
                "known_files": {key: value["path"] for key, value in CLIENT_FILE_DEFINITIONS.items()},
                "detected_files": {key: display_path(bundle_dir, path, source_label) for key, path in detected_paths.items()},
                "missing_files": missing_files,
                "loaded_files": loaded_files,
                "failed_files": failed_files,
                "loaded_summaries": loaded_summaries,
                "supported_scopes": SUPPORTED_SCOPES,
                "normalized_source_counts": normalized_source_counts,
            },
            "findings": findings,
            "metadata": {
                "normalizer": "client_bundle",
                "normalizer_version": "0.1.0",
                "risk_engine": "source-priority-mapping",
                "ai_required": False,
                "detected_files": {key: display_path(bundle_dir, path, source_label) for key, path in detected_paths.items()},
                "missing_files": missing_files,
                "loaded_files": loaded_files,
                "failed_files": failed_files,
                "loaded_summaries": loaded_summaries,
                "normalized_finding_count": len(findings),
                "scope_finding_counts": scope_counts,
            },
            "notes": notes,
        }
    )


def load_optional_json(
    detected_paths: dict[str, Path],
    key: str,
    loaded_files: dict[str, str],
    loaded_summaries: dict[str, dict[str, Any]],
    failed_files: dict[str, str],
    bundle_dir: Path,
    source_label: str,
) -> dict[str, Any] | None:
    path = detected_paths.get(key)
    if path is None:
        return None
    try:
        data = load_json_file(path)
    except Exception as exc:
        failed_files[key] = str(exc)
        return None
    if not isinstance(data, dict):
        failed_files[key] = "JSON root is not an object"
        return None
    loaded_files[key] = display_path(bundle_dir, path, source_label)
    loaded_summaries[key] = summarize_source_json(key, data)
    return data


def normalize_client_source_file(key: str, data: dict[str, Any], source_file: Path) -> list[dict[str, Any]]:
    if key in {"linux_security_summary", "linux_network_exposure_summary", "linux_log_audit_summary", "linux_service_inventory_summary"}:
        return normalize_linux_security_findings(data, source_file, source_script_name=linux_source_script_for_key(key, data))
    if key == "host_windows_events_summary":
        rows = normalize_windows_event_summary_rows(as_records(as_dict(data.get("InvestigationSummary")).get("Findings")), data)
    elif key == "server_rdp_profile_cache_cleanup":
        return normalize_rdp_cache_cleanup(data, source_file, key)
    else:
        rows = as_records(data.get("Findings"))
    return normalize_source_rows(key, data, rows, source_file)


WINDOWS_EVENT_FINDING_ID_BY_TITLE = {
    "failed logons were detected": "FAILED-LOGONS",
    "account lifecycle changes were detected": "ACCOUNT-LIFECYCLE-CHANGES",
    "security group membership changes were detected": "SECURITY-GROUP-CHANGES",
    "account lockouts were detected": "ACCOUNT-LOCKOUTS",
    "services were installed": "SERVICE-INSTALLATIONS",
    "rdp logons were detected": "RDP-LOGONS",
    "explicit credentials used by suspicious process names": "SUSPICIOUS-EXPLICIT-CREDENTIALS",
    "explicit credential use was detected": "EXPLICIT-CREDENTIAL-USE",
}

WINDOWS_EVENT_IDS_BY_FINDING_ID = {
    "FAILED-LOGONS": [4625],
    "ACCOUNT-LIFECYCLE-CHANGES": [4720, 4722, 4725, 4726],
    "SECURITY-GROUP-CHANGES": [4728, 4732, 4756],
    "ACCOUNT-LOCKOUTS": [4740],
    "SERVICE-INSTALLATIONS": [7045],
    "RDP-LOGONS": [4624],
    "SUSPICIOUS-EXPLICIT-CREDENTIALS": [4648],
    "EXPLICIT-CREDENTIAL-USE": [4648],
}


def normalize_windows_event_summary_rows(rows: list[dict[str, Any]], data: dict[str, Any]) -> list[dict[str, Any]]:
    normalized = []
    computer = computer_name(data)
    for row in rows:
        output = dict(row)
        title = str(first_value(output, ["Title"], "") or "").strip()
        event_finding_id = str(first_value(output, ["FindingId", "Id", "FindingType"], "") or "").strip()
        if not event_finding_id:
            event_finding_id = WINDOWS_EVENT_FINDING_ID_BY_TITLE.get(title.lower(), "")
        if event_finding_id:
            output.setdefault("FindingId", event_finding_id)
            output.setdefault("FindingType", "WindowsEventSecurityIndicator")
            output.setdefault("EventIds", WINDOWS_EVENT_IDS_BY_FINDING_ID.get(event_finding_id, []))
        output.setdefault("AffectedObject", computer or title or "Windows event security summary")
        output.setdefault("EventCategory", event_finding_id.replace("-", " ").title() if event_finding_id else "Windows Event Security")
        normalized.append(output)
    return normalized


def linux_source_script_for_key(key: str, data: dict[str, Any]) -> str:
    explicit = data.get("source_script") or data.get("SourceScript")
    if explicit:
        return str(explicit)
    return {
        "linux_security_summary": "linux-security-audit.sh",
        "linux_network_exposure_summary": "linux-network-exposure-audit.sh",
        "linux_log_audit_summary": "linux-log-audit.sh",
        "linux_service_inventory_summary": "linux-service-inventory-audit.sh",
    }.get(key, "linux-security-audit.sh")

def normalize_source_rows(key: str, data: dict[str, Any], rows: list[dict[str, Any]], source_file: Path) -> list[dict[str, Any]]:
    timestamp = source_timestamp(data)
    scope = CLIENT_FILE_DEFINITIONS[key]["scope"]
    source_script_name = source_script_for(key, data, source_file)
    findings = []
    seen_listener_keys: set[tuple[str, int, str, str]] = set()
    for index, row in enumerate(rows, start=1):
        normalized_row = normalize_source_row_before_finding(key, row)
        if normalized_row is None:
            continue
        row = normalized_row
        severity = normalize_source_severity(first_value(row, ["Severity", "TriageSeverity", "ActionPriority", "ReviewPriority"]))
        source_id = first_value(row, ["Id", "FindingId", "FindingType", "ControlId"], "")
        affected_object = affected_object_for(row, data, key, index)
        evidence = compact_evidence(row)
        if key == "network_windows_network_exposure":
            evidence.update(network_port_context_evidence(row, data, evidence))
            evidence.update(network_firewall_rule_context_evidence(row, data, evidence))
        if key in {"server_windows_rdp_exposure", "workstation_windows_rdp_exposure"}:
            evidence.update(rdp_exposure_context_evidence(row, data, evidence))
        if key in {"server_windows_local_admins", "workstation_windows_local_admins"}:
            evidence.update(local_admin_context_evidence(row, data, evidence))
        if key == "server_windows_server_security":
            evidence.update(server_security_context_evidence(row, data, evidence))
        if key == "workstation_windows_workstation_security":
            evidence.update(workstation_security_context_evidence(row, data, evidence))
        if key == "host_windows_security_audit":
            evidence.update(aggregate_host_network_context_evidence(row, evidence))
            evidence.update(host_security_context_evidence(row, data, evidence))
        evidence.update(
            {
                "scope": scope,
                "computer_name": computer_name(data),
                "source_file": str(source_file),
            }
        )
        if key == "network_windows_network_exposure":
            listener_key = network_listener_dedupe_key(evidence)
            if listener_key is not None:
                if listener_key in seen_listener_keys:
                    continue
                seen_listener_keys.add(listener_key)
                source_id = network_listener_source_id(source_id, evidence)
            firewall_source_id = network_firewall_rule_source_id(source_id, evidence)
            if firewall_source_id:
                source_id = firewall_source_id
        if key in {"server_windows_local_admins", "workstation_windows_local_admins"}:
            source_id = local_admin_source_id(source_id, row, affected_object, evidence)
        if key in {"server_windows_rdp_exposure", "workstation_windows_rdp_exposure"}:
            source_id = rdp_exposure_source_id(source_id, row, evidence)
        if key == "server_windows_server_security":
            source_id = server_security_source_id(source_id, row, affected_object, evidence)
        if key == "workstation_windows_workstation_security":
            source_id = workstation_security_source_id(source_id, row, affected_object, evidence)
        findings.append(
            build_common_finding(
                finding_id=build_finding_id(PREFIX_BY_KEY[key], source_id, index),
                title=str(first_value(row, ["Title", "FindingType", "Control", "EventLabel"], "Finding requires review")),
                category=CATEGORY_BY_KEY[key],
                severity=severity,
                affected_object=affected_object,
                object_type=OBJECT_TYPE_BY_KEY[key],
                source_script_name=source_script_name,
                evidence=evidence,
                risk_factors=risk_factors(row),
                business_impact=str(
                    first_value(
                        row,
                        ["WhyItMatters", "BusinessImpact"],
                        f"{DISPLAY_NAME_BY_KEY.get(key, key)} evidence requires owner validation before remediation.",
                    )
                ),
                technical_impact=str(
                    first_value(
                        row,
                        ["Evidence", "Details", "TechnicalImpact"],
                        "The source report identified local Windows evidence that needs administrator review.",
                    )
                ),
                recommendation=str(
                    first_value(
                        row,
                        ["Recommendation", "SuggestedFix", "AdminAction", "RecommendedAction"],
                        "Review the source evidence, confirm ownership, and use approved change control before remediation.",
                    )
                ),
                timestamp_utc=timestamp,
                safety_reason=safety_reason_for(key),
            )
        )
    return findings


def normalize_source_row_before_finding(key: str, row: dict[str, Any]) -> dict[str, Any] | None:
    if key != "server_windows_server_security":
        return row
    finding_type = str(first_value(row, ["FindingType"], "") or "").strip().lower()
    if finding_type != "unquotedservicepath":
        return row

    path_name = service_path_from_row(row)
    assessment = unquoted_service_path_assessment(path_name)
    if assessment["status"] == "safe":
        return None

    normalized = dict(row)
    if path_name:
        normalized.setdefault("PathName", path_name)
    if assessment.get("executable_path"):
        normalized["ExecutablePath"] = assessment["executable_path"]
    normalized["PathParsingStatus"] = assessment["label"]
    normalized["PathParsingReason"] = assessment["reason"]

    if assessment["status"] == "uncertain":
        normalized["FindingType"] = "ServicePathNeedsValidation"
        normalized["Severity"] = "Info"
        normalized["Title"] = "Service path requires validation"
        normalized["Recommendation"] = (
            "Validate the service ImagePath manually before treating this as an unquoted service path risk."
        )
    return normalized


def service_path_from_row(row: dict[str, Any]) -> str:
    value = first_value(row, ["PathName", "ImagePath", "ServicePath", "CommandLine"], "")
    if value:
        return str(value).strip()
    evidence = str(first_value(row, ["Evidence", "Details", "TechnicalImpact"], "") or "")
    match = re.search(r"\b(?:PathName|ImagePath|ServicePath)\s*=\s*(?P<path>.+?)(?:;|$)", evidence, flags=re.IGNORECASE)
    if not match:
        return ""
    path_name = match.group("path").strip()
    return path_name.rstrip(".").strip()


def unquoted_service_path_assessment(path_name: str) -> dict[str, str]:
    text = str(path_name or "").strip()
    if not text:
        return {
            "status": "uncertain",
            "label": "Needs validation",
            "reason": "No service executable path was available to verify the unquoted service path finding.",
            "executable_path": "",
        }
    if text.startswith('"'):
        return {
            "status": "safe",
            "label": "Suppressed",
            "reason": "The service executable path is already quoted.",
            "executable_path": "",
        }

    executable_path = service_command_executable_path(text)
    if not executable_path:
        return {
            "status": "uncertain",
            "label": "Needs validation",
            "reason": "The parser could not confirm an executable path ending in .exe.",
            "executable_path": "",
        }
    if not re.search(r"\s", executable_path):
        return {
            "status": "safe",
            "label": "Suppressed",
            "reason": "Only command arguments contain spaces; the unquoted executable path itself does not.",
            "executable_path": executable_path,
        }
    return {
        "status": "unsafe",
        "label": "Confirmed unquoted executable path",
        "reason": "The unquoted executable path contains spaces before the .exe extension.",
        "executable_path": executable_path,
    }


def service_command_executable_path(command_line: str) -> str:
    match = re.search(r"\.exe\b", str(command_line or ""), flags=re.IGNORECASE)
    if not match:
        return ""
    return str(command_line or "")[: match.end()].strip()


def server_security_source_id(source_id: Any, row: dict[str, Any], affected_object: str, evidence: dict[str, Any]) -> str:
    explicit_source_id = first_value(row, ["Id", "FindingId", "ControlId"], "")
    if explicit_source_id:
        return str(explicit_source_id)

    finding_type = str(first_value(row, ["FindingType"], "") or source_id or "").strip()
    if not finding_type:
        return str(source_id or "")

    object_name = str(first_value(row, ["Name", "ServiceName", "ShareName", "TaskName"], "") or affected_object or "").strip()
    if not object_name:
        object_name = "object"

    digest = stable_row_digest(
        finding_type,
        object_name,
        first_value(row, ["AccountName", "StartName", "UserId"], ""),
        first_value(row, ["AccessRight", "AccessControlType"], ""),
        evidence.get("path_name"),
        evidence.get("evidence"),
    )
    type_token = sanitize_id(finding_type)[:24]
    object_token = sanitize_id(object_name)[:16]
    if object_token:
        return f"{type_token}-{object_token}-{digest}"
    return f"{type_token}-{digest}"


def stable_row_digest(*values: Any) -> str:
    text = "\x1f".join(str(value or "") for value in values)
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:8].upper()


def network_listener_dedupe_key(evidence: dict[str, Any]) -> tuple[str, int, str, str] | None:
    finding_type = str(evidence.get("finding_type") or "")
    if finding_type.lower() != "riskylisteningport":
        return None
    port = normalize_port_value(evidence.get("port"))
    if port is None:
        return None
    return (
        str(evidence.get("protocol") or "TCP").upper(),
        port,
        str(evidence.get("process_name") or "").lower(),
        str(evidence.get("bind_scope") or "").lower(),
    )


def network_listener_source_id(source_id: Any, evidence: dict[str, Any]) -> str:
    port = normalize_port_value(evidence.get("port"))
    if port is None:
        return str(source_id or "")
    finding_type = str(evidence.get("finding_type") or source_id or "RiskyListeningPort")
    protocol = str(evidence.get("protocol") or "TCP").upper()
    return f"{finding_type}-{protocol}-{port}"


def network_firewall_rule_source_id(source_id: Any, evidence: dict[str, Any]) -> str:
    finding_type = str(evidence.get("finding_type") or "").strip()
    if finding_type.lower() != "firewallallowssensitiveport":
        return ""
    port = normalize_port_value(evidence.get("port"))
    protocol = str(evidence.get("protocol") or "TCP").upper()
    if port is None:
        return str(source_id or "")
    rule_name = str(evidence.get("firewall_rule_name") or evidence.get("firewall_rule_display_name") or "rule")
    digest = stable_row_digest(finding_type, protocol, port, rule_name, evidence.get("remote_addresses"), evidence.get("firewall_profile"))
    return f"FW-SENSITIVE-{protocol}-{port}-{sanitize_id(rule_name)[:12] or 'RULE'}-{digest}"


def local_admin_source_id(source_id: Any, row: dict[str, Any], affected_object: str, evidence: dict[str, Any]) -> str:
    explicit_source_id = first_value(row, ["Id", "FindingId", "ControlId"], "")
    if explicit_source_id:
        return str(explicit_source_id)
    finding_type = str(first_value(row, ["FindingType"], "") or source_id or "LocalAdminFinding")
    principal = str(first_value(row, ["Principal", "Name"], "") or affected_object or "principal")
    digest = stable_row_digest(
        finding_type,
        principal,
        evidence.get("principal_category"),
        evidence.get("object_class"),
        evidence.get("principal_source"),
        evidence.get("sid"),
    )
    principal_token = sanitize_id(principal)[:20] or "PRINCIPAL"
    return f"{sanitize_id(finding_type)[:28]}-{principal_token}-{digest}"


def rdp_exposure_source_id(source_id: Any, row: dict[str, Any], evidence: dict[str, Any]) -> str:
    explicit_source_id = first_value(row, ["Id", "FindingId", "ControlId"], "")
    if explicit_source_id:
        return str(explicit_source_id)
    finding_type = str(first_value(row, ["FindingType"], "") or source_id or "RdpExposureFinding")
    if str(finding_type).lower() == "rdplistening":
        port = normalize_port_value(evidence.get("port"))
        if port is not None:
            return f"{finding_type}-TCP-{port}"
    return finding_type


def workstation_security_source_id(source_id: Any, row: dict[str, Any], affected_object: str, evidence: dict[str, Any]) -> str:
    explicit_source_id = first_value(row, ["Id", "FindingId", "ControlId"], "")
    if explicit_source_id:
        return str(explicit_source_id)

    finding_type = str(first_value(row, ["FindingType"], "") or source_id or "WorkstationSecurityFinding")
    object_name = str(first_value(row, ["Name", "MountPoint", "ProfileName"], "") or affected_object or "object")
    digest = stable_row_digest(
        finding_type,
        object_name,
        evidence.get("mount_point"),
        evidence.get("firewall_profile"),
        evidence.get("policy_name"),
    )
    object_token = sanitize_id(object_name)[:18] or "OBJECT"
    return f"{sanitize_id(finding_type)[:28]}-{object_token}-{digest}"


def normalize_port_value(value: Any) -> int | None:
    if isinstance(value, bool) or value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def aggregate_host_network_context_evidence(row: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    if not is_aggregate_host_network_exposure(row, evidence):
        return {}

    raw_evidence = str(first_value(row, ["Evidence"], "") or evidence.get("evidence") or "")
    exposed_ports = parse_aggregate_exposed_ports(raw_evidence)
    if not exposed_ports:
        return {}

    return {
        "exposed_ports": exposed_ports,
        "summary": aggregate_exposed_ports_summary(exposed_ports),
        "risk_explanation": (
            "Broadly listening Windows management and file-sharing services may be expected on Windows servers, "
            "but access should be validated against documented host role, service ownership, firewall scope, and monitoring."
        ),
        "bind_scope_explanation": ALL_INTERFACES_BIND_SCOPE_EXPLANATION,
        "aggregate_network_context": (
            "Broadly listening Windows management or file-sharing services may be expected on Windows servers, "
            "but reachability should be validated against trusted domain, management, VPN, or application networks. "
            "This evidence describes local listener bindings only and does not prove internet exposure."
        ),
    }


def is_aggregate_host_network_exposure(row: dict[str, Any], evidence: dict[str, Any]) -> bool:
    finding_id = str(first_value(row, ["Id", "FindingId"], "") or evidence.get("id") or evidence.get("finding_id") or "")
    area = str(first_value(row, ["Area"], "") or evidence.get("area") or "")
    title = str(first_value(row, ["Title"], "") or evidence.get("title") or "")
    raw_evidence = str(first_value(row, ["Evidence"], "") or evidence.get("evidence") or "")

    if finding_id.upper() == "WIN-NET-001":
        return True
    if area.lower() == "network exposure" and "ports are listening broadly" in title.lower():
        return True
    return bool(raw_evidence and "ports are listening broadly" in title.lower())


HOST_WINRM_POLICY_BY_ID = {
    "WIN-WINRM-002": {"policy_name": "ClientAllowBasic", "scope": "Client", "setting_label": "AllowBasic"},
    "WIN-WINRM-003": {"policy_name": "ClientAllowUnencryptedTraffic", "scope": "Client", "setting_label": "AllowUnencryptedTraffic"},
    "WIN-WINRM-004": {"policy_name": "ClientAllowDigest", "scope": "Client", "setting_label": "AllowDigest"},
    "WIN-WINRM-005": {"policy_name": "ServiceAllowBasic", "scope": "Service", "setting_label": "AllowBasic"},
    "WIN-WINRM-006": {"policy_name": "ServiceAllowAutoConfig", "scope": "Service", "setting_label": "AllowAutoConfig"},
    "WIN-WINRM-007": {"policy_name": "ServiceAllowUnencryptedTraffic", "scope": "Service", "setting_label": "AllowUnencryptedTraffic"},
    "WIN-WINRM-008": {"policy_name": "ServiceDisableRunAs", "scope": "Service", "setting_label": "DisableRunAs"},
    "WIN-WINRM-009": {"policy_name": "AllowRemoteShellAccess", "scope": "WinRS", "setting_label": "AllowRemoteShellAccess"},
}


def host_security_context_evidence(row: dict[str, Any], data: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    finding_id = str(first_value(row, ["Id", "FindingId", "ControlId"], "") or evidence.get("id") or evidence.get("finding_id") or "").strip().upper()
    if finding_id.startswith("WIN-SMB-"):
        return host_smb_baseline_context(row, data, evidence, finding_id)
    if finding_id.startswith("WIN-WINRM-"):
        return host_winrm_baseline_context(row, data, evidence, finding_id)
    if finding_id.startswith("WIN-FW-"):
        return host_firewall_baseline_context(row, data, evidence, finding_id)
    if finding_id.startswith("WIN-DEF-"):
        return host_defender_baseline_context(row, data, evidence, finding_id)
    if finding_id.startswith("WIN-UAC-"):
        return host_uac_baseline_context(row, data, evidence, finding_id)
    if finding_id.startswith("WIN-PS-"):
        return host_powershell_logging_context(row, data, evidence, finding_id)
    return {}


def host_defender_baseline_context(row: dict[str, Any], data: dict[str, Any], evidence: dict[str, Any], finding_id: str) -> dict[str, Any]:
    defender = as_dict(data.get("Defender"))
    core = as_dict(data.get("CoreSettings"))
    disabled_components = []
    for component in ["AMServiceEnabled", "AntivirusEnabled", "RealTimeProtectionEnabled", "BehaviorMonitorEnabled", "IoavProtectionEnabled", "NISEnabled"]:
        if component in defender and not bool(defender.get(component)):
            disabled_components.append(component)

    setting_key = ""
    current_value: Any = ""
    expected_value = "Enabled or approved managed EDR replacement"
    if finding_id == "WIN-DEF-001":
        setting_key = "Get-MpComputerStatus"
        current_value = "Unavailable"
        summary = "Microsoft Defender status could not be collected and endpoint protection health requires validation."
    elif finding_id == "WIN-DEF-003":
        setting_key = "DefenderDisableAntiSpywarePolicy"
        current_value = core.get("DefenderDisableAntiSpywarePolicy", "")
        expected_value = "0 / Not configured unless an approved EDR owns this control"
        summary = "Microsoft Defender Antivirus is disabled by policy and requires approved endpoint protection ownership validation."
    else:
        setting_key = "DefenderProtectionComponents"
        current_value = ", ".join(disabled_components) if disabled_components else str(first_value(row, ["Evidence"], "") or evidence.get("evidence") or "")
        summary = "Microsoft Defender protection components are disabled or unhealthy and require endpoint protection validation."

    return {
        "baseline_control_id": finding_id,
        "control_family": "Endpoint protection baseline",
        "endpoint_protection_product": "Microsoft Defender or approved EDR",
        "setting_key": setting_key,
        "current_value": current_value,
        "expected_value": expected_value,
        "defender_am_service_enabled": defender.get("AMServiceEnabled", ""),
        "defender_antivirus_enabled": defender.get("AntivirusEnabled", ""),
        "defender_realtime_protection_enabled": defender.get("RealTimeProtectionEnabled", ""),
        "defender_behavior_monitor_enabled": defender.get("BehaviorMonitorEnabled", ""),
        "defender_ioav_protection_enabled": defender.get("IoavProtectionEnabled", ""),
        "defender_signature_last_updated": defender.get("AntivirusSignatureLastUpdated", ""),
        "disabled_defender_components": disabled_components,
        "summary": summary,
        "risk_explanation": "Endpoint protection findings can indicate missing preventive controls or an approved third-party EDR replacement that must be documented with management ownership and current health evidence.",
        "customer_question": "Which endpoint protection platform owns this host, is it centrally managed, and was the current protection state intentionally approved?",
        "safe_next_step": "Validate endpoint protection policy, EDR ownership, host assignment, and last healthy check-in before changing Defender or equivalent controls.",
    }


def host_uac_baseline_context(row: dict[str, Any], data: dict[str, Any], evidence: dict[str, Any], finding_id: str) -> dict[str, Any]:
    core = as_dict(data.get("CoreSettings"))
    mapping = {
        "WIN-UAC-001": {
            "setting_name": "User Account Control",
            "setting_key": "UacEnabled",
            "registry_name": "EnableLUA",
            "current_value": core.get("UacEnabled", ""),
            "expected_value": "1 / Enabled",
        },
        "WIN-UAC-002": {
            "setting_name": "Administrator elevation prompt behavior",
            "setting_key": "UacConsentPromptBehaviorAdmin",
            "registry_name": "ConsentPromptBehaviorAdmin",
            "current_value": core.get("UacConsentPromptBehaviorAdmin", ""),
            "expected_value": "1 or 2 / Secure desktop credential or consent prompt",
        },
        "WIN-UAC-003": {
            "setting_name": "UAC secure desktop prompting",
            "setting_key": "UacPromptOnSecureDesktop",
            "registry_name": "PromptOnSecureDesktop",
            "current_value": core.get("UacPromptOnSecureDesktop", ""),
            "expected_value": "1 / Enabled",
        },
    }
    item = mapping.get(finding_id, {})
    setting_name = str(item.get("setting_name") or "UAC baseline control")
    return {
        "baseline_control_id": finding_id,
        "control_family": "Windows privilege control baseline",
        "privilege_control": "User Account Control",
        "setting_name": setting_name,
        "setting_key": item.get("setting_key", ""),
        "registry_name": item.get("registry_name", ""),
        "current_value": item.get("current_value", ""),
        "expected_value": item.get("expected_value", ""),
        "summary": f"{setting_name} is not aligned with the expected Windows privilege-control baseline and requires application dependency validation.",
        "risk_explanation": "Weak UAC settings can reduce Windows privilege boundaries and make elevation prompts easier to bypass, spoof, or miss during user-session compromise.",
        "customer_question": "Is there a documented legacy application, remote-support, or managed elevation workflow that requires this UAC configuration?",
        "safe_next_step": "Validate application compatibility, support workflow, user impact, and change window before changing UAC policy.",
    }


def host_powershell_logging_context(row: dict[str, Any], data: dict[str, Any], evidence: dict[str, Any], finding_id: str) -> dict[str, Any]:
    ps_logging = as_dict(data.get("PowerShellLogging"))
    mapping = {
        "WIN-PS-001": {
            "policy_name": "PowerShell Script Block Logging",
            "setting_key": "ScriptBlockLoggingEnabled",
            "registry_name": "EnableScriptBlockLogging",
            "current_value": ps_logging.get("ScriptBlockLoggingEnabled", ""),
            "expected_value": "1 / Enabled",
            "data_sensitivity_note": "Script block logging records executed PowerShell content and should be forwarded to protected central logging with retention and access controls.",
        },
        "WIN-PS-002": {
            "policy_name": "PowerShell Transcription",
            "setting_key": "TranscriptionEnabled",
            "registry_name": "EnableTranscripting",
            "current_value": ps_logging.get("TranscriptionEnabled", ""),
            "expected_value": "1 / Enabled after protected transcript path approval",
            "data_sensitivity_note": "PowerShell transcripts can contain sensitive command content; enable only with a protected transcript path, restricted access, and retention rules.",
        },
    }
    item = mapping.get(finding_id, {})
    policy_name = str(item.get("policy_name") or "PowerShell logging policy")
    return {
        "baseline_control_id": finding_id,
        "control_family": "PowerShell logging baseline",
        "logging_channel": "PowerShell",
        "policy_name": policy_name,
        "setting_key": item.get("setting_key", ""),
        "registry_name": item.get("registry_name", ""),
        "current_value": item.get("current_value", ""),
        "expected_value": item.get("expected_value", ""),
        "policy_values": ps_logging,
        "summary": f"{policy_name} is not enabled by policy and requires detection and logging coverage validation.",
        "risk_explanation": "Limited PowerShell logging can reduce visibility into administrative misuse, malware execution, and post-compromise activity. Logging must be balanced with sensitive-data handling requirements.",
        "customer_question": "How is PowerShell activity monitored centrally, and what protected log collection or alternate EDR telemetry covers this host?",
        "safe_next_step": "Validate central log collection, retention, sensitive-data handling, and EDR telemetry before enabling or changing PowerShell logging policy.",
        "data_sensitivity_note": item.get("data_sensitivity_note", ""),
    }


def host_smb_baseline_context(row: dict[str, Any], data: dict[str, Any], evidence: dict[str, Any], finding_id: str) -> dict[str, Any]:
    core = as_dict(data.get("CoreSettings"))
    mapping = {
        "WIN-SMB-001": {
            "protocol_setting": "SMBv1 server protocol",
            "setting_key": "Smb1ServerEnabled",
            "current_value": core.get("Smb1ServerEnabled"),
            "expected_value": "False / Disabled",
        },
        "WIN-SMB-002": {
            "protocol_setting": "SMBv1 client driver",
            "setting_key": "Smb1ClientDriverStart",
            "current_value": core.get("Smb1ClientDriverStart"),
            "expected_value": "4 / Disabled",
        },
        "WIN-SMB-003": {
            "protocol_setting": "Insecure SMB guest logons",
            "setting_key": "InsecureGuestAuthPolicy",
            "current_value": core.get("InsecureGuestAuthPolicy"),
            "expected_value": "0 / Disabled",
        },
    }
    item = mapping.get(finding_id, {})
    setting = str(item.get("protocol_setting") or "SMB baseline control")
    return {
        "baseline_control_id": finding_id,
        "control_family": "SMB baseline",
        "protocol_family": "SMB",
        "protocol_setting": setting,
        "setting_key": item.get("setting_key", ""),
        "current_value": item.get("current_value", ""),
        "expected_value": item.get("expected_value", ""),
        "summary": f"{setting} is not aligned with the expected Windows hardening baseline and requires legacy dependency validation.",
        "risk_explanation": "Legacy or weak SMB settings can increase lateral movement, downgrade, or unauthenticated access risk. This is protocol policy evidence, not proof that TCP 445 is reachable from untrusted networks.",
        "customer_question": "Is there a documented legacy SMB dependency, owner, compensating control, and retirement date for this host?",
        "safe_next_step": "Validate application, NAS, print, and legacy file-sharing dependencies before changing SMB policy through approved change control.",
    }


def host_winrm_baseline_context(row: dict[str, Any], data: dict[str, Any], evidence: dict[str, Any], finding_id: str) -> dict[str, Any]:
    remote_access = as_dict(data.get("RemoteAccess"))
    winrm_policy = as_dict(data.get("WinRmPolicy"))
    base = {
        "baseline_control_id": finding_id,
        "control_family": "WinRM baseline",
        "protocol_family": "WinRM",
        "common_service": "Windows Remote Management",
        "summary": "WinRM remote management configuration requires owner, source-network, authentication, encryption, and logging validation.",
        "risk_explanation": "WinRM is a legitimate administration channel, but weak authentication, unencrypted traffic, broad listener configuration, or remote shell access can increase remote management exposure. This is configuration evidence only and does not prove internet reachability.",
        "customer_question": "Which management platform owns WinRM on this host, which source networks may use it, and what authentication and logging controls apply?",
        "safe_next_step": "Validate management dependency, allowed source networks, authentication policy, encryption, and log collection before disabling or changing WinRM settings.",
    }
    if finding_id == "WIN-WINRM-001":
        base.update(
            {
                "winrm_service_status": remote_access.get("WinRmService", ""),
                "setting_key": "WinRmService",
                "current_value": remote_access.get("WinRmService", ""),
                "expected_value": "Stopped unless explicitly required and restricted",
                "summary": f"WinRM service status is {remote_access.get('WinRmService', 'Unknown')} and requires remote administration scope validation.",
            }
        )
        return base

    policy = HOST_WINRM_POLICY_BY_ID.get(finding_id, {})
    policy_name = str(policy.get("policy_name") or "")
    current_value = winrm_policy.get(policy_name, "") if policy_name else ""
    expected_value = "1 / Enabled" if finding_id == "WIN-WINRM-008" else "0 / Disabled"
    base.update(
        {
            "winrm_policy_scope": policy.get("scope", ""),
            "winrm_policy_name": policy_name,
            "setting_key": policy_name,
            "setting_label": policy.get("setting_label", ""),
            "current_value": current_value,
            "expected_value": expected_value,
            "summary": f"WinRM policy {policy_name or finding_id} is not aligned with the expected management hardening baseline.",
        }
    )
    return base


def host_firewall_baseline_context(row: dict[str, Any], data: dict[str, Any], evidence: dict[str, Any], finding_id: str) -> dict[str, Any]:
    profile_name = firewall_profile_name_from_row(row, evidence)
    profile = matching_firewall_profile(data, profile_name)
    if not profile_name:
        profile_name = str(profile.get("Name") or "")
    return {
        "baseline_control_id": finding_id,
        "control_family": "Windows Firewall baseline",
        "firewall_profile": profile_name,
        "firewall_enabled": profile.get("Enabled", ""),
        "default_inbound_action": profile.get("DefaultInboundAction", ""),
        "default_outbound_action": profile.get("DefaultOutboundAction", ""),
        "allow_inbound_rules": profile.get("AllowInboundRules", ""),
        "log_allowed": profile.get("LogAllowed", ""),
        "log_blocked": profile.get("LogBlocked", ""),
        "summary": f"Windows Firewall profile {profile_name or 'Unknown'} is not aligned with the expected host firewall baseline.",
        "risk_explanation": "Host firewall profile settings affect local exposure and lateral movement resistance. This is local firewall configuration evidence, not a claim of internet exposure.",
        "customer_question": "Which endpoint policy owns this firewall profile, which inbound services are approved, and is the current profile behavior intentional?",
        "safe_next_step": "Validate endpoint management policy, required inbound rules, remote administration paths, and profile assignment before changing firewall defaults.",
    }


def firewall_profile_name_from_row(row: dict[str, Any], evidence: dict[str, Any]) -> str:
    for value in [first_value(row, ["ProfileName", "Name", "FirewallProfile"], ""), evidence.get("profile_name"), evidence.get("firewall_profile")]:
        text = str(value or "").strip()
        if text in {"Domain", "Private", "Public"}:
            return text
    evidence_text = str(first_value(row, ["Evidence"], "") or evidence.get("evidence") or "")
    match = re.search(r"\b(Domain|Private|Public)\s+profile\b", evidence_text, flags=re.IGNORECASE)
    return match.group(1).title() if match else ""


def matching_firewall_profile(data: dict[str, Any], profile_name: str) -> dict[str, Any]:
    target = str(profile_name or "").lower()
    for profile in as_records(data.get("FirewallProfiles")):
        if str(profile.get("Name") or "").lower() == target:
            return profile
    return {}


def parse_aggregate_exposed_ports(raw_evidence: str) -> list[dict[str, Any]]:
    deduped: dict[tuple[str, int, str], dict[str, Any]] = {}
    for fragment in str(raw_evidence or "").split(";"):
        parsed = parse_aggregate_endpoint_fragment(fragment)
        if parsed is None:
            continue
        protocol, port, bind_address, process = parsed
        scope = bind_scope(bind_address)
        context = lookup_port_context(protocol, port)
        key = (protocol.upper(), port, process.lower())
        entry = deduped.get(key)
        if entry is None:
            entry = {
                "protocol": protocol.upper(),
                "port": port,
                "bind_addresses": [],
                "bind_address": bind_address,
                "bind_scope": scope,
                "process_name": process,
                "common_service": context["common_service"],
                "common_name": context["common_name"],
                "exposure_type": context["exposure_type"],
                "risk_explanation": context["risk_explanation"],
                "acceptable_when": context["acceptable_when"],
                "customer_question": context["customer_question"],
                "safe_next_step": context["safe_next_step"],
                "port_context_confidence": context["mapping_confidence"],
            }
            if scope == "All interfaces":
                entry["bind_scope_explanation"] = ALL_INTERFACES_BIND_SCOPE_EXPLANATION
            deduped[key] = entry

        addresses = entry.setdefault("bind_addresses", [])
        if bind_address and bind_address not in addresses:
            addresses.append(bind_address)
        if entry.get("bind_scope") != "All interfaces" and scope == "All interfaces":
            entry["bind_scope"] = "All interfaces"
            entry["bind_scope_explanation"] = ALL_INTERFACES_BIND_SCOPE_EXPLANATION

    return sorted(deduped.values(), key=lambda item: (as_int(item.get("port")), str(item.get("process_name", "")).lower()))


def parse_aggregate_endpoint_fragment(fragment: str) -> tuple[str, int, str, str] | None:
    text = str(fragment or "").strip()
    if not text:
        return None

    endpoint, _, process = text.partition(" ")
    process = process.strip()
    if not process:
        process = "Unknown"

    endpoint = endpoint.strip()
    match = re.match(r"^(?P<address>.+):(?P<port>\d{1,5})$", endpoint)
    if not match:
        return None

    address = normalize_aggregate_bind_address(match.group("address"))
    port = as_int(match.group("port"), -1)
    if port < 0 or port > 65535:
        return None
    return "TCP", port, address, process


def normalize_aggregate_bind_address(address: str) -> str:
    text = str(address or "").strip()
    if text in {"", "::", "[::]"}:
        return "::"
    return text


def aggregate_exposed_ports_summary(exposed_ports: list[dict[str, Any]]) -> str:
    labels = [aggregate_port_label(item) for item in exposed_ports]
    port_text = join_human_list(labels)
    return (
        f"High-value Windows management and file-sharing ports are listening broadly: {port_text}. "
        "These services may be expected on Windows servers, but reachability should be limited to trusted domain, management, VPN, or application networks."
    )


def aggregate_port_label(item: dict[str, Any]) -> str:
    common_name = str(item.get("common_name") or "")
    service = str(item.get("common_service") or "")
    if service == "Windows Remote Management" and common_name:
        service_label = common_name
    elif common_name == "RDP":
        service_label = common_name
    else:
        service_label = service or common_name
    return f"{item.get('protocol', 'TCP')} {item.get('port')} {service_label}".strip()


def join_human_list(values: list[str]) -> str:
    values = [value for value in values if value]
    if len(values) <= 1:
        return "".join(values)
    if len(values) == 2:
        return " and ".join(values)
    return ", ".join(values[:-1]) + f", and {values[-1]}"


def local_admin_context_evidence(row: dict[str, Any], data: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    principal = str(first_value(row, ["Principal", "Name"], "") or "").strip()
    member = matching_local_admin_member(data, principal)
    principal_category = str(first_value(row, ["PrincipalCategory"], "") or member.get("PrincipalCategory") or "").strip()
    object_class = str(first_value(row, ["ObjectClass"], "") or member.get("ObjectClass") or "").strip()
    principal_source = str(first_value(row, ["PrincipalSource"], "") or member.get("PrincipalSource") or "").strip()
    sid = str(first_value(row, ["Sid", "SID"], "") or member.get("Sid") or member.get("SID") or "").strip()
    enabled = first_value(row, ["Enabled"], member.get("Enabled") if member else "")
    last_logon_utc = str(first_value(row, ["LastLogonUtc"], "") or member.get("LastLogonUtc") or "").strip()
    admin_group_name = str(data.get("AdministratorsGroupName") or "Administrators").strip()
    admin_group_sid = str(data.get("AdministratorsGroupSid") or "S-1-5-32-544").strip()
    finding_type = str(first_value(row, ["FindingType"], "") or evidence.get("finding_type") or "").strip()
    summary = local_admin_summary(principal, principal_category, object_class, principal_source, admin_group_name, finding_type)
    return {
        "principal": principal,
        "principal_category": principal_category,
        "object_class": object_class,
        "principal_source": principal_source,
        "sid": sid,
        "enabled": enabled,
        "last_logon_utc": last_logon_utc,
        "administrators_group_name": admin_group_name,
        "administrators_group_sid": admin_group_sid,
        "summary": summary,
        "risk_explanation": (
            "Local administrator membership grants full administrative control on the host. "
            "Membership should be limited to approved break-glass, endpoint management, or server administration principals."
        ),
        "customer_question": "Who owns this local administrator principal, why is it required, and how is membership approved and reviewed?",
        "safe_next_step": "Validate owner, business purpose, group membership, and change approval before removing or changing local administrator access.",
    }


def matching_local_admin_member(data: dict[str, Any], principal: str) -> dict[str, Any]:
    if not principal:
        return {}
    principal_lower = principal.lower()
    principal_leaf = principal_lower.split("\\")[-1]
    for member in as_records(data.get("LocalAdministrators")):
        name = str(member.get("Name") or "").lower()
        if name == principal_lower or name.split("\\")[-1] == principal_leaf:
            return member
    return {}


def local_admin_summary(
    principal: str,
    principal_category: str,
    object_class: str,
    principal_source: str,
    admin_group_name: str,
    finding_type: str,
) -> str:
    principal_text = principal or "A principal"
    category_text = principal_category or object_class or principal_source or "principal"
    group_text = admin_group_name or "Administrators"
    if finding_type == "UnresolvedLocalAdmin":
        return f"{principal_text} is an unresolved SID in the local {group_text} group and requires ownership validation."
    return f"{principal_text} ({category_text}) has local administrator rights through the {group_text} group."


def rdp_exposure_context_evidence(row: dict[str, Any], data: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    summary_data = as_dict(data.get("Summary"))
    registry = as_dict(data.get("Registry"))
    term_service = as_dict(data.get("TermService"))
    finding_type = str(first_value(row, ["FindingType"], "") or evidence.get("finding_type") or "").strip()
    port = normalize_port_value(first_value(row, ["Port", "RdpPort", "LocalPort"], summary_data.get("RdpPort") or registry.get("PortNumber") or 3389))
    if port is None:
        port = 3389
    listeners = matching_rdp_listeners(data, port)
    bind_addresses = unique_string_values(listener_bind_addresses(listeners))
    bind_address = bind_addresses[0] if bind_addresses else ""
    scope = bind_scope_for_addresses(bind_addresses, combined_row_text(row))
    context = lookup_port_context("TCP", port)
    remote_users = as_records(data.get("RemoteDesktopUsers"))
    firewall_rules = enabled_inbound_allow_firewall_rules(data)
    output = {
        "protocol": "TCP",
        "port": port,
        "bind_address": bind_address,
        "bind_addresses": bind_addresses,
        "bind_scope": scope,
        "common_service": context["common_service"],
        "common_name": context["common_name"],
        "exposure_type": context["exposure_type"],
        "rdp_enabled": summary_data.get("RdpEnabled"),
        "network_level_authentication_required": summary_data.get("NetworkLevelAuthenticationRequired"),
        "term_service_status": summary_data.get("TermServiceStatus") or term_service.get("Status"),
        "term_service_start_mode": summary_data.get("TermServiceStartMode") or term_service.get("StartMode"),
        "remote_desktop_user_count": summary_data.get("RemoteDesktopUserCount", len(remote_users)),
        "enabled_inbound_allow_rule_count": summary_data.get("EnabledInboundAllowRuleCount", len(firewall_rules)),
        "listener_count": summary_data.get("ListenerCount", len(listeners)),
        "remote_desktop_users": [str(item.get("Name") or "").strip() for item in remote_users if str(item.get("Name") or "").strip()][:20],
        "enabled_inbound_firewall_rules": [str(item.get("DisplayName") or item.get("Name") or "").strip() for item in firewall_rules if str(item.get("DisplayName") or item.get("Name") or "").strip()][:20],
        "risk_explanation": context["risk_explanation"],
        "customer_question": context["customer_question"],
        "safe_next_step": context["safe_next_step"],
        "summary": rdp_exposure_summary(finding_type, port, scope, summary_data, len(remote_users), len(firewall_rules), len(listeners)),
    }
    if scope == "All interfaces":
        output["bind_scope_explanation"] = ALL_INTERFACES_BIND_SCOPE_EXPLANATION
    return output


def matching_rdp_listeners(data: dict[str, Any], port: int) -> list[dict[str, Any]]:
    listeners = []
    for listener in as_records(data.get("Listeners")):
        if as_int(listener.get("LocalPort"), -1) == port:
            listeners.append(listener)
    return listeners


def enabled_inbound_allow_firewall_rules(data: dict[str, Any]) -> list[dict[str, Any]]:
    rules = []
    for rule in as_records(data.get("FirewallRules")):
        if str(rule.get("Enabled") or "").lower() == "true" and str(rule.get("Action") or "").lower() == "allow" and str(rule.get("Direction") or "").lower() == "inbound":
            rules.append(rule)
    return rules


def rdp_exposure_summary(
    finding_type: str,
    port: int,
    bind_scope_value: str,
    summary_data: dict[str, Any],
    remote_user_count: int,
    firewall_rule_count: int,
    listener_count: int,
) -> str:
    enabled = summary_data.get("RdpEnabled")
    nla = summary_data.get("NetworkLevelAuthenticationRequired")
    if finding_type == "RdpNlaDisabled":
        return "RDP is enabled but Network Level Authentication is not required. Validate legacy client requirements before changing policy."
    if finding_type == "RdpAllowedUsersPresent":
        return f"The Remote Desktop Users group has {remote_user_count} direct member(s) that require owner and approval review."
    if finding_type == "RdpFirewallAllowsInbound":
        return f"{firewall_rule_count} enabled inbound firewall allow rule(s) were found for Remote Desktop. Validate allowed profiles and source networks."
    if finding_type == "RdpListening":
        scope_text = f" with bind scope {bind_scope_value}" if bind_scope_value else ""
        return f"RDP is listening on TCP {port}{scope_text}. This is local listener evidence only and does not prove internet exposure."
    return f"Remote Desktop configuration requires review. RDP enabled={enabled}; NLA required={nla}; TCP port={port}; listeners={listener_count}."


def server_security_context_evidence(row: dict[str, Any], data: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    finding_type = str(first_value(row, ["FindingType"], "") or evidence.get("finding_type") or "").strip()
    finding_type_lower = finding_type.lower()
    if finding_type_lower in {"servicerunsascustomaccount", "unquotedservicepath", "servicepathneedsvalidation"}:
        return server_service_context(row, data, evidence, finding_type)
    if finding_type_lower == "scheduledtaskrunshighest":
        return server_scheduled_task_context(row, data, evidence)
    if finding_type_lower == "broadsmbshareaccess":
        return server_smb_share_context(row, data, evidence)
    return {}


def server_service_context(row: dict[str, Any], data: dict[str, Any], evidence: dict[str, Any], finding_type: str) -> dict[str, Any]:
    service_name = str(first_value(row, ["ServiceName", "Name"], "") or "").strip()
    service = matching_service(data, service_name)
    display_name = str(first_value(row, ["DisplayName", "ServiceDisplayName"], "") or service.get("DisplayName") or "").strip()
    start_name = str(first_value(row, ["StartName", "AccountName"], "") or service.get("StartName") or "").strip()
    start_mode = str(first_value(row, ["StartMode"], "") or service.get("StartMode") or "").strip()
    state = str(first_value(row, ["State", "ServiceState"], "") or service.get("State") or "").strip()
    path_name = str(first_value(row, ["PathName", "ImagePath", "ServicePath", "CommandLine"], "") or service.get("PathName") or "").strip()
    executable_path = str(first_value(row, ["ExecutablePath"], "") or evidence.get("executable_path") or "").strip()
    summary = server_service_summary(finding_type, service_name, start_name, start_mode, state)
    return {
        "service_name": service_name,
        "service_display_name": display_name,
        "service_start_name": start_name,
        "service_start_mode": start_mode,
        "service_state": state,
        "service_path": path_name,
        "executable_path": executable_path,
        "summary": summary,
        "customer_question": "Who owns this Windows service, what application depends on it, and is the service account/path configuration approved?",
        "safe_next_step": "Validate service owner, dependency, credential custody, and approved change window before changing the service account or ImagePath.",
        "risk_explanation": "Windows service configuration can affect application availability and privilege boundaries. Service account and executable path findings require owner review before remediation.",
    }


def matching_service(data: dict[str, Any], service_name: str) -> dict[str, Any]:
    if not service_name:
        return {}
    service_lower = service_name.lower()
    for service in as_records(data.get("Services")):
        name = str(service.get("Name") or "").lower()
        display = str(service.get("DisplayName") or "").lower()
        if service_lower in {name, display}:
            return service
    return {}


def server_service_summary(finding_type: str, service_name: str, start_name: str, start_mode: str, state: str) -> str:
    service_text = service_name or "A Windows service"
    if finding_type == "ServiceRunsAsCustomAccount":
        return f"{service_text} runs as {start_name or 'a custom or domain account'} and requires owner, dependency, and credential review."
    if finding_type == "UnquotedServicePath":
        return f"{service_text} has an unquoted executable path finding that requires validation before any service configuration change."
    if finding_type == "ServicePathNeedsValidation":
        return f"{service_text} has service path evidence that could not be safely classified and requires manual validation."
    state_text = f" State={state}; StartMode={start_mode}." if state or start_mode else ""
    return f"{service_text} configuration requires owner review.{state_text}"


def server_scheduled_task_context(row: dict[str, Any], data: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    task_label = str(first_value(row, ["TaskName", "Name"], "") or "").strip()
    task = matching_scheduled_task(data, task_label)
    task_name = str(task.get("TaskName") or task_label.split("\\")[-1] or task_label).strip()
    task_path = str(task.get("TaskPath") or "").strip()
    user_id = str(first_value(row, ["UserId", "TaskUser"], "") or task.get("UserId") or "").strip()
    run_level = str(first_value(row, ["RunLevel"], "") or task.get("RunLevel") or "").strip()
    state = str(first_value(row, ["State"], "") or task.get("State") or "").strip()
    full_name = f"{task_path}{task_name}" if task_path else task_label or task_name
    return {
        "task_name": task_name,
        "task_path": task_path,
        "task_full_name": full_name,
        "task_user_id": user_id,
        "task_run_level": run_level,
        "task_state": state,
        "summary": f"Scheduled task {full_name or 'Unknown'} runs with highest privileges and requires owner and action-path review.",
        "customer_question": "Who owns this scheduled task, what action path does it run, and why are highest privileges required?",
        "safe_next_step": "Validate task owner, action path, trigger, and required privileges before changing or disabling the task.",
        "risk_explanation": "Scheduled tasks running with elevated privileges can be legitimate maintenance automation or persistence risk and must be reviewed in context.",
    }


def matching_scheduled_task(data: dict[str, Any], task_label: str) -> dict[str, Any]:
    if not task_label:
        return {}
    label_lower = task_label.lower()
    for task in as_records(data.get("ScheduledTasks")):
        name = str(task.get("TaskName") or "")
        path = str(task.get("TaskPath") or "")
        full = f"{path}{name}".lower()
        if label_lower in {name.lower(), full} or label_lower.endswith(name.lower()):
            return task
    return {}


def server_smb_share_context(row: dict[str, Any], data: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    share_name = str(first_value(row, ["ShareName", "Name"], "") or "").strip()
    share = matching_smb_share(data, share_name)
    access = matching_smb_share_access(data, share_name, row)
    account = str(first_value(row, ["AccountName", "Principal"], "") or access.get("AccountName") or "").strip()
    access_right = str(first_value(row, ["AccessRight"], "") or access.get("AccessRight") or "").strip()
    access_type = str(first_value(row, ["AccessControlType"], "") or access.get("AccessControlType") or "").strip()
    share_path = str(share.get("Path") or "").strip()
    share_state = str(share.get("ShareState") or "").strip()
    share_type = str(share.get("ShareType") or "").strip()
    return {
        "share_name": share_name,
        "share_path": share_path,
        "share_state": share_state,
        "share_type": share_type,
        "share_special": share.get("Special") if "Special" in share else "",
        "access_account": account,
        "access_right": access_right,
        "access_control_type": access_type,
        "summary": f"SMB share {share_name or 'Unknown'} grants {access_right or 'broad'} access to {account or 'a broad principal'} and requires owner validation.",
        "customer_question": "Who owns this share, what data classification applies, and which groups should have access?",
        "safe_next_step": "Validate share owner, business purpose, data sensitivity, and approved group membership before changing SMB share permissions.",
        "risk_explanation": "Broad SMB share permissions can expose business data or administrative files to more users than intended. Access changes require owner validation and change control.",
    }


def matching_smb_share(data: dict[str, Any], share_name: str) -> dict[str, Any]:
    if not share_name:
        return {}
    share_lower = share_name.lower()
    for share in as_records(data.get("SmbShares")):
        if str(share.get("Name") or "").lower() == share_lower:
            return share
    return {}


def matching_smb_share_access(data: dict[str, Any], share_name: str, row: dict[str, Any]) -> dict[str, Any]:
    share_lower = share_name.lower()
    account = str(first_value(row, ["AccountName", "Principal"], "") or "").lower()
    for access in as_records(data.get("SmbShareAccess")):
        if share_lower and str(access.get("ShareName") or "").lower() != share_lower:
            continue
        if account and str(access.get("AccountName") or "").lower() != account:
            continue
        return access
    return {}


def workstation_security_context_evidence(row: dict[str, Any], data: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    finding_type = str(first_value(row, ["FindingType"], "") or evidence.get("finding_type") or "").strip()
    finding_type_lower = finding_type.lower()
    if finding_type_lower.startswith("defender"):
        return workstation_defender_context(row, data)
    if finding_type_lower == "bitlockervolumenotprotected":
        return workstation_bitlocker_context(row, data)
    if finding_type_lower == "firewallprofiledisabled":
        return workstation_firewall_context(row, data)
    if finding_type_lower == "remoteassistanceenabled":
        return workstation_policy_context(
            row,
            data,
            policy_name="Remote Assistance",
            policy_key="RemoteAssistance",
            summary="Remote Assistance is enabled and requires support-process validation.",
            customer_question="Is Remote Assistance approved for this endpoint population and restricted by support process?",
        )
    if finding_type_lower == "llmnrnotdisabledbypolicy":
        return workstation_policy_context(
            row,
            data,
            policy_name="LLMNR",
            policy_key="LlmnrPolicy",
            summary="LLMNR is not disabled by policy and requires name-resolution dependency validation.",
            customer_question="Is LLMNR still required for any legacy name-resolution dependency?",
        )
    if finding_type_lower == "powershellscriptblockloggingnotenabled":
        return workstation_policy_context(
            row,
            data,
            policy_name="PowerShell Script Block Logging",
            policy_key="PowerShellLogging",
            summary="PowerShell Script Block Logging is not enabled by policy and requires logging coverage validation.",
            customer_question="Is PowerShell activity centrally logged with enough detail for investigation and detection?",
        )
    return {}


def workstation_defender_context(row: dict[str, Any], data: dict[str, Any]) -> dict[str, Any]:
    defender = as_dict(data.get("DefenderStatus"))
    return {
        "defender_am_service_enabled": defender.get("AMServiceEnabled"),
        "defender_antivirus_enabled": defender.get("AntivirusEnabled"),
        "defender_realtime_protection_enabled": defender.get("RealTimeProtectionEnabled"),
        "defender_behavior_monitor_enabled": defender.get("BehaviorMonitorEnabled"),
        "summary": "Microsoft Defender protection state requires validation against the approved endpoint protection standard.",
        "customer_question": "Which endpoint protection platform is approved for this workstation and is real-time protection centrally enforced?",
        "safe_next_step": "Validate endpoint protection policy and management ownership before changing Defender or equivalent controls.",
        "risk_explanation": "Endpoint protection findings can indicate missing preventive controls or an approved third-party replacement that must be documented.",
    }


def workstation_bitlocker_context(row: dict[str, Any], data: dict[str, Any]) -> dict[str, Any]:
    mount_point = str(first_value(row, ["MountPoint", "Name"], "") or "").strip()
    volume = matching_bitlocker_volume(data, mount_point)
    protection_status = str(first_value(row, ["ProtectionStatus"], "") or volume.get("ProtectionStatus") or "").strip()
    volume_status = str(first_value(row, ["VolumeStatus"], "") or volume.get("VolumeStatus") or "").strip()
    encryption_method = str(first_value(row, ["EncryptionMethod"], "") or volume.get("EncryptionMethod") or "").strip()
    return {
        "mount_point": mount_point,
        "volume_type": volume.get("VolumeType", ""),
        "protection_status": protection_status,
        "volume_status": volume_status,
        "encryption_method": encryption_method,
        "lock_status": volume.get("LockStatus", ""),
        "summary": f"Fixed volume {mount_point or 'Unknown'} is not fully protected by BitLocker and requires endpoint encryption policy validation.",
        "customer_question": "Should this fixed volume be encrypted under the customer endpoint encryption policy?",
        "safe_next_step": "Validate recovery-key custody, endpoint management policy, and user impact before enabling or changing BitLocker.",
        "risk_explanation": "Unprotected fixed volumes can expose data if a device is lost, stolen, or accessed offline.",
    }


def matching_bitlocker_volume(data: dict[str, Any], mount_point: str) -> dict[str, Any]:
    mount_lower = mount_point.lower()
    for volume in as_records(data.get("BitLockerVolumes")):
        if str(volume.get("MountPoint") or "").lower() == mount_lower:
            return volume
    return {}


def workstation_firewall_context(row: dict[str, Any], data: dict[str, Any]) -> dict[str, Any]:
    profile_name = str(first_value(row, ["ProfileName", "Name"], "") or "").strip()
    profile = matching_firewall_profile(data, profile_name)
    return {
        "firewall_profile": profile_name,
        "firewall_enabled": profile.get("Enabled", ""),
        "default_inbound_action": profile.get("DefaultInboundAction", ""),
        "default_outbound_action": profile.get("DefaultOutboundAction", ""),
        "summary": f"Windows Firewall {profile_name or 'profile'} profile is disabled and requires endpoint policy validation.",
        "customer_question": "Which firewall profile should be enforced on this endpoint and what management policy controls it?",
        "safe_next_step": "Validate endpoint firewall policy, network profile classification, and required allow rules before enabling or changing the profile.",
        "risk_explanation": "Disabled host firewall profiles can allow broader local network exposure than intended, depending on network profile and allow rules.",
    }


def matching_firewall_profile(data: dict[str, Any], profile_name: str) -> dict[str, Any]:
    profile_lower = profile_name.lower()
    for profile in as_records(data.get("FirewallProfiles")):
        if str(profile.get("Name") or "").lower() == profile_lower:
            return profile
    return {}


def workstation_policy_context(
    row: dict[str, Any],
    data: dict[str, Any],
    *,
    policy_name: str,
    policy_key: str,
    summary: str,
    customer_question: str,
) -> dict[str, Any]:
    policy = as_dict(data.get(policy_key))
    return {
        "policy_name": policy_name,
        "policy_values": policy,
        "summary": summary,
        "customer_question": customer_question,
        "safe_next_step": "Validate current endpoint management policy and dependency impact before changing this setting.",
        "risk_explanation": "Endpoint policy findings should be remediated through approved policy management rather than one-off local changes.",
    }


def network_port_context_evidence(row: dict[str, Any], data: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    finding_type = str(first_value(row, ["FindingType"], "") or evidence.get("finding_type") or "")
    if finding_type.lower() != "riskylisteningport":
        return {}

    protocol = listener_protocol(row)
    port = listener_port(row)
    if port is None:
        return {}

    listeners = matching_listeners(data, port, protocol, process_name(row))
    listener = listeners[0] if listeners else {}
    process = process_name(row) or str(listener.get("ProcessName") or listener.get("process_name") or "")
    service_name = str(first_value(row, ["ServiceName", "Service"], "") or listener.get("ServiceName") or listener.get("service_name") or "").strip()
    service_display_name = str(first_value(row, ["ServiceDisplayName"], "") or listener.get("ServiceDisplayName") or listener.get("service_display_name") or "").strip()
    process_path = str(first_value(row, ["ProcessPath", "ExecutablePath"], "") or listener.get("ProcessPath") or listener.get("ExecutablePath") or "").strip()
    row_bind_address = str(
        first_value(row, ["LocalAddress", "BindAddress", "ListeningAddress"], "")
        or listener.get("LocalAddress")
        or listener.get("local_address")
        or ""
    ).strip()
    bind_addresses = unique_string_values(
        [
            row_bind_address,
            *listener_bind_addresses(listeners),
        ]
    )
    bind_address = row_bind_address or (bind_addresses[0] if bind_addresses else "")
    scope = bind_scope_for_addresses(bind_addresses, combined_row_text(row))
    if not bind_address and scope == "All interfaces":
        bind_address = "0.0.0.0"
        bind_addresses = unique_string_values([bind_address, *bind_addresses])

    context = lookup_port_context(protocol, port)
    bind_scope_explanation = ALL_INTERFACES_BIND_SCOPE_EXPLANATION if scope == "All interfaces" else ""
    source_endpoints = [
        source_endpoint_label(address, port, process)
        for address in bind_addresses
        if address
    ]

    summary = listening_port_summary(protocol, port, process, scope, bind_address, context)
    context_evidence = {
        "protocol": protocol.upper(),
        "port": port,
        "process_name": process,
        "service_name": service_name,
        "service_display_name": service_display_name,
        "process_path": process_path,
        "bind_address": bind_address,
        "bind_addresses": bind_addresses,
        "source_endpoints": source_endpoints,
        "bind_scope": scope,
        "common_service": context["common_service"],
        "common_name": context["common_name"],
        "exposure_type": context["exposure_type"],
        "risk_explanation": context["risk_explanation"],
        "acceptable_when": context["acceptable_when"],
        "customer_question": context["customer_question"],
        "safe_next_step": context["safe_next_step"],
        "port_context_confidence": context["mapping_confidence"],
        "summary": summary,
    }
    if bind_scope_explanation:
        context_evidence["bind_scope_explanation"] = bind_scope_explanation
    return context_evidence


def network_firewall_rule_context_evidence(row: dict[str, Any], data: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    finding_type = str(first_value(row, ["FindingType"], "") or evidence.get("finding_type") or "")
    if finding_type.lower() != "firewallallowssensitiveport":
        return {}

    protocol = listener_protocol(row)
    port = listener_port(row)
    if port is None:
        return {}

    rule_name = str(first_value(row, ["RuleName", "Name"], "") or "").strip()
    rule_display_name = str(first_value(row, ["RuleDisplayName", "DisplayName", "Title"], "") or "").strip()
    matching_rule = matching_firewall_allow_rule(data, rule_name, rule_display_name, protocol, port)
    protocol = str(first_value(row, ["Protocol"], "") or matching_rule.get("Protocol") or protocol or "TCP").upper()
    context = lookup_port_context(protocol, port)
    remote_addresses = first_value(row, ["RemoteAddresses", "RemoteAddress"], "") or matching_rule.get("RemoteAddresses") or matching_rule.get("RemoteAddress") or ""
    local_addresses = first_value(row, ["LocalAddresses", "LocalAddress"], "") or matching_rule.get("LocalAddresses") or matching_rule.get("LocalAddress") or ""
    firewall_profile = str(first_value(row, ["Profile", "Profiles"], "") or matching_rule.get("Profiles") or matching_rule.get("Profile") or "").strip()
    program = str(first_value(row, ["Program", "ApplicationPath"], "") or matching_rule.get("Program") or matching_rule.get("ApplicationPath") or "").strip()
    service_name = str(first_value(row, ["ServiceName", "Service"], "") or matching_rule.get("ServiceName") or matching_rule.get("Service") or "").strip()
    rule_action = str(first_value(row, ["Action"], "") or matching_rule.get("Action") or "Allow").strip()
    rule_enabled = first_value(row, ["Enabled"], matching_rule.get("Enabled", True))
    return {
        "protocol": protocol,
        "port": port,
        "firewall_rule_name": rule_name or str(matching_rule.get("Name") or ""),
        "firewall_rule_display_name": rule_display_name or str(matching_rule.get("DisplayName") or ""),
        "firewall_profile": firewall_profile,
        "firewall_direction": "Inbound",
        "firewall_action": rule_action,
        "firewall_enabled": rule_enabled,
        "local_ports": str(first_value(row, ["LocalPorts", "LocalPort"], "") or matching_rule.get("LocalPorts") or matching_rule.get("LocalPort") or port),
        "local_addresses": local_addresses,
        "remote_addresses": remote_addresses,
        "program": windows_basename(program),
        "service_name": service_name,
        "common_service": context["common_service"],
        "common_name": context["common_name"],
        "exposure_type": context["exposure_type"],
        "risk_explanation": (
            f"An enabled inbound firewall allow rule permits {protocol} {port} ({context['common_name']}). "
            "This is firewall policy evidence only; actual reachability still depends on network routing, profile matching, and allowed source networks."
        ),
        "customer_question": "Which business service owns this firewall allow rule, which profiles and source networks should use it, and is it still required?",
        "safe_next_step": "Validate rule owner, profile scope, remote address restrictions, service dependency, and change approval before disabling or narrowing the rule.",
        "summary": firewall_rule_summary(protocol, port, context, rule_display_name or rule_name, firewall_profile, remote_addresses),
    }


def matching_firewall_allow_rule(data: dict[str, Any], rule_name: str, rule_display_name: str, protocol: str, port: int) -> dict[str, Any]:
    name_lower = str(rule_name or "").lower()
    display_lower = str(rule_display_name or "").lower()
    for rule in as_records(data.get("InboundAllowFirewallRules")) + as_records(data.get("FirewallRules")):
        if name_lower and str(rule.get("Name") or "").lower() == name_lower:
            return rule
        if display_lower and str(rule.get("DisplayName") or "").lower() == display_lower:
            return rule
        if str(rule.get("Protocol") or "").upper() not in {"", protocol.upper(), "ANY"}:
            continue
        ports_text = str(rule.get("LocalPorts") or rule.get("LocalPort") or "")
        if port in firewall_rule_matching_ports(ports_text, [port]):
            return rule
    return {}


def firewall_rule_matching_ports(local_ports: Any, sensitive_ports: list[int]) -> list[int]:
    text = str(local_ports or "").strip()
    if not text or text.lower() in {"any", "rpc", "rpc-epmap", "rpc dynamic ports"}:
        return []
    matches: list[int] = []
    for token in re.split(r"[,;\s]+", text):
        token = token.strip()
        if not token:
            continue
        range_match = re.match(r"^(\d{1,5})-(\d{1,5})$", token)
        if range_match:
            low, high = int(range_match.group(1)), int(range_match.group(2))
            for port in sensitive_ports:
                if low <= port <= high:
                    matches.append(port)
            continue
        if token.isdigit():
            port = int(token)
            if port in sensitive_ports:
                matches.append(port)
    return sorted(set(matches))


def windows_basename(path_value: Any) -> str:
    text = str(path_value or "").strip().strip('"')
    if not text:
        return ""
    try:
        return PureWindowsPath(text).name or text
    except Exception:
        return text.split("\\")[-1]


def firewall_rule_summary(protocol: str, port: int, context: dict[str, str], rule_name: str, profile: str, remote_addresses: Any) -> str:
    rule_text = f" '{rule_name}'" if rule_name else ""
    profile_text = f" on profile {profile}" if profile else ""
    remote_text = f" with remote address scope {remote_addresses}" if remote_addresses else ""
    return (
        f"Inbound firewall allow rule{rule_text} permits {protocol.upper()} {port} ({context['common_name']})"
        f"{profile_text}{remote_text}. Validate owner, profile scope, and allowed sources before changing it."
    )


def listener_protocol(row: dict[str, Any]) -> str:
    value = first_value(row, ["Protocol", "TransportProtocol"], "")
    if value:
        text = str(value).upper()
        return "UDP" if "UDP" in text else "TCP"
    match = re.search(r"\b(TCP|UDP)\b", combined_row_text(row), flags=re.IGNORECASE)
    return match.group(1).upper() if match else "TCP"


def listener_port(row: dict[str, Any]) -> int | None:
    value = first_value(row, ["LocalPort", "Port", "ListeningPort"], None)
    if value not in (None, ""):
        try:
            return int(value)
        except (TypeError, ValueError):
            pass
    text = combined_row_text(row)
    match = re.search(r"\b(?:TCP|UDP)\s+(\d{1,5})\b", text, flags=re.IGNORECASE)
    if not match:
        match = re.search(r"\bport\s+(\d{1,5})\b", text, flags=re.IGNORECASE)
    if match:
        port = int(match.group(1))
        if 0 <= port <= 65535:
            return port
    return None


def matching_listener(data: dict[str, Any], port: int, protocol: str, process: str = "") -> dict[str, Any]:
    candidates = matching_listeners(data, port, protocol, process)
    return candidates[0] if candidates else {}


def matching_listeners(data: dict[str, Any], port: int, protocol: str, process: str = "") -> list[dict[str, Any]]:
    listener_key = "ListeningUdpPorts" if protocol.upper() == "UDP" else "ListeningTcpPorts"
    candidates = []
    for listener in as_records(data.get(listener_key)):
        if as_int(listener.get("LocalPort"), -1) == port:
            candidates.append(listener)
    if process:
        process_matches = [
            listener
            for listener in candidates
            if str(listener.get("ProcessName") or "").lower() == process.lower()
        ]
        if process_matches:
            return process_matches
    return candidates


def listener_bind_addresses(listeners: list[dict[str, Any]]) -> list[str]:
    addresses = []
    for listener in listeners:
        address = str(listener.get("LocalAddress") or listener.get("local_address") or "").strip()
        if address:
            addresses.append(address)
    return addresses


def unique_string_values(values: list[Any]) -> list[str]:
    output = []
    seen = set()
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        output.append(text)
    return output


def bind_scope_for_addresses(addresses: list[str], row_text: str = "") -> str:
    scopes = [bind_scope(address, row_text) for address in addresses if address]
    if "All interfaces" in scopes or "all interfaces" in row_text.lower():
        return "All interfaces"
    if "Specific interface" in scopes:
        return "Specific interface"
    if scopes and all(scope == "Loopback only" for scope in scopes):
        return "Loopback only"
    return bind_scope("", row_text)


def source_endpoint_label(address: str, port: int, process: str) -> str:
    process_text = f" {process}" if process else ""
    return f"{address}:{port}{process_text}"


def process_name(row: dict[str, Any]) -> str:
    value = first_value(row, ["ProcessName", "OwningProcessName"], "")
    if value:
        return str(value)
    match = re.search(r"\bby process\s+([^.]+)", combined_row_text(row), flags=re.IGNORECASE)
    return match.group(1).strip() if match else ""


def bind_scope(address: str, row_text: str = "") -> str:
    text = str(address or "").strip().lower()
    if text in {"0.0.0.0", "::", "[::]", "*", "any"} or "all interfaces" in row_text.lower():
        return "All interfaces"
    if text.startswith("127.") or text == "::1" or text == "localhost":
        return "Loopback only"
    if text:
        return "Specific interface"
    return "Not collected"


def combined_row_text(row: dict[str, Any]) -> str:
    return " ".join(
        str(first_value(row, [key], "") or "")
        for key in ["Evidence", "Name", "Title", "Details", "Recommendation"]
    )


def listening_port_summary(
    protocol: str,
    port: int,
    process: str,
    scope: str,
    bind_address: str,
    context: dict[str, str],
) -> str:
    service_label = context["common_service"]
    if context["common_name"] and context["common_name"] != context["common_service"]:
        service_label = f"{context['common_service']} ({context['common_name']})"
    if scope == "All interfaces":
        listener_text = "listening on all interfaces"
    elif scope == "Loopback only":
        listener_text = "listening on loopback only"
    elif bind_address:
        listener_text = f"listening on {bind_address}"
    else:
        listener_text = "listening"
    process_text = f" by process {process}" if process else ""
    exposure_label = "remote administration exposure" if context["exposure_type"] == "Remote administration service" else context["exposure_type"].lower()
    return (
        f"{protocol.upper()} {port} is commonly used by {service_label}. "
        f"It is {listener_text}{process_text} and should be validated as an approved {exposure_label}."
    )


def normalize_rdp_cache_cleanup(data: dict[str, Any], source_file: Path, key: str) -> list[dict[str, Any]]:
    findings = []
    timestamp = source_timestamp(data)
    scope = CLIENT_FILE_DEFINITIONS[key]["scope"]
    source_script_name = "Clear-RDPUserProfileCache.ps1"
    computer = computer_name(data)
    candidate_files = as_int(data.get("CandidateFiles"), 0)
    candidate_bytes = as_int(data.get("CandidateBytes"), 0)
    failed_files = as_int(data.get("FailedFiles"), 0)
    skipped_profiles = as_int(data.get("SkippedProfileCount"), 0)

    if candidate_files > 0:
        severity = "Low"
        if candidate_bytes >= 10 * 1024 * 1024 * 1024:
            severity = "Medium"
        findings.append(
            build_common_finding(
                finding_id="SERVER-RDP-CACHE-0001",
                title="RDP profile cache cleanup candidates were found",
                category=CATEGORY_BY_KEY[key],
                severity=severity,
                affected_object=computer or "rdp-profile-cache",
                object_type=OBJECT_TYPE_BY_KEY[key],
                source_script_name=source_script_name,
                evidence={
                    "scope": scope,
                    "computer_name": computer,
                    "mode": str(data.get("Mode") or ""),
                    "profile_root": str(data.get("ProfileRoot") or ""),
                    "minimum_age_days": as_int(data.get("MinimumAgeDays"), 0),
                    "candidate_files": candidate_files,
                    "candidate_bytes": candidate_bytes,
                    "skipped_profile_count": skipped_profiles,
                    "source_file": str(source_file),
                },
                risk_factors=["RDP profile cache candidates", f"CandidateFiles={candidate_files}"],
                business_impact="Large RDP profile caches can affect server capacity and user experience.",
                technical_impact="The dry-run cleanup report identified old cache files eligible for owner-approved cleanup.",
                recommendation="Review profile ownership and run cleanup only during an approved maintenance window.",
                timestamp_utc=timestamp,
                safety_reason="RDP profile cleanup can affect active users and must remain review-only until approved.",
            )
        )

    if failed_files > 0:
        findings.append(
            build_common_finding(
                finding_id="SERVER-RDP-CACHE-0002",
                title="RDP profile cache cleanup failures were recorded",
                category=CATEGORY_BY_KEY[key],
                severity="Medium",
                affected_object=computer or "rdp-profile-cache",
                object_type=OBJECT_TYPE_BY_KEY[key],
                source_script_name=source_script_name,
                evidence={
                    "scope": scope,
                    "computer_name": computer,
                    "failed_files": failed_files,
                    "source_file": str(source_file),
                },
                risk_factors=["Cleanup failures"],
                business_impact="Cleanup failures can leave storage pressure unresolved and may indicate permission or file lock issues.",
                technical_impact="The cleanup report recorded files that could not be deleted.",
                recommendation="Review failure samples and schedule a controlled maintenance window before retrying cleanup.",
                timestamp_utc=timestamp,
                safety_reason="Do not force-delete profile files without owner review and active-session validation.",
            )
        )
    return findings


def summarize_source_json(key: str, data: dict[str, Any]) -> dict[str, Any]:
    summary = data.get("Summary")
    if isinstance(summary, dict):
        return summary
    if key == "host_windows_events_summary":
        investigation = as_dict(data.get("InvestigationSummary"))
        return {
            "total_events": data.get("TotalEvents", 0),
            "verdict": investigation.get("Verdict", ""),
            "finding_count": investigation.get("FindingCount", 0),
            "high_count": investigation.get("HighCount", 0),
            "medium_count": investigation.get("MediumCount", 0),
        }
    if key == "server_rdp_profile_cache_cleanup":
        return {
            "mode": data.get("Mode", ""),
            "profile_count": data.get("ProfileCount", 0),
            "skipped_profile_count": data.get("SkippedProfileCount", 0),
            "candidate_files": data.get("CandidateFiles", 0),
            "candidate_bytes": data.get("CandidateBytes", 0),
            "failed_files": data.get("FailedFiles", 0),
        }
    return {
        "generated_at_utc": data.get("GeneratedAtUtc", ""),
        "computer_name": computer_name(data),
    }


def build_environment_summary(
    client_info: dict[str, Any] | None,
    collection_summary: dict[str, Any] | None,
    manifest: dict[str, Any] | None,
    bundle_dir: Path,
    source_label: str,
) -> dict[str, Any]:
    client = client_info or {}
    summary = collection_summary or {}
    manifest_data = manifest or {}
    return {
        "company": "",
        "domain": str(client.get("UserDomain") or ""),
        "computer_name": str(client.get("ComputerName") or manifest_data.get("CollectionId") or ""),
        "user_domain": str(client.get("UserDomain") or ""),
        "os_caption": str(client.get("OsCaption") or ""),
        "os_version": str(client.get("OsVersion") or ""),
        "is_administrator": bool(client.get("IsAdministrator")) if "IsAdministrator" in client else False,
        "collection_id": str(summary.get("CollectionId") or manifest_data.get("CollectionId") or ""),
        "scope_resolved": as_string_list(summary.get("ScopeResolved") or manifest_data.get("ScopeResolved")),
        "safety_mode": str(summary.get("SafetyMode") or manifest_data.get("SafetyMode") or ""),
        "bundle_directory": str(bundle_dir),
        "input": source_label,
    }


def collection_generated_at(collection_summary: dict[str, Any] | None, manifest: dict[str, Any] | None) -> str:
    for source in (collection_summary, manifest):
        if isinstance(source, dict):
            value = source.get("GeneratedAtUtc") or source.get("generated_at_utc")
            if value:
                return str(value)
    return utc_now()


def scope_file_counts(detected_paths: dict[str, Path]) -> dict[str, int]:
    counts = {scope: 0 for scope in ["Client", *SUPPORTED_SCOPES]}
    if "ad_shared" in detected_paths:
        counts["AD"] += 1
    for key in detected_paths:
        definition = CLIENT_FILE_DEFINITIONS.get(key)
        if definition:
            counts[definition["scope"]] += 1
    return counts


def display_path(bundle_dir: Path, path: Path, source_label: str) -> str:
    try:
        relative = path.relative_to(bundle_dir).as_posix()
    except ValueError:
        return str(path)
    if source_label.lower().endswith(".zip"):
        return f"{source_label}!{relative}"
    return str(path)


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_records(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def as_string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    return [str(value)]


def as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def first_value(row: dict[str, Any], keys: list[str], default: Any = "") -> Any:
    lower_map = {key.lower(): key for key in row}
    for key in keys:
        actual = lower_map.get(key.lower())
        if actual is not None and row.get(actual) not in (None, ""):
            return row[actual]
    return default


def compact_evidence(row: dict[str, Any]) -> dict[str, Any]:
    evidence = {}
    for key, value in row.items():
        if value in (None, ""):
            continue
        if isinstance(value, list) and not value:
            continue
        evidence[to_snake_case(key)] = value
    return evidence


def risk_factors(row: dict[str, Any]) -> list[str]:
    factors = []
    for key in [
        "FindingType",
        "Area",
        "RiskLevel",
        "Control",
        "EventLabel",
        "OperationalImpact",
        "Severity",
        "BackupEvidenceSource",
        "BackupEvidenceConfidence",
        "RestoreTestEvidenceStatus",
        "MonitoringEvidenceStatus",
    ]:
        value = first_value(row, [key], "")
        if value:
            factors.append(str(value))
    return list(dict.fromkeys(factors))


def affected_object_for(row: dict[str, Any], data: dict[str, Any], key: str, index: int) -> str:
    value = first_value(
        row,
        [
            "AffectedObject",
            "Path",
            "Principal",
            "TargetUserName",
            "SubjectUserName",
            "Name",
            "ServiceName",
            "ControlId",
            "FindingId",
            "Id",
            "Title",
        ],
        "",
    )
    if value:
        return str(value)
    computer = computer_name(data)
    return computer or f"{key}-{index}"


def source_timestamp(data: dict[str, Any]) -> str:
    metadata = as_dict(data.get("ReportMetadata"))
    return str(data.get("GeneratedAtUtc") or metadata.get("GeneratedAtUtc") or utc_now())


def computer_name(data: dict[str, Any]) -> str:
    metadata = as_dict(data.get("ReportMetadata"))
    return str(data.get("ComputerName") or metadata.get("ComputerName") or "")


def source_script_for(key: str, data: dict[str, Any], source_file: Path) -> str:
    metadata = as_dict(data.get("ReportMetadata"))
    return str(
        metadata.get("ScriptName")
        or data.get("ToolName")
        or data.get("ReportType")
        or DISPLAY_NAME_BY_KEY.get(key)
        or source_file.name
    )


def build_finding_id(prefix: str, source_id: Any, index: int) -> str:
    source_text = sanitize_id(source_id)
    if source_text:
        return f"{prefix}-{source_text}"
    return f"{prefix}-{index:04d}"


def sanitize_id(value: Any) -> str:
    text = str(value or "").strip().upper()
    if not text:
        return ""
    return "".join(char if char.isalnum() else "-" for char in text).strip("-")[:48]


def safety_reason_for(key: str) -> str:
    scope = CLIENT_FILE_DEFINITIONS[key]["scope"]
    if "rdp" in key:
        return "Remote access changes can break administration paths and require explicit owner review and approved change control."
    if "network" in key:
        return "Network exposure and firewall changes can break access paths and require owner review and approved change control."
    if "server_windows_server_security" in key:
        return "Server service, scheduled task, and share permission changes require owner validation and approved change control."
    if "workstation_windows_workstation_security" in key:
        return "Endpoint hardening changes require owner validation and approved change control."
    if "local_admins" in key:
        return "Local administrator membership changes require host owner approval and controlled access validation."
    if "events" in key:
        return "Security event findings are indicators for investigation and are not remediation instructions."
    if "backup" in key:
        return "Backup remediation, restore operations, and backup configuration changes require owner review and approved change control."
    return f"{scope} configuration changes require owner review and approved change control."


def to_snake_case(value: str) -> str:
    output = []
    for index, char in enumerate(str(value)):
        if char.isupper() and index > 0 and output[-1] != "_":
            output.append("_")
        if char in {" ", "-", "."}:
            output.append("_")
        else:
            output.append(char.lower())
    return "".join(output).strip("_")

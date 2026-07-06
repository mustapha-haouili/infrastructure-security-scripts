"""SecureInfra client collection bundle support."""

from __future__ import annotations

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


CLIENT_FILE_DEFINITIONS: dict[str, dict[str, str]] = {
    "client_info": {"scope": "Client", "path": "client-info.json"},
    "collection_summary": {"scope": "Client", "path": "collection-summary.json"},
    "manifest": {"scope": "Client", "path": "manifest.json"},
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
}
SUPPORTED_SCOPES = ["AD", "Host", "Server", "Workstation", "Network", "Backup"]
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
}

# Client bundles are report-only evidence packages. Keep limits conservative
# enough for normal collector output while rejecting archive bombs and non-report
# content before anything is extracted.
MAX_ZIP_ENTRIES = 512
MAX_ZIP_MEMBER_SIZE_BYTES = 25 * 1024 * 1024
ALLOWED_ZIP_EXTENSIONS = {".json", ".csv", ".md", ".txt", ".log"}
ALLOWED_ZIP_ROOT_FILES = {"client-info.json", "collection-summary.json", "manifest.json"}
ALLOWED_ZIP_TOP_LEVEL_DIRS = {"ad-shared", "host", "server", "workstation", "network", "backup", "logs"}


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
    return detected


def missing_client_files(detected_files: dict[str, Path]) -> list[str]:
    missing = [
        definition["path"]
        for key, definition in CLIENT_FILE_DEFINITIONS.items()
        if key not in detected_files and definition["scope"] in SUPPORTED_SCOPES + ["Client"] and definition["scope"] != "Backup"
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

    for metadata_key in ("host_windows_remediation_plan", "host_windows_hardening_preview"):
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
    if key == "host_windows_events_summary":
        rows = as_records(as_dict(data.get("InvestigationSummary")).get("Findings"))
    elif key == "server_rdp_profile_cache_cleanup":
        return normalize_rdp_cache_cleanup(data, source_file, key)
    else:
        rows = as_records(data.get("Findings"))
    return normalize_source_rows(key, data, rows, source_file)


def normalize_source_rows(key: str, data: dict[str, Any], rows: list[dict[str, Any]], source_file: Path) -> list[dict[str, Any]]:
    timestamp = source_timestamp(data)
    scope = CLIENT_FILE_DEFINITIONS[key]["scope"]
    source_script_name = source_script_for(key, data, source_file)
    findings = []
    for index, row in enumerate(rows, start=1):
        severity = normalize_source_severity(first_value(row, ["Severity", "TriageSeverity", "ActionPriority", "ReviewPriority"]))
        source_id = first_value(row, ["Id", "FindingId", "FindingType", "ControlId"], "")
        affected_object = affected_object_for(row, data, key, index)
        evidence = compact_evidence(row)
        if key == "network_windows_network_exposure":
            evidence.update(network_port_context_evidence(row, data, evidence))
        evidence.update(
            {
                "scope": scope,
                "computer_name": computer_name(data),
                "source_file": str(source_file),
            }
        )
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


def network_port_context_evidence(row: dict[str, Any], data: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    finding_type = str(first_value(row, ["FindingType"], "") or evidence.get("finding_type") or "")
    if finding_type.lower() != "riskylisteningport":
        return {}

    protocol = listener_protocol(row)
    port = listener_port(row)
    if port is None:
        return {}

    listener = matching_listener(data, port, protocol, process_name(row))
    process = process_name(row) or str(listener.get("ProcessName") or listener.get("process_name") or "")
    bind_address = str(
        first_value(row, ["LocalAddress", "BindAddress", "ListeningAddress"], "")
        or listener.get("LocalAddress")
        or listener.get("local_address")
        or ""
    ).strip()
    scope = bind_scope(bind_address, combined_row_text(row))
    if not bind_address and scope == "All interfaces":
        bind_address = "0.0.0.0"

    context = lookup_port_context(protocol, port)
    risk_explanation = context["risk_explanation"]
    if scope == "All interfaces":
        risk_explanation = (
            risk_explanation
            + " Listening on all interfaces means the service binds to all local interfaces. Actual reachability depends on firewall rules, routing, segmentation, and allowed source networks."
        )

    summary = listening_port_summary(protocol, port, process, scope, bind_address, context)
    return {
        "protocol": protocol.upper(),
        "port": port,
        "process_name": process,
        "bind_address": bind_address,
        "bind_scope": scope,
        "common_service": context["common_service"],
        "common_name": context["common_name"],
        "exposure_type": context["exposure_type"],
        "risk_explanation": risk_explanation,
        "acceptable_when": context["acceptable_when"],
        "customer_question": context["customer_question"],
        "safe_next_step": context["safe_next_step"],
        "port_context_confidence": context["mapping_confidence"],
        "summary": summary,
    }


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
    listener_key = "ListeningUdpPorts" if protocol.upper() == "UDP" else "ListeningTcpPorts"
    candidates = []
    for listener in as_records(data.get(listener_key)):
        if as_int(listener.get("LocalPort"), -1) == port:
            candidates.append(listener)
    if process:
        for listener in candidates:
            if str(listener.get("ProcessName") or "").lower() == process.lower():
                return listener
    return candidates[0] if candidates else {}


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

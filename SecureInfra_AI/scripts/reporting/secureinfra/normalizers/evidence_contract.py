"""Shared normalized finding evidence contract helpers."""

from __future__ import annotations

import re
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any


SUMMARY_FALLBACK_KEYS = ["summary", "evidence", "description", "message", "reason", "finding"]
DETAIL_KEYS = [
    "finding_type",
    "issue_type",
    "action_priority",
    "change_risk",
    "gpo_name",
    "target_path",
    "admin_action",
    "verification_step",
    "recommendation",
    "protocol",
    "port",
    "process_name",
    "bind_address",
    "listening_address",
    "bind_scope",
    "common_service",
    "common_name",
    "exposure_type",
    "risk_explanation",
    "acceptable_when",
    "customer_question",
    "safe_next_step",
    "port_context_confidence",
    "scope",
    "source_report_type",
    "machine_name",
    "source_script",
    "affected_object",
]
KNOWN_COLLECTION_SEGMENTS = {"ad-shared", "host", "server", "workstation", "network", "backup", "logs"}
UNSAFE_KEYS = {
    "access_key",
    "access_token",
    "api_key",
    "archive_path",
    "bundle_input",
    "credential",
    "credentials",
    "input_path",
    "local_path",
    "password",
    "private_key",
    "raw_zip_path",
    "refresh_token",
    "secret",
    "session_cookie",
    "token",
    "zip_path",
}
UNSAFE_KEY_SUFFIXES = (
    "_access_key",
    "_access_token",
    "_api_key",
    "_credential",
    "_credentials",
    "_password",
    "_private_key",
    "_refresh_token",
    "_secret",
    "_session_cookie",
    "_token",
)
UNSAFE_TEXT_MARKERS = ("downstream-reporting-workspace", "customer-projects")
PATHISH_KEYS = {
    "archive_path",
    "bundle_directory",
    "detected_bundles",
    "detected_files",
    "input",
    "input_directory",
    "loaded_bundles",
    "loaded_files",
    "previous_source_file",
    "raw_zip_path",
    "source_file",
    "source_files",
    "zip_path",
}
WINDOWS_ABSOLUTE_PATH_RE = re.compile(r"\b[A-Za-z]:\\[^\r\n\t\"<>|]+")
SECRET_ASSIGNMENT_RE = re.compile(
    r"\b(api[_-]?key|access[_-]?token|refresh[_-]?token|token|password|secret|credential)\s*[:=]\s*[^;\s,\]\)]+",
    re.IGNORECASE,
)


def normalize_report_evidence_contract(report: dict[str, Any]) -> dict[str, Any]:
    """Apply a consistent evidence contract and redact unsafe local metadata."""
    if not isinstance(report, dict):
        return report

    context = report_context(report)
    findings = report.get("findings")
    if isinstance(findings, list):
        for finding in findings:
            if isinstance(finding, dict):
                normalize_finding_evidence(finding, context)

    sanitized = sanitize_report_value(report)
    if isinstance(sanitized, dict):
        report.clear()
        report.update(sanitized)
    return report


def normalize_finding_evidence(finding: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    evidence = finding.get("evidence")
    if not isinstance(evidence, dict):
        evidence = {}
    evidence = sanitize_mapping(evidence)

    summary, summary_key = evidence_summary(finding, evidence)
    if summary:
        evidence["summary"] = summary

    details, detail_keys = evidence_details(finding, evidence, context or {})
    if details:
        evidence["details"] = details

    if not text_value(evidence.get("confidence")):
        evidence["confidence"] = evidence_confidence(evidence, bool(summary_key))

    key_fields = list_values(evidence.get("key_fields"))
    if summary_key and summary_key != "summary":
        key_fields.append(summary_key)
    key_fields.extend(detail_keys)
    safe_key_fields = unique_values(
        key
        for key in key_fields
        if key and not is_unsafe_key(key) and not contains_unsafe_marker(str(key))
    )
    if safe_key_fields:
        evidence["key_fields"] = safe_key_fields

    finding["evidence"] = evidence
    return evidence


def evidence_summary(finding: dict[str, Any], evidence: dict[str, Any]) -> tuple[str, str]:
    for key in SUMMARY_FALLBACK_KEYS:
        value = text_value(evidence.get(key))
        if value:
            return sanitize_text(value), key

    parts = []
    title = text_value(finding.get("title"))
    affected_object = text_value(finding.get("affected_object"))
    source_script = text_value(finding.get("source_script"))
    if title:
        parts.append(title)
    if affected_object:
        parts.append(f"affected_object: {affected_object}")
    if source_script:
        parts.append(f"source_script: {source_script}")
    return sanitize_text("; ".join(parts)), "finding_context" if parts else ""


def evidence_details(
    finding: dict[str, Any],
    evidence: dict[str, Any],
    context: dict[str, Any],
) -> tuple[str, list[str]]:
    parts = []
    used_keys: list[str] = []
    for key in DETAIL_KEYS:
        value = detail_value(key, finding, evidence, context)
        rendered = render_detail_value(value)
        if not rendered:
            continue
        parts.append(f"{key}: {rendered}")
        used_keys.append(key)
    return "; ".join(parts), used_keys


def detail_value(key: str, finding: dict[str, Any], evidence: dict[str, Any], context: dict[str, Any]) -> Any:
    if key in evidence:
        return evidence.get(key)
    if key == "machine_name":
        return evidence.get("computer_name") or context.get("machine_name")
    if key == "source_report_type":
        return context.get("source_report_type")
    if key == "source_script":
        return finding.get("source_script") or context.get("source_script")
    if key == "affected_object":
        return finding.get("affected_object")
    if key == "recommendation":
        return finding.get("recommendation")
    return None


def evidence_confidence(evidence: dict[str, Any], has_direct_summary: bool) -> str:
    for key, value in evidence.items():
        normalized = normalize_key(key)
        if normalized == "confidence" or normalized.endswith("_confidence"):
            rendered = render_detail_value(value)
            if rendered:
                return rendered
    if evidence.get("source_report_type") or evidence.get("source_script") or has_direct_summary:
        return "Medium"
    return "Low"


def report_context(report: dict[str, Any]) -> dict[str, Any]:
    environment = report.get("environment_summary") if isinstance(report.get("environment_summary"), dict) else {}
    metadata = report.get("metadata") if isinstance(report.get("metadata"), dict) else {}
    return {
        "machine_name": first_text(
            environment.get("machine_name"),
            environment.get("computer_name"),
            environment.get("source_host"),
            metadata.get("machine_name"),
        ),
        "source_report_type": first_text(
            environment.get("source_report_type"),
            metadata.get("source_report_type"),
            report.get("report_type"),
        ),
        "source_script": first_text(environment.get("source_script"), metadata.get("source_script")),
    }


def sanitize_report_value(value: Any, pathish: bool = False) -> Any:
    if isinstance(value, dict):
        return sanitize_mapping(value, pathish=pathish)
    if isinstance(value, list):
        return [sanitize_report_value(item, pathish=pathish) for item in value]
    if isinstance(value, str):
        if pathish:
            return sanitize_pathish_text(value)
        return sanitize_text(value)
    return value


def sanitize_mapping(data: dict[str, Any], pathish: bool = False) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    for key, value in data.items():
        if is_unsafe_key(key):
            continue
        sanitized[key] = sanitize_report_value(value, pathish=pathish or is_pathish_key(key))
    return sanitized


def sanitize_text(value: str) -> str:
    text = str(value)
    text = SECRET_ASSIGNMENT_RE.sub(lambda match: f"{match.group(1)}=[redacted]", text)
    text = WINDOWS_ABSOLUTE_PATH_RE.sub(lambda match: safe_windows_path_label(match.group(0)), text)
    if contains_unsafe_marker(text):
        return "[redacted internal path]"
    return text


def sanitize_pathish_text(value: str) -> str:
    text = str(value)
    if contains_unsafe_marker(text):
        return "[redacted internal path]"
    if WINDOWS_ABSOLUTE_PATH_RE.search(text):
        return WINDOWS_ABSOLUTE_PATH_RE.sub(lambda match: safe_windows_path_label(match.group(0)), text)
    if text.startswith("/"):
        return safe_posix_path_label(text)
    return sanitize_text(text)


def safe_windows_path_label(value: str) -> str:
    path_text = value.strip().rstrip(".,;)]}")
    trailing = value[len(path_text) :]
    if contains_unsafe_marker(path_text):
        return "[redacted internal path]" + trailing

    path_part, separator, member_part = path_text.partition("!")
    label = windows_relative_label(path_part)
    if separator:
        member = sanitize_archive_member(member_part)
        if member:
            label = f"{label}!{member}"
    if label.lower().endswith(".zip") and not label.lower().startswith("secureinfra-client-collection"):
        label = "[redacted bundle file]"
    return label + trailing


def safe_posix_path_label(value: str) -> str:
    path_text = value.strip().rstrip(".,;)]}")
    trailing = value[len(path_text) :]
    if contains_unsafe_marker(path_text):
        return "[redacted internal path]" + trailing

    path_part, separator, member_part = path_text.partition("!")
    label = posix_relative_label(path_part)
    if separator:
        member = sanitize_archive_member(member_part)
        if member:
            label = f"{label}!{member}"
    if label.lower().endswith(".zip") and not label.lower().startswith("secureinfra-client-collection"):
        label = "[redacted bundle file]"
    return label + trailing


def windows_relative_label(path_text: str) -> str:
    path = PureWindowsPath(path_text)
    parts = list(path.parts)
    lowered = [part.lower() for part in parts]
    for index, part in enumerate(lowered):
        if part in KNOWN_COLLECTION_SEGMENTS:
            return "/".join(parts[index:]).replace("\\", "/")
    name = path.name
    return name or "[redacted local path]"


def posix_relative_label(path_text: str) -> str:
    path = PurePosixPath(path_text)
    parts = [part for part in path.parts if part != "/"]
    lowered = [part.lower() for part in parts]
    for index, part in enumerate(lowered):
        if part in KNOWN_COLLECTION_SEGMENTS:
            return "/".join(parts[index:])
    name = path.name
    return name or "[redacted local path]"


def sanitize_archive_member(value: str) -> str:
    member = value.replace("\\", "/").strip("/")
    parts = [part for part in member.split("/") if part and part not in {".", ".."}]
    safe_parts = [part for part in parts if not contains_unsafe_marker(part)]
    return "/".join(safe_parts)


def render_detail_value(value: Any) -> str:
    value = sanitize_report_value(value)
    if value in (None, ""):
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        rendered = [render_detail_value(item) for item in value]
        return ", ".join(item for item in rendered if item)
    if isinstance(value, dict):
        rendered = []
        for key, item in value.items():
            if is_unsafe_key(key):
                continue
            item_text = render_detail_value(item)
            if item_text:
                rendered.append(f"{key}={item_text}")
        return ", ".join(rendered)
    return str(value).strip()


def text_value(value: Any) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float, bool)):
        return str(value)
    return ""


def first_text(*values: Any) -> str:
    for value in values:
        rendered = text_value(value)
        if rendered:
            return sanitize_text(rendered)
    return ""


def list_values(value: Any) -> list[str]:
    if value in (None, ""):
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    return [str(value)]


def unique_values(values: Any) -> list[str]:
    output = []
    seen = set()
    for value in values:
        text = str(value).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        output.append(text)
    return output


def normalize_key(key: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(key).lower()).strip("_")


def is_unsafe_key(key: Any) -> bool:
    normalized = normalize_key(key)
    return normalized in UNSAFE_KEYS or normalized.endswith(UNSAFE_KEY_SUFFIXES)


def is_pathish_key(key: Any) -> bool:
    return normalize_key(key) in PATHISH_KEYS


def contains_unsafe_marker(value: str) -> bool:
    lowered = str(value).lower()
    return any(marker in lowered for marker in UNSAFE_TEXT_MARKERS)

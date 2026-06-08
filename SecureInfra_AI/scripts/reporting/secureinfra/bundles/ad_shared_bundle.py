"""Active Directory shared report bundle support."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from secureinfra.loaders.json_loader import load_json_file
from secureinfra.normalizers.ad_inactive_users import normalize_ad_inactive_users, severity_counts, utc_now


KNOWN_AD_SHARED_FILES = {
    "inactive_users": "inactive-users.json",
    "password_never_expires": "password-never-expires.json",
    "service_accounts": "service-accounts.json",
    "spn_exposure": "spn-exposure.json",
    "stale_computers": "stale-computers.json",
    "privileged_groups": "privileged-groups.json",
    "privileged_identity_protection": "privileged-identity-protection.json",
    "gpo_health": "gpo-health.json",
}

IMPLEMENTED_NORMALIZERS = {"inactive_users"}


def discover_ad_shared_bundle(input_dir: str | Path) -> dict[str, Path]:
    """Return known AD shared report files that exist in an input directory."""
    bundle_dir = Path(input_dir)
    if not bundle_dir.exists():
        raise FileNotFoundError(f"AD shared input directory not found: {bundle_dir}")
    if not bundle_dir.is_dir():
        raise ValueError(f"AD shared input must be a directory: {bundle_dir}")

    return {
        key: candidate
        for key, filename in KNOWN_AD_SHARED_FILES.items()
        if (candidate := bundle_dir / filename).is_file()
    }


def missing_ad_shared_files(detected_files: dict[str, Path]) -> list[str]:
    return [filename for key, filename in KNOWN_AD_SHARED_FILES.items() if key not in detected_files]


def summary_from_loaded_json(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    summary = data.get("Summary") or data.get("summary")
    return summary if isinstance(summary, dict) else {}


def normalize_ad_shared_bundle(input_dir: str | Path) -> dict[str, Any]:
    """Normalize an AD shared report directory.

    Phase 1.5 only converts inactive-users.json into detailed findings. Other
    known JSON files are loaded safely and listed for future normalizer support.
    """
    bundle_dir = Path(input_dir)
    detected_paths = discover_ad_shared_bundle(bundle_dir)
    missing_files = missing_ad_shared_files(detected_paths)
    loaded_files: dict[str, str] = {}
    loaded_summaries: dict[str, dict[str, Any]] = {}
    notes: list[str] = [
        "Only report types with implemented normalizers are converted into detailed findings. Other detected files are loaded and listed for future normalizer support.",
        "Human owner review and approved change control are required before remediation.",
    ]
    findings: list[dict[str, Any]] = []
    environment_summary: dict[str, Any] = {
        "bundle_directory": str(bundle_dir),
        "implemented_normalizers": sorted(IMPLEMENTED_NORMALIZERS),
    }
    generated_at_utc = utc_now()

    for key, path in detected_paths.items():
        data = load_json_file(path)
        loaded_files[key] = str(path)
        loaded_summaries[key] = summary_from_loaded_json(data)

        if key == "inactive_users":
            inactive_report = normalize_ad_inactive_users(data, source_file=path)
            findings.extend(inactive_report["findings"])
            generated_at_utc = inactive_report.get("generated_at_utc", generated_at_utc)
            environment_summary.update(
                {
                    "company": inactive_report.get("environment_summary", {}).get("company", ""),
                    "domain": inactive_report.get("environment_summary", {}).get("domain", ""),
                }
            )
            notes.append("inactive-users.json was normalized into detailed findings.")
        else:
            notes.append(f"File detected and loaded: {path.name}. Detailed normalizer is not implemented yet.")

    if "inactive_users" not in detected_paths:
        notes.append("inactive-users.json was not found, so no detailed AD inactive user findings were generated.")

    detected_files = {key: str(path) for key, path in detected_paths.items()}
    counts = severity_counts(findings)
    return {
        "report_id": f"secureinfra-ai-ad-shared-{generated_at_utc.replace(':', '').replace('-', '')}",
        "report_type": "ad-shared",
        "tool_name": "SecureInfra AI AD Shared Bundle Analyzer",
        "source_files": list(loaded_files.values()),
        "generated_at_utc": generated_at_utc,
        "environment_summary": environment_summary,
        "summary": {
            "total_findings": len(findings),
            "normalized_finding_count": len(findings),
            "severity_counts": counts,
            "detected_file_count": len(detected_files),
            "loaded_file_count": len(loaded_files),
            "missing_optional_file_count": len(missing_files),
        },
        "report_type_metadata": {
            "report_type": "ad-shared",
            "known_files": KNOWN_AD_SHARED_FILES,
            "implemented_normalizers": sorted(IMPLEMENTED_NORMALIZERS),
            "detected_files": detected_files,
            "missing_files": missing_files,
            "loaded_files": loaded_files,
            "loaded_summaries": loaded_summaries,
        },
        "findings": findings,
        "metadata": {
            "normalizer": "ad_shared_bundle",
            "normalizer_version": "0.1.0",
            "risk_engine": "deterministic-rules",
            "ai_required": False,
            "detected_files": detected_files,
            "missing_files": missing_files,
            "loaded_files": loaded_files,
            "loaded_summaries": loaded_summaries,
            "normalized_finding_count": len(findings),
        },
        "notes": notes,
    }

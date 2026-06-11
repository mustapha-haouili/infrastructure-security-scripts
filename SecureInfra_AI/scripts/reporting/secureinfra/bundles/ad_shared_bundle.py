"""Active Directory shared report bundle support."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from secureinfra.loaders.json_loader import load_json_file
from secureinfra.normalizers.ad_common import severity_counts, utc_now
from secureinfra.normalizers.ad_inactive_users import normalize_ad_inactive_users
from secureinfra.normalizers.ad_password_never_expires import normalize_password_never_expires
from secureinfra.normalizers.ad_privileged_groups import normalize_privileged_groups
from secureinfra.normalizers.ad_privileged_identity import normalize_privileged_identity
from secureinfra.normalizers.ad_service_accounts import normalize_service_accounts
from secureinfra.normalizers.ad_spn_exposure import normalize_spn_exposure
from secureinfra.normalizers.ad_stale_computers import normalize_stale_computers
from secureinfra.normalizers.gpo_health import normalize_gpo_health


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

NORMALIZERS = {
    "inactive_users": normalize_ad_inactive_users,
    "password_never_expires": normalize_password_never_expires,
    "service_accounts": normalize_service_accounts,
    "spn_exposure": normalize_spn_exposure,
    "stale_computers": normalize_stale_computers,
    "privileged_groups": normalize_privileged_groups,
    "privileged_identity_protection": normalize_privileged_identity,
    "gpo_health": normalize_gpo_health,
}
IMPLEMENTED_NORMALIZERS = set(NORMALIZERS)


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

    Known AD/GPO report types are converted into detailed findings. Missing
    optional files are reported for visibility and do not stop analysis.
    """
    bundle_dir = Path(input_dir)
    detected_paths = discover_ad_shared_bundle(bundle_dir)
    missing_files = missing_ad_shared_files(detected_paths)
    loaded_files: dict[str, str] = {}
    loaded_summaries: dict[str, dict[str, Any]] = {}
    notes: list[str] = [
        "Detected AD/GPO report types with implemented normalizers are converted into detailed findings.",
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

        if key in NORMALIZERS:
            normalized_report = NORMALIZERS[key](data, source_file=path)
            findings.extend(normalized_report["findings"])
            generated_at_utc = normalized_report.get("generated_at_utc", generated_at_utc)
            environment_summary.update(
                {
                    "company": normalized_report.get("environment_summary", {}).get("company", environment_summary.get("company", "")),
                    "domain": normalized_report.get("environment_summary", {}).get("domain", environment_summary.get("domain", "")),
                }
            )
            notes.append(f"{path.name} was normalized into detailed findings.")
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

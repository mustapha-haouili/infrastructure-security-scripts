#!/usr/bin/env python3
"""
Analyze JSON audit results and generate SecureInfra AI Markdown reports.

Supported report types are normalized with deterministic rules and do not
require AI.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from secureinfra.bundles.ad_shared_bundle import KNOWN_AD_SHARED_FILES, normalize_ad_shared_bundle
from secureinfra.bundles.client_bundle import normalize_client_bundle
from secureinfra.bundles.multi_bundle import normalize_multi_bundle
from secureinfra.control_mapping import add_control_mappings
from secureinfra.correlation.correlator import add_correlations
from secureinfra.history.comparison import add_history_comparison
from secureinfra.loaders.json_loader import load_json_file
from secureinfra.normalizers.ad_inactive_users import normalize_ad_inactive_users
from secureinfra.normalizers.ad_password_never_expires import normalize_password_never_expires
from secureinfra.normalizers.ad_privileged_groups import normalize_privileged_groups
from secureinfra.normalizers.ad_privileged_identity import normalize_privileged_identity
from secureinfra.normalizers.ad_service_accounts import normalize_service_accounts
from secureinfra.normalizers.ad_spn_exposure import normalize_spn_exposure
from secureinfra.normalizers.ad_stale_computers import normalize_stale_computers
from secureinfra.normalizers.gpo_health import normalize_gpo_health
from secureinfra.normalizers.windows_host import normalize_windows_host_audit
from secureinfra.normalizers.windows_network import normalize_windows_network_exposure
from secureinfra.normalizers.windows_server import normalize_windows_server_audit
from secureinfra.normalizers.windows_workstation import normalize_windows_workstation_audit
from secureinfra.report_generator.markdown_report import generate_markdown_reports
from secureinfra.validators.schema_validator import validate_normalized_report


NORMALIZER_BY_TYPE = {
    "ad-inactive-users": normalize_ad_inactive_users,
    "ad-password-never-expires": normalize_password_never_expires,
    "ad-privileged-groups": normalize_privileged_groups,
    "ad-privileged-identity": normalize_privileged_identity,
    "ad-service-accounts": normalize_service_accounts,
    "ad-spn-exposure": normalize_spn_exposure,
    "ad-stale-computers": normalize_stale_computers,
    "gpo-health": normalize_gpo_health,
    "windows-host-audit": normalize_windows_host_audit,
    "windows-server-audit": normalize_windows_server_audit,
    "windows-workstation-audit": normalize_windows_workstation_audit,
    "windows-network-exposure": normalize_windows_network_exposure,
}
SUPPORTED_TYPES = set(NORMALIZER_BY_TYPE) | {"ad-shared", "client-bundle", "multi-bundle"}
SUPPORTED_LANGUAGES = {"en"}
FUTURE_LANGUAGES = {"de"}
SUPPORTED_FORMATS = {"markdown"}


def default_output_dir() -> Path:
    secureinfra_ai_root = Path(__file__).resolve().parents[2]
    return secureinfra_ai_root / "reports"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Normalize JSON audit output and generate SecureInfra AI reports.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s --input SecureInfra_AI/examples/sample-input/active-directory/sample-ad-inactive-users.json --type ad-inactive-users --output SecureInfra_AI/reports
  %(prog)s --input reports/ad-shared --type ad-shared --output reports/output --language en --format markdown
  %(prog)s --input reports/secureinfra-client-collection-CLIENT-20260619-120000 --type ad-shared --output reports/output
  %(prog)s --input reports/secureinfra-client-collection-CLIENT-20260619-120000 --type client-bundle --output reports/client-output
  %(prog)s --input reports/secureinfra-client-collection-CLIENT-20260619-120000.zip --type client-bundle --output reports/client-output
  %(prog)s --input reports/client-bundles --type multi-bundle --output reports/fleet-output
  %(prog)s --input reports/ad-shared --type ad-shared --output reports/output --previous-normalized-report reports/previous/normalized-report.json
  %(prog)s --input reports/ad-shared/service-accounts.json --type ad-service-accounts --output reports/output
  %(prog)s --input reports/ad-shared/gpo-health.json --type gpo-health --output reports/output
  %(prog)s --input reports/windows-security-audit.json --type windows-host-audit --output reports/output
  %(prog)s --input reports/windows-server-security.json --type windows-server-audit --output reports/output
  %(prog)s --input reports/windows-workstation-security.json --type windows-workstation-audit --output reports/output
  %(prog)s --input reports/windows-network-exposure.json --type windows-network-exposure --output reports/output
  %(prog)s --input report.json --type ad-inactive-users --language en --format markdown
""",
    )
    parser.add_argument("--input", required=True, help="JSON audit result file or supported report directory to analyze")
    parser.add_argument("--type", required=True, choices=sorted(SUPPORTED_TYPES), help="Input report type")
    parser.add_argument("--output", default=str(default_output_dir()), help="Output directory for generated reports")
    parser.add_argument("--language", default="en", help="Report language. Phase 1 supports: en")
    parser.add_argument("--format", default="markdown", help="Report format. Phase 1 supports: markdown")
    parser.add_argument(
        "--previous-normalized-report",
        help="Optional previous normalized-report.json to compare against the current run.",
    )
    return parser.parse_args(argv)


def validate_args(args: argparse.Namespace) -> None:
    if args.language in FUTURE_LANGUAGES:
        raise ValueError(f"Language '{args.language}' is reserved for future support and is not implemented yet.")
    if args.language not in SUPPORTED_LANGUAGES:
        raise ValueError(f"Unsupported language: {args.language}")
    if args.format not in SUPPORTED_FORMATS:
        raise ValueError(f"Unsupported format: {args.format}")


def validate_input_path(input_path: Path, report_type: str) -> None:
    if report_type in NORMALIZER_BY_TYPE:
        if not input_path.exists():
            raise FileNotFoundError(f"Input JSON file not found: {input_path}")
        if not input_path.is_file():
            raise ValueError(f"--type {report_type} requires --input to be a JSON file")
    elif report_type == "ad-shared":
        if not input_path.exists():
            raise FileNotFoundError(f"AD shared input directory not found: {input_path}")
        if not input_path.is_dir():
            raise ValueError("--type ad-shared requires --input to be a directory")
    elif report_type == "client-bundle":
        if not input_path.exists():
            raise FileNotFoundError(f"Client bundle input not found: {input_path}")
        if not input_path.is_dir() and input_path.suffix.lower() != ".zip":
            raise ValueError("--type client-bundle requires --input to be a collection directory or .zip archive")
    elif report_type == "multi-bundle":
        if not input_path.exists():
            raise FileNotFoundError(f"Multi-bundle input directory not found: {input_path}")
        if not input_path.is_dir():
            raise ValueError("--type multi-bundle requires --input to be a directory containing client bundle folders or .zip archives")


def validate_previous_report_path(previous_report_path: Path) -> None:
    if not previous_report_path.exists():
        raise FileNotFoundError(f"Previous normalized report not found: {previous_report_path}")
    if not previous_report_path.is_file():
        raise ValueError("--previous-normalized-report must point to a JSON file")


def has_known_ad_shared_files(input_dir: Path) -> bool:
    return any((input_dir / filename).is_file() for filename in KNOWN_AD_SHARED_FILES.values())


def resolve_ad_shared_input_path(input_path: Path) -> Path:
    """Accept either an ad-shared directory or a client collection root."""
    if has_known_ad_shared_files(input_path):
        return input_path

    nested_ad_shared = input_path / "ad-shared"
    if nested_ad_shared.is_dir() and has_known_ad_shared_files(nested_ad_shared):
        return nested_ad_shared

    return input_path


def analyze(args: argparse.Namespace) -> tuple[dict, list[Path]]:
    validate_args(args)
    input_path = Path(args.input)
    output_dir = Path(args.output)
    previous_report_path = Path(args.previous_normalized_report) if args.previous_normalized_report else None
    validate_input_path(input_path, args.type)
    if previous_report_path:
        validate_previous_report_path(previous_report_path)

    if args.type in NORMALIZER_BY_TYPE:
        data = load_json_file(input_path)
        normalized_report = NORMALIZER_BY_TYPE[args.type](data, source_file=input_path)
    elif args.type == "ad-shared":
        normalized_report = normalize_ad_shared_bundle(resolve_ad_shared_input_path(input_path))
    elif args.type == "client-bundle":
        normalized_report = normalize_client_bundle(input_path)
    elif args.type == "multi-bundle":
        normalized_report = normalize_multi_bundle(input_path)
    else:
        raise ValueError(f"Unsupported report type: {args.type}")

    normalized_report = add_correlations(normalized_report)
    if previous_report_path:
        previous_report = load_json_file(previous_report_path)
        normalized_report = add_history_comparison(normalized_report, previous_report, previous_report_path)
    normalized_report = add_control_mappings(normalized_report)
    validate_normalized_report(normalized_report)
    output_dir.mkdir(parents=True, exist_ok=True)
    normalized_path = output_dir / "normalized-report.json"
    normalized_path.write_text(json.dumps(normalized_report, indent=2) + "\n", encoding="utf-8")
    report_paths = generate_markdown_reports(normalized_report, output_dir, language=args.language)
    return normalized_report, [normalized_path, *report_paths]


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        normalized_report, output_paths = analyze(args)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"Normalized findings: {len(normalized_report.get('findings', []))}")
    for path in output_paths:
        print(f"Wrote: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

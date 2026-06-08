#!/usr/bin/env python3
"""
Analyze JSON audit results and generate SecureInfra AI Markdown reports.

Phase 1 supports Active Directory inactive user reports. Risk classification is
deterministic and does not require AI.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from secureinfra.bundles.ad_shared_bundle import normalize_ad_shared_bundle
from secureinfra.loaders.json_loader import load_json_file
from secureinfra.normalizers.ad_inactive_users import normalize_ad_inactive_users
from secureinfra.report_generator.markdown_report import generate_markdown_reports


SUPPORTED_TYPES = {"ad-inactive-users", "ad-shared"}
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
  %(prog)s --input report.json --type ad-inactive-users --language en --format markdown
""",
    )
    parser.add_argument("--input", required=True, help="JSON audit result file to analyze")
    parser.add_argument("--type", required=True, choices=sorted(SUPPORTED_TYPES), help="Input report type")
    parser.add_argument("--output", default=str(default_output_dir()), help="Output directory for generated reports")
    parser.add_argument("--language", default="en", help="Report language. Phase 1 supports: en")
    parser.add_argument("--format", default="markdown", help="Report format. Phase 1 supports: markdown")
    return parser.parse_args(argv)


def validate_args(args: argparse.Namespace) -> None:
    if args.language in FUTURE_LANGUAGES:
        raise ValueError(f"Language '{args.language}' is reserved for future support and is not implemented yet.")
    if args.language not in SUPPORTED_LANGUAGES:
        raise ValueError(f"Unsupported language: {args.language}")
    if args.format not in SUPPORTED_FORMATS:
        raise ValueError(f"Unsupported format: {args.format}")


def validate_input_path(input_path: Path, report_type: str) -> None:
    if report_type == "ad-inactive-users":
        if not input_path.exists():
            raise FileNotFoundError(f"Input JSON file not found: {input_path}")
        if not input_path.is_file():
            raise ValueError("--type ad-inactive-users requires --input to be a JSON file")
    elif report_type == "ad-shared":
        if not input_path.exists():
            raise FileNotFoundError(f"AD shared input directory not found: {input_path}")
        if not input_path.is_dir():
            raise ValueError("--type ad-shared requires --input to be a directory")


def analyze(args: argparse.Namespace) -> tuple[dict, list[Path]]:
    validate_args(args)
    input_path = Path(args.input)
    output_dir = Path(args.output)
    validate_input_path(input_path, args.type)

    if args.type == "ad-inactive-users":
        data = load_json_file(input_path)
        normalized_report = normalize_ad_inactive_users(data, source_file=input_path)
    elif args.type == "ad-shared":
        normalized_report = normalize_ad_shared_bundle(input_path)
    else:
        raise ValueError(f"Unsupported report type: {args.type}")

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

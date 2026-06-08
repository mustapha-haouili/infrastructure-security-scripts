#!/usr/bin/env python3
"""
Generate a Markdown report from one or more JSON audit result files.

The parser accepts schema-aligned reports with a top-level "findings" array and
also handles existing script outputs that use names such as "Findings",
"Results", "ReviewPriority", or "ActionPriority".

Examples:
  python3 scripts/reporting/generate-markdown-report.py examples/sample-output/windows/windows-host-audit.example.json
  python3 scripts/reporting/generate-markdown-report.py reports/audit.json reports/gpo.json --output reports/summary.md
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any


SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational", "Unknown"]

SEVERITY_ALIASES = {
    "critical": "Critical",
    "crit": "Critical",
    "high": "High",
    "medium": "Medium",
    "moderate": "Medium",
    "med": "Medium",
    "low": "Low",
    "info": "Informational",
    "informational": "Informational",
    "none": "Informational",
    "ok": "Informational",
    "hold": "Informational",
}

PRIORITY_ALIASES = {
    "urgent": "P1",
    "immediate": "P1",
    "critical": "P1",
    "high": "P1",
    "medium": "P2",
    "moderate": "P2",
    "low": "P3",
    "info": "P4",
    "informational": "P4",
}

FINDING_HINT_KEYS = {
    "actionpriority",
    "adminaction",
    "category",
    "controlid",
    "description",
    "evidence",
    "exposurepriority",
    "finding_id",
    "findingid",
    "findingtype",
    "recommendation",
    "recommendedaction",
    "reviewpriority",
    "severity",
    "technical_details",
    "title",
}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a Markdown report from JSON audit result files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s examples/sample-output/windows/windows-host-audit.example.json
      Generate a report under reports/.
  %(prog)s reports/windows.json reports/gpo.json --output reports/assessment-summary.md
      Combine multiple JSON result files into one Markdown report.
  %(prog)s reports/audit.json --title "Example GmbH Infrastructure Security Review"
      Use a custom report title.
""",
    )
    parser.add_argument("json_files", nargs="+", help="One or more JSON audit result files")
    parser.add_argument("--output", help="Markdown output path. Default: reports/assessment-report-TIMESTAMP.md")
    parser.add_argument("--title", default="Infrastructure Security Assessment Report", help="Report title")
    return parser.parse_args(argv)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def first_value(item: dict[str, Any], names: list[str]) -> Any:
    lower_map = {key.lower(): key for key in item}
    for name in names:
        key = lower_map.get(name.lower())
        if key is not None:
            value = item.get(key)
            if value not in (None, ""):
                return value
    return None


def normalize_severity(value: Any) -> str:
    if value is None:
        return "Unknown"
    raw = str(value).strip()
    if not raw:
        return "Unknown"
    normalized = SEVERITY_ALIASES.get(raw.lower())
    if normalized:
        return normalized
    if raw.upper() == "P1":
        return "High"
    if raw.upper() == "P2":
        return "Medium"
    if raw.upper() == "P3":
        return "Low"
    if raw.upper() == "P4":
        return "Informational"
    return raw[:1].upper() + raw[1:].lower()


def normalize_priority(value: Any) -> str:
    if value is None:
        return "Not Assigned"
    raw = str(value).strip()
    if not raw:
        return "Not Assigned"
    upper = raw.upper()
    if upper in {"P1", "P2", "P3", "P4"}:
        return upper
    return PRIORITY_ALIASES.get(raw.lower(), raw)


def as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float, bool)):
        return str(value)
    return json.dumps(value, ensure_ascii=True, sort_keys=True)


def markdown_inline(value: Any) -> str:
    text = as_text(value).replace("\r", " ").replace("\n", " ").strip()
    return text.replace("|", "\\|")


def is_finding_like(item: Any) -> bool:
    if not isinstance(item, dict):
        return False
    keys = {key.lower().replace("-", "_") for key in item}
    compact_keys = {key.replace("_", "") for key in keys}
    return bool((keys | compact_keys) & FINDING_HINT_KEYS)


def normalize_finding(item: dict[str, Any], source: Path, context: str) -> dict[str, str]:
    finding_id = first_value(
        item,
        [
            "finding_id",
            "FindingId",
            "FindingID",
            "Id",
            "ID",
            "ControlId",
            "control_id",
            "Rule",
            "rule",
        ],
    )
    title = first_value(
        item,
        [
            "title",
            "Title",
            "Finding",
            "FindingType",
            "Name",
            "DisplayName",
            "ControlId",
            "SamAccountName",
            "ComputerName",
        ],
    )
    severity_value = first_value(
        item,
        ["severity", "Severity", "RiskLevel", "risk_level", "ReviewPriority", "ActionPriority", "ExposurePriority"],
    )
    priority_value = first_value(
        item,
        ["remediation_priority", "RemediationPriority", "Priority", "ActionPriority", "ReviewPriority", "ExposurePriority"],
    )

    return {
        "finding_id": as_text(finding_id) or f"{source.stem}:{context}",
        "title": as_text(title) or f"{context} finding",
        "category": as_text(first_value(item, ["category", "Category", "FindingCategory", "RiskCategory", "AccountCategory", "ComputerCategory"]))
        or context,
        "severity": normalize_severity(severity_value),
        "affected_object": as_text(
            first_value(
                item,
                [
                    "affected_object",
                    "AffectedObject",
                    "Object",
                    "Target",
                    "ComputerName",
                    "Hostname",
                    "Host",
                    "Name",
                    "SamAccountName",
                    "DistinguishedName",
                    "GroupName",
                    "ControlId",
                    "Path",
                    "file",
                ],
            )
        ),
        "description": as_text(first_value(item, ["description", "Description", "FindingDescription", "FindingDetails", "Details", "Message"])),
        "technical_details": as_text(
            first_value(item, ["technical_details", "TechnicalDetails", "TechnicalDetail", "Detail", "Evidence", "evidence", "RiskFlagsText", "ReviewReasonsText"])
        ),
        "business_impact": as_text(first_value(item, ["business_impact", "BusinessImpact", "OperationalImpact", "Impact"])),
        "recommendation": as_text(
            first_value(
                item,
                [
                    "recommendation",
                    "Recommendation",
                    "RecommendedAction",
                    "AdminAction",
                    "SuggestedRemediation",
                    "NextReviewStep",
                    "DeletionGuidance",
                    "CleanupGuidance",
                ],
            )
        ),
        "remediation_priority": normalize_priority(priority_value),
        "remediation_status": as_text(first_value(item, ["remediation_status", "RemediationStatus", "Status", "State"])) or "Open",
        "evidence": as_text(first_value(item, ["evidence", "Evidence", "EvidenceText", "RiskFlags", "ReviewReasons"])),
        "timestamp": as_text(first_value(item, ["timestamp", "Timestamp", "GeneratedAtUtc", "TimeCreated", "LastLogonDateUtc"])),
        "source": str(source),
        "context": context,
    }


def extract_findings(data: Any, source: Path, context: str = "root") -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []

    if isinstance(data, list):
        finding_items = [item for item in data if is_finding_like(item)]
        if finding_items:
            return [normalize_finding(item, source, context) for item in finding_items]
        for index, value in enumerate(data):
            findings.extend(extract_findings(value, source, f"{context}[{index}]"))
        return findings

    if isinstance(data, dict):
        for key, value in data.items():
            child_context = str(key)
            if isinstance(value, list) and any(is_finding_like(item) for item in value):
                findings.extend(normalize_finding(item, source, child_context) for item in value if is_finding_like(item))
            else:
                findings.extend(extract_findings(value, source, child_context))

    return findings


def severity_counts(findings: list[dict[str, str]]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for item in findings:
        severity = item.get("severity") or "Unknown"
        counts[severity if severity in SEVERITY_ORDER else "Unknown"] += 1
    return counts


def render_markdown_report(title: str, source_files: list[Path], findings: list[dict[str, str]], generated_at: str) -> str:
    counts = severity_counts(findings)
    lines: list[str] = [
        f"# {title}",
        "",
        f"Generated at UTC: {generated_at}",
        "",
        "## Sources",
        "",
    ]

    for path in source_files:
        lines.append(f"- `{path}`")

    lines.extend(
        [
            "",
            "## Executive Summary",
            "",
            f"Reviewed {len(source_files)} JSON input file(s) and extracted {len(findings)} finding-like record(s).",
            "",
        ]
    )

    if findings:
        high_count = counts["Critical"] + counts["High"]
        lines.append(f"{high_count} item(s) are Critical or High priority and should be reviewed first.")
    else:
        lines.append("No finding-like records were detected in the supplied JSON input.")

    lines.extend(
        [
            "",
            "## Findings By Severity",
            "",
            "| Severity | Count |",
            "|---|---:|",
        ]
    )
    for severity in SEVERITY_ORDER:
        lines.append(f"| {severity} | {counts[severity]} |")

    if not findings:
        lines.append("")
        return "\n".join(lines)

    grouped: dict[str, list[dict[str, str]]] = {severity: [] for severity in SEVERITY_ORDER}
    for item in findings:
        severity = item.get("severity") if item.get("severity") in SEVERITY_ORDER else "Unknown"
        grouped[severity].append(item)

    lines.extend(["", "## Technical Findings", ""])
    for severity in SEVERITY_ORDER:
        items = grouped[severity]
        if not items:
            continue
        lines.extend([f"### {severity}", ""])
        for index, item in enumerate(items, start=1):
            heading_id = markdown_inline(item.get("finding_id")) or f"{severity}-{index}"
            heading_title = markdown_inline(item.get("title")) or "Untitled finding"
            lines.extend(
                [
                    f"#### {heading_id} - {heading_title}",
                    "",
                    f"- Source: `{markdown_inline(item.get('source'))}`",
                    f"- Category: {markdown_inline(item.get('category')) or 'Not specified'}",
                    f"- Affected object: {markdown_inline(item.get('affected_object')) or 'Not specified'}",
                    f"- Priority: {markdown_inline(item.get('remediation_priority')) or 'Not Assigned'}",
                    f"- Status: {markdown_inline(item.get('remediation_status')) or 'Open'}",
                ]
            )
            for label, key in [
                ("Description", "description"),
                ("Technical details", "technical_details"),
                ("Business impact", "business_impact"),
                ("Recommendation", "recommendation"),
                ("Evidence", "evidence"),
            ]:
                value = markdown_inline(item.get(key))
                if value:
                    lines.append(f"- {label}: {value}")
            lines.append("")

    return "\n".join(lines)


def default_output_path() -> Path:
    timestamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    return Path("reports") / f"assessment-report-{timestamp}.md"


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    source_files = [Path(raw_path) for raw_path in args.json_files]
    findings: list[dict[str, str]] = []

    try:
        for path in source_files:
            if not path.exists():
                raise FileNotFoundError(f"Input file not found: {path}")
            findings.extend(extract_findings(load_json(path), path))
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    generated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    report = render_markdown_report(args.title, source_files, findings, generated_at)
    output_path = Path(args.output) if args.output else default_output_path()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report + "\n", encoding="utf-8")
    print(f"Wrote Markdown report: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

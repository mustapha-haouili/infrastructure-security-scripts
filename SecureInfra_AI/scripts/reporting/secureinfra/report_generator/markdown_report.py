"""Generate Markdown reports from normalized SecureInfra AI reports."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from secureinfra.risk_engine.rules import SEVERITY_ORDER, SEVERITY_RANK


def md(value: Any) -> str:
    text = str(value or "").replace("\r", " ").replace("\n", " ").strip()
    return text.replace("|", "\\|")


def severity_count(report: dict[str, Any], severity: str) -> int:
    return int(report.get("summary", {}).get("severity_counts", {}).get(severity, 0))


def sorted_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        findings,
        key=lambda item: (
            SEVERITY_RANK.get(str(item.get("severity")), 99),
            str(item.get("finding_id", "")),
        ),
    )


def findings_by_severity(report: dict[str, Any], severity: str) -> list[dict[str, Any]]:
    return [item for item in report.get("findings", []) if item.get("severity") == severity]


def bullet_list(items: list[str]) -> list[str]:
    if not items:
        return ["- None identified."]
    return [f"- {item}" for item in items]


def bundle_metadata(report: dict[str, Any]) -> dict[str, Any]:
    report_type_metadata = report.get("report_type_metadata")
    if isinstance(report_type_metadata, dict):
        return report_type_metadata
    metadata = report.get("metadata")
    return metadata if isinstance(metadata, dict) else {}


def render_file_list(file_map: dict[str, Any]) -> list[str]:
    if not file_map:
        return ["- None identified."]
    return [f"- {md(key)}: `{md(value)}`" for key, value in sorted(file_map.items())]


def render_executive_summary(report: dict[str, Any], language: str = "en") -> str:
    findings = sorted_findings(report.get("findings", []))
    top_risks = [item for item in findings if item.get("severity") != "Hold"][:5]
    env = report.get("environment_summary", {})
    critical_high = severity_count(report, "Critical") + severity_count(report, "High")
    report_type = str(report.get("report_type") or bundle_metadata(report).get("report_type") or "")
    shared_metadata = bundle_metadata(report)

    lines = [
        "# Executive Summary",
        "",
        f"Generated at UTC: {md(report.get('generated_at_utc'))}",
        f"Tool: {md(report.get('tool_name'))}",
        f"Company: {md(env.get('company')) or 'Not provided'}",
        f"Domain: `{md(env.get('domain')) or 'Not provided'}`",
        "",
        "## Overall Risk Summary",
        "",
    ]
    if critical_high:
        lines.append(
            f"The analysis identified {critical_high} Critical or High finding(s) that should be reviewed first by human owners."
        )
    else:
        lines.append("No Critical or High findings were identified in the supplied evidence.")

    if report_type == "ad-shared":
        detected_files = shared_metadata.get("detected_files", {})
        loaded_files = shared_metadata.get("loaded_files", {})
        missing_files = shared_metadata.get("missing_files", [])
        normalized_count = report.get("summary", {}).get("normalized_finding_count", len(findings))
        lines.extend(
            [
                "",
                "## Detected AD Report Files",
                "",
                *render_file_list(detected_files if isinstance(detected_files, dict) else {}),
                "",
                "## Loaded AD Report Files",
                "",
                *render_file_list(loaded_files if isinstance(loaded_files, dict) else {}),
                "",
                "## Missing Optional Files",
                "",
            ]
        )
        if isinstance(missing_files, list) and missing_files:
            lines.extend(f"- {md(item)}" for item in missing_files)
        else:
            lines.append("- None identified.")
        lines.extend(
            [
                "",
                "## Normalized Finding Count",
                "",
                f"{normalized_count} finding(s) were converted into detailed normalized findings.",
            ]
        )

    lines.extend(
        [
            "",
            "## Number Of Findings",
            "",
            "| Severity | Count |",
            "|---|---:|",
        ]
    )
    for severity in SEVERITY_ORDER:
        lines.append(f"| {severity} | {severity_count(report, severity)} |")

    lines.extend(["", "## Top 5 Risks", ""])
    if top_risks:
        for index, item in enumerate(top_risks, start=1):
            lines.append(f"{index}. {md(item.get('title'))}: `{md(item.get('affected_object'))}`.")
    else:
        lines.append("No non-hold risks were identified.")

    business_impacts = []
    for item in top_risks:
        impact = md(item.get("business_impact"))
        if impact and impact not in business_impacts:
            business_impacts.append(impact)

    lines.extend(["", "## Business Impact", ""])
    lines.extend(bullet_list(business_impacts[:5]))

    first_actions = [
        "Review Critical findings with identity, application, and system owners.",
        "Confirm privileged access requirements before changing privileged accounts.",
        "Validate SPN-bearing and service account dependencies before remediation.",
        "Keep Hold items out of normal cleanup until product owners approve action.",
        "Use approved change control before disabling, rotating, moving, or deleting accounts.",
    ]
    lines.extend(["", "## Recommended First Actions", ""])
    lines.extend(bullet_list(first_actions))

    if report_type == "ad-shared":
        lines.extend(
            [
                "",
                "## Limitations",
                "",
                "- Only report types with implemented normalizers are converted into detailed findings. Other detected files are loaded and listed for future normalizer support.",
                "- Current detailed normalization is limited to `inactive-users.json`.",
                "- Missing optional files are reported for visibility and do not stop analysis.",
            ]
        )
    lines.append("")
    return "\n".join(lines)


def render_technical_findings(report: dict[str, Any], language: str = "en") -> str:
    lines = [
        "# Technical Findings",
        "",
        f"Generated at UTC: {md(report.get('generated_at_utc'))}",
        "",
    ]
    findings = sorted_findings(report.get("findings", []))
    if not findings:
        lines.append("No findings were identified.")
        lines.append("")
        return "\n".join(lines)

    for item in findings:
        evidence = item.get("evidence", {}) if isinstance(item.get("evidence"), dict) else {}
        risk_factors = item.get("risk_factors", []) if isinstance(item.get("risk_factors"), list) else []
        lines.extend(
            [
                f"## {md(item.get('finding_id'))} - {md(item.get('title'))}",
                "",
                f"- Finding ID: `{md(item.get('finding_id'))}`",
                f"- Title: {md(item.get('title'))}",
                f"- Severity: {md(item.get('severity'))}",
                f"- Affected object: `{md(item.get('affected_object'))}`",
                f"- Object type: {md(item.get('object_type'))}",
                f"- Source script: `{md(item.get('source_script'))}`",
                f"- Remediation priority: {md(item.get('remediation_priority'))}",
                f"- Requires owner review: {item.get('requires_owner_review')}",
                f"- Requires change approval: {item.get('requires_change_approval')}",
                f"- Safe to auto-remediate: {item.get('safe_to_auto_remediate')}",
                "",
                "### Evidence",
                "",
            ]
        )
        for key in sorted(evidence):
            value = evidence[key]
            if isinstance(value, list):
                rendered = ", ".join(md(part) for part in value) or "None"
            else:
                rendered = md(value)
            lines.append(f"- {md(key)}: {rendered}")

        lines.extend(["", "### Risk Factors", ""])
        lines.extend(bullet_list([md(value) for value in risk_factors]))
        lines.extend(
            [
                "",
                "### Technical Impact",
                "",
                md(item.get("technical_impact")) or "Not provided.",
                "",
                "### Recommendation",
                "",
                md(item.get("recommendation")) or "Not provided.",
                "",
                "### Safety Notes",
                "",
                f"- {md(item.get('not_safe_for_auto_remediation_reason'))}",
                "",
            ]
        )

    return "\n".join(lines)


def render_remediation_plan(report: dict[str, Any], language: str = "en") -> str:
    findings = sorted_findings(report.get("findings", []))
    immediate = [item for item in findings if item.get("remediation_priority") == "Immediate Review"]
    high = [item for item in findings if item.get("remediation_priority") == "High Priority"]
    planned = [item for item in findings if item.get("remediation_priority") == "Planned Remediation"]
    owner_review = [item for item in findings if item.get("requires_owner_review")]
    not_auto = [item for item in findings if not item.get("safe_to_auto_remediate")]
    hold = [item for item in findings if item.get("severity") == "Hold" or item.get("remediation_priority") == "Hold"]

    def action_lines(items: list[dict[str, Any]]) -> list[str]:
        if not items:
            return ["- None identified."]
        return [
            f"- `{md(item.get('affected_object'))}` ({md(item.get('severity'))}): {md(item.get('recommendation'))}"
            for item in items
        ]

    lines = [
        "# Remediation Plan",
        "",
        "This plan is advisory. Human approval is required before remediation.",
        "",
        "## Immediate Review Items",
        "",
        *action_lines(immediate),
        "",
        "## High Priority Actions",
        "",
        *action_lines(high),
        "",
        "## Planned Remediation",
        "",
        *action_lines(planned),
        "",
        "## Items Requiring Owner Approval",
        "",
        *action_lines(owner_review),
        "",
        "## Items Not Safe For Auto-Remediation",
        "",
        *action_lines(not_auto),
        "",
        "## Items On Hold",
        "",
        *action_lines(hold),
        "",
    ]
    return "\n".join(lines)


def generate_markdown_reports(normalized_report: dict[str, Any], output_dir: str | Path, language: str = "en") -> list[Path]:
    if language != "en":
        raise ValueError("Phase 1 Markdown generation supports only language=en")

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    reports = {
        "executive-summary.md": render_executive_summary(normalized_report, language),
        "technical-findings.md": render_technical_findings(normalized_report, language),
        "remediation-plan.md": render_remediation_plan(normalized_report, language),
    }
    written: list[Path] = []
    for file_name, content in reports.items():
        path = output_path / file_name
        path.write_text(content, encoding="utf-8")
        written.append(path)
    return written

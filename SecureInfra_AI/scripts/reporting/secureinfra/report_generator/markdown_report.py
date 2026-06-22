"""Generate Markdown reports from normalized SecureInfra AI reports."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from secureinfra.risk_engine.rules import SEVERITY_ORDER, SEVERITY_RANK


WINDOWS_STANDALONE_REPORT_TYPES = {
    "windows-host-audit",
    "windows-server-audit",
    "windows-workstation-audit",
    "windows-network-exposure",
}


def md(value: Any) -> str:
    text = "" if value is None else str(value)
    text = text.replace("\r", " ").replace("\n", " ").strip()
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
    elif report_type == "client-bundle":
        detected_files = shared_metadata.get("detected_files", {})
        loaded_files = shared_metadata.get("loaded_files", {})
        missing_files = shared_metadata.get("missing_files", [])
        failed_files = shared_metadata.get("failed_files", {})
        scope_counts = report.get("summary", {}).get("scope_finding_counts", {})
        normalized_count = report.get("summary", {}).get("normalized_finding_count", len(findings))
        lines.extend(
            [
                "",
                "## Client Bundle Coverage",
                "",
                f"Collection ID: `{md(env.get('collection_id')) or 'Not provided'}`",
                f"Computer: `{md(env.get('computer_name')) or 'Not provided'}`",
                f"Scopes: `{md(', '.join(env.get('scope_resolved', [])) if isinstance(env.get('scope_resolved'), list) else env.get('scope_resolved')) or 'Not provided'}`",
                "",
                "## Findings By Scope",
                "",
                "| Scope | Count |",
                "|---|---:|",
            ]
        )
        if isinstance(scope_counts, dict):
            for scope, count in sorted(scope_counts.items()):
                lines.append(f"| {md(scope)} | {md(count)} |")
        else:
            lines.append("| Not provided | 0 |")
        lines.extend(
            [
                "",
                "## Loaded Client Files",
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
        lines.extend(["", "## Failed Files", ""])
        if isinstance(failed_files, dict) and failed_files:
            lines.extend(render_file_list(failed_files))
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
    elif report_type == "multi-bundle":
        machine_inventory = shared_metadata.get("machine_inventory", [])
        coverage_matrix = shared_metadata.get("coverage_matrix", [])
        failed_bundles = shared_metadata.get("failed_bundles", [])
        skipped_bundles = shared_metadata.get("skipped_bundles", [])
        scope_counts = report.get("summary", {}).get("scope_finding_counts", {})
        top_machines = report.get("summary", {}).get("top_risky_machines", [])
        lines.extend(
            [
                "",
                "## Fleet Collection Coverage",
                "",
                f"Input directory: `{md(env.get('input_directory')) or 'Not provided'}`",
                f"Detected bundles: {md(report.get('summary', {}).get('detected_bundle_count', 0))}",
                f"Loaded bundles: {md(report.get('summary', {}).get('loaded_bundle_count', 0))}",
                f"Skipped duplicate bundles: {md(report.get('summary', {}).get('skipped_bundle_count', 0))}",
                f"Failed bundles: {md(report.get('summary', {}).get('failed_bundle_count', 0))}",
                f"Machine count: {md(report.get('summary', {}).get('machine_count', 0))}",
                f"Coverage status: {md(env.get('coverage_status')) or 'Not provided'}",
                "",
                "## Findings By Scope",
                "",
                "| Scope | Count |",
                "|---|---:|",
            ]
        )
        if isinstance(scope_counts, dict):
            for scope, count in sorted(scope_counts.items()):
                lines.append(f"| {md(scope)} | {md(count)} |")
        else:
            lines.append("| Not provided | 0 |")

        lines.extend(["", "## Machines", "", "| Machine | Findings | Critical | High | Coverage |", "|---|---:|---:|---:|---|"])
        if isinstance(machine_inventory, list) and machine_inventory:
            for machine in machine_inventory[:25]:
                if not isinstance(machine, dict):
                    continue
                machine_counts = machine.get("severity_counts", {}) if isinstance(machine.get("severity_counts"), dict) else {}
                lines.append(
                    "| "
                    f"{md(machine.get('machine_name'))} | "
                    f"{md(machine.get('finding_count', 0))} | "
                    f"{md(machine_counts.get('Critical', 0))} | "
                    f"{md(machine_counts.get('High', 0))} | "
                    f"{md(machine.get('coverage_status'))} |"
                )
        else:
            lines.append("| None identified | 0 | 0 | 0 | Not provided |")

        lines.extend(["", "## Top Risky Machines", ""])
        if isinstance(top_machines, list) and top_machines:
            for item in top_machines[:10]:
                if isinstance(item, dict):
                    lines.append(
                        f"- `{md(item.get('machine_name'))}`: score {md(item.get('risk_score'))}, "
                        f"{md(item.get('critical'))} Critical, {md(item.get('high'))} High, "
                        f"{md(item.get('finding_count'))} total finding(s)."
                    )
        else:
            lines.append("- None identified.")

        lines.extend(["", "## Skipped Duplicate Bundles", ""])
        if isinstance(skipped_bundles, list) and skipped_bundles:
            for item in skipped_bundles:
                if isinstance(item, dict):
                    lines.append(f"- `{md(item.get('input'))}`: {md(item.get('reason'))}")
        else:
            lines.append("- None identified.")

        lines.extend(["", "## Failed Bundles", ""])
        if isinstance(failed_bundles, list) and failed_bundles:
            for item in failed_bundles:
                if isinstance(item, dict):
                    lines.append(f"- `{md(item.get('input'))}`: {md(item.get('error'))}")
        else:
            lines.append("- None identified.")

        if isinstance(coverage_matrix, list) and coverage_matrix:
            missing_rows = [
                row
                for row in coverage_matrix
                if isinstance(row, dict) and (row.get("status") in {"Needs rerun", "Failed"} or row.get("required_missing"))
            ]
            lines.extend(["", "## Coverage Items Requiring Attention", ""])
            if missing_rows:
                for row in missing_rows[:25]:
                    missing = row.get("required_missing") if isinstance(row.get("required_missing"), list) else []
                    detail = ", ".join(md(item) for item in missing) if missing else md(row.get("status"))
                    lines.append(f"- `{md(row.get('machine_name'))}` {md(row.get('scope'))}: {detail}")
            else:
                lines.append("- None identified.")
    elif report_type in WINDOWS_STANDALONE_REPORT_TYPES:
        source_summary = shared_metadata.get("source_summary", {})
        lines.extend(
            [
                "",
                "## Windows Scope Coverage",
                "",
                f"Analyzer type: `{md(report_type)}`",
                f"Beta status: `{md(shared_metadata.get('normalizer_status')) or 'beta'}`",
                f"Computer: `{md(env.get('computer_name')) or 'Not provided'}`",
                f"Scope: `{md(env.get('scope')) or 'Not provided'}`",
                f"Source script: `{md(env.get('source_script')) or 'Not provided'}`",
                f"Source report type: `{md(env.get('source_report_type')) or 'Not provided'}`",
                "",
                "## Source Summary",
                "",
            ]
        )
        if isinstance(source_summary, dict) and source_summary:
            lines.extend(render_file_list(source_summary))
        else:
            lines.append("- None identified.")

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

    correlations = report.get("correlations", [])
    if isinstance(correlations, list):
        lines.extend(["", "## Related Finding Groups", ""])
        if correlations:
            for item in correlations[:5]:
                lines.append(
                    f"- {md(item.get('correlation_id'))}: {md(item.get('key'))} links {md(item.get('finding_count'))} finding(s)."
                )
        else:
            lines.append("- None identified.")

    history = report.get("history_comparison")
    if isinstance(history, dict):
        lines.extend(
            [
                "",
                "## Historical Comparison",
                "",
                f"- Previous report: `{md(history.get('previous_report_id'))}`",
                f"- Previous file: `{md(history.get('previous_source_file')) or 'Not provided'}`",
                f"- New findings: {md(history.get('new_count'))}",
                f"- Persistent findings: {md(history.get('persistent_count'))}",
                f"- Resolved findings: {md(history.get('resolved_count'))}",
            ]
        )
        resolved = history.get("resolved_findings", [])
        if isinstance(resolved, list) and resolved:
            lines.extend(["", "Resolved since previous run:"])
            for item in resolved[:5]:
                if isinstance(item, dict):
                    lines.append(
                        f"- `{md(item.get('finding_id'))}` ({md(item.get('severity'))}): {md(item.get('title'))}"
                    )

    business_impacts = []
    for item in top_risks:
        impact = md(item.get("business_impact"))
        if impact and impact not in business_impacts:
            business_impacts.append(impact)

    lines.extend(["", "## Business Impact", ""])
    lines.extend(bullet_list(business_impacts[:5]))

    if report_type in WINDOWS_STANDALONE_REPORT_TYPES:
        first_actions = [
            "Review Critical and High Windows findings with the host or service owner.",
            "Confirm business need and access paths before changing firewall, remote access, service, or endpoint settings.",
            "Validate monitoring and rollback expectations before approved remediation.",
            "Use approved change control before changing local administrators, services, shares, encryption, logging, or network exposure.",
        ]
    else:
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
                "- Only known AD/GPO JSON report shapes with implemented normalizers are converted into detailed findings.",
                "- Current detailed normalization covers AD inactive users, password-never-expires accounts, service accounts, SPN exposure, stale computers, privileged groups, privileged identity protection, and GPO health.",
                "- Missing optional files are reported for visibility and do not stop analysis.",
            ]
        )
    elif report_type == "client-bundle":
        lines.extend(
            [
                "",
                "## Limitations",
                "",
                "- Current detailed client-bundle normalization covers AD/GPO, Windows host audit findings, event summary findings, local administrator findings, RDP exposure findings, RDP cache cleanup review items, server security inventory, workstation security inventory, and network exposure findings.",
                "- Remediation plans and hardening previews are loaded for coverage visibility and are not counted again as findings.",
                "- Missing optional scope files are reported for visibility and do not stop analysis.",
            ]
        )
    elif report_type == "multi-bundle":
        lines.extend(
            [
                "",
                "## Limitations",
                "",
                "- Current fleet analysis aggregates client-bundle outputs; unsupported source files remain visible as coverage gaps until normalizers are added.",
                "- If the same AD collection is included in many host bundles, those AD findings can appear once per bundle and should be collected once per domain for clean fleet counts.",
                "- Missing or failed scope files are reported per machine and do not stop analysis of other bundles.",
            ]
        )
    elif report_type in WINDOWS_STANDALONE_REPORT_TYPES:
        lines.extend(
            [
                "",
                "## Limitations",
                "",
                "- This beta standalone analyzer normalizes one supported Windows JSON report at a time.",
                "- It is report-only and does not change Windows configuration.",
                "- Findings are derived from the source report's existing Findings array and require human review before remediation.",
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

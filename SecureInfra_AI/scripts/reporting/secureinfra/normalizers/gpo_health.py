"""Normalize Group Policy health reports."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from secureinfra.normalizers.ad_common import (
    base_normalized_report,
    build_common_finding,
    generated_at_utc,
    normalize_source_severity,
    row_identifier,
    source_script,
)


def build_evidence(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "finding_type": str(row.get("FindingType") or ""),
        "action_priority": str(row.get("ActionPriority") or ""),
        "gpo_id": str(row.get("GpoId") or ""),
        "gpo_name": str(row.get("GpoName") or row.get("DisplayName") or ""),
        "target_path": str(row.get("TargetPath") or ""),
        "title": str(row.get("Title") or ""),
        "evidence": str(row.get("Evidence") or ""),
        "admin_action": str(row.get("AdminAction") or ""),
        "change_risk": str(row.get("ChangeRisk") or ""),
        "verification_step": str(row.get("VerificationStep") or ""),
        "recommendation": str(row.get("Recommendation") or ""),
    }


def risk_factors_for(row: dict[str, Any]) -> list[str]:
    factors = []
    for key in ["FindingType", "ChangeRisk", "ActionPriority"]:
        value = str(row.get(key) or "").strip()
        if value:
            factors.append(value)
    return factors


def normalize_gpo_health(data: dict[str, Any], source_file: str | Path) -> dict[str, Any]:
    rows = data.get("Findings")
    if not isinstance(rows, list):
        raise ValueError("GPO health report must contain a Findings list")

    timestamp_utc = generated_at_utc(data)
    script_name = source_script(data, "Get-ADGPOHealthReport.ps1")
    findings = []
    for index, row in enumerate(rows, start=1):
        severity = normalize_source_severity(row.get("Severity") or row.get("ActionPriority"))
        affected_object = row_identifier(row, f"gpo-health-finding-{index}")
        findings.append(
            build_common_finding(
                finding_id=f"GPO-HEALTH-{index:04d}",
                title=str(row.get("Title") or "GPO health finding requires review"),
                category="Group Policy Health",
                severity=severity,
                affected_object=affected_object,
                object_type="Group Policy Object",
                source_script_name=script_name,
                evidence=build_evidence(row),
                risk_factors=risk_factors_for(row),
                business_impact="GPO health issues can affect policy reliability, baseline coverage, and administrative confidence in endpoint configuration.",
                technical_impact="The source report identified GPO, link, permission, inheritance, or SYSVOL consistency evidence that needs administrator review.",
                recommendation=str(row.get("Recommendation") or row.get("AdminAction") or "Review the GPO owner, scope, backup, and staged test plan before making changes."),
                timestamp_utc=timestamp_utc,
                safety_reason="GPO changes require owner review, backup or export, staged testing, and approved change control.",
            )
        )

    return base_normalized_report(
        report_type="gpo-health",
        tool_name="SecureInfra AI GPO Health Analyzer",
        source_file=source_file,
        data=data,
        findings=findings,
        source_script_name=script_name,
        input_count=len(rows),
        normalizer_name="gpo_health",
    )

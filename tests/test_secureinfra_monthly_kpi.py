import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SECUREINFRA_REPORTING = ROOT / "SecureInfra_AI" / "scripts" / "reporting"
SAMPLE_INPUT = ROOT / "SecureInfra_AI" / "examples" / "sample-input" / "active-directory" / "sample-ad-inactive-users.json"
MONTHLY_KPI_PATH = SECUREINFRA_REPORTING / "secureinfra" / "history" / "monthly_kpi.py"

sys.path.insert(0, str(SECUREINFRA_REPORTING))

from secureinfra.history.monthly_kpi import add_monthly_kpi_summary, build_monthly_kpi_summary


ANALYZER_PATH = SECUREINFRA_REPORTING / "secureinfra_analyzer.py"
spec = importlib.util.spec_from_file_location("secureinfra_monthly_kpi_analyzer", ANALYZER_PATH)
secureinfra_analyzer = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = secureinfra_analyzer
spec.loader.exec_module(secureinfra_analyzer)


def finding(
    finding_id: str,
    severity: str,
    title: str,
    category: str = "Fictional Security Review",
    affected_object: str = "EXAMPLE-SRV01",
    source_script: str = "ExampleDefensiveAudit.ps1",
    recommendation: str = "Review this fictional finding with the owner.",
    evidence: dict | None = None,
) -> dict:
    return {
        "finding_id": finding_id,
        "title": title,
        "category": category,
        "severity": severity,
        "affected_object": affected_object,
        "object_type": "Fictional object",
        "source_script": source_script,
        "evidence": evidence or {"computer_name": "EXAMPLE-SRV01", "source_report_type": "fictional-report"},
        "risk_factors": [],
        "business_impact": "Fictional impact for monthly trend testing.",
        "technical_impact": "Fictional evidence for deterministic trend testing.",
        "recommendation": recommendation,
        "remediation_priority": "High Priority" if severity in {"Critical", "High"} else "Planned Remediation",
        "requires_owner_review": True,
        "requires_change_approval": severity in {"Critical", "High", "Medium"},
        "safe_to_auto_remediate": False,
        "not_safe_for_auto_remediation_reason": "Owner review is required for this fictional test finding.",
        "status": "Open",
        "timestamp_utc": "2026-06-01T00:00:00Z",
    }


def report(findings: list[dict], report_id: str = "secureinfra-ai-test-current", metadata: dict | None = None) -> dict:
    counts = {severity: 0 for severity in ["Critical", "High", "Medium", "Low", "Info", "Hold"]}
    for item in findings:
        counts[item["severity"]] += 1
    return {
        "report_id": report_id,
        "tool_name": "SecureInfra AI Fictional Test Analyzer",
        "report_type": "fictional-normalized-report",
        "source_files": ["reports/example-normalized-report.json"],
        "generated_at_utc": "2026-06-30T00:00:00Z",
        "environment_summary": {
            "company": "",
            "domain": "example.local",
            "computer_name": "EXAMPLE-SRV01",
        },
        "summary": {
            "total_findings": len(findings),
            "normalized_finding_count": len(findings),
            "severity_counts": counts,
        },
        "findings": findings,
        "metadata": metadata or {"normalizer": "fictional_test"},
        "notes": ["Fictional normalized report for monthly KPI tests."],
    }


class SecureInfraMonthlyKpiTests(unittest.TestCase):
    def test_baseline_monthly_summary_without_previous_report(self):
        current = report(
            [
                finding("FIND-CRIT-001", "Critical", "Privileged access requires review"),
                finding("FIND-HIGH-001", "High", "Firewall exposure requires review"),
            ]
        )

        summary = build_monthly_kpi_summary(current)

        self.assertEqual(summary["comparison_mode"], "baseline")
        self.assertEqual(summary["total_findings"], 2)
        self.assertEqual(summary["critical_count"], 1)
        self.assertEqual(summary["high_count"], 1)
        self.assertEqual(summary["new_findings"], [])
        self.assertEqual(summary["persistent_findings"], [])
        self.assertEqual(summary["resolved_findings"], [])
        self.assertEqual(summary["risk_reduction_score"], 0)
        self.assertTrue(any("No previous normalized report" in item for item in summary["limitations"]))

    def test_comparison_tracks_new_persistent_resolved_and_score(self):
        previous = report(
            [
                finding("FIND-CRIT-001", "Critical", "Privileged access requires review", affected_object="alex.admin"),
                finding("FIND-RDP-001", "High", "RDP exposure requires review", affected_object="EXAMPLE-SRV01"),
                finding(
                    "OLD-COMP-ID",
                    "Medium",
                    "Stale computer account requires lifecycle review",
                    category="Active Directory Security",
                    affected_object="EXAMPLE-OLD01",
                    source_script="Get-ADStaleComputerReport.ps1",
                ),
            ],
            report_id="secureinfra-ai-test-previous",
        )
        current = report(
            [
                finding("FIND-CRIT-001", "Critical", "Privileged access requires review", affected_object="alex.admin"),
                finding("FIND-FW-NEW", "High", "Firewall exposure requires review", affected_object="EXAMPLE-SRV02"),
                finding(
                    "NEW-COMP-ID",
                    "Medium",
                    "Stale computer account requires lifecycle review",
                    category="Active Directory Security",
                    affected_object="EXAMPLE-OLD01",
                    source_script="Get-ADStaleComputerReport.ps1",
                ),
                finding("FIND-LOW-001", "Low", "Low priority configuration review"),
            ]
        )

        summary = build_monthly_kpi_summary(current, previous, "reports/previous/normalized-report.json")

        self.assertEqual(summary["comparison_mode"], "comparison")
        self.assertEqual({item["finding_id"] for item in summary["new_findings"]}, {"FIND-FW-NEW", "FIND-LOW-001"})
        self.assertEqual({item["finding_id"] for item in summary["resolved_findings"]}, {"FIND-RDP-001"})
        persistent_by_id = {item["finding_id"]: item for item in summary["persistent_findings"]}
        self.assertIn("FIND-CRIT-001", persistent_by_id)
        self.assertEqual(persistent_by_id["FIND-CRIT-001"]["matched_on"], "finding_id")
        self.assertIn("NEW-COMP-ID", persistent_by_id)
        self.assertEqual(persistent_by_id["NEW-COMP-ID"]["matched_on"], "fallback_fingerprint")
        self.assertEqual(summary["matching_summary"]["matched_by_finding_id"], 1)
        self.assertEqual(summary["matching_summary"]["matched_by_fallback_fingerprint"], 1)
        self.assertEqual(summary["risk_reduction_score"], -10)
        self.assertEqual(summary["risk_reduction_score_components"]["resolved_critical_high_points"], 10)
        self.assertEqual(summary["risk_reduction_score_components"]["new_critical_high_points"], -10)
        self.assertEqual(summary["risk_reduction_score_components"]["persistent_critical_high_points"], -10)

    def test_coverage_summary_groups_expected_dimensions(self):
        current = report(
            [
                finding(
                    "FIND-001",
                    "High",
                    "Server finding",
                    source_script="Invoke-WindowsSecurityAudit.ps1",
                    evidence={"computer_name": "EXAMPLE-SRV01", "source_report_type": "windows-host-audit"},
                ),
                finding(
                    "FIND-002",
                    "Medium",
                    "Network finding",
                    source_script="Get-WindowsNetworkExposureAudit.ps1",
                    evidence={"machine_name": "EXAMPLE-SRV02", "source_report_type": "windows-network-exposure"},
                ),
            ],
            metadata={"normalizer": "client_bundle"},
        )

        summary = build_monthly_kpi_summary(current)
        coverage = summary["coverage_summary"]

        self.assertIn({"source_script": "Invoke-WindowsSecurityAudit.ps1", "finding_count": 1}, coverage["by_source_script"])
        self.assertIn({"report_type": "windows-network-exposure", "finding_count": 1}, coverage["by_report_type"])
        self.assertEqual(coverage["by_analyzer_type"], [{"analyzer_type": "client_bundle", "finding_count": 2}])
        self.assertIn({"source_host": "EXAMPLE-SRV02", "finding_count": 1}, coverage["by_source_host"])

    def test_evidence_gaps_include_missing_failed_and_coverage_items(self):
        current = report(
            [finding("FIND-001", "High", "Coverage-sensitive finding")],
            metadata={
                "normalizer": "client_bundle",
                "missing_files": ["ad-shared/gpo-health.json"],
                "failed_files": {"host/windows-events/summary.json": "JSON root is not an object"},
                "coverage_matrix": [
                    {
                        "machine_name": "EXAMPLE-SRV01",
                        "scope": "Server",
                        "status": "Needs rerun",
                        "required_missing": ["server/windows-server-security.json"],
                    }
                ],
            },
        )

        summary = build_monthly_kpi_summary(current)
        gaps = "\n".join(summary["evidence_gaps"])

        self.assertIn("Missing optional evidence file: ad-shared/gpo-health.json", gaps)
        self.assertIn("Failed evidence file: host/windows-events/summary.json", gaps)
        self.assertIn("Coverage gap for EXAMPLE-SRV01 Server", gaps)

    def test_add_monthly_kpi_summary_updates_report_summary(self):
        current = report([finding("FIND-001", "High", "Monthly test finding")])

        add_monthly_kpi_summary(current)

        self.assertIn("monthly_kpi_summary", current)
        self.assertEqual(current["summary"]["monthly_risk_reduction_score"], 0)

    def test_cli_monthly_summary_generates_normalized_and_markdown_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            with contextlib.redirect_stdout(io.StringIO()):
                exit_code = secureinfra_analyzer.main(
                    [
                        "--input",
                        str(SAMPLE_INPUT),
                        "--type",
                        "ad-inactive-users",
                        "--output",
                        str(output_dir),
                        "--monthly-summary",
                    ]
                )

            self.assertEqual(exit_code, 0)
            normalized = json.loads((output_dir / "normalized-report.json").read_text(encoding="utf-8"))
            self.assertIn("monthly_kpi_summary", normalized)
            self.assertTrue((output_dir / "monthly-kpi-summary.md").exists())
            monthly_markdown = (output_dir / "monthly-kpi-summary.md").read_text(encoding="utf-8")
            self.assertIn("Monthly Improvement Summary", monthly_markdown)
            self.assertIn("Executive KPI Snapshot", monthly_markdown)

    def test_monthly_kpi_has_no_external_dependency_or_private_data_requirement(self):
        source = MONTHLY_KPI_PATH.read_text(encoding="utf-8").lower()
        blocked_terms = [
            "requests",
            "boto3",
            "azure",
            "google.cloud",
            "openai",
            "customer",
            "pricing",
            "branding",
            "private prompt",
        ]

        for term in blocked_terms:
            self.assertNotIn(term, source)


if __name__ == "__main__":
    unittest.main()

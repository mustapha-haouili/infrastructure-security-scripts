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
WINDOWS_SAMPLE = ROOT / "SecureInfra_AI" / "examples" / "sample-input" / "windows" / "sample-windows-host-security-audit.json"

sys.path.insert(0, str(SECUREINFRA_REPORTING))

from secureinfra.control_mapping import add_control_mappings, control_references_for_finding
from secureinfra.control_mapping.catalog import CONTROL_CATALOG
from secureinfra.validators.schema_validator import validate_normalized_report


ANALYZER_PATH = SECUREINFRA_REPORTING / "secureinfra_analyzer.py"
spec = importlib.util.spec_from_file_location("secureinfra_control_mapping_analyzer", ANALYZER_PATH)
secureinfra_analyzer = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = secureinfra_analyzer
spec.loader.exec_module(secureinfra_analyzer)


def finding(finding_id: str, title: str, category: str = "Security Review", evidence: dict | None = None) -> dict:
    return {
        "finding_id": finding_id,
        "title": title,
        "category": category,
        "severity": "Medium",
        "affected_object": "EXAMPLE-SRV01",
        "object_type": "Fictional test object",
        "source_script": "ExampleDefensiveAudit.ps1",
        "evidence": evidence or {},
        "risk_factors": [],
        "business_impact": "Fictional example impact for owner review.",
        "technical_impact": "Fictional example evidence for deterministic mapping.",
        "recommendation": "Review the fictional example before any approved change.",
        "remediation_priority": "Planned Remediation",
        "requires_owner_review": True,
        "requires_change_approval": True,
        "safe_to_auto_remediate": False,
        "not_safe_for_auto_remediation_reason": "Fictional example requires owner review.",
        "status": "Open",
        "timestamp_utc": "2026-06-01T00:00:00Z",
    }


class SecureInfraControlMappingTests(unittest.TestCase):
    def test_add_control_mappings_uses_metadata_without_changing_findings(self):
        original_finding = finding("AD-INACTIVE-0001", "Inactive user account requires lifecycle review")
        original_keys = set(original_finding)
        report = {
            "findings": [original_finding],
            "metadata": {"normalizer": "unit_test"},
        }

        add_control_mappings(report)

        self.assertEqual(set(report["findings"][0]), original_keys)
        self.assertNotIn("control_references", report["findings"][0])
        references = report["metadata"]["control_references_by_finding_id"]["AD-INACTIVE-0001"]
        self.assertIn(
            {
                "framework": "CIS Controls IG1",
                "control_id": "CIS-IG1-05",
                "label": "Account Management",
                "mapping_confidence": "medium",
            },
            references,
        )
        self.assertEqual(report["metadata"]["control_mapping_summary"]["CIS Controls IG1:CIS-IG1-05"], 1)

    def test_control_references_cover_initial_generic_themes(self):
        cases = [
            (finding("AD-INACTIVE-0001", "Inactive user account requires lifecycle review"), "CIS-IG1-05"),
            (finding("AD-COMP-0001", "Stale computer account requires lifecycle review"), "CIS-IG1-01"),
            (finding("AD-PNE-0001", "PasswordNeverExpires account requires exception review"), "CIS-IG1-05"),
            (finding("AD-PGROUP-0001", "Privileged group membership addition requires review"), "CIS-IG1-06"),
            (finding("AD-PID-0001", "Privileged identity protection gap requires review"), "CIS-IG1-06"),
            (finding("AD-SVC-0001", "Strict service account requires owner and dependency review"), "BSI-SMB-IDENTITY"),
            (finding("AD-SPN-0001", "SPN-bearing account requires exposure review"), "BSI-SMB-IDENTITY"),
            (finding("GPO-HEALTH-0001", "AD and SYSVOL GPO versions differ"), "CIS-IG1-04"),
            (finding("HOST-WIN-WIN-FW-001", "Windows Firewall profile is disabled"), "CIS-IG1-12"),
            (finding("LINUX-SSH-0001", "SSH root login is enabled"), "CIS-IG1-04"),
            (finding("DOCKER-0001", "Docker container runs as root"), "PR.PS"),
            (finding("SECRET-SCAN-0001", "Secret token pattern was detected"), "PR.DS"),
            (finding("BACKUP-0001", "Backup readiness coverage is missing"), "CIS-IG1-11"),
            (finding("PATCH-0001", "Patch posture shows outdated package evidence"), "CIS-IG1-07"),
        ]

        for item, expected_control_id in cases:
            with self.subTest(finding_id=item["finding_id"]):
                control_ids = {reference["control_id"] for reference in control_references_for_finding(item)}
                self.assertIn(expected_control_id, control_ids)

    def test_fleet_original_finding_id_is_used_for_mapping(self):
        item = finding(
            "FLEET-EXAMPLE-SRV01-AD-INACTIVE-0001",
            "Fleet finding copied from a client bundle",
            evidence={"original_finding_id": "AD-INACTIVE-0001", "machine_name": "EXAMPLE-SRV01"},
        )

        control_ids = {reference["control_id"] for reference in control_references_for_finding(item)}

        self.assertIn("CIS-IG1-05", control_ids)

    def test_analyzer_adds_control_mapping_before_windows_schema_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            with contextlib.redirect_stdout(io.StringIO()):
                exit_code = secureinfra_analyzer.main(
                    [
                        "--input",
                        str(WINDOWS_SAMPLE),
                        "--type",
                        "windows-host-audit",
                        "--output",
                        str(output_dir),
                    ]
                )

            self.assertEqual(exit_code, 0)
            normalized = json.loads((output_dir / "normalized-report.json").read_text(encoding="utf-8"))
            validate_normalized_report(normalized)
            references_by_id = normalized["metadata"]["control_references_by_finding_id"]
            self.assertIn("HOST-WIN-WIN-DEF-003", references_by_id)
            self.assertIn("control_mapping_summary", normalized["metadata"])
            self.assertTrue(normalized["metadata"]["control_mapping_summary"])

    def test_catalog_does_not_claim_certification_or_attestation(self):
        text = json.dumps(CONTROL_CATALOG).lower()
        blocked_terms = [
            "certified",
            "certification",
            "compliance attestation",
            "audit attestation",
            "official audit",
            "official compliance",
        ]
        for term in blocked_terms:
            self.assertNotIn(term, text)


if __name__ == "__main__":
    unittest.main()

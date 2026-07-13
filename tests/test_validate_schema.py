import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPORTING_ROOT = ROOT / "SecureInfra_AI" / "scripts" / "reporting"
SAMPLE_INPUT = ROOT / "SecureInfra_AI" / "examples" / "sample-input" / "active-directory" / "sample-ad-inactive-users.json"
VALIDATOR = ROOT / "scripts" / "reporting" / "validate_schema.py"

sys.path.insert(0, str(REPORTING_ROOT))

from secureinfra.loaders.json_loader import load_json_file
from secureinfra.normalizers.ad_inactive_users import normalize_ad_inactive_users
from secureinfra.normalizers.evidence_contract import normalize_report_evidence_contract


class ValidateSchemaCliTests(unittest.TestCase):
    def build_valid_report(self) -> dict:
        report = normalize_ad_inactive_users(load_json_file(SAMPLE_INPUT), "sample-ad-inactive-users.json")
        return normalize_report_evidence_contract(report)

    def run_validator(self, report: dict, *extra_args: str) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "normalized-report.json"
            report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(VALIDATOR), "--input", str(report_path), *extra_args],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

    def test_validate_schema_accepts_valid_normalized_report(self):
        result = self.run_validator(self.build_valid_report())

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Normalized report validation passed", result.stdout)
        self.assertIn("Findings validated", result.stdout)

    def test_validate_schema_accepts_directory_input(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            report_dir = Path(temp_dir)
            report_path = report_dir / "normalized-report.json"
            report_path.write_text(json.dumps(self.build_valid_report(), indent=2) + "\n", encoding="utf-8")

            result = subprocess.run(
                [sys.executable, str(VALIDATOR), "--input", str(report_dir)],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("normalized-report.json", result.stdout)

    def test_validate_schema_rejects_schema_violation(self):
        report = self.build_valid_report()
        del report["report_id"]

        result = self.run_validator(report)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("report_id", result.stderr)

    def test_validate_schema_rejects_duplicate_finding_ids(self):
        report = self.build_valid_report()
        if len(report["findings"]) < 2:
            report["findings"].append(copy.deepcopy(report["findings"][0]))
        report["findings"][1]["finding_id"] = report["findings"][0]["finding_id"]
        report["summary"]["normalized_finding_count"] = len(report["findings"])
        if "total_findings" in report["summary"]:
            report["summary"]["total_findings"] = len(report["findings"])
        counts = {}
        for finding in report["findings"]:
            counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
        report["summary"]["severity_counts"] = counts

        result = self.run_validator(report)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate finding_id", result.stderr)

    def test_validate_schema_rejects_hold_as_technical_severity(self):
        report = self.build_valid_report()
        report["findings"][0]["severity"] = "Hold"
        report["findings"][0]["status"] = "Hold"
        report["findings"][0]["remediation_priority"] = "Hold"
        report["summary"]["severity_counts"] = {"Hold": 1}

        result = self.run_validator(report)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("severity", result.stderr)
        self.assertIn("Hold", result.stderr)

    def test_validate_schema_strict_safety_rejects_private_path_leak(self):
        report = self.build_valid_report()
        report["metadata"]["debug_path"] = r"X:\Users\Example\customer-projects\sample"

        result = self.run_validator(report, "--strict-safety")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("local Windows drive path", result.stderr)


if __name__ == "__main__":
    unittest.main()

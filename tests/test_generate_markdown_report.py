import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "reporting" / "generate-markdown-report.py"

spec = importlib.util.spec_from_file_location("generate_markdown_report", MODULE_PATH)
generate_markdown_report = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = generate_markdown_report
spec.loader.exec_module(generate_markdown_report)


class GenerateMarkdownReportTests(unittest.TestCase):
    def test_extracts_top_level_findings(self):
        data = {
            "findings": [
                {
                    "finding_id": "AD-001",
                    "title": "Inactive enabled users",
                    "severity": "High",
                    "recommendation": "Confirm owner and disable after approval.",
                }
            ]
        }

        findings = generate_markdown_report.extract_findings(data, Path("sample.json"))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["finding_id"], "AD-001")
        self.assertEqual(findings[0]["severity"], "High")
        self.assertEqual(findings[0]["remediation_priority"], "Not Assigned")

    def test_extracts_existing_script_priority_records(self):
        data = {
            "InactiveUsers": [
                {
                    "SamAccountName": "julia.reed",
                    "ReviewPriority": "High",
                    "RecommendedAction": "Confirm owner.",
                }
            ]
        }

        findings = generate_markdown_report.extract_findings(data, Path("inactive-users.json"))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["title"], "julia.reed")
        self.assertEqual(findings[0]["severity"], "High")
        self.assertEqual(findings[0]["remediation_priority"], "P1")

    def test_main_writes_markdown_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_path = root / "audit.json"
            output_path = root / "report.md"
            input_path.write_text(
                json.dumps(
                    {
                        "Findings": [
                            {
                                "FindingId": "WIN-001",
                                "Title": "SMBv1 enabled",
                                "Severity": "High",
                                "Recommendation": "Disable after dependency review.",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            exit_code = generate_markdown_report.main([str(input_path), "--output", str(output_path)])

            self.assertEqual(exit_code, 0)
            content = output_path.read_text(encoding="utf-8")
            self.assertIn("Infrastructure Security Assessment Report", content)
            self.assertIn("WIN-001", content)
            self.assertIn("SMBv1 enabled", content)


if __name__ == "__main__":
    unittest.main()

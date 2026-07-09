import json
import platform
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class LinuxSecurityAuditReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if platform.system() != "Linux":
            raise unittest.SkipTest("linux-security-audit.sh report test requires Linux")
        if shutil.which("bash") is None:
            raise unittest.SkipTest("bash is not available")

    def test_quick_report_includes_summary_and_json(self):
        reports_root = ROOT / "reports"
        reports_root.mkdir(exist_ok=True)

        with tempfile.TemporaryDirectory(prefix="linux-audit-test-", dir=reports_root) as tmp:
            output_dir = Path(tmp)
            summary_path = output_dir / "summary.json"
            relative_output = output_dir.relative_to(ROOT).as_posix()
            relative_summary = summary_path.relative_to(ROOT).as_posix()

            result = subprocess.run(
                [
                    "bash",
                    "scripts/linux/linux-security-audit.sh",
                    "--quick",
                    "--output-dir",
                    relative_output,
                    "--summary-json",
                    relative_summary,
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=90,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

            report_paths = list(output_dir.glob("linux-security-audit-*.txt"))
            self.assertEqual(len(report_paths), 1)

            report_text = report_paths[0].read_text(encoding="utf-8")
            self.assertIn("Finding summary", report_text)
            self.assertIn("Recommended actions", report_text)
            self.assertIn("Evidence collected", report_text)
            self.assertIn(f"Summary JSON: {relative_summary}", report_text)

            payload = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertIn("finding_counts", payload)
            self.assertIn("findings", payload)
            self.assertTrue(payload["quick_mode"])

            finding_total = sum(payload["finding_counts"].values())
            self.assertEqual(finding_total, len(payload["findings"]))


if __name__ == "__main__":
    unittest.main()

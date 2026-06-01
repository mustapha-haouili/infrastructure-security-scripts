import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ShellArgumentValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if shutil.which("bash") is None:
            raise unittest.SkipTest("bash is not available")

    def assert_missing_value(self, script: str, option: str, *extra_args: str):
        result = subprocess.run(
            ["bash", script, option, *extra_args],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(f"Option {option} requires a value.", result.stderr)

    def test_linux_security_audit_requires_output_dir(self):
        self.assert_missing_value("scripts/linux/linux-security-audit.sh", "--output-dir")
        self.assert_missing_value("scripts/linux/linux-security-audit.sh", "--output-dir", "--quick")
        self.assert_missing_value("scripts/linux/linux-security-audit.sh", "--summary-json")

    def test_linux_hardening_requires_paths(self):
        self.assert_missing_value("scripts/linux/linux-hardening-baseline.sh", "--backup-dir")
        self.assert_missing_value("scripts/linux/linux-hardening-baseline.sh", "--report-dir")

    def test_linux_inventory_requires_output_dir(self):
        self.assert_missing_value("scripts/linux/collect-linux-inventory.sh", "--output-dir")

    def test_devsecops_scripts_require_option_values(self):
        self.assert_missing_value("scripts/devsecops/docker-image-audit.sh", "--output-dir")
        self.assert_missing_value("scripts/devsecops/kubernetes-rbac-audit.sh", "--context")
        self.assert_missing_value("scripts/devsecops/kubernetes-rbac-audit.sh", "--output-dir")

    def test_disk_monitor_requires_threshold_values(self):
        self.assert_missing_value("scripts/monitoring/disk-space-monitor.sh", "--warn")
        self.assert_missing_value("scripts/monitoring/disk-space-monitor.sh", "--crit")
        self.assert_missing_value("scripts/monitoring/disk-space-monitor.sh", "--exclude-types")


if __name__ == "__main__":
    unittest.main()

import os
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ShellArgumentValidationTests(unittest.TestCase):
    bash_executable = None
    bash_env = None

    @classmethod
    def setUpClass(cls):
        cls.bash_executable = cls.find_usable_bash()
        if cls.bash_executable is None:
            raise unittest.SkipTest("bash is not available")
        cls.bash_env = cls.build_bash_env(cls.bash_executable)

    @staticmethod
    def find_usable_bash():
        candidates = [
            shutil.which("bash"),
            r"C:\Program Files\Git\bin\bash.exe",
            r"C:\Program Files\Git\usr\bin\bash.exe",
        ]
        seen = set()
        for candidate in candidates:
            if not candidate:
                continue
            path = str(candidate)
            key = path.lower()
            if key in seen or not Path(path).is_file():
                continue
            seen.add(key)
            result = subprocess.run(
                [path, "--version"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            if result.returncode == 0 and "GNU bash" in result.stdout + result.stderr:
                return path
        return None

    @staticmethod
    def build_bash_env(bash_path: str):
        env = os.environ.copy()
        path_parts = []
        path = Path(bash_path)
        if path.name.lower() == "bash.exe":
            git_root = path.parent.parent
            path_parts.extend([str(git_root / "usr" / "bin"), str(git_root / "bin")])
        path_parts.append(env.get("PATH", ""))
        env["PATH"] = os.pathsep.join(part for part in path_parts if part)
        return env

    def assert_missing_value(self, script: str, option: str, *extra_args: str):
        result = subprocess.run(
            [self.bash_executable, script, option, *extra_args],
            cwd=ROOT,
            env=self.bash_env,
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

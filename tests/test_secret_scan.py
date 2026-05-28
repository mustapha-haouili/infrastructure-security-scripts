import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "devsecops" / "secret-scan.py"

spec = importlib.util.spec_from_file_location("secret_scan", MODULE_PATH)
secret_scan = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = secret_scan
spec.loader.exec_module(secret_scan)


class SecretScanTests(unittest.TestCase):
    def test_detects_github_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            token = "ghp_" + ("A" * 36)
            (root / "app.conf").write_text(f"deployment_token = '{token}'\n", encoding="utf-8")
            findings = secret_scan.scan(root, allowlist=set(), include_hidden=True, max_file_size=1024 * 1024)
            self.assertTrue(any(item.rule == "github-token" for item in findings))

    def test_ignore_comment_suppresses_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            token = "ghp_" + ("B" * 36)
            (root / "app.conf").write_text(f"deployment_token = '{token}'  # secret-scan: ignore\n", encoding="utf-8")
            findings = secret_scan.scan(root, allowlist=set(), include_hidden=True, max_file_size=1024 * 1024)
            self.assertEqual(findings, [])

    def test_clean_file_has_no_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "readme.txt").write_text("normal configuration value\n", encoding="utf-8")
            findings = secret_scan.scan(root, allowlist=set(), include_hidden=True, max_file_size=1024 * 1024)
            self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()

import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SECUREINFRA_REPORTING = ROOT / "SecureInfra_AI" / "scripts" / "reporting"
sys.path.insert(0, str(SECUREINFRA_REPORTING))

from secureinfra.bundles import client_bundle
from secureinfra.bundles.client_bundle import normalize_client_bundle
from secureinfra.bundles.multi_bundle import normalize_multi_bundle


def write_zip(path: Path, entries: dict[str, str | bytes]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, payload in entries.items():
            archive.writestr(name, payload)


def safe_client_bundle_entries(machine_name: str = "LAB-SRV01") -> dict[str, str]:
    return {
        "client-info.json": json.dumps(
            {
                "ComputerName": machine_name,
                "UserDomain": "example",
                "IsAdministrator": True,
                "OsCaption": "Windows Server 2022",
                "OsVersion": "20348.1",
            }
        ),
        "collection-summary.json": json.dumps(
            {
                "CollectionId": f"secureinfra-client-{machine_name}-20260619-120000",
                "GeneratedAtUtc": "2026-06-19T12:00:00Z",
                "SafetyMode": "Audit and dry-run only. No remediation is applied.",
                "ScopeResolved": ["Host"],
            }
        ),
        "manifest.json": json.dumps(
            {
                "SchemaVersion": "1.0",
                "CollectionId": f"secureinfra-client-{machine_name}-20260619-120000",
                "GeneratedAtUtc": "2026-06-19T12:00:00Z",
                "ScopeResolved": ["Host"],
            }
        ),
        "host/windows-security-audit.json": json.dumps(
            {
                "ReportMetadata": {
                    "ComputerName": machine_name,
                    "GeneratedAtUtc": "2026-06-19T12:00:00Z",
                    "ScriptName": "Invoke-WindowsSecurityAudit.ps1",
                },
                "Summary": {"FindingCount": 1},
                "Findings": [
                    {
                        "Id": "WIN-FW-001",
                        "Severity": "High",
                        "Area": "Firewall",
                        "Title": "Windows Firewall profile is disabled",
                        "WhyItMatters": "Disabled firewall profiles increase exposure.",
                        "Recommendation": "Enable Windows Firewall after reviewing allow rules.",
                        "Evidence": "Domain profile Enabled=False",
                    }
                ],
            }
        ),
        "host/windows-security-audit-findings.csv": "Id,Severity\nWIN-FW-001,High\n",
        "host/windows-security-audit-review.md": "# Windows Security Audit\n",
        "host/windows-events/summary.txt": "No event details in this fictional test bundle.\n",
        "logs/windows-security-audit.log": "collector log\n",
    }


class SecureInfraBundleSafetyTests(unittest.TestCase):
    def assert_rejects_zip(self, entries: dict[str, str | bytes], pattern: str) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "bundle.zip"
            write_zip(archive_path, entries)

            with self.assertRaisesRegex(ValueError, pattern):
                normalize_client_bundle(archive_path)

    def test_safe_client_bundle_zip_still_loads(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "safe-client-bundle.zip"
            write_zip(archive_path, safe_client_bundle_entries())

            report = normalize_client_bundle(archive_path)

            self.assertEqual(report["report_type"], "client-bundle")
            self.assertEqual(report["summary"]["normalized_finding_count"], 1)
            self.assertIn("host_windows_security_audit", report["metadata"]["loaded_files"])

    def test_rejects_parent_traversal_path(self):
        self.assert_rejects_zip({"../evil.json": "{}"}, "Unsafe zip entry path")

    def test_rejects_linux_absolute_path(self):
        self.assert_rejects_zip({"/tmp/evil.json": "{}"}, "absolute path")

    def test_rejects_windows_absolute_path(self):
        self.assert_rejects_zip({"C:\\Temp\\evil.json": "{}"}, "absolute path")

    def test_rejects_backslash_traversal_path(self):
        self.assert_rejects_zip({"..\\evil.json": "{}"}, "Unsafe zip entry path")

    def test_rejects_oversized_entry(self):
        original_limit = client_bundle.MAX_ZIP_MEMBER_SIZE_BYTES
        client_bundle.MAX_ZIP_MEMBER_SIZE_BYTES = 4
        try:
            self.assert_rejects_zip({"client-info.json": '{"too":"large"}'}, "too large")
        finally:
            client_bundle.MAX_ZIP_MEMBER_SIZE_BYTES = original_limit

    def test_rejects_unexpected_extension(self):
        self.assert_rejects_zip({"host/preview.html": "<script>alert(1)</script>"}, "extension")

    def test_rejects_too_many_entries(self):
        original_limit = client_bundle.MAX_ZIP_ENTRIES
        client_bundle.MAX_ZIP_ENTRIES = 1
        try:
            self.assert_rejects_zip({"client-info.json": "{}", "manifest.json": "{}"}, "too many entries")
        finally:
            client_bundle.MAX_ZIP_ENTRIES = original_limit

    def test_multi_bundle_marks_unsafe_child_zip_failed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive_path = root / "unsafe-client-bundle.zip"
            write_zip(archive_path, {"../evil.json": "{}"})

            report = normalize_multi_bundle(root)

            self.assertEqual(report["report_type"], "multi-bundle")
            self.assertEqual(report["summary"]["loaded_bundle_count"], 0)
            self.assertEqual(report["summary"]["failed_bundle_count"], 1)
            self.assertIn("Unsafe zip entry path", report["report_type_metadata"]["failed_bundles"][0]["error"])


if __name__ == "__main__":
    unittest.main()

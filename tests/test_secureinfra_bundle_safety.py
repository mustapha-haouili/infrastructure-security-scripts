import hashlib
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


def with_hashed_manifest(entries: dict[str, str | bytes]) -> dict[str, str | bytes]:
    output = dict(entries)
    manifest = json.loads(str(output["manifest.json"]))
    records = []
    for name, payload in sorted(output.items()):
        if name in {"manifest.json", "bundle-manifest.json"}:
            continue
        raw = payload if isinstance(payload, bytes) else payload.encode("utf-8")
        records.append(
            {
                "Path": name.replace("/", "\\"),
                "SizeBytes": len(raw),
                "Sha256": hashlib.sha256(raw).hexdigest().upper(),
            }
        )
    manifest["Files"] = records
    output["manifest.json"] = json.dumps(manifest)
    return output


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
            write_zip(archive_path, with_hashed_manifest(safe_client_bundle_entries()))

            report = normalize_client_bundle(archive_path)

            self.assertEqual(report["report_type"], "client-bundle")
            self.assertEqual(report["summary"]["normalized_finding_count"], 1)
            self.assertIn("host_windows_security_audit", report["metadata"]["loaded_files"])
            self.assertEqual(report["metadata"]["bundle_integrity"]["status"], "verified")

    def test_rejects_missing_file_declared_by_manifest(self):
        entries = with_hashed_manifest(safe_client_bundle_entries())
        del entries["host/windows-security-audit.json"]
        self.assert_rejects_zip(entries, "manifest membership mismatch")

    def test_rejects_file_modified_after_manifest_creation(self):
        entries = with_hashed_manifest(safe_client_bundle_entries())
        entries["host/windows-security-audit.json"] = json.dumps({"Findings": []})
        self.assert_rejects_zip(entries, "manifest (size|SHA-256) mismatch")

    def test_empty_files_array_is_explicitly_legacy_unverified(self):
        entries = with_hashed_manifest(safe_client_bundle_entries())
        manifest = json.loads(str(entries["manifest.json"]))
        manifest["Files"] = []
        entries["manifest.json"] = json.dumps(manifest)
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "legacy-bundle.zip"
            write_zip(archive_path, entries)
            report = normalize_client_bundle(archive_path)
        self.assertEqual(report["metadata"]["bundle_integrity"]["status"], "legacy-empty-file-list")

    def test_rejects_inconsistent_manifest_alias_metadata(self):
        entries = with_hashed_manifest(safe_client_bundle_entries())
        alias = json.loads(str(entries["manifest.json"]))
        alias["CollectionId"] = "different-run"
        entries["bundle-manifest.json"] = json.dumps(alias)
        self.assert_rejects_zip(entries, "contain different metadata")

    def test_rejects_expanded_bundle_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle_dir = root / "bundle"
            entries = with_hashed_manifest(safe_client_bundle_entries())
            for relative_name, payload in entries.items():
                target = bundle_dir / relative_name
                target.parent.mkdir(parents=True, exist_ok=True)
                raw = payload if isinstance(payload, bytes) else payload.encode("utf-8")
                target.write_bytes(raw)

            source = bundle_dir / "host" / "windows-security-audit.json"
            outside = root / "outside.json"
            source.replace(outside)
            try:
                source.symlink_to(outside)
            except (NotImplementedError, OSError):
                self.skipTest("Symbolic links are unavailable in this test environment")

            with self.assertRaisesRegex(ValueError, "symbolic link or reparse point"):
                normalize_client_bundle(bundle_dir)

    def test_compatibility_report_is_loaded_as_evidence_gap_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "safe-client-bundle.zip"
            entries = safe_client_bundle_entries()
            entries["compatibility-report.json"] = json.dumps(
                {
                    "SchemaVersion": "1.0",
                    "Contract": "secureinfra-windows-compatibility/1.0",
                    "GeneratedAtUtc": "2026-07-20T12:00:00Z",
                    "Host": {"Name": "LAB-SRV01", "OsVersion": "10.0", "Is64BitOperatingSystem": True, "Is64BitProcess": True},
                    "Runtime": {
                        "Ready": True,
                        "PowerShellVersion": "5.1.19041.1",
                        "PowerShellEdition": "Desktop",
                        "LanguageMode": "FullLanguage",
                        "SelectedHost": "WindowsPowerShell",
                        "AutomaticInstall": "prohibited",
                    },
                    "ScopeRequested": ["AD"],
                    "Capabilities": [],
                    "ScopeReadiness": [
                        {"Scope": "AD", "Status": "Unavailable", "MissingCapabilities": [], "Action": "Install approved RSAT features."},
                        {"Scope": "ExchangeServer", "Status": "Limited", "MissingCapabilities": [], "Action": "Use Exchange management tools."},
                    ],
                    "HardFailures": [],
                    "Limitations": ["AD: Unavailable", "ExchangeServer: Limited"],
                    "Safety": {
                        "Mode": "read-only-capability-discovery",
                        "Downloads": "prohibited",
                        "PackageInstallation": "prohibited",
                        "ServiceChanges": "prohibited",
                        "AutomaticRemediation": "prohibited",
                    },
                }
            )
            write_zip(archive_path, entries)

            report = normalize_client_bundle(archive_path)

            self.assertIn("compatibility_report", report["metadata"]["loaded_files"])
            summary = report["metadata"]["loaded_summaries"]["compatibility_report"]
            self.assertTrue(summary["runtime_ready"])
            self.assertEqual(summary["limited_scope_count"], 1)
            compatibility_note = next(note for note in report["notes"] if "Compatibility evidence gaps" in note)
            self.assertIn("AD", compatibility_note)
            self.assertNotIn("ExchangeServer", compatibility_note)

    def test_compatibility_contract_accepts_explicit_role_applicability(self):
        profile = {
            "SchemaVersion": "1.0",
            "Contract": "secureinfra-windows-compatibility/1.0",
            "GeneratedAtUtc": "2026-08-13T12:00:00Z",
            "Host": {
                "Name": "LAB-SRV01",
                "OsVersion": "10.0",
                "Is64BitOperatingSystem": True,
                "Is64BitProcess": True,
                "DomainRole": 3,
                "IsDomainController": False,
            },
            "Runtime": {
                "Ready": True,
                "PowerShellVersion": "5.1",
                "PowerShellEdition": "Desktop",
                "LanguageMode": "FullLanguage",
                "SelectedHost": "WindowsPowerShell",
                "AutomaticInstall": "prohibited",
            },
            "ScopeRequested": ["All"],
            "Capabilities": [],
            "ScopeReadiness": [
                {"Scope": "AD", "Status": "NotApplicable", "MissingCapabilities": [], "Action": ""}
            ],
            "HardFailures": [],
            "Limitations": [],
            "Safety": {
                "Mode": "read-only-capability-discovery",
                "Downloads": "prohibited",
                "PackageInstallation": "prohibited",
                "ServiceChanges": "prohibited",
                "AutomaticRemediation": "prohibited",
            },
        }

        client_bundle.validate_windows_compatibility_report(profile)
        profile["Host"]["IsDomainController"] = True
        with self.assertRaisesRegex(ValueError, "Conflicting"):
            client_bundle.validate_windows_compatibility_report(profile)

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

    def test_rejects_excessive_total_uncompressed_size(self):
        original_limit = client_bundle.MAX_BUNDLE_TOTAL_SIZE_BYTES
        client_bundle.MAX_BUNDLE_TOTAL_SIZE_BYTES = 10
        try:
            self.assert_rejects_zip(
                {"client-info.json": "123456", "manifest.json": "123456"},
                "total uncompressed size",
            )
        finally:
            client_bundle.MAX_BUNDLE_TOTAL_SIZE_BYTES = original_limit

    def test_rejects_duplicate_normalized_zip_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "duplicate.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("client-info.json", "{}")
                archive.writestr("CLIENT-INFO.JSON", "{}")
            with self.assertRaisesRegex(ValueError, "duplicate normalized entry path"):
                normalize_client_bundle(archive_path)

    def test_rejects_zip_symbolic_link_member(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "symlink.zip"
            link = zipfile.ZipInfo("host/windows-security-audit.json")
            link.create_system = 3
            link.external_attr = (0o120777 << 16)
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr(link, "../../outside.json")
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                normalize_client_bundle(archive_path)

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

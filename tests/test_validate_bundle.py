import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.reporting import validate_bundle


def write_zip(path: Path, entries: dict[str, str | bytes]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, payload in entries.items():
            archive.writestr(name, payload)


def safe_client_bundle_entries(machine_name: str = "LAB-SRV01") -> dict[str, str]:
    return {
        "client-info.json": json.dumps({"ComputerName": machine_name, "UserDomain": "example"}),
        "collection-summary.json": json.dumps(
            {
                "CollectionId": f"secureinfra-client-{machine_name}-20260709-120000",
                "GeneratedAtUtc": "2026-07-09T12:00:00Z",
                "SafetyMode": "Audit and dry-run only. No remediation is applied.",
                "ScopeResolved": ["Host"],
            }
        ),
        "manifest.json": json.dumps(
            {
                "SchemaVersion": "1.0",
                "CollectionId": f"secureinfra-client-{machine_name}-20260709-120000",
                "GeneratedAtUtc": "2026-07-09T12:00:00Z",
                "ScopeResolved": ["Host"],
            }
        ),
        "host/windows-security-audit.json": json.dumps(
            {
                "ReportMetadata": {"ComputerName": machine_name, "ScriptName": "Invoke-WindowsSecurityAudit.ps1"},
                "Summary": {"FindingCount": 0},
                "Findings": [],
            }
        ),
        "host/windows-security-audit-findings.csv": "Id,Severity\n",
        "host/windows-security-audit-review.md": "# Review\n",
        "logs/windows-security-audit.log": "collector log\n",
    }


class ValidateBundleTests(unittest.TestCase):
    def test_validate_bundle_accepts_safe_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "secureinfra-client-collection-LAB-SRV01.zip"
            write_zip(archive_path, safe_client_bundle_entries())

            result = validate_bundle.validate_input_bundle(archive_path, strict_safety=True)

            self.assertEqual(result.bundle_count, 1)
            self.assertEqual(result.errors, [])

    def test_validate_bundle_accepts_compatibility_report_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "secureinfra-client-collection-LAB-SRV01.zip"
            entries = safe_client_bundle_entries()
            entries["compatibility-report.json"] = json.dumps(
                {
                    "SchemaVersion": "1.0",
                    "Contract": "secureinfra-windows-compatibility/1.0",
                    "GeneratedAtUtc": "2026-07-20T12:00:00Z",
                    "Host": {"Name": "LAB-SRV01", "OsVersion": "10.0", "Is64BitOperatingSystem": True, "Is64BitProcess": True},
                    "Runtime": {
                        "Ready": True,
                        "PowerShellVersion": "5.1",
                        "PowerShellEdition": "Desktop",
                        "LanguageMode": "FullLanguage",
                        "SelectedHost": "WindowsPowerShell",
                        "AutomaticInstall": "prohibited",
                    },
                    "ScopeRequested": ["Host"],
                    "Capabilities": [],
                    "ScopeReadiness": [],
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
            )
            write_zip(archive_path, entries)

            result = validate_bundle.validate_input_bundle(archive_path, strict_safety=True)

            self.assertEqual(result.errors, [])

    def test_validate_bundle_rejects_unsafe_compatibility_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "secureinfra-client-collection-LAB-SRV01.zip"
            entries = safe_client_bundle_entries()
            entries["compatibility-report.json"] = json.dumps(
                {"SchemaVersion": "1.0", "Contract": "untrusted/1.0", "Runtime": {"Ready": True}}
            )
            write_zip(archive_path, entries)

            with self.assertRaises(validate_bundle.BundleValidationError) as context:
                validate_bundle.validate_input_bundle(archive_path, strict_safety=True)

            self.assertIn("compatibility report", str(context.exception))

    def test_validate_bundle_accepts_directory_of_multiple_zips(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_zip(root / "secureinfra-client-collection-LAB-SRV01.zip", safe_client_bundle_entries("LAB-SRV01"))
            write_zip(root / "secureinfra-client-collection-LAB-SRV02.zip", safe_client_bundle_entries("LAB-SRV02"))

            result = validate_bundle.validate_input_bundle(root, expected_bundle_count=2, strict_safety=True)

            self.assertEqual(result.bundle_count, 2)

    def test_validate_bundle_accepts_expanded_client_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle_dir = Path(tmp) / "secureinfra-client-collection-LAB-SRV01"
            for relative_name, payload in safe_client_bundle_entries().items():
                target = bundle_dir / relative_name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(payload, encoding="utf-8")

            result = validate_bundle.validate_input_bundle(bundle_dir, strict_safety=True)

            self.assertEqual(result.bundle_count, 1)

    def test_validate_bundle_rejects_unsafe_zip_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "bundle.zip"
            write_zip(archive_path, {"../evil.json": "{}"})

            with self.assertRaises(validate_bundle.BundleValidationError) as context:
                validate_bundle.validate_input_bundle(archive_path)

            self.assertIn("Unsafe zip entry path", str(context.exception))

    def test_validate_bundle_rejects_invalid_json_member(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "bundle.zip"
            entries = safe_client_bundle_entries()
            entries["client-info.json"] = "{not valid json"
            write_zip(archive_path, entries)

            with self.assertRaises(validate_bundle.BundleValidationError) as context:
                validate_bundle.validate_input_bundle(archive_path)

            self.assertIn("invalid JSON", str(context.exception))

    def test_validate_bundle_rejects_missing_expected_bundle_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_zip(root / "secureinfra-client-collection-LAB-SRV01.zip", safe_client_bundle_entries("LAB-SRV01"))

            with self.assertRaises(validate_bundle.BundleValidationError) as context:
                validate_bundle.validate_input_bundle(root, expected_bundle_count=2)

            self.assertIn("Expected at least 2 bundle candidates", str(context.exception))

    def test_validate_bundle_strict_safety_rejects_private_prompt_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "bundle.zip"
            entries = safe_client_bundle_entries()
            entries["logs/private-prompts/notes.txt"] = "not customer deliverable safe\n"
            write_zip(archive_path, entries)

            with self.assertRaises(validate_bundle.BundleValidationError) as context:
                validate_bundle.validate_input_bundle(archive_path, strict_safety=True)

            self.assertIn("forbidden sensitive path segment", str(context.exception))


    def test_validate_bundle_strict_safety_rejects_sensitive_wrapper_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "bundle.zip"
            entries = {f"private-prompts/{name}": payload for name, payload in safe_client_bundle_entries().items()}
            write_zip(archive_path, entries)

            with self.assertRaises(validate_bundle.BundleValidationError) as context:
                validate_bundle.validate_input_bundle(archive_path, strict_safety=True)

            self.assertIn("forbidden sensitive path segment", str(context.exception))

    def test_validate_bundle_main_returns_nonzero_for_bad_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "bundle.zip"
            write_zip(archive_path, {"../evil.json": "{}"})

            exit_code = validate_bundle.main(["--input", str(archive_path), "--quiet"])

            self.assertEqual(exit_code, 1)


if __name__ == "__main__":
    unittest.main()

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "scripts" / "linux" / "Start-SecureInfraLinuxCollection.sh"
CONTRACT = ROOT / "COLLECTION_BUNDLE_CONTRACT.md"
SECUREINFRA_REPORTING = ROOT / "SecureInfra_AI" / "scripts" / "reporting"
sys.path.insert(0, str(SECUREINFRA_REPORTING))

from secureinfra.bundles.client_bundle import normalize_client_bundle
from secureinfra.validators.schema_validator import validate_normalized_report
from scripts.reporting import validate_bundle


class LinuxCollectionLauncherContractTests(unittest.TestCase):
    def test_linux_launcher_exists_and_invokes_supported_collectors(self):
        self.assertTrue(LAUNCHER.exists(), "Linux collection launcher should exist")
        content = LAUNCHER.read_text(encoding="utf-8")

        self.assertIn("collect-linux-inventory.sh", content)
        self.assertIn("linux-security-audit.sh", content)
        self.assertIn("linux-network-exposure-audit.sh", content)
        self.assertIn("linux-log-audit.sh", content)
        self.assertIn("linux-service-inventory-audit.sh", content)
        self.assertIn("linux-hardening-baseline.sh", content)
        self.assertIn("backup-readiness-audit.sh", content)
        self.assertIn("linux/linux-security-summary.json", content)
        self.assertIn("linux/linux-network-exposure-summary.json", content)
        self.assertIn("linux/linux-log-audit-summary.json", content)
        self.assertIn("linux/linux-service-inventory-summary.json", content)
        self.assertIn("bundle-manifest.json", content)
        self.assertIn("Read-only collection", content)
        self.assertIn("--collector-timeout-seconds", content)

    def test_collection_bundle_contract_documents_linux_bundle_layout(self):
        self.assertTrue(CONTRACT.exists(), "COLLECTION_BUNDLE_CONTRACT.md should exist")
        content = CONTRACT.read_text(encoding="utf-8")

        self.assertIn("Start-SecureInfraLinuxCollection.sh", content)
        self.assertIn("linux/linux-security-summary.json", content)
        self.assertIn("linux/linux-network-exposure-summary.json", content)
        self.assertIn("linux/linux-log-audit-summary.json", content)
        self.assertIn("linux/linux-service-inventory-summary.json", content)
        self.assertIn("linux/linux-inventory.json", content)
        self.assertIn("backup/backup-readiness.json", content)
        self.assertIn("Docker and Kubernetes planned contract", content)

    def test_linux_bundle_with_manifest_alias_validates_and_normalizes(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle_dir = Path(tmp) / "secureinfra-linux-bundle-linux-app01-20260709-120000"
            linux_dir = bundle_dir / "linux"
            log_dir = bundle_dir / "logs"
            linux_dir.mkdir(parents=True)
            log_dir.mkdir()

            (bundle_dir / "client-info.json").write_text(
                json.dumps(
                    {
                        "ComputerName": "linux-app01",
                        "Platform": "Linux",
                        "CollectorLauncher": "Start-SecureInfraLinuxCollection.sh",
                        "GeneratedAtUtc": "2026-07-09T12:00:00Z",
                    }
                ),
                encoding="utf-8",
            )
            manifest = {
                "SchemaVersion": "1.0",
                "BundleType": "secureinfra-linux-client-collection",
                "GeneratedAtUtc": "2026-07-09T12:00:00Z",
                "SourceLauncher": "Start-SecureInfraLinuxCollection.sh",
            }
            (bundle_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            (bundle_dir / "bundle-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            (bundle_dir / "collection-summary.json").write_text(
                json.dumps({"GeneratedAtUtc": "2026-07-09T12:00:00Z", "ScopeResolved": ["Linux"]}),
                encoding="utf-8",
            )
            (log_dir / "collector-status.txt").write_text("linux-security-audit\tcompleted\tlinux/linux-security-summary.json\n", encoding="utf-8")
            (linux_dir / "linux-security-summary.json").write_text(
                json.dumps(
                    {
                        "host": "linux-app01",
                        "generated_at_utc": "2026-07-09T12:00:00Z",
                        "root_context": False,
                        "quick_mode": True,
                        "finding_counts": {"medium": 2, "info": 1},
                        "findings": [
                            {
                                "id": "LINUX-NETWORK-PORT-6379",
                                "severity": "high",
                                "title": "Linux host is listening on TCP 6379 / Redis",
                                "recommendation": "Validate the business need and allowed source networks.",
                                "evidence": "TCP 6379 / Redis; bind scope: all interfaces; local listener: 0.0.0.0:6379. This is bind evidence, not proof of internet reachability.",
                            },
                            {
                                "id": "LINUX-LOG-AUDITD-001",
                                "severity": "medium",
                                "title": "Linux audit service is not active or could not be verified",
                                "recommendation": "Validate whether auditd or an equivalent audit control is required.",
                                "evidence": "systemctl is-active auditd did not return active.",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )

            result = validate_bundle.validate_input_bundle(bundle_dir, strict_safety=True)
            self.assertEqual(result.errors, [])

            normalized = normalize_client_bundle(bundle_dir)
            validate_normalized_report(normalized)

            categories = {finding["category"] for finding in normalized["findings"]}
            self.assertIn("Linux Network Security", categories)
            self.assertIn("Linux Logging and Audit", categories)
            self.assertEqual(normalized["summary"]["scope_finding_counts"]["Linux"], 2)
            self.assertIn("bundle_manifest", normalized["metadata"]["loaded_files"])

    def test_launcher_avoids_powershell_style_paths_or_private_terms(self):
        content = LAUNCHER.read_text(encoding="utf-8")
        self.assertNotRegex(content, re.compile(r"[A-Za-z]:\\"))
        self.assertNotIn("downstream-reporting-workspace", content)
        self.assertNotIn("customer-projects", content)


if __name__ == "__main__":
    unittest.main()

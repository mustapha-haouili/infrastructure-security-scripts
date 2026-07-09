import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SECUREINFRA_REPORTING = ROOT / "SecureInfra_AI" / "scripts" / "reporting"
sys.path.insert(0, str(SECUREINFRA_REPORTING))

from secureinfra.bundles.client_bundle import normalize_client_bundle
from secureinfra.normalizers.linux_security import normalize_linux_security_audit
from secureinfra.validators.schema_validator import validate_normalized_report
from scripts.reporting import validate_bundle


def sample_linux_summary() -> dict:
    return {
        "host": "linux-app01",
        "generated_at_utc": "2026-07-09T12:00:00Z",
        "root_context": False,
        "quick_mode": True,
        "finding_counts": {"critical": 0, "high": 1, "medium": 2, "info": 1},
        "findings": [
            {
                "id": "LINUX-SSH-001",
                "severity": "high",
                "title": "SSH root login is enabled",
                "recommendation": "Set PermitRootLogin no and use named administrative accounts with sudo.",
                "evidence": "PermitRootLogin=yes",
            },
            {
                "id": "LINUX-FIREWALL-001",
                "severity": "medium",
                "title": "Firewall status could not be verified",
                "recommendation": "Install or expose a supported firewall tool, or document the host firewall control used by this system.",
                "evidence": "No ufw, firewall-cmd, nft, or iptables command found",
            },
            {
                "id": "LINUX-NETWORK-PORT-6379",
                "severity": "high",
                "title": "Linux host is listening on TCP 6379 / Redis",
                "recommendation": "Validate the business need, allowed source networks, firewall policy, and service owner before changing the listener.",
                "evidence": "TCP 6379 / Redis; bind scope: all interfaces; local listener: 0.0.0.0:6379. This is bind evidence, not proof of internet reachability.",
            },
            {
                "id": "LINUX-LOG-AUDITD-001",
                "severity": "medium",
                "title": "Linux audit service is not active or could not be verified",
                "recommendation": "Validate whether auditd or an equivalent audit control is required.",
                "evidence": "systemctl is-active auditd did not return active.",
            },
            {
                "id": "LINUX-PACKAGE-UPDATES-001",
                "severity": "medium",
                "title": "Linux package updates are available in local package metadata",
                "recommendation": "Review pending package updates with the system owner and apply through the approved patch process.",
                "evidence": "apt local metadata reports 12 upgradable package(s). The audit did not refresh repositories.",
            },
            {
                "id": "LINUX-FILESYSTEM-001",
                "severity": "high",
                "title": "World-writable files exist under /etc",
                "recommendation": "Remove world-writable permissions from system configuration files after validating ownership and application requirements.",
                "evidence": "World-writable /etc files: /etc/example.conf",
            },
            {
                "id": "LINUX-AUDIT-COVERAGE-001",
                "severity": "info",
                "title": "Audit was not run as root",
                "recommendation": "Run with sudo for complete shadow, service, and package evidence.",
                "evidence": "Current user: analyst",
            },
        ],
    }


class LinuxSecurityNormalizerTests(unittest.TestCase):
    def test_linux_security_summary_normalizes_to_schema_valid_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "linux-security-summary.json"
            source.write_text(json.dumps(sample_linux_summary()), encoding="utf-8")

            normalized = normalize_linux_security_audit(sample_linux_summary(), source)
            validate_normalized_report(normalized)

            self.assertEqual(normalized["summary"]["normalized_finding_count"], 7)
            ssh = normalized["findings"][0]
            self.assertEqual(ssh["finding_id"], "LINUX-SSH-001")
            self.assertEqual(ssh["category"], "Linux SSH Configuration")
            self.assertEqual(ssh["severity"], "High")
            self.assertEqual(ssh["source_script"], "linux-security-audit.sh")
            self.assertFalse(ssh["safe_to_auto_remediate"])
            self.assertEqual(ssh["evidence"]["scope"], "Linux")
            self.assertIn("audit_coverage_limitation", ssh["evidence"])

    def test_client_bundle_discovers_dynamic_linux_summary_filename(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle_dir = Path(tmp) / "secureinfra-client-collection-LINUX-APP01-20260709-120000"
            linux_dir = bundle_dir / "linux"
            linux_dir.mkdir(parents=True)
            (bundle_dir / "client-info.json").write_text(json.dumps({"ComputerName": "linux-app01"}), encoding="utf-8")
            (bundle_dir / "collection-summary.json").write_text(
                json.dumps({"GeneratedAtUtc": "2026-07-09T12:00:00Z", "ScopeResolved": ["Linux"]}),
                encoding="utf-8",
            )
            (linux_dir / "linux-security-audit-linux-app01-20260709-120000.summary.json").write_text(
                json.dumps(sample_linux_summary()),
                encoding="utf-8",
            )

            normalized = normalize_client_bundle(bundle_dir)
            validate_normalized_report(normalized)

            self.assertEqual(normalized["summary"]["scope_finding_counts"]["Linux"], 7)
            self.assertEqual(normalized["report_type_metadata"]["normalized_source_counts"]["linux_security_summary"], 7)
            categories = {item["category"] for item in normalized["findings"]}
            self.assertIn("Linux SSH Configuration", categories)
            self.assertIn("Linux Network Security", categories)
            self.assertIn("Linux Logging and Audit", categories)
            self.assertIn("Linux Patch Management", categories)
            self.assertIn("Linux Filesystem Permissions", categories)

    def test_validate_bundle_accepts_linux_only_evidence_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "secureinfra-linux-evidence.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr(
                    "linux/linux-security-audit-linux-app01-20260709-120000.summary.json",
                    json.dumps(sample_linux_summary()),
                )
                archive.writestr("linux/linux-security-audit-linux-app01-20260709-120000.txt", "Linux Security Audit Report\n")

            result = validate_bundle.validate_input_bundle(archive_path, strict_safety=True)

            self.assertEqual(result.bundle_count, 1)
            self.assertEqual(result.errors, [])


if __name__ == "__main__":
    unittest.main()

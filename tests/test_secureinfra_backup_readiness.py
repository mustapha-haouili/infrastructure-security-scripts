import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SECUREINFRA_REPORTING = ROOT / "SecureInfra_AI" / "scripts" / "reporting"
SAMPLE_OUTPUT = ROOT / "examples" / "sample-output" / "backup" / "backup-readiness.example.json"

sys.path.insert(0, str(SECUREINFRA_REPORTING))

from secureinfra.control_mapping import add_control_mappings
from secureinfra.normalizers.backup_readiness import normalize_backup_readiness
from secureinfra.validators.schema_validator import validate_normalized_report


class SecureInfraBackupReadinessTests(unittest.TestCase):
    def load_windows_sample(self) -> dict:
        return json.loads(SAMPLE_OUTPUT.read_text(encoding="utf-8"))

    def linux_sample(self) -> dict:
        return {
            "ToolName": "backup-readiness-audit.sh",
            "ReportType": "backup-readiness",
            "Platform": "linux",
            "GeneratedAtUtc": "2026-06-15T11:00:00Z",
            "HostName": "EXAMPLE-LINUX01",
            "WarningAgeDays": 14,
            "CriticalAgeDays": 30,
            "Summary": {
                "BackupHealthStatus": "Unverified",
                "DetectedToolCount": 1,
                "BackupServiceCount": 0,
                "BackupTimerCount": 1,
                "ExpectedBackupPathCount": 1,
                "MissingExpectedPathCount": 1,
                "StaleExpectedPathCount": 0,
                "LastBackupEvidenceTimestamp": "",
                "RestoreTestEvidenceStatus": "missing",
                "MonitoringEvidenceStatus": "missing",
                "FindingCount": 4,
                "SeverityCounts": {"Critical": 0, "High": 1, "Medium": 2, "Low": 0, "Info": 1},
            },
            "BackupEvidence": {
                "Tools": [{"name": "restic", "path": "/usr/bin/restic"}],
                "Timers": [{"name": "example-backup.timer"}],
                "ExpectedBackupPaths": [
                    {
                        "path": "/mnt/example-backups",
                        "exists": False,
                        "last_write_time_utc": "",
                        "age_days": "",
                        "status": "missing",
                        "limitation": "Only path metadata was checked.",
                    }
                ],
            },
            "Findings": [
                {
                    "FindingType": "ExpectedBackupPathMissing",
                    "Severity": "High",
                    "Title": "Expected backup path is missing",
                    "AffectedObject": "/mnt/example-backups",
                    "Evidence": "The expected backup path was not present. Contents were not enumerated.",
                    "Recommendation": "Confirm the expected backup target, mount state, permissions, and backup job ownership.",
                    "BackupEvidenceSource": "expected_backup_path",
                    "BackupEvidenceConfidence": "high",
                    "RestoreTestEvidenceStatus": "not_provided",
                    "MonitoringEvidenceStatus": "not_provided",
                    "Limitations": ["Only path metadata was checked."],
                },
                {
                    "FindingType": "BackupServicePresentHealthUnverified",
                    "Severity": "Info",
                    "Title": "Backup-related tool or schedule signal is present but health is unverified",
                    "AffectedObject": "EXAMPLE-LINUX01",
                    "Evidence": "restic and example-backup.timer were visible, but job success was not verified.",
                    "Recommendation": "Review backup job history, alerts, recent successful backup evidence, and restore test evidence.",
                    "BackupEvidenceSource": "tool_and_scheduler_inventory",
                    "BackupEvidenceConfidence": "low",
                    "RestoreTestEvidenceStatus": "not_provided",
                    "MonitoringEvidenceStatus": "not_provided",
                    "Limitations": ["Tool and schedule inventory does not prove backup success or restoreability."],
                },
                {
                    "FindingType": "RestoreTestEvidenceMissing",
                    "Severity": "Medium",
                    "Title": "Restore test evidence was not provided",
                    "AffectedObject": "EXAMPLE-LINUX01",
                    "Evidence": "This collector does not run restore operations.",
                    "Recommendation": "Confirm the date, scope, and result of the latest approved restore test.",
                    "BackupEvidenceSource": "governance_review",
                    "BackupEvidenceConfidence": "low",
                    "RestoreTestEvidenceStatus": "missing",
                    "MonitoringEvidenceStatus": "not_provided",
                    "Limitations": ["Restore readiness cannot be proven without a documented restore test."],
                },
                {
                    "FindingType": "BackupMonitoringEvidenceMissing",
                    "Severity": "Medium",
                    "Title": "Backup monitoring evidence was not provided",
                    "AffectedObject": "EXAMPLE-LINUX01",
                    "Evidence": "No backup monitoring alert evidence was collected.",
                    "Recommendation": "Confirm backup monitoring ownership, alert routing, and failure escalation procedures.",
                    "BackupEvidenceSource": "governance_review",
                    "BackupEvidenceConfidence": "low",
                    "RestoreTestEvidenceStatus": "not_provided",
                    "MonitoringEvidenceStatus": "missing",
                    "Limitations": ["Monitoring coverage should be validated in the backup or monitoring platform."],
                },
            ],
            "Limitations": ["This collector does not read backup contents."],
            "Notes": ["Audit-only backup readiness evidence."],
        }

    def test_windows_sample_output_normalizes_correctly(self):
        normalized = normalize_backup_readiness(self.load_windows_sample(), SAMPLE_OUTPUT)

        self.assertEqual(normalized["report_type"], "backup-readiness")
        self.assertEqual(normalized["environment_summary"]["platform"], "windows")
        self.assertEqual(normalized["environment_summary"]["scope"], "Backup")
        self.assertEqual(normalized["summary"]["normalized_finding_count"], 4)
        self.assertTrue(any(item["finding_id"].startswith("BACKUP-READINESS-") for item in normalized["findings"]))
        validate_normalized_report(normalized)

    def test_linux_sample_output_normalizes_correctly(self):
        normalized = normalize_backup_readiness(self.linux_sample(), "linux-backup-readiness.json")

        self.assertEqual(normalized["environment_summary"]["platform"], "linux")
        self.assertEqual(normalized["environment_summary"]["source_host"], "EXAMPLE-LINUX01")
        self.assertEqual(normalized["summary"]["severity_counts"]["High"], 1)
        validate_normalized_report(normalized)

    def test_stale_backup_evidence_creates_high_finding(self):
        normalized = normalize_backup_readiness(self.load_windows_sample(), SAMPLE_OUTPUT)

        stale = [item for item in normalized["findings"] if "STALE" in item["finding_id"]]
        self.assertEqual(len(stale), 1)
        self.assertEqual(stale[0]["severity"], "High")
        self.assertEqual(stale[0]["evidence"]["backup_evidence_source"], "expected_backup_path")
        self.assertIn("last_backup_evidence_timestamp", stale[0]["evidence"])

    def test_missing_expected_backup_path_creates_high_finding(self):
        normalized = normalize_backup_readiness(self.linux_sample(), "linux-backup-readiness.json")

        missing_path = [
            item
            for item in normalized["findings"]
            if item["evidence"].get("finding_type") == "ExpectedBackupPathMissing"
        ]
        self.assertEqual(len(missing_path), 1)
        self.assertEqual(missing_path[0]["severity"], "High")
        self.assertEqual(missing_path[0]["affected_object"], "/mnt/example-backups")

    def test_service_presence_alone_does_not_mark_backup_healthy(self):
        data = self.load_windows_sample()
        normalized = normalize_backup_readiness(data, SAMPLE_OUTPUT)

        self.assertEqual(data["Summary"]["BackupHealthStatus"], "Unverified")
        service_findings = [
            item
            for item in normalized["findings"]
            if item["evidence"].get("finding_type") == "BackupServicePresentHealthUnverified"
        ]
        self.assertEqual(len(service_findings), 1)
        self.assertEqual(service_findings[0]["severity"], "Info")
        self.assertEqual(service_findings[0]["evidence"]["backup_evidence_confidence"], "low")

    def test_restore_test_evidence_missing_is_governance_gap(self):
        normalized = normalize_backup_readiness(self.load_windows_sample(), SAMPLE_OUTPUT)

        restore = [
            item
            for item in normalized["findings"]
            if item["evidence"].get("finding_type") == "RestoreTestEvidenceMissing"
        ]
        self.assertEqual(len(restore), 1)
        self.assertEqual(restore[0]["severity"], "Medium")
        self.assertEqual(restore[0]["evidence"]["restore_test_evidence_status"], "missing")
        self.assertIn("Restore test evidence", restore[0]["object_type"])

    def test_normalized_output_schema_compatibility(self):
        validate_normalized_report(normalize_backup_readiness(self.load_windows_sample(), SAMPLE_OUTPUT))
        validate_normalized_report(normalize_backup_readiness(self.linux_sample(), "linux-backup-readiness.json"))

    def test_control_mapping_includes_backup_readiness(self):
        normalized = add_control_mappings(normalize_backup_readiness(self.load_windows_sample(), SAMPLE_OUTPUT))

        mapping = normalized["metadata"]["control_references_by_finding_id"]
        labels = {
            reference["label"]
            for references in mapping.values()
            for reference in references
        }
        self.assertIn("Data Recovery", labels)
        self.assertIn("Recovery Readiness", labels)
        self.assertIn("Data Protection", labels)
        self.assertIn("Operational Continuity", labels)

    def test_examples_do_not_collect_secrets_or_backup_contents(self):
        text = SAMPLE_OUTPUT.read_text(encoding="utf-8").lower()
        blocked_fragments = [
            "filecontents",
            "content_sample",
            "backup_payload",
            "private key",
            "api_key",
            "access_token",
            "password:",
            "corp.local",
            "contoso",
            "192.168.",
            "10.0.",
            "172.16.",
        ]

        for fragment in blocked_fragments:
            self.assertNotIn(fragment, text)
        self.assertIn("example", text)
        self.assertIn("not enumerated or read", text)

    def test_collectors_and_normalizer_do_not_add_external_service_dependencies(self):
        files = [
            ROOT / "scripts" / "windows" / "backup" / "Get-WindowsBackupReadinessAudit.ps1",
            ROOT / "scripts" / "linux" / "backup-readiness-audit.sh",
            ROOT / "SecureInfra_AI" / "scripts" / "reporting" / "secureinfra" / "normalizers" / "backup_readiness.py",
        ]
        blocked_fragments = ["Invoke-WebRequest", "curl ", "wget ", "requests", "boto3", "azure", "google-cloud"]

        for path in files:
            text = path.read_text(encoding="utf-8")
            for fragment in blocked_fragments:
                self.assertNotIn(fragment, text, f"{fragment} found in {path}")


if __name__ == "__main__":
    unittest.main()

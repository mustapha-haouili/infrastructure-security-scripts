import importlib.util
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SECUREINFRA_REPORTING = ROOT / "SecureInfra_AI" / "scripts" / "reporting"
SAMPLE_INPUT = ROOT / "SecureInfra_AI" / "examples" / "sample-input" / "active-directory" / "sample-ad-inactive-users.json"

sys.path.insert(0, str(SECUREINFRA_REPORTING))

from secureinfra.bundles.ad_shared_bundle import discover_ad_shared_bundle, normalize_ad_shared_bundle
from secureinfra.loaders.csv_loader import load_csv_file
from secureinfra.loaders.json_loader import load_json_file
from secureinfra.normalizers.ad_inactive_users import normalize_ad_inactive_users
from secureinfra.report_generator.markdown_report import generate_markdown_reports
from secureinfra.risk_engine.rules import classify_ad_inactive_user


ANALYZER_PATH = SECUREINFRA_REPORTING / "secureinfra_analyzer.py"
spec = importlib.util.spec_from_file_location("secureinfra_analyzer", ANALYZER_PATH)
secureinfra_analyzer = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = secureinfra_analyzer
spec.loader.exec_module(secureinfra_analyzer)


class SecureInfraAITests(unittest.TestCase):
    def create_ad_shared_bundle(self, root: Path, include_inactive_users: bool = True) -> Path:
        bundle_dir = root / "ad-shared"
        bundle_dir.mkdir()
        sample_data = load_json_file(SAMPLE_INPUT)
        if include_inactive_users:
            (bundle_dir / "inactive-users.json").write_text(json.dumps(sample_data), encoding="utf-8-sig")
        reports = {
            "password-never-expires.json": {
                "GeneratedAtUtc": "2026-06-08T09:00:00Z",
                "Domain": "example.local",
                "Summary": {"SampleRecords": 1},
                "PasswordNeverExpiresAccounts": [
                    {
                        "ReviewPriority": "High",
                        "AccountCategory": "ServiceAccountCandidate",
                        "SamAccountName": "svc-fixed-password",
                        "Enabled": True,
                        "PasswordNeverExpires": True,
                        "PasswordAgeDays": 420,
                        "HasSPN": False,
                        "PrivilegedGroupCount": 0,
                        "RiskFlags": ["PasswordNeverExpires", "OldPassword"],
                        "RecommendedAction": "Validate owner and exception status before rotation planning.",
                        "DistinguishedName": "CN=svc-fixed-password,OU=Service Accounts,DC=example,DC=local",
                    }
                ],
            },
            "service-accounts.json": {
                "GeneratedAtUtc": "2026-06-08T09:00:00Z",
                "Domain": "example.local",
                "Summary": {"SampleRecords": 1},
                "ServiceAccounts": [
                    {
                        "ReviewPriority": "High",
                        "AccountType": "UserServiceAccount",
                        "SamAccountName": "svc-legacy-api",
                        "Enabled": True,
                        "HasSPN": True,
                        "SPNCount": 1,
                        "PasswordNeverExpires": True,
                        "PasswordAgeDays": 365,
                        "PrivilegedGroupCount": 0,
                        "OwnerEvidenceMissing": True,
                        "RiskFlags": ["SPN", "PasswordNeverExpires", "MissingOwner"],
                        "RecommendedAction": "Confirm service owner and dependency before any change.",
                        "DistinguishedName": "CN=svc-legacy-api,OU=Service Accounts,DC=example,DC=local",
                    }
                ],
            },
            "spn-exposure.json": {
                "GeneratedAtUtc": "2026-06-08T09:00:00Z",
                "Domain": "example.local",
                "Summary": {"SampleRecords": 1},
                "SPNAccounts": [
                    {
                        "ExposurePriority": "High",
                        "SamAccountName": "app-web-legacy",
                        "Enabled": True,
                        "SPNCount": 2,
                        "ServicePrincipalNames": ["HTTP/app.example.local", "HTTP/app-web-legacy.example.local"],
                        "PasswordNeverExpires": True,
                        "PasswordAgeDays": 300,
                        "PrivilegedGroupCount": 0,
                        "EncryptionRisk": "UnknownOrDefault",
                        "RiskFlags": ["SPN", "PasswordNeverExpires", "EncryptionReview"],
                        "RecommendedAction": "Confirm application owner, SPN requirement, and rotation plan.",
                        "DistinguishedName": "CN=app-web-legacy,OU=Applications,DC=example,DC=local",
                    }
                ],
            },
            "stale-computers.json": {
                "GeneratedAtUtc": "2026-06-08T09:00:00Z",
                "Domain": "example.local",
                "Summary": {"SampleRecords": 1},
                "StaleComputers": [
                    {
                        "ReviewPriority": "Medium",
                        "ComputerCategory": "Server",
                        "Name": "EXAMPLE-SRV-OLD01",
                        "DNSHostName": "example-srv-old01.example.local",
                        "Enabled": True,
                        "InactiveDays": 180,
                        "CleanupReadiness": "Owner review required",
                        "CanDeleteNow": False,
                        "PotentialCleanupCandidate": False,
                        "IsDomainController": False,
                        "IsServerOS": True,
                        "HasSPN": True,
                        "SPNCount": 1,
                        "RiskFlags": ["Server", "SPN"],
                        "RecommendedAction": "Confirm server owner and service dependency before cleanup.",
                        "DistinguishedName": "CN=EXAMPLE-SRV-OLD01,OU=Servers,DC=example,DC=local",
                    }
                ],
            },
            "privileged-groups.json": {
                "GeneratedAtUtc": "2026-06-08T09:00:00Z",
                "Domain": "example.local",
                "Summary": {"SampleRecords": 1, "TotalChanges": 1},
                "Changes": [
                    {
                        "ChangeType": "Added",
                        "ActionPriority": "P1 - Immediate validation",
                        "Severity": "Critical",
                        "GroupName": "Domain Admins",
                        "GroupSID": "S-1-5-21-1111111111-2222222222-3333333333-512",
                        "GroupTier": "Tier0",
                        "MemberName": "Alex Admin",
                        "MemberSamAccountName": "alex.admin",
                        "MemberObjectClass": "user",
                        "MemberSID": "S-1-5-21-1111111111-2222222222-3333333333-1101",
                        "MemberDN": "CN=Alex Admin,OU=Admins,DC=example,DC=local",
                        "RiskFlagsText": "CriticalGroup",
                        "AdminAction": "Validate change ticket and privileged access approval before modifying membership.",
                        "VerificationStep": "Review group membership and recent privileged group change events.",
                    }
                ],
            },
            "privileged-identity-protection.json": {
                "GeneratedAtUtc": "2026-06-08T09:00:00Z",
                "Domain": "example.local",
                "Summary": {"SampleRecords": 1, "PrivilegedIdentityCount": 1},
                "Findings": [
                    {
                        "FindingType": "PrivilegedIdentityProtectionGap",
                        "Severity": "High",
                        "ActionPriority": "P2 - Protection gap review",
                        "Subject": "julia.admin",
                        "GroupName": "Domain Admins",
                        "Evidence": "Smartcard logon is not required and Protected Users membership was not observed.",
                        "AdminAction": "Validate owner evidence and privileged protection controls before any account change.",
                        "VerificationStep": "Review privileged group membership, smartcard requirement, and Protected Users membership.",
                    }
                ],
            },
            "gpo-health.json": {
                "GeneratedAtUtc": "2026-06-08T09:00:00Z",
                "Domain": "example.local",
                "Summary": {"SampleRecords": 1, "TotalFindings": 1},
                "Findings": [
                    {
                        "Severity": "High",
                        "ActionPriority": "P2 - Replication review",
                        "FindingType": "AdSysvolVersionMismatch",
                        "GpoId": "{11111111-2222-3333-4444-555555555555}",
                        "GpoName": "EX Workstation Baseline",
                        "TargetPath": "OU=Workstations,DC=example,DC=local",
                        "Title": "AD and SYSVOL GPO versions differ",
                        "Evidence": "User AD/SYSVOL=18/16; Computer AD/SYSVOL=20/20.",
                        "AdminAction": "Check DFSR/SYSVOL replication and GPO consistency before relying on this policy.",
                        "ChangeRisk": "High",
                        "VerificationStep": "Compare GPO status in GPMC and replication health.",
                        "Recommendation": "Review SYSVOL replication health and validate the policy before production changes.",
                    }
                ],
            },
        }
        for file_name, payload in reports.items():
            (bundle_dir / file_name).write_text(json.dumps(payload), encoding="utf-8-sig")
        return bundle_dir

    def test_sample_json_loads_correctly(self):
        data = load_json_file(SAMPLE_INPUT)

        self.assertEqual(data["Domain"], "example.local")
        self.assertEqual(len(data["InactiveUsers"]), 6)

    def test_json_loader_supports_utf8_bom(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bom.json"
            path.write_text('{"Domain": "example.local"}', encoding="utf-8-sig")

            data = load_json_file(path)

            self.assertEqual(data["Domain"], "example.local")

    def test_csv_loader_supports_utf8_bom(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bom.csv"
            path.write_text("Name,Domain\nEXAMPLE-DC01,example.local\n", encoding="utf-8-sig")

            rows = load_csv_file(path)

            self.assertEqual(rows, [{"Name": "EXAMPLE-DC01", "Domain": "example.local"}])

    def test_normalizer_creates_findings(self):
        data = load_json_file(SAMPLE_INPUT)
        report = normalize_ad_inactive_users(data, SAMPLE_INPUT)

        self.assertEqual(report["metadata"]["ai_required"], False)
        self.assertEqual(len(report["findings"]), 6)
        self.assertEqual(report["findings"][0]["finding_id"], "AD-INACTIVE-0001")
        self.assertEqual(report["findings"][0]["safe_to_auto_remediate"], False)

    def test_critical_risk_rule_works(self):
        risk = classify_ad_inactive_user(
            {
                "SamAccountName": "tier0.example",
                "Enabled": True,
                "InactiveDays": 120,
                "PrivilegedGroups": ["Domain Admins"],
                "HasSPN": False,
            }
        )

        self.assertEqual(risk["severity"], "Critical")
        self.assertEqual(risk["remediation_priority"], "Immediate Review")
        self.assertTrue(risk["requires_owner_review"])
        self.assertFalse(risk["safe_to_auto_remediate"])

    def test_hold_rule_works(self):
        risk = classify_ad_inactive_user(
            {
                "SamAccountName": "HealthMailbox-EXAMPLE-02",
                "Enabled": True,
                "InactiveDays": 300,
                "AccountCategory": "Exchange HealthMailbox",
                "RiskFlags": ["SystemManaged"],
            }
        )

        self.assertEqual(risk["severity"], "Hold")
        self.assertEqual(risk["remediation_priority"], "Hold")
        self.assertEqual(risk["status"], "Hold")

    def test_markdown_reports_are_generated(self):
        data = load_json_file(SAMPLE_INPUT)
        report = normalize_ad_inactive_users(data, SAMPLE_INPUT)

        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            paths = generate_markdown_reports(report, output_dir)

            self.assertEqual({path.name for path in paths}, {"executive-summary.md", "technical-findings.md", "remediation-plan.md"})
            self.assertIn("Overall Risk Summary", (output_dir / "executive-summary.md").read_text(encoding="utf-8"))
            self.assertIn("Technical Findings", (output_dir / "technical-findings.md").read_text(encoding="utf-8"))
            self.assertIn("Items Not Safe For Auto-Remediation", (output_dir / "remediation-plan.md").read_text(encoding="utf-8"))

    def test_cli_generates_normalized_and_markdown_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            with contextlib.redirect_stdout(io.StringIO()):
                exit_code = secureinfra_analyzer.main(
                    [
                        "--input",
                        str(SAMPLE_INPUT),
                        "--type",
                        "ad-inactive-users",
                        "--output",
                        str(output_dir),
                    ]
                )

            self.assertEqual(exit_code, 0)
            self.assertTrue((output_dir / "normalized-report.json").exists())
            self.assertTrue((output_dir / "executive-summary.md").exists())
            normalized = json.loads((output_dir / "normalized-report.json").read_text(encoding="utf-8"))
            self.assertEqual(normalized["summary"]["severity_counts"]["Critical"], 2)

    def test_ad_shared_discovers_known_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle_dir = self.create_ad_shared_bundle(Path(tmp))

            detected = discover_ad_shared_bundle(bundle_dir)

            self.assertIn("inactive_users", detected)
            self.assertIn("password_never_expires", detected)
            self.assertIn("privileged_identity_protection", detected)
            self.assertIn("gpo_health", detected)

    def test_ad_shared_directory_input_includes_inactive_user_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle_dir = self.create_ad_shared_bundle(Path(tmp))
            output_dir = Path(tmp) / "output"

            with contextlib.redirect_stdout(io.StringIO()):
                exit_code = secureinfra_analyzer.main(
                    [
                        "--input",
                        str(bundle_dir),
                        "--type",
                        "ad-shared",
                        "--output",
                        str(output_dir),
                        "--language",
                        "en",
                        "--format",
                        "markdown",
                    ]
                )

            self.assertEqual(exit_code, 0)
            normalized = json.loads((output_dir / "normalized-report.json").read_text(encoding="utf-8"))
            self.assertEqual(normalized["report_type"], "ad-shared")
            self.assertEqual(normalized["summary"]["normalized_finding_count"], 13)
            self.assertEqual(normalized["summary"]["severity_counts"]["Critical"], 3)
            self.assertIn("inactive_users", normalized["metadata"]["detected_files"])
            self.assertEqual(normalized["metadata"]["missing_files"], [])
            self.assertIn("gpo-health.json was normalized into detailed findings", " ".join(normalized["notes"]))
            self.assertTrue(any(item["finding_id"].startswith("AD-PNE-") for item in normalized["findings"]))
            self.assertTrue(any(item["finding_id"].startswith("AD-SVC-") for item in normalized["findings"]))
            self.assertTrue(any(item["finding_id"].startswith("AD-SPN-") for item in normalized["findings"]))
            self.assertTrue(any(item["finding_id"].startswith("AD-COMP-") for item in normalized["findings"]))
            self.assertTrue(any(item["finding_id"].startswith("AD-PGROUP-") for item in normalized["findings"]))
            self.assertTrue(any(item["finding_id"].startswith("AD-PID-") for item in normalized["findings"]))
            self.assertTrue(any(item["finding_id"].startswith("GPO-HEALTH-") for item in normalized["findings"]))
            self.assertTrue((output_dir / "executive-summary.md").exists())
            executive = (output_dir / "executive-summary.md").read_text(encoding="utf-8")
            self.assertIn("Detected AD Report Files", executive)
            self.assertIn("Limitations", executive)

    def test_direct_service_account_cli_generates_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle_dir = self.create_ad_shared_bundle(Path(tmp))
            output_dir = Path(tmp) / "output"

            with contextlib.redirect_stdout(io.StringIO()):
                exit_code = secureinfra_analyzer.main(
                    [
                        "--input",
                        str(bundle_dir / "service-accounts.json"),
                        "--type",
                        "ad-service-accounts",
                        "--output",
                        str(output_dir),
                    ]
                )

            self.assertEqual(exit_code, 0)
            normalized = json.loads((output_dir / "normalized-report.json").read_text(encoding="utf-8"))
            self.assertEqual(normalized["report_type"], "ad-service-accounts")
            self.assertEqual(normalized["summary"]["normalized_finding_count"], 1)
            self.assertEqual(normalized["findings"][0]["safe_to_auto_remediate"], False)

    def test_direct_gpo_health_cli_generates_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle_dir = self.create_ad_shared_bundle(Path(tmp))
            output_dir = Path(tmp) / "output"

            with contextlib.redirect_stdout(io.StringIO()):
                exit_code = secureinfra_analyzer.main(
                    [
                        "--input",
                        str(bundle_dir / "gpo-health.json"),
                        "--type",
                        "gpo-health",
                        "--output",
                        str(output_dir),
                    ]
                )

            self.assertEqual(exit_code, 0)
            normalized = json.loads((output_dir / "normalized-report.json").read_text(encoding="utf-8"))
            self.assertEqual(normalized["report_type"], "gpo-health")
            self.assertEqual(normalized["summary"]["normalized_finding_count"], 1)
            self.assertEqual(normalized["findings"][0]["finding_id"], "GPO-HEALTH-0001")
            self.assertEqual(normalized["findings"][0]["safe_to_auto_remediate"], False)

    def test_ad_shared_missing_optional_files_do_not_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle_dir = self.create_ad_shared_bundle(Path(tmp), include_inactive_users=False)

            report = normalize_ad_shared_bundle(bundle_dir)

            self.assertEqual(report["summary"]["normalized_finding_count"], 7)
            self.assertIn("inactive-users.json", report["metadata"]["missing_files"])
            self.assertIn("inactive-users.json was not found", " ".join(report["notes"]))

    def test_ad_inactive_users_rejects_directory_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            with contextlib.redirect_stderr(io.StringIO()):
                exit_code = secureinfra_analyzer.main(
                    [
                        "--input",
                        tmp,
                        "--type",
                        "ad-inactive-users",
                        "--output",
                        str(Path(tmp) / "output"),
                    ]
                )

            self.assertEqual(exit_code, 1)

    def test_no_real_customer_data_in_secureinfra_ai_samples(self):
        sample_root = ROOT / "SecureInfra_AI" / "examples"
        allowed_terms = {
            "example.local",
            "example gmbh",
            "example-dc01",
            "example",
            "alex admin",
            "julia reed",
        }
        blocked_fragments = [
            "mustapha",
            "haouili",
            "mh_laptop",
            "terminal2019",
            "contoso",
            "corp.local",
            "production.local",
            "administrator@",
            "192.168.",
            "10.0.",
            "172.16.",
        ]

        for path in sample_root.rglob("*"):
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8").lower()
            for fragment in blocked_fragments:
                self.assertNotIn(fragment, text, f"{fragment} found in {path}")
            self.assertTrue(any(term in text for term in allowed_terms), f"No fictional marker found in {path}")


if __name__ == "__main__":
    unittest.main()

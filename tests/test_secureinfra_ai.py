import importlib.util
import contextlib
import copy
import io
import json
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SECUREINFRA_REPORTING = ROOT / "SecureInfra_AI" / "scripts" / "reporting"
SAMPLE_INPUT = ROOT / "SecureInfra_AI" / "examples" / "sample-input" / "active-directory" / "sample-ad-inactive-users.json"

sys.path.insert(0, str(SECUREINFRA_REPORTING))

from secureinfra.bundles.ad_shared_bundle import discover_ad_shared_bundle, normalize_ad_shared_bundle
from secureinfra.loaders.csv_loader import load_csv_file
from secureinfra.loaders.json_loader import load_json_file
from secureinfra.normalizers.ad_inactive_users import normalize_ad_inactive_users
from secureinfra.normalizers.ad_privileged_identity import normalize_privileged_identity
from secureinfra.normalizers.ad_service_accounts import normalize_service_accounts
from secureinfra.normalizers.ad_spn_exposure import normalize_spn_exposure
from secureinfra.report_generator.markdown_report import generate_markdown_reports
from secureinfra.risk_engine.rules import classify_ad_inactive_user
from secureinfra.validators.schema_validator import SchemaValidationError, validate_normalized_report


ANALYZER_PATH = SECUREINFRA_REPORTING / "secureinfra_analyzer.py"
spec = importlib.util.spec_from_file_location("secureinfra_analyzer", ANALYZER_PATH)
secureinfra_analyzer = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = secureinfra_analyzer
spec.loader.exec_module(secureinfra_analyzer)


class SecureInfraAITests(unittest.TestCase):
    def built_in_admin_account_row(self) -> dict:
        return {
            "ReviewPriority": "Critical",
            "ExposurePriority": "Critical",
            "SamAccountName": "Administrator",
            "AccountCategory": "BuiltInAdministrator",
            "Enabled": True,
            "InactiveDays": 2014,
            "AdminCount": 1,
            "PrivilegedGroupCount": 1,
            "PrivilegedGroups": ["Domain Admins"],
            "PasswordNeverExpires": True,
            "HasSPN": True,
            "SPNCount": 1,
            "ServicePrincipalNames": ["HOST/example-dc01.example.local"],
            "RiskFlags": [
                "Enabled",
                "PasswordNeverExpires",
                "AdminCount1",
                "HasSPN",
                "PrivilegedGroupMember",
                "ServiceAccountCandidate",
            ],
            "ReviewReasons": ["Built-in Administrator requires governance review."],
            "DistinguishedName": "CN=Administrator,CN=Users,DC=example,DC=local",
            "ObjectSid": "S-1-5-21-1111111111-2222222222-3333333333-500",
        }

    def assert_evidence_contract(self, normalized: dict) -> None:
        for finding in normalized["findings"]:
            evidence = finding.get("evidence")
            self.assertIsInstance(evidence, dict, finding.get("finding_id"))
            self.assertTrue(evidence.get("summary"), finding.get("finding_id"))
            self.assertTrue(evidence.get("details"), finding.get("finding_id"))
            self.assertTrue(evidence.get("confidence"), finding.get("finding_id"))

    def assert_no_internal_paths(self, normalized: dict, *blocked_paths: Path) -> None:
        serialized = json.dumps(normalized, sort_keys=True).lower()
        for blocked in ["bundle_input", "downstream-reporting-workspace", "customer-projects", "c:\\", "d:\\"]:
            self.assertNotIn(blocked, serialized)
        for blocked_path in blocked_paths:
            self.assertNotIn(str(blocked_path).lower(), serialized)

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
                        "SamAccountName": "svc-legacy-api",
                        "Enabled": True,
                        "SPNCount": 2,
                        "ServicePrincipalNames": ["HTTP/app.example.local", "HTTP/app-web-legacy.example.local"],
                        "PasswordNeverExpires": True,
                        "PasswordAgeDays": 300,
                        "PrivilegedGroupCount": 0,
                        "EncryptionRisk": "UnknownOrDefault",
                        "RiskFlags": ["SPN", "PasswordNeverExpires", "EncryptionReview"],
                        "RecommendedAction": "Confirm application owner, SPN requirement, and rotation plan.",
                        "DistinguishedName": "CN=svc-legacy-api,OU=Applications,DC=example,DC=local",
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
                        "Subject": "alex.admin",
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

    def create_client_bundle(self, root: Path, machine_name: str = "EXAMPLE-SRV01") -> Path:
        bundle_dir = root / f"secureinfra-client-collection-{machine_name}-20260619-120000"
        bundle_dir.mkdir()
        self.create_ad_shared_bundle(bundle_dir)
        (bundle_dir / "client-info.json").write_text(
            json.dumps(
                {
                    "ComputerName": machine_name,
                    "UserDomain": "example",
                    "IsAdministrator": True,
                    "OsCaption": "Windows Server 2022",
                    "OsVersion": "10.0.20348",
                    "CollectionHostUtc": "2026-06-15T09:00:00Z",
                }
            ),
            encoding="utf-8",
        )
        (bundle_dir / "collection-summary.json").write_text(
            json.dumps(
                {
                    "CollectionId": f"secureinfra-client-{machine_name}-20260619-120000",
                    "GeneratedAtUtc": "2026-06-15T09:00:00Z",
                    "SafetyMode": "Audit and dry-run only. No remediation is applied.",
                    "ScopeResolved": ["AD", "Host", "Server"],
                    "TaskCount": 5,
                }
            ),
            encoding="utf-8",
        )
        (bundle_dir / "manifest.json").write_text(
            json.dumps(
                {
                    "SchemaVersion": "1.0",
                    "CollectionId": f"secureinfra-client-{machine_name}-20260619-120000",
                    "GeneratedAtUtc": "2026-06-15T09:00:00Z",
                    "ScopeResolved": ["AD", "Host", "Server"],
                    "Tasks": [],
                    "Files": [],
                }
            ),
            encoding="utf-8",
        )

        host_dir = bundle_dir / "host"
        events_dir = host_dir / "windows-events"
        server_dir = bundle_dir / "server"
        events_dir.mkdir(parents=True)
        server_dir.mkdir()

        (host_dir / "windows-security-audit.json").write_text(
            json.dumps(
                {
                    "ReportMetadata": {
                        "ComputerName": machine_name,
                        "GeneratedAtUtc": "2026-06-15T09:00:00Z",
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
                            "AutoFixEligible": True,
                            "RequiresAdmin": True,
                            "RiskLevel": "Medium",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        (events_dir / "summary.json").write_text(
            json.dumps(
                {
                    "ComputerName": machine_name,
                    "GeneratedAtUtc": "2026-06-15T09:00:00Z",
                    "InvestigationSummary": {
                        "Verdict": "Review high-priority indicators",
                        "FindingCount": 1,
                        "HighCount": 1,
                        "MediumCount": 0,
                        "Findings": [
                            {
                                "Severity": "High",
                                "Title": "Services were installed",
                                "WhyItMatters": "New services can be normal software installation or persistence.",
                                "Recommendation": "Verify service name, file path, vendor, and change ticket.",
                                "Evidence": "Count=1; Services=ExampleSvc [C:\\Program Files\\Example\\svc.exe]",
                            }
                        ],
                    },
                }
            ),
            encoding="utf-8",
        )
        (host_dir / "windows-remediation-plan.json").write_text(
            json.dumps(
                {
                    "ReportMetadata": {"ComputerName": machine_name, "GeneratedAtUtc": "2026-06-15T09:00:00Z"},
                    "Summary": {"PlanItemCount": 1},
                    "PlanItems": [{"PlanItemId": "PLAN-001-WIN-FW-001", "ApprovalStatus": "NotApproved"}],
                }
            ),
            encoding="utf-8",
        )
        (host_dir / "windows-hardening-preview.json").write_text(
            json.dumps(
                {
                    "ComputerName": machine_name,
                    "GeneratedAtUtc": "2026-06-15T09:00:00Z",
                    "Applied": False,
                    "Summary": {"TotalControls": 1},
                    "Results": [{"ControlId": "WIN-HARDEN-FW-001", "Status": "DryRun"}],
                }
            ),
            encoding="utf-8",
        )
        (server_dir / "windows-local-admins.json").write_text(
            json.dumps(
                {
                    "ToolName": "Get-WindowsLocalAdminInventory",
                    "ReportType": "windows-local-admin-inventory",
                    "GeneratedAtUtc": "2026-06-15T09:00:00Z",
                    "ComputerName": machine_name,
                    "Summary": {"FindingCount": 1},
                    "Findings": [
                        {
                            "FindingType": "DomainGroupLocalAdmin",
                            "Severity": "High",
                            "Principal": "EXAMPLE\\Server Admins",
                            "Title": "Domain group has local administrator rights",
                            "Evidence": "EXAMPLE\\Server Admins is a domain group in local Administrators.",
                            "Recommendation": "Confirm this group is approved for local administration.",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        (server_dir / "windows-rdp-exposure.json").write_text(
            json.dumps(
                {
                    "ToolName": "Get-WindowsRDPExposureAudit",
                    "ReportType": "windows-rdp-exposure",
                    "GeneratedAtUtc": "2026-06-15T09:00:00Z",
                    "ComputerName": machine_name,
                    "Summary": {"FindingCount": 1, "RdpEnabled": True},
                    "Findings": [
                        {
                            "FindingType": "RdpEnabled",
                            "Severity": "Medium",
                            "Title": "Remote Desktop is enabled",
                            "Evidence": "fDenyTSConnections=0; TermService=Running; Port=3389.",
                            "Recommendation": "Confirm RDP is business-required and restricted.",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        (server_dir / "rdp-profile-cache-cleanup.json").write_text(
            json.dumps(
                {
                    "ComputerName": machine_name,
                    "GeneratedAtUtc": "2026-06-15T09:00:00Z",
                    "Mode": "DryRun",
                    "ProfileRoot": "C:\\Users",
                    "MinimumAgeDays": 14,
                    "ProfileCount": 4,
                    "SkippedProfileCount": 0,
                    "CandidateFiles": 12,
                    "CandidateBytes": 1048576,
                    "FailedFiles": 0,
                    "Profiles": [],
                }
            ),
            encoding="utf-8",
        )
        return bundle_dir

    def add_expanded_scope_reports(self, bundle_dir: Path, machine_name: str = "EXAMPLE-SRV01") -> None:
        network_dir = bundle_dir / "network"
        server_dir = bundle_dir / "server"
        workstation_dir = bundle_dir / "workstation"
        network_dir.mkdir(exist_ok=True)
        server_dir.mkdir(exist_ok=True)
        workstation_dir.mkdir(exist_ok=True)

        (network_dir / "windows-network-exposure.json").write_text(
            json.dumps(
                {
                    "ToolName": "Get-WindowsNetworkExposureAudit",
                    "ReportType": "windows-network-exposure",
                    "GeneratedAtUtc": "2026-06-15T09:00:00Z",
                    "ComputerName": machine_name,
                    "Summary": {"FindingCount": 2},
                    "Findings": [
                        {
                            "FindingType": "FirewallProfileDisabled",
                            "Severity": "High",
                            "Name": "Public",
                            "Title": "Windows Firewall profile is disabled",
                            "Evidence": "Public profile Enabled=False.",
                            "Recommendation": "Enable the firewall profile after validating approved rules.",
                        },
                        {
                            "FindingType": "RiskyListeningPort",
                            "Severity": "High",
                            "Name": "TCP 3389",
                            "Title": "Sensitive TCP port is listening",
                            "Evidence": "TCP 3389 is listening on all interfaces by process svchost.",
                            "Recommendation": "Confirm the listener is required and restricted.",
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )
        (server_dir / "windows-server-security.json").write_text(
            json.dumps(
                {
                    "ToolName": "Get-WindowsServerSecurityInventory",
                    "ReportType": "windows-server-security-inventory",
                    "GeneratedAtUtc": "2026-06-15T09:00:00Z",
                    "ComputerName": machine_name,
                    "Summary": {"FindingCount": 2},
                    "Findings": [
                        {
                            "FindingType": "ServiceRunsAsCustomAccount",
                            "Severity": "High",
                            "Name": "LegacyAppSvc",
                            "Title": "Service runs as a custom or domain account",
                            "Evidence": "LegacyAppSvc starts as EXAMPLE\\svc-legacy.",
                            "Recommendation": "Confirm owner, rotation, and least privilege.",
                        },
                        {
                            "FindingType": "BroadSmbShareAccess",
                            "Severity": "High",
                            "Name": "Projects",
                            "Title": "SMB share grants broad access",
                            "Evidence": "Projects grants Change to Everyone.",
                            "Recommendation": "Validate business need and narrow share permissions.",
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )
        (workstation_dir / "windows-workstation-security.json").write_text(
            json.dumps(
                {
                    "ToolName": "Get-WindowsWorkstationSecurityInventory",
                    "ReportType": "windows-workstation-security-inventory",
                    "GeneratedAtUtc": "2026-06-15T09:00:00Z",
                    "ComputerName": machine_name,
                    "Summary": {"FindingCount": 2},
                    "Findings": [
                        {
                            "FindingType": "DefenderRealTimeProtectionDisabled",
                            "Severity": "High",
                            "Name": "Defender",
                            "Title": "Defender real-time protection is disabled",
                            "Evidence": "RealTimeProtectionEnabled=False.",
                            "Recommendation": "Re-enable real-time protection unless an approved exception exists.",
                        },
                        {
                            "FindingType": "BitLockerVolumeNotProtected",
                            "Severity": "High",
                            "Name": "C:",
                            "Title": "Fixed volume is not fully protected by BitLocker",
                            "Evidence": "C: ProtectionStatus=Off.",
                            "Recommendation": "Confirm encryption policy and enable BitLocker through endpoint management.",
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )

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

    def test_normalized_report_schema_validation_accepts_valid_report(self):
        data = load_json_file(SAMPLE_INPUT)
        report = normalize_ad_inactive_users(data, SAMPLE_INPUT)

        validate_normalized_report(report)

    def test_normalized_report_schema_validation_rejects_missing_finding_field(self):
        data = load_json_file(SAMPLE_INPUT)
        report = normalize_ad_inactive_users(data, SAMPLE_INPUT)
        invalid_report = copy.deepcopy(report)
        del invalid_report["findings"][0]["severity"]

        with self.assertRaisesRegex(SchemaValidationError, r"\$\.findings\[0\]\.severity"):
            validate_normalized_report(invalid_report)

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

    def test_ad_account_missing_values_remain_unknown(self):
        data = {
            "GeneratedAtUtc": "2026-06-08T09:00:00Z",
            "InactiveUsers": [
                {
                    "SamAccountName": "review.user",
                    "ReviewPriority": "Medium",
                    "AccountCategory": "StandardUser",
                    "RiskFlags": [],
                    "ReviewReasons": [],
                }
            ],
        }

        report = normalize_ad_inactive_users(data, SAMPLE_INPUT)
        evidence = report["findings"][0]["evidence"]

        self.assertIsNone(evidence["enabled"])
        self.assertIsNone(evidence["inactive_days"])
        self.assertIsNone(evidence["admin_count"])
        self.assertIsNone(evidence["password_never_expires"])
        self.assertEqual(evidence["activity_evidence_source"], "Not collected")
        self.assertEqual(evidence["activity_evidence_confidence"], "Needs Corroboration")
        self.assertTrue(evidence["activity_validation_required"])

    def test_service_account_classification_requires_strong_indicator(self):
        data = {
            "GeneratedAtUtc": "2026-06-08T09:00:00Z",
            "ServiceAccounts": [
                {
                    "ReviewPriority": "Medium",
                    "SamAccountName": "standard.user",
                    "AdminCount": 1,
                    "OwnerEvidenceMissing": True,
                    "RiskFlags": ["PrivilegedAccess", "MissingOwner"],
                },
                {
                    "ReviewPriority": "High",
                    "SamAccountName": "svc-api",
                    "HasSPN": True,
                    "SPNCount": 1,
                    "RiskFlags": ["SPN"],
                },
            ],
        }

        report = normalize_service_accounts(data, SAMPLE_INPUT)
        residue = report["findings"][0]
        service = report["findings"][1]

        self.assertEqual(residue["evidence"]["classification"], "Privileged Residue Candidates")
        self.assertEqual(residue["evidence"]["service_account_confidence"], "Low")
        self.assertEqual(residue["object_type"], "Active Directory account review candidate")
        self.assertNotIn("service account requires", residue["title"].lower())
        self.assertEqual(service["evidence"]["classification"], "Strict Service Accounts")
        self.assertEqual(service["evidence"]["service_account_confidence"], "High")
        self.assertEqual(service["object_type"], "Active Directory service account")

    def test_built_in_administrator_with_spn_is_not_strict_service_account(self):
        data = {
            "GeneratedAtUtc": "2026-06-08T09:00:00Z",
            "ServiceAccounts": [self.built_in_admin_account_row()],
        }

        report = normalize_service_accounts(data, SAMPLE_INPUT)
        finding = report["findings"][0]
        evidence = finding["evidence"]

        self.assertEqual(evidence["classification"], "Built-in Administrator Governance Review")
        self.assertEqual(evidence["service_account_confidence"], "NotApplicable")
        self.assertNotEqual(evidence["classification"], "Strict Service Accounts")
        self.assertNotIn("ServiceAccountCandidate", evidence["risk_flags"])
        self.assertNotIn("service account", evidence["summary"].lower())
        self.assertIn("built-in administrator account", evidence["summary"])
        self.assertIn("enabled: true", evidence["summary"])
        self.assertIn("inactivity evidence: 2014 days", evidence["summary"])
        self.assertIn("AdminCount=1", evidence["summary"])
        self.assertIn("PasswordNeverExpires: true", evidence["summary"])
        self.assertIn("SPN/dependency review required", evidence["summary"])
        self.assertIn("password custody", finding["recommendation"])
        self.assertFalse(finding["safe_to_auto_remediate"])

    def test_built_in_administrator_password_and_admincount_are_privileged_governance(self):
        data = {
            "GeneratedAtUtc": "2026-06-08T09:00:00Z",
            "InactiveUsers": [self.built_in_admin_account_row()],
        }

        report = normalize_ad_inactive_users(data, SAMPLE_INPUT)
        finding = report["findings"][0]
        evidence = finding["evidence"]

        self.assertEqual(finding["severity"], "Critical")
        self.assertEqual(finding["title"], "Built-in Administrator enabled and inactive")
        self.assertEqual(evidence["classification"], "Built-in Administrator Governance Review")
        self.assertEqual(evidence["service_account_confidence"], "NotApplicable")
        self.assertNotIn("ServiceAccountCandidate", evidence["risk_flags"])
        self.assertNotIn("ServiceAccountCandidate", finding["risk_factors"])
        self.assertIn("break-glass purpose", finding["recommendation"])
        self.assertIn("password custody", finding["recommendation"])
        self.assertIn("change approval", finding["recommendation"])
        self.assertNotIn("delete", finding["recommendation"].lower().replace("do not delete", ""))
        self.assertFalse(finding["safe_to_auto_remediate"])

    def test_spn_on_built_in_administrator_is_dependency_review_not_service_classification(self):
        data = {
            "GeneratedAtUtc": "2026-06-08T09:00:00Z",
            "SPNAccounts": [self.built_in_admin_account_row()],
        }

        report = normalize_spn_exposure(data, SAMPLE_INPUT)
        finding = report["findings"][0]
        evidence = finding["evidence"]

        self.assertEqual(evidence["classification"], "Built-in Administrator Governance Review")
        self.assertEqual(evidence["service_account_confidence"], "NotApplicable")
        self.assertNotEqual(evidence["classification"], "Strict Service Accounts")
        self.assertIn("SPN/dependency review required", evidence["summary"])
        self.assertIn("SPN exposure", finding["technical_impact"])
        self.assertIn("SPN/dependency exposure", finding["recommendation"])
        self.assertNotIn("ServiceAccountCandidate", evidence["risk_flags"])

    def test_privileged_identity_missing_activity_is_not_zero_or_false(self):
        data = {
            "GeneratedAtUtc": "2026-06-08T09:00:00Z",
            "Findings": [
                {
                    "FindingType": "PrivilegedIdentityProtectionGap",
                    "Severity": "High",
                    "Subject": "admin.user",
                    "GroupName": "Domain Admins",
                    "Evidence": "Protected Users membership was not observed.",
                    "AdminAction": "Validate protection controls.",
                }
            ],
        }

        report = normalize_privileged_identity(data, SAMPLE_INPUT)
        evidence = report["findings"][0]["evidence"]

        self.assertIsNone(evidence["enabled"])
        self.assertIsNone(evidence["inactive_days"])
        self.assertIsNone(evidence["password_never_expires"])
        self.assertEqual(evidence["activity_evidence_confidence"], "Needs Corroboration")
        self.assertTrue(evidence["activity_validation_required"])

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

    def test_cli_schema_validation_failure_stops_output(self):
        original_normalizer = secureinfra_analyzer.NORMALIZER_BY_TYPE["ad-inactive-users"]

        def invalid_normalizer(data, source_file):
            report = original_normalizer(data, source_file)
            report["findings"][0]["severity"] = "Urgent"
            return report

        secureinfra_analyzer.NORMALIZER_BY_TYPE["ad-inactive-users"] = invalid_normalizer
        try:
            with tempfile.TemporaryDirectory() as tmp:
                output_dir = Path(tmp) / "output"
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as stderr:
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

                self.assertEqual(exit_code, 1)
                self.assertIn("Normalized report schema validation failed", stderr.getvalue())
                self.assertFalse((output_dir / "normalized-report.json").exists())
        finally:
            secureinfra_analyzer.NORMALIZER_BY_TYPE["ad-inactive-users"] = original_normalizer

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
            self.assertGreaterEqual(normalized["summary"]["correlation_count"], 2)
            self.assert_evidence_contract(normalized)
            self.assertIn("inactive_users", normalized["metadata"]["detected_files"])
            self.assertEqual(normalized["metadata"]["missing_files"], [])
            self.assertIn("gpo-health.json was normalized into detailed findings", " ".join(normalized["notes"]))
            correlation_keys = {item["normalized_key"] for item in normalized["correlations"]}
            self.assertIn("alex.admin", correlation_keys)
            self.assertIn("svc-legacy-api", correlation_keys)
            self.assertTrue(
                any(
                    "AD-PGROUP-0001" in item["finding_ids"] and "AD-PID-0001" in item["finding_ids"]
                    for item in normalized["correlations"]
                )
            )
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

    def test_ad_shared_collection_root_input_resolves_ad_shared_subdirectory(self):
        with tempfile.TemporaryDirectory() as tmp:
            collection_root = Path(tmp)
            bundle_dir = self.create_ad_shared_bundle(collection_root)
            (collection_root / "manifest.json").write_text(json.dumps({"tool": "collector"}), encoding="utf-8")
            output_dir = collection_root / "output"

            with contextlib.redirect_stdout(io.StringIO()):
                exit_code = secureinfra_analyzer.main(
                    [
                        "--input",
                        str(collection_root),
                        "--type",
                        "ad-shared",
                        "--output",
                        str(output_dir),
                    ]
                )

            self.assertEqual(exit_code, 0)
            normalized = json.loads((output_dir / "normalized-report.json").read_text(encoding="utf-8"))
            self.assertEqual(normalized["summary"]["detected_file_count"], 8)
            self.assertEqual(normalized["summary"]["missing_optional_file_count"], 0)
            self.assertEqual(normalized["environment_summary"]["bundle_directory"], "ad-shared")
            self.assert_no_internal_paths(normalized, collection_root, bundle_dir)

    def test_client_bundle_directory_input_combines_ad_host_and_server_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle_dir = self.create_client_bundle(Path(tmp))
            output_dir = Path(tmp) / "output"

            with contextlib.redirect_stdout(io.StringIO()):
                exit_code = secureinfra_analyzer.main(
                    [
                        "--input",
                        str(bundle_dir),
                        "--type",
                        "client-bundle",
                        "--output",
                        str(output_dir),
                    ]
                )

            self.assertEqual(exit_code, 0)
            normalized = json.loads((output_dir / "normalized-report.json").read_text(encoding="utf-8"))
            self.assertEqual(normalized["report_type"], "client-bundle")
            self.assertEqual(normalized["summary"]["normalized_finding_count"], 18)
            self.assertEqual(normalized["summary"]["scope_finding_counts"]["AD"], 13)
            self.assertEqual(normalized["summary"]["scope_finding_counts"]["Host"], 2)
            self.assertEqual(normalized["summary"]["scope_finding_counts"]["Server"], 3)
            self.assertEqual(normalized["summary"]["scope_finding_counts"]["Workstation"], 0)
            self.assertEqual(normalized["environment_summary"]["computer_name"], "EXAMPLE-SRV01")
            self.assertIn("host_windows_remediation_plan", normalized["metadata"]["loaded_files"])
            self.assertIn("host_windows_hardening_preview", normalized["metadata"]["loaded_files"])
            finding_ids = {item["finding_id"] for item in normalized["findings"]}
            self.assertIn("HOST-WIN-WIN-FW-001", finding_ids)
            self.assertIn("HOST-EVENT-SERVICE-INSTALLATIONS", finding_ids)
            self.assertIn("SERVER-RDP-CACHE-0001", finding_ids)
            event_finding = next(item for item in normalized["findings"] if item["finding_id"] == "HOST-EVENT-SERVICE-INSTALLATIONS")
            self.assertEqual(event_finding["evidence"]["event_ids"], [7045])
            self.assertEqual(event_finding["evidence"]["finding_type"], "WindowsEventSecurityIndicator")
            self.assert_evidence_contract(normalized)
            self.assert_no_internal_paths(normalized, bundle_dir)

    def test_client_bundle_zip_input_is_supported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle_dir = self.create_client_bundle(root)
            archive_path = root / "secureinfra-client-collection.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                for path in bundle_dir.rglob("*"):
                    if path.is_file():
                        archive.write(path, path.relative_to(bundle_dir))
            output_dir = root / "output"

            with contextlib.redirect_stdout(io.StringIO()):
                exit_code = secureinfra_analyzer.main(
                    [
                        "--input",
                        str(archive_path),
                        "--type",
                        "client-bundle",
                        "--output",
                        str(output_dir),
                    ]
                )

            self.assertEqual(exit_code, 0)
            normalized = json.loads((output_dir / "normalized-report.json").read_text(encoding="utf-8"))
            self.assertEqual(normalized["report_type"], "client-bundle")
            self.assertEqual(normalized["summary"]["normalized_finding_count"], 18)
            self.assertTrue(any("secureinfra-client-collection.zip!" in value for value in normalized["source_files"]))
            self.assert_no_internal_paths(normalized, root, archive_path)

    def test_client_bundle_normalizes_expanded_network_server_and_workstation_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle_dir = self.create_client_bundle(root)
            self.add_expanded_scope_reports(bundle_dir)
            output_dir = root / "output"

            with contextlib.redirect_stdout(io.StringIO()):
                exit_code = secureinfra_analyzer.main(
                    [
                        "--input",
                        str(bundle_dir),
                        "--type",
                        "client-bundle",
                        "--output",
                        str(output_dir),
                    ]
                )

            self.assertEqual(exit_code, 0)
            normalized = json.loads((output_dir / "normalized-report.json").read_text(encoding="utf-8"))
            self.assertEqual(normalized["summary"]["normalized_finding_count"], 24)
            self.assertEqual(normalized["summary"]["scope_finding_counts"]["Network"], 2)
            self.assertEqual(normalized["summary"]["scope_finding_counts"]["Server"], 5)
            self.assertEqual(normalized["summary"]["scope_finding_counts"]["Workstation"], 2)
            self.assertEqual(normalized["summary"]["scope_file_counts"]["Network"], 1)
            finding_ids = {item["finding_id"] for item in normalized["findings"]}
            self.assertTrue(any(item.startswith("NETWORK-EXPOSURE-") for item in finding_ids))
            self.assertTrue(any(item.startswith("SERVER-SECURITY-") for item in finding_ids))
            self.assertTrue(any(item.startswith("WORKSTATION-SECURITY-") for item in finding_ids))
            self.assertIn("network_windows_network_exposure", normalized["metadata"]["loaded_files"])
            self.assertIn("server_windows_server_security", normalized["metadata"]["loaded_files"])
            self.assertIn("workstation_windows_workstation_security", normalized["metadata"]["loaded_files"])

    def test_multi_bundle_keeps_server_security_finding_ids_unique(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fleet_dir = root / "fleet-input"
            fleet_dir.mkdir()
            bundle_dir = self.create_client_bundle(fleet_dir, machine_name="DEMO-SERVER")
            self.add_expanded_scope_reports(bundle_dir, machine_name="DEMO-SERVER")
            server_report_path = bundle_dir / "server" / "windows-server-security.json"
            server_report = json.loads(server_report_path.read_text(encoding="utf-8"))
            server_report["Findings"].append(
                {
                    "FindingType": "BroadSmbShareAccess",
                    "Severity": "Medium",
                    "Name": "Projects",
                    "Title": "SMB share grants broad access",
                    "Evidence": "Projects grants Read to Authenticated Users.",
                    "Recommendation": "Validate business need and narrow share permissions.",
                }
            )
            server_report["Summary"]["FindingCount"] = len(server_report["Findings"])
            server_report_path.write_text(json.dumps(server_report), encoding="utf-8")
            output_dir = root / "output"

            with contextlib.redirect_stdout(io.StringIO()):
                exit_code = secureinfra_analyzer.main(
                    [
                        "--input",
                        str(fleet_dir),
                        "--type",
                        "multi-bundle",
                        "--output",
                        str(output_dir),
                    ]
                )

            self.assertEqual(exit_code, 0)
            normalized = json.loads((output_dir / "normalized-report.json").read_text(encoding="utf-8"))
            finding_ids = [item["finding_id"] for item in normalized["findings"]]
            self.assertEqual(len(finding_ids), len(set(finding_ids)))
            self.assertTrue(
                any("BROADSMBSHAREACCESS-PROJECTS" in finding_id for finding_id in finding_ids),
                finding_ids,
            )
            validate_normalized_report(normalized)

    def test_multi_bundle_directory_input_combines_many_client_bundles(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fleet_dir = root / "fleet-input"
            fleet_dir.mkdir()
            self.create_client_bundle(fleet_dir, machine_name="EXAMPLE-SRV01")
            zipped_bundle = self.create_client_bundle(fleet_dir, machine_name="EXAMPLE-SRV02")
            archive_path = fleet_dir / "secureinfra-client-collection-EXAMPLE-SRV02.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                for path in zipped_bundle.rglob("*"):
                    if path.is_file():
                        archive.write(path, path.relative_to(zipped_bundle))
            shutil.rmtree(zipped_bundle)
            output_dir = root / "output"

            with contextlib.redirect_stdout(io.StringIO()):
                exit_code = secureinfra_analyzer.main(
                    [
                        "--input",
                        str(fleet_dir),
                        "--type",
                        "multi-bundle",
                        "--output",
                        str(output_dir),
                    ]
                )

            self.assertEqual(exit_code, 0)
            normalized = json.loads((output_dir / "normalized-report.json").read_text(encoding="utf-8"))
            self.assertEqual(normalized["report_type"], "multi-bundle")
            self.assertEqual(normalized["summary"]["normalized_finding_count"], 36)
            self.assertEqual(normalized["summary"]["loaded_bundle_count"], 2)
            self.assertEqual(normalized["summary"]["machine_count"], 2)
            self.assertEqual(normalized["summary"]["scope_finding_counts"]["AD"], 26)
            self.assertEqual(normalized["summary"]["scope_finding_counts"]["Host"], 4)
            self.assertEqual(normalized["summary"]["scope_finding_counts"]["Server"], 6)
            machine_names = {item["machine_name"] for item in normalized["report_type_metadata"]["machine_inventory"]}
            self.assertEqual(machine_names, {"EXAMPLE-SRV01", "EXAMPLE-SRV02"})
            self.assertEqual(len(normalized["report_type_metadata"]["coverage_matrix"]), 14)
            finding_ids = [item["finding_id"] for item in normalized["findings"]]
            self.assertEqual(len(finding_ids), len(set(finding_ids)))
            self.assertTrue(all(item.startswith("FLEET-") for item in finding_ids))
            evidence_machines = {item["evidence"]["machine_name"] for item in normalized["findings"]}
            self.assertEqual(evidence_machines, {"EXAMPLE-SRV01", "EXAMPLE-SRV02"})
            self.assertTrue(any(str(value).endswith(".zip!ad-shared") for value in normalized["source_files"]))
            self.assert_evidence_contract(normalized)
            self.assert_no_internal_paths(normalized, root, fleet_dir)

    def test_multi_bundle_skips_duplicate_collection_zip_and_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fleet_dir = root / "fleet-input"
            fleet_dir.mkdir()
            bundle_dir = self.create_client_bundle(fleet_dir, machine_name="EXAMPLE-SRV01")
            archive_path = fleet_dir / "secureinfra-client-collection-EXAMPLE-SRV01.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                for path in bundle_dir.rglob("*"):
                    if path.is_file():
                        archive.write(path, path.relative_to(bundle_dir))
            output_dir = root / "output"

            with contextlib.redirect_stdout(io.StringIO()):
                exit_code = secureinfra_analyzer.main(
                    [
                        "--input",
                        str(fleet_dir),
                        "--type",
                        "multi-bundle",
                        "--output",
                        str(output_dir),
                    ]
                )

            self.assertEqual(exit_code, 0)
            normalized = json.loads((output_dir / "normalized-report.json").read_text(encoding="utf-8"))
            self.assertEqual(normalized["summary"]["detected_bundle_count"], 2)
            self.assertEqual(normalized["summary"]["loaded_bundle_count"], 1)
            self.assertEqual(normalized["summary"]["skipped_bundle_count"], 1)
            self.assertEqual(normalized["summary"]["normalized_finding_count"], 18)
            self.assertEqual(len(normalized["report_type_metadata"]["skipped_bundles"]), 1)

    def test_cli_with_previous_report_adds_history_comparison(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bundle_dir = self.create_ad_shared_bundle(root)
            output_dir = root / "output"
            previous_path = root / "previous-normalized-report.json"
            previous_path.write_text(
                json.dumps(
                    {
                        "report_id": "previous-secureinfra-run",
                        "generated_at_utc": "2026-06-01T09:00:00Z",
                        "findings": [
                            {
                                "finding_id": "AD-PGROUP-0001",
                                "title": "Previous privileged group finding",
                                "severity": "Critical",
                                "affected_object": "alex.admin",
                                "source_script": "Watch-ADPrivilegedGroupChanges.ps1",
                            },
                            {
                                "finding_id": "AD-OLD-0001",
                                "title": "Old service account finding",
                                "severity": "Medium",
                                "affected_object": "svc-retired",
                                "source_script": "Get-ADServiceAccountAudit.ps1",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )

            with contextlib.redirect_stdout(io.StringIO()):
                exit_code = secureinfra_analyzer.main(
                    [
                        "--input",
                        str(bundle_dir),
                        "--type",
                        "ad-shared",
                        "--output",
                        str(output_dir),
                        "--previous-normalized-report",
                        str(previous_path),
                    ]
                )

            self.assertEqual(exit_code, 0)
            normalized = json.loads((output_dir / "normalized-report.json").read_text(encoding="utf-8"))
            history = normalized["history_comparison"]
            self.assertEqual(history["previous_report_id"], "previous-secureinfra-run")
            self.assertEqual(history["matched_on"], "finding_id")
            self.assertIn("AD-PGROUP-0001", history["persistent_finding_ids"])
            self.assertIn("AD-OLD-0001", history["resolved_finding_ids"])
            self.assertIn("GPO-HEALTH-0001", history["new_finding_ids"])
            self.assertEqual(normalized["summary"]["persistent_finding_count"], len(history["persistent_finding_ids"]))
            self.assertEqual(normalized["summary"]["resolved_finding_count"], 1)
            self.assertEqual(history["resolved_findings"][0]["finding_id"], "AD-OLD-0001")
            executive = (output_dir / "executive-summary.md").read_text(encoding="utf-8")
            self.assertIn("Historical Comparison", executive)
            self.assertIn("Resolved findings: 1", executive)

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
            evidence = normalized["findings"][0]["evidence"]
            self.assertEqual(evidence["summary"], "User AD/SYSVOL=18/16; Computer AD/SYSVOL=20/20.")
            self.assertIn("finding_type: AdSysvolVersionMismatch", evidence["details"])
            self.assertIn("gpo_name: EX Workstation Baseline", evidence["details"])
            self.assertIn("admin_action: Check DFSR/SYSVOL replication", evidence["details"])
            self.assertIn("verification_step: Compare GPO status", evidence["details"])
            self.assertIn("recommendation: Review SYSVOL replication health", evidence["details"])
            self.assertIn("affected_object: EX Workstation Baseline", evidence["details"])
            self.assertIn("evidence", evidence["key_fields"])
            self.assert_no_internal_paths(normalized, bundle_dir)

    def test_gpo_evidence_contract_uses_structured_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            gpo_path = root / "gpo-health.json"
            output_dir = root / "output"
            gpo_path.write_text(
                json.dumps(
                    {
                        "GeneratedAtUtc": "2026-06-08T09:00:00Z",
                        "Domain": "example.local",
                        "Findings": [
                            {
                                "Severity": "Medium",
                                "ActionPriority": "P3 - Policy cleanup review",
                                "FindingType": "LegacyKeywordMatch",
                                "GpoName": "EX Legacy Baseline",
                                "TargetPath": "OU=Servers,DC=example,DC=local",
                                "Title": "Legacy keyword found in GPO evidence",
                                "Evidence": "Matched legacy keyword 'Windows Server 2003'.",
                                "AdminAction": "Review whether the setting is still required.",
                                "ChangeRisk": "Medium",
                                "VerificationStep": "Confirm the policy setting in GPMC before changing it.",
                                "Recommendation": "Export the GPO and test any cleanup in a staged OU first.",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            with contextlib.redirect_stdout(io.StringIO()):
                exit_code = secureinfra_analyzer.main(
                    [
                        "--input",
                        str(gpo_path),
                        "--type",
                        "gpo-health",
                        "--output",
                        str(output_dir),
                    ]
                )

            self.assertEqual(exit_code, 0)
            normalized = json.loads((output_dir / "normalized-report.json").read_text(encoding="utf-8"))
            evidence = normalized["findings"][0]["evidence"]
            self.assertEqual(evidence["summary"], "Matched legacy keyword 'Windows Server 2003'.")
            self.assertIn("finding_type: LegacyKeywordMatch", evidence["details"])
            self.assertIn("action_priority: P3 - Policy cleanup review", evidence["details"])
            self.assertIn("change_risk: Medium", evidence["details"])
            self.assertIn("gpo_name: EX Legacy Baseline", evidence["details"])
            self.assertIn("admin_action: Review whether the setting is still required.", evidence["details"])
            self.assertIn("verification_step: Confirm the policy setting in GPMC", evidence["details"])
            self.assertIn("recommendation: Export the GPO", evidence["details"])
            self.assertEqual(evidence["confidence"], "Medium")
            self.assert_no_internal_paths(normalized, root, gpo_path)

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

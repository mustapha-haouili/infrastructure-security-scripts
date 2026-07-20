import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SECUREINFRA_REPORTING = ROOT / "SecureInfra_AI" / "scripts" / "reporting"
WINDOWS_SAMPLE_ROOT = ROOT / "SecureInfra_AI" / "examples" / "sample-input" / "windows"

sys.path.insert(0, str(SECUREINFRA_REPORTING))

from secureinfra.loaders.json_loader import load_json_file
from secureinfra.bundles.client_bundle import normalize_client_source_file
from secureinfra.network_context.port_catalog import lookup_port_context
from secureinfra.normalizers.windows_host import normalize_windows_host_audit
from secureinfra.normalizers.windows_network import normalize_windows_network_exposure
from secureinfra.normalizers.windows_server import normalize_windows_server_audit
from secureinfra.normalizers.windows_workstation import normalize_windows_workstation_audit
from secureinfra.report_generator.markdown_report import generate_markdown_reports
from secureinfra.validators.schema_validator import SchemaValidationError, validate_normalized_report


ANALYZER_PATH = SECUREINFRA_REPORTING / "secureinfra_analyzer.py"
spec = importlib.util.spec_from_file_location("secureinfra_windows_analyzer", ANALYZER_PATH)
secureinfra_analyzer = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = secureinfra_analyzer
spec.loader.exec_module(secureinfra_analyzer)


WINDOWS_SAMPLE_CASES = [
    {
        "report_type": "windows-host-audit",
        "path": WINDOWS_SAMPLE_ROOT / "sample-windows-host-security-audit.json",
        "normalizer": normalize_windows_host_audit,
        "computer_name": "LAB-DC01",
        "scope": "Host",
        "finding_prefix": "HOST-WIN-",
    },
    {
        "report_type": "windows-server-audit",
        "path": WINDOWS_SAMPLE_ROOT / "sample-windows-server-security.json",
        "normalizer": normalize_windows_server_audit,
        "computer_name": "LAB-SRV01",
        "scope": "Server",
        "finding_prefix": "SERVER-SECURITY-",
    },
    {
        "report_type": "windows-workstation-audit",
        "path": WINDOWS_SAMPLE_ROOT / "sample-windows-workstation-security.json",
        "normalizer": normalize_windows_workstation_audit,
        "computer_name": "LAB-WS01",
        "scope": "Workstation",
        "finding_prefix": "WORKSTATION-SECURITY-",
    },
    {
        "report_type": "windows-network-exposure",
        "path": WINDOWS_SAMPLE_ROOT / "sample-windows-network-exposure.json",
        "normalizer": normalize_windows_network_exposure,
        "computer_name": "LAB-SRV01",
        "scope": "Network",
        "finding_prefix": "NETWORK-EXPOSURE-",
    },
]


class SecureInfraWindowsNormalizerTests(unittest.TestCase):
    def assert_evidence_contract(self, report: dict) -> None:
        for finding in report["findings"]:
            evidence = finding.get("evidence")
            self.assertIsInstance(evidence, dict, finding.get("finding_id"))
            self.assertTrue(evidence.get("summary"), finding.get("finding_id"))
            self.assertTrue(evidence.get("details"), finding.get("finding_id"))
            self.assertTrue(evidence.get("confidence"), finding.get("finding_id"))

    def test_windows_samples_load(self):
        for case in WINDOWS_SAMPLE_CASES:
            with self.subTest(report_type=case["report_type"]):
                data = load_json_file(case["path"])

                self.assertIsInstance(data, dict)
                self.assertIsInstance(data["Findings"], list)
                self.assertGreater(len(data["Findings"]), 0)
                self.assertEqual(data.get("ComputerName") or data.get("ReportMetadata", {}).get("ComputerName"), case["computer_name"])

    def test_windows_samples_normalize_to_common_finding_contract(self):
        for case in WINDOWS_SAMPLE_CASES:
            with self.subTest(report_type=case["report_type"]):
                data = load_json_file(case["path"])
                report = case["normalizer"](data, case["path"])

                self.assertEqual(report["report_type"], case["report_type"])
                self.assertEqual(report["environment_summary"]["computer_name"], case["computer_name"])
                self.assertEqual(report["environment_summary"]["scope"], case["scope"])
                self.assertEqual(report["report_type_metadata"]["normalizer_status"], "beta")
                self.assertEqual(report["metadata"]["ai_required"], False)
                self.assertEqual(report["summary"]["normalized_finding_count"], len(data["Findings"]))
                self.assertTrue(all(item["safe_to_auto_remediate"] is False for item in report["findings"]))
                self.assertTrue(any(item["finding_id"].startswith(case["finding_prefix"]) for item in report["findings"]))
                self.assert_evidence_contract(report)

    def test_windows_samples_pass_schema_validation(self):
        for case in WINDOWS_SAMPLE_CASES:
            with self.subTest(report_type=case["report_type"]):
                data = load_json_file(case["path"])
                report = case["normalizer"](data, case["path"])

                validate_normalized_report(report)

    def test_network_port_context_catalog_common_ports_and_fallback(self):
        cases = [
            ("tcp", 5985, "Windows Remote Management", "WinRM over HTTP"),
            ("tcp", 5986, "Windows Remote Management", "WinRM over HTTPS"),
            ("tcp", 3389, "Remote Desktop Protocol", "RDP"),
            ("tcp", 445, "SMB", "Server Message Block"),
            ("tcp", 80, "HTTP web service", "Hypertext Transfer Protocol"),
            ("udp", 137, "NetBIOS Name Service", "NetBIOS over TCP/IP name service"),
            ("udp", 138, "NetBIOS Datagram Service", "NetBIOS over TCP/IP datagram service"),
            ("udp", 500, "IKE", "Internet Key Exchange for IPsec"),
            ("udp", 4500, "IPsec NAT-T", "IPsec NAT Traversal"),
        ]
        for protocol, port, service, common_name in cases:
            with self.subTest(port=port):
                context = lookup_port_context(protocol, port)
                self.assertEqual(context["common_service"], service)
                self.assertEqual(context["common_name"], common_name)
                self.assertNotIn("exploitable", context["risk_explanation"].lower())

        fallback = lookup_port_context("tcp", 49152)
        self.assertEqual(fallback["common_service"], "Unknown or custom service")
        self.assertEqual(fallback["exposure_type"], "Listening service requiring validation")
        self.assertIn("Validate owner, purpose, firewall scope, and monitoring", fallback["risk_explanation"])

    def test_windows_local_admin_findings_use_stable_principal_ids_and_context(self):
        data = {
            "ToolName": "Get-WindowsLocalAdminInventory",
            "ReportType": "windows-local-admin-inventory",
            "GeneratedAtUtc": "2026-06-15T09:00:00Z",
            "ComputerName": "LAB-SRV01",
            "AdministratorsGroupName": "Administrators",
            "AdministratorsGroupSid": "S-1-5-32-544",
            "Summary": {"FindingCount": 4},
            "LocalAdministrators": [
                {
                    "Name": r"EXAMPLE\Server Admins",
                    "ObjectClass": "Group",
                    "PrincipalSource": "ActiveDirectory",
                    "PrincipalCategory": "DomainGroup",
                    "Sid": "S-1-5-21-100-200-300-1001",
                },
                {
                    "Name": r"EXAMPLE\Helpdesk Admins",
                    "ObjectClass": "Group",
                    "PrincipalSource": "ActiveDirectory",
                    "PrincipalCategory": "DomainGroup",
                    "Sid": "S-1-5-21-100-200-300-1002",
                },
                {
                    "Name": r"LAB-SRV01\breakglass",
                    "ObjectClass": "User",
                    "PrincipalSource": "Local",
                    "PrincipalCategory": "LocalUser",
                    "Sid": "S-1-5-21-100-200-300-501",
                    "Enabled": True,
                    "LastLogonUtc": "2026-06-01T10:00:00Z",
                    "PasswordRequired": False,
                },
            ],
            "Findings": [
                {
                    "FindingType": "DomainGroupLocalAdmin",
                    "Severity": "High",
                    "Principal": r"EXAMPLE\Server Admins",
                    "Title": "Domain group has local administrator rights",
                    "Evidence": r"EXAMPLE\Server Admins is a domain group in local Administrators.",
                    "Recommendation": "Confirm this group is approved for local administration.",
                },
                {
                    "FindingType": "DomainGroupLocalAdmin",
                    "Severity": "High",
                    "Principal": r"EXAMPLE\Helpdesk Admins",
                    "Title": "Domain group has local administrator rights",
                    "Evidence": r"EXAMPLE\Helpdesk Admins is a domain group in local Administrators.",
                    "Recommendation": "Confirm this group is approved for local administration.",
                },
                {
                    "FindingType": "EnabledLocalAdminUser",
                    "Severity": "Medium",
                    "Principal": r"LAB-SRV01\breakglass",
                    "Title": "Enabled local user has administrator rights",
                    "Evidence": r"LAB-SRV01\breakglass is enabled and belongs to local Administrators.",
                    "Recommendation": "Confirm owner and password management.",
                },
                {
                    "FindingType": "LocalAdminPasswordNotRequired",
                    "Severity": "High",
                    "Principal": r"LAB-SRV01\breakglass",
                    "Title": "Local admin user does not require a password",
                    "Evidence": r"LAB-SRV01\breakglass has PasswordRequired set to false.",
                    "Recommendation": "Require a password or disable the account after approved review.",
                },
            ],
        }

        findings = normalize_client_source_file("server_windows_local_admins", data, Path("windows-local-admins.json"))
        finding_ids = [finding["finding_id"] for finding in findings]

        self.assertEqual(len(finding_ids), 4)
        self.assertEqual(len(finding_ids), len(set(finding_ids)))
        self.assertTrue(all(finding_id.startswith("SERVER-LADMIN-") for finding_id in finding_ids))
        first = findings[0]
        self.assertEqual(first["affected_object"], r"EXAMPLE\Server Admins")
        self.assertEqual(first["evidence"]["principal_category"], "DomainGroup")
        self.assertEqual(first["evidence"]["object_class"], "Group")
        self.assertEqual(first["evidence"]["principal_source"], "ActiveDirectory")
        self.assertIn("local administrator rights", first["evidence"]["summary"])
        self.assertIn("Who owns this local administrator principal", first["evidence"]["customer_question"])
        self.assertFalse(first["safe_to_auto_remediate"])
        password_finding = next(item for item in findings if item["evidence"]["finding_type"] == "LocalAdminPasswordNotRequired")
        self.assertFalse(password_finding["evidence"]["password_required"])
        self.assertIn("PasswordRequired=false", password_finding["evidence"]["summary"])

    def test_windows_rdp_exposure_findings_include_configuration_and_port_context(self):
        data = {
            "ToolName": "Get-WindowsRDPExposureAudit",
            "ReportType": "windows-rdp-exposure",
            "GeneratedAtUtc": "2026-06-15T09:00:00Z",
            "ComputerName": "LAB-SRV01",
            "Summary": {
                "FindingCount": 5,
                "RdpEnabled": True,
                "NetworkLevelAuthenticationRequired": False,
                "RdpPort": 3389,
                "TermServiceStatus": "Running",
                "TermServiceStartMode": "Manual",
                "RemoteDesktopUserCount": 1,
                "EnabledInboundAllowRuleCount": 1,
                "ListenerCount": 1,
            },
            "Registry": {"fDenyTSConnections": 0, "UserAuthentication": 0, "PortNumber": 3389},
            "TermService": {"Name": "TermService", "Status": "Running", "StartMode": "Manual"},
            "RemoteDesktopUsers": [{"Name": r"EXAMPLE\RDP Users", "ObjectClass": "Group", "PrincipalSource": "ActiveDirectory"}],
            "FirewallRules": [
                {
                    "Name": "RemoteDesktop-UserMode-In-TCP",
                    "DisplayName": "Remote Desktop - User Mode (TCP-In)",
                    "Enabled": "True",
                    "Direction": "Inbound",
                    "Action": "Allow",
                    "Profile": "Domain",
                }
            ],
            "Listeners": [{"LocalAddress": "0.0.0.0", "LocalPort": 3389, "ProcessName": "svchost"}],
            "Findings": [
                {
                    "FindingType": "RdpEnabled",
                    "Severity": "Medium",
                    "Title": "Remote Desktop is enabled",
                    "Evidence": "fDenyTSConnections=0; TermService=Running; Port=3389.",
                    "Recommendation": "Confirm RDP is business-required and restricted.",
                },
                {
                    "FindingType": "RdpNlaDisabled",
                    "Severity": "High",
                    "Title": "RDP Network Level Authentication is not required",
                    "Evidence": "UserAuthentication=0.",
                    "Recommendation": "Require NLA unless a documented legacy exception exists.",
                },
                {
                    "FindingType": "RdpAllowedUsersPresent",
                    "Severity": "Medium",
                    "Title": "Remote Desktop Users group has direct members",
                    "Evidence": "1 direct member(s) are present.",
                    "Recommendation": "Review each member.",
                },
                {
                    "FindingType": "RdpFirewallAllowsInbound",
                    "Severity": "Medium",
                    "Title": "Firewall has enabled inbound Remote Desktop allow rules",
                    "Evidence": "1 enabled allow rule(s) were found.",
                    "Recommendation": "Restrict RDP firewall exposure.",
                },
                {
                    "FindingType": "RdpListening",
                    "Severity": "High",
                    "Title": "RDP listener is active",
                    "Evidence": "TCP port 3389 has 1 listening endpoint(s).",
                    "Recommendation": "Confirm exposure is intended.",
                },
            ],
        }

        findings = normalize_client_source_file("server_windows_rdp_exposure", data, Path("windows-rdp-exposure.json"))
        by_type = {finding["evidence"]["finding_type"]: finding for finding in findings}
        rdp_enabled = by_type["RdpEnabled"]
        rdp_listening = by_type["RdpListening"]

        self.assertEqual(rdp_enabled["finding_id"], "SERVER-RDP-RDPENABLED")
        self.assertEqual(rdp_enabled["evidence"]["port"], 3389)
        self.assertEqual(rdp_enabled["evidence"]["common_name"], "RDP")
        self.assertEqual(rdp_enabled["evidence"]["rdp_enabled"], True)
        self.assertEqual(rdp_enabled["evidence"]["network_level_authentication_required"], False)
        self.assertEqual(rdp_enabled["evidence"]["remote_desktop_users"], [r"EXAMPLE\RDP Users"])
        self.assertEqual(rdp_enabled["evidence"]["enabled_inbound_firewall_rules"], ["Remote Desktop - User Mode (TCP-In)"])
        self.assertIn("Who requires RDP access", rdp_enabled["evidence"]["customer_question"])
        self.assertEqual(rdp_listening["finding_id"], "SERVER-RDP-RDPLISTENING-TCP-3389")
        self.assertEqual(rdp_listening["evidence"]["bind_scope"], "All interfaces")
        self.assertIn("does not prove internet exposure", rdp_listening["evidence"]["summary"])
        self.assertFalse(rdp_listening["safe_to_auto_remediate"])

    def test_windows_server_inventory_findings_include_service_task_and_share_context(self):
        data = {
            "ToolName": "Get-WindowsServerSecurityInventory",
            "ReportType": "windows-server-security-inventory",
            "GeneratedAtUtc": "2026-06-15T09:00:00Z",
            "ComputerName": "LAB-SRV01",
            "Summary": {"FindingCount": 4},
            "Services": [
                {
                    "Name": "LegacyAppSvc",
                    "DisplayName": "Legacy Application Service",
                    "State": "Running",
                    "StartMode": "Auto",
                    "StartName": r"EXAMPLE\svc-legacy-app",
                    "PathName": r"C:\Program Files\Legacy App\legacy.exe -service",
                }
            ],
            "ScheduledTasks": [
                {
                    "TaskName": "LegacyAdminTask",
                    "TaskPath": "\\Legacy\\",
                    "State": "Ready",
                    "UserId": r"EXAMPLE\svc-task",
                    "RunLevel": "Highest",
                }
            ],
            "SmbShares": [
                {
                    "Name": "Projects",
                    "Path": r"D:\Shares\Projects",
                    "Description": "Project share",
                    "ShareState": "Online",
                    "ShareType": "FileSystemDirectory",
                    "Special": False,
                }
            ],
            "SmbShareAccess": [
                {
                    "ShareName": "Projects",
                    "AccountName": "Everyone",
                    "AccessControlType": "Allow",
                    "AccessRight": "Change",
                }
            ],
            "Findings": [
                {
                    "FindingType": "ServiceRunsAsCustomAccount",
                    "Severity": "High",
                    "Name": "LegacyAppSvc",
                    "Title": "Service runs as a custom or domain account",
                    "Evidence": r"LegacyAppSvc starts as EXAMPLE\svc-legacy-app.",
                    "Recommendation": "Confirm owner and credential rotation.",
                },
                {
                    "FindingType": "UnquotedServicePath",
                    "Severity": "High",
                    "Name": "LegacyAppSvc",
                    "Title": "Service path is unquoted and contains spaces",
                    "Evidence": r"LegacyAppSvc PathName=C:\Program Files\Legacy App\legacy.exe -service.",
                    "Recommendation": "Validate and quote if required.",
                },
                {
                    "FindingType": "ScheduledTaskRunsHighest",
                    "Severity": "Medium",
                    "Name": r"\Legacy\LegacyAdminTask",
                    "Title": "Scheduled task runs with highest privileges",
                    "Evidence": r"\Legacy\LegacyAdminTask runs as EXAMPLE\svc-task.",
                    "Recommendation": "Confirm task owner and privilege requirement.",
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

        findings = normalize_client_source_file("server_windows_server_security", data, Path("windows-server-security.json"))
        by_type = {finding["evidence"]["finding_type"]: finding for finding in findings}

        service = by_type["ServiceRunsAsCustomAccount"]
        self.assertEqual(service["evidence"]["service_name"], "LegacyAppSvc")
        self.assertEqual(service["evidence"]["service_display_name"], "Legacy Application Service")
        self.assertEqual(service["evidence"]["service_start_name"], r"EXAMPLE\svc-legacy-app")
        self.assertEqual(service["evidence"]["service_state"], "Running")
        self.assertIn("Who owns this Windows service", service["evidence"]["customer_question"])
        self.assertFalse(service["safe_to_auto_remediate"])

        unquoted = by_type["UnquotedServicePath"]
        self.assertEqual(unquoted["evidence"]["service_start_mode"], "Auto")
        self.assertIn("unquoted executable path", unquoted["evidence"]["summary"])
        self.assertIn("approved change window", unquoted["evidence"]["safe_next_step"])

        task = by_type["ScheduledTaskRunsHighest"]
        self.assertEqual(task["evidence"]["task_name"], "LegacyAdminTask")
        self.assertEqual(task["evidence"]["task_path"], "\\Legacy\\")
        self.assertEqual(task["evidence"]["task_run_level"], "Highest")
        self.assertIn("action path", task["evidence"]["customer_question"])

        share = by_type["BroadSmbShareAccess"]
        self.assertEqual(share["evidence"]["share_name"], "Projects")
        self.assertEqual(share["evidence"]["access_account"], "Everyone")
        self.assertEqual(share["evidence"]["access_right"], "Change")
        self.assertEqual(share["evidence"]["share_state"], "Online")
        self.assertIn("Who owns this share", share["evidence"]["customer_question"])
        self.assertEqual(len({finding["finding_id"] for finding in findings}), len(findings))

    def test_windows_workstation_inventory_findings_have_stable_object_ids_and_context(self):
        data = {
            "ToolName": "Get-WindowsWorkstationSecurityInventory",
            "ReportType": "windows-workstation-security-inventory",
            "GeneratedAtUtc": "2026-06-15T09:00:00Z",
            "ComputerName": "LAB-WS01",
            "Summary": {"FindingCount": 6},
            "DefenderStatus": {
                "AMServiceEnabled": True,
                "AntivirusEnabled": True,
                "RealTimeProtectionEnabled": False,
                "BehaviorMonitorEnabled": True,
            },
            "BitLockerVolumes": [
                {
                    "MountPoint": "C:",
                    "VolumeType": "OperatingSystem",
                    "ProtectionStatus": "Off",
                    "VolumeStatus": "FullyDecrypted",
                    "EncryptionMethod": "None",
                    "LockStatus": "Unlocked",
                },
                {
                    "MountPoint": "D:",
                    "VolumeType": "FixedData",
                    "ProtectionStatus": "Off",
                    "VolumeStatus": "FullyDecrypted",
                    "EncryptionMethod": "None",
                    "LockStatus": "Unlocked",
                },
            ],
            "FirewallProfiles": [
                {"Name": "Domain", "Enabled": False, "DefaultInboundAction": "Block", "DefaultOutboundAction": "Allow"},
                {"Name": "Public", "Enabled": False, "DefaultInboundAction": "Block", "DefaultOutboundAction": "Allow"},
            ],
            "RemoteAssistance": {"fAllowToGetHelp": 1},
            "LlmnrPolicy": {"EnableMulticast": 1},
            "PowerShellLogging": {"EnableScriptBlockLogging": 0},
            "Findings": [
                {
                    "FindingType": "DefenderRealTimeProtectionDisabled",
                    "Severity": "High",
                    "Name": "Defender",
                    "Title": "Defender real-time protection is disabled",
                    "Evidence": "RealTimeProtectionEnabled=False.",
                    "Recommendation": "Re-enable real-time protection unless an exception exists.",
                },
                {
                    "FindingType": "BitLockerVolumeNotProtected",
                    "Severity": "High",
                    "Name": "C:",
                    "Title": "Fixed volume is not fully protected by BitLocker",
                    "Evidence": "C: ProtectionStatus=Off.",
                    "Recommendation": "Confirm encryption policy.",
                },
                {
                    "FindingType": "BitLockerVolumeNotProtected",
                    "Severity": "High",
                    "Name": "D:",
                    "Title": "Fixed volume is not fully protected by BitLocker",
                    "Evidence": "D: ProtectionStatus=Off.",
                    "Recommendation": "Confirm encryption policy.",
                },
                {
                    "FindingType": "FirewallProfileDisabled",
                    "Severity": "Medium",
                    "Name": "Domain",
                    "Title": "Windows Firewall profile is disabled",
                    "Evidence": "Domain profile Enabled=False.",
                    "Recommendation": "Enable the firewall profile after validation.",
                },
                {
                    "FindingType": "FirewallProfileDisabled",
                    "Severity": "High",
                    "Name": "Public",
                    "Title": "Windows Firewall profile is disabled",
                    "Evidence": "Public profile Enabled=False.",
                    "Recommendation": "Enable the firewall profile after validation.",
                },
                {
                    "FindingType": "PowerShellScriptBlockLoggingNotEnabled",
                    "Severity": "Medium",
                    "Name": "PowerShell",
                    "Title": "PowerShell Script Block Logging is not enabled by policy",
                    "Evidence": "EnableScriptBlockLogging=0.",
                    "Recommendation": "Enable Script Block Logging through approved endpoint policy.",
                },
            ],
        }

        findings = normalize_client_source_file("workstation_windows_workstation_security", data, Path("windows-workstation-security.json"))
        finding_ids = [finding["finding_id"] for finding in findings]
        self.assertEqual(len(finding_ids), len(set(finding_ids)))
        self.assertTrue(all(finding_id.startswith("WORKSTATION-SECURITY-") for finding_id in finding_ids))

        by_object = {finding["affected_object"]: finding for finding in findings}
        defender = by_object["Defender"]
        self.assertEqual(defender["evidence"]["defender_realtime_protection_enabled"], False)
        self.assertIn("endpoint protection", defender["evidence"]["customer_question"])

        bitlocker_c = by_object["C:"]
        self.assertEqual(bitlocker_c["evidence"]["mount_point"], "C:")
        self.assertEqual(bitlocker_c["evidence"]["volume_type"], "OperatingSystem")
        self.assertEqual(bitlocker_c["evidence"]["protection_status"], "Off")
        self.assertIn("recovery-key custody", bitlocker_c["evidence"]["safe_next_step"])

        public_firewall = by_object["Public"]
        self.assertEqual(public_firewall["evidence"]["firewall_profile"], "Public")
        self.assertEqual(public_firewall["evidence"]["default_inbound_action"], "Block")
        self.assertIn("Which firewall profile", public_firewall["evidence"]["customer_question"])

        powershell = by_object["PowerShell"]
        self.assertEqual(powershell["evidence"]["policy_name"], "PowerShell Script Block Logging")
        self.assertIn("centrally logged", powershell["evidence"]["customer_question"])
        self.assertFalse(powershell["safe_to_auto_remediate"])

    def test_windows_network_listener_findings_include_port_context(self):
        data = {
            "ToolName": "Get-WindowsNetworkExposureAudit",
            "ReportType": "windows-network-exposure",
            "GeneratedAtUtc": "2026-06-15T09:00:00Z",
            "ComputerName": "LAB-SRV01",
            "Summary": {"FindingCount": 6},
            "ListeningTcpPorts": [
                {"LocalAddress": "0.0.0.0", "LocalPort": 5985, "OwningProcess": 4, "ProcessName": "System"},
                {"LocalAddress": "10.10.10.25", "LocalPort": 5986, "OwningProcess": 4, "ProcessName": "System"},
                {"LocalAddress": "0.0.0.0", "LocalPort": 3389, "OwningProcess": 1200, "ProcessName": "svchost"},
                {"LocalAddress": "0.0.0.0", "LocalPort": 445, "OwningProcess": 4, "ProcessName": "System"},
                {"LocalAddress": "10.10.10.25", "LocalPort": 80, "OwningProcess": 4300, "ProcessName": "labweb"},
                {"LocalAddress": "127.0.0.1", "LocalPort": 49152, "OwningProcess": 5500, "ProcessName": "customsvc"},
            ],
            "Findings": [
                {
                    "FindingType": "RiskyListeningPort",
                    "Severity": "High",
                    "Name": "TCP 5985",
                    "Title": "Sensitive TCP port is listening",
                    "Evidence": "TCP 5985 is listening on all interfaces by process System.",
                    "Recommendation": "Confirm the listener is required and restricted.",
                },
                {
                    "FindingType": "RiskyListeningPort",
                    "Severity": "High",
                    "Name": "TCP 5986",
                    "Title": "Sensitive TCP port is listening",
                    "Evidence": "TCP 5986 is listening by process System.",
                    "Recommendation": "Confirm the listener is required and restricted.",
                },
                {
                    "FindingType": "RiskyListeningPort",
                    "Severity": "High",
                    "Name": "TCP 3389",
                    "Title": "Sensitive TCP port is listening",
                    "Evidence": "TCP 3389 is listening on all interfaces by process svchost.",
                    "Recommendation": "Confirm the listener is required and restricted.",
                },
                {
                    "FindingType": "RiskyListeningPort",
                    "Severity": "High",
                    "Name": "TCP 445",
                    "Title": "Sensitive TCP port is listening",
                    "Evidence": "TCP 445 is listening on all interfaces by process System.",
                    "Recommendation": "Confirm the listener is required and restricted.",
                },
                {
                    "FindingType": "RiskyListeningPort",
                    "Severity": "Medium",
                    "Name": "TCP 80",
                    "Title": "Sensitive TCP port is listening",
                    "Evidence": "TCP 80 is listening by process labweb.",
                    "Recommendation": "Confirm the listener is required and restricted.",
                },
                {
                    "FindingType": "RiskyListeningPort",
                    "Severity": "Low",
                    "Name": "TCP 49152",
                    "Title": "Sensitive TCP port is listening",
                    "Evidence": "TCP 49152 is listening by process customsvc.",
                    "Recommendation": "Confirm the listener is required and restricted.",
                },
            ],
        }

        report = normalize_windows_network_exposure(data, "windows-network-exposure.json")
        by_port = {finding["evidence"]["port"]: finding for finding in report["findings"]}

        winrm_http = by_port[5985]
        evidence = winrm_http["evidence"]
        self.assertEqual(evidence["protocol"], "TCP")
        self.assertEqual(evidence["process_name"], "System")
        self.assertEqual(evidence["bind_address"], "0.0.0.0")
        self.assertEqual(evidence["bind_scope"], "All interfaces")
        self.assertEqual(evidence["common_service"], "Windows Remote Management")
        self.assertEqual(evidence["common_name"], "WinRM over HTTP")
        self.assertEqual(evidence["exposure_type"], "Remote administration service")
        self.assertEqual(evidence["port_context_confidence"], "high")
        self.assertIn("Windows Remote Management (WinRM over HTTP)", evidence["summary"])
        self.assertIn("approved remote administration exposure", evidence["summary"])
        self.assertEqual(evidence["risk_explanation"], "WinRM over HTTP is commonly used for Windows remote administration and automation. It should be restricted to trusted management networks and validated before changes.")
        self.assertNotIn("Listening on all interfaces", evidence["risk_explanation"])
        self.assertEqual(evidence["risk_explanation"].count("Listening on all interfaces"), 0)
        self.assertEqual(evidence["risk_explanation"].count("WinRM over HTTP"), 1)
        self.assertEqual(
            evidence["bind_scope_explanation"],
            "Listening on all interfaces means the service binds to all local interfaces. Actual reachability depends on firewall rules, routing, segmentation, and allowed source networks.",
        )
        self.assertEqual(evidence["bind_scope_explanation"].count("Listening on all interfaces"), 1)
        self.assertIn(
            "Actual reachability depends on firewall rules, routing, segmentation, and allowed source networks",
            evidence["bind_scope_explanation"],
        )
        self.assertIn("risk_explanation: WinRM over HTTP", evidence["details"])
        self.assertIn("bind_scope_explanation: Listening on all interfaces means", evidence["details"])
        self.assertEqual(evidence["details"].count("bind_scope_explanation:"), 1)
        risk_detail = next(part for part in evidence["details"].split("; ") if part.startswith("risk_explanation:"))
        bind_scope_detail = next(part for part in evidence["details"].split("; ") if part.startswith("bind_scope_explanation:"))
        self.assertNotIn("Listening on all interfaces", risk_detail)
        self.assertIn("Actual reachability depends on firewall rules", bind_scope_detail)
        self.assertIn("customer_question: Which management tools", evidence["details"])
        self.assertIn("safe_next_step: Validate WinRM owner", evidence["details"])
        self.assertIn("Which management tools", evidence["customer_question"])
        self.assertIn("Validate WinRM owner", evidence["safe_next_step"])
        self.assertFalse(winrm_http["safe_to_auto_remediate"])

        with tempfile.TemporaryDirectory() as tmp:
            paths = generate_markdown_reports(report, Path(tmp))
            technical = (Path(tmp) / "technical-findings.md").read_text(encoding="utf-8")
            self.assertIn("- Risk explanation: WinRM over HTTP", technical)
            self.assertIn("- Bind scope explanation: Listening on all interfaces means", technical)

        self.assertEqual(by_port[5986]["evidence"]["common_name"], "WinRM over HTTPS")
        self.assertEqual(by_port[3389]["evidence"]["common_name"], "RDP")
        self.assertEqual(by_port[445]["evidence"]["common_service"], "SMB")
        self.assertEqual(by_port[80]["evidence"]["common_service"], "HTTP web service")
        self.assertEqual(by_port[49152]["evidence"]["common_service"], "Unknown or custom service")
        self.assertEqual(by_port[49152]["evidence"]["bind_scope"], "Loopback only")
        self.assertTrue(all(finding["safe_to_auto_remediate"] is False for finding in report["findings"]))


    def test_windows_network_structured_tcp_udp_service_metadata_is_normalized(self):
        data = {
            "ToolName": "Get-WindowsNetworkExposureAudit",
            "ReportType": "windows-network-exposure",
            "GeneratedAtUtc": "2026-06-15T09:00:00Z",
            "ComputerName": "LAB-SRV01",
            "Summary": {"FindingCount": 2, "ListeningTcpPortCount": 1, "ListeningUdpPortCount": 1},
            "ListeningTcpPorts": [
                {
                    "Protocol": "TCP",
                    "LocalAddress": "0.0.0.0",
                    "LocalPort": 5985,
                    "BindScope": "All interfaces",
                    "OwningProcess": 4,
                    "ProcessName": "svchost.exe",
                    "ProcessPath": r"C:\Windows\System32\svchost.exe",
                    "ServiceName": "WinRM",
                    "ServiceDisplayName": "Windows Remote Management",
                    "ServiceStartMode": "Auto",
                    "ServiceState": "Running",
                }
            ],
            "ListeningUdpPorts": [
                {
                    "Protocol": "UDP",
                    "LocalAddress": "0.0.0.0",
                    "LocalPort": 53,
                    "BindScope": "All interfaces",
                    "OwningProcess": 2222,
                    "ProcessName": "dns.exe",
                    "ServiceName": "DNS",
                    "ServiceDisplayName": "DNS Server",
                }
            ],
            "Findings": [
                {
                    "FindingType": "RiskyListeningPort",
                    "Severity": "High",
                    "Title": "Sensitive TCP port is listening",
                    "Protocol": "TCP",
                    "LocalPort": 5985,
                    "LocalAddress": "0.0.0.0",
                    "BindScope": "All interfaces",
                    "ProcessName": "svchost.exe",
                    "ProcessPath": r"C:\Windows\System32\svchost.exe",
                    "ServiceName": "WinRM",
                    "ServiceDisplayName": "Windows Remote Management",
                    "Evidence": "TCP 5985 is listening on all interfaces by process svchost.exe service WinRM.",
                    "Recommendation": "Confirm the listener is required and restricted.",
                },
                {
                    "FindingType": "RiskyListeningPort",
                    "Severity": "Medium",
                    "Title": "Sensitive UDP port is listening",
                    "Protocol": "UDP",
                    "LocalPort": 53,
                    "LocalAddress": "0.0.0.0",
                    "BindScope": "All interfaces",
                    "ProcessName": "dns.exe",
                    "ServiceName": "DNS",
                    "ServiceDisplayName": "DNS Server",
                    "Evidence": "UDP 53 is listening on all interfaces by process dns.exe service DNS.",
                    "Recommendation": "Confirm the listener is required and restricted.",
                },
            ],
        }

        report = normalize_windows_network_exposure(data, "windows-network-exposure.json")
        by_port = {finding["evidence"].get("port"): finding for finding in report["findings"]}

        winrm = by_port[5985]
        self.assertEqual(winrm["finding_id"], "NETWORK-EXPOSURE-RISKYLISTENINGPORT-TCP-5985")
        self.assertEqual(winrm["evidence"]["protocol"], "TCP")
        self.assertEqual(winrm["evidence"]["bind_scope"], "All interfaces")
        self.assertEqual(winrm["evidence"]["service_name"], "WinRM")
        self.assertEqual(winrm["evidence"]["service_display_name"], "Windows Remote Management")
        self.assertEqual(winrm["evidence"]["process_path"], "svchost.exe")
        self.assertIn("Actual reachability depends", winrm["evidence"]["bind_scope_explanation"])

        dns = by_port[53]
        self.assertEqual(dns["finding_id"], "NETWORK-EXPOSURE-RISKYLISTENINGPORT-UDP-53")
        self.assertEqual(dns["evidence"]["protocol"], "UDP")
        self.assertEqual(dns["evidence"]["service_name"], "DNS")
        self.assertEqual(dns["evidence"]["common_name"], "Domain Name System")
        self.assertFalse(dns["safe_to_auto_remediate"])
        validate_normalized_report(report)

    def test_windows_network_sensitive_firewall_rule_context_is_normalized(self):
        data = {
            "ToolName": "Get-WindowsNetworkExposureAudit",
            "ReportType": "windows-network-exposure",
            "GeneratedAtUtc": "2026-06-15T09:00:00Z",
            "ComputerName": "LAB-SRV01",
            "Summary": {"FindingCount": 1, "SensitiveFirewallRuleCount": 1},
            "InboundAllowFirewallRules": [
                {
                    "Name": "WINRM-HTTP-In",
                    "DisplayName": "Windows Remote Management (HTTP-In)",
                    "Enabled": "True",
                    "Direction": "Inbound",
                    "Action": "Allow",
                    "Profiles": "Domain,Private",
                    "Protocol": "TCP",
                    "LocalPorts": "5985",
                    "RemoteAddresses": "10.10.0.0/16",
                    "Program": r"C:\Windows\System32\svchost.exe",
                    "ServiceName": "WinRM",
                }
            ],
            "Findings": [
                {
                    "FindingType": "FirewallAllowsSensitivePort",
                    "Severity": "High",
                    "Title": "Inbound firewall allow rule permits sensitive Windows port",
                    "RuleName": "WINRM-HTTP-In",
                    "RuleDisplayName": "Windows Remote Management (HTTP-In)",
                    "Profile": "Domain,Private",
                    "Protocol": "TCP",
                    "LocalPort": 5985,
                    "LocalPorts": "5985",
                    "RemoteAddresses": "10.10.0.0/16",
                    "Program": r"C:\Windows\System32\svchost.exe",
                    "ServiceName": "WinRM",
                    "Evidence": "Firewall rule 'Windows Remote Management (HTTP-In)' allows inbound TCP 5985.",
                    "Recommendation": "Validate rule owner, profile scope, remote address restrictions, service dependency, and change approval.",
                }
            ],
        }

        report = normalize_windows_network_exposure(data, "windows-network-exposure.json")
        finding = report["findings"][0]
        evidence = finding["evidence"]

        self.assertTrue(finding["finding_id"].startswith("NETWORK-EXPOSURE-FW-SENSITIVE-TCP-5985-WINRM-HTTP-"))
        self.assertEqual(evidence["finding_type"], "FirewallAllowsSensitivePort")
        self.assertEqual(evidence["protocol"], "TCP")
        self.assertEqual(evidence["port"], 5985)
        self.assertEqual(evidence["common_name"], "WinRM over HTTP")
        self.assertEqual(evidence["firewall_rule_name"], "WINRM-HTTP-In")
        self.assertEqual(evidence["firewall_profile"], "Domain,Private")
        self.assertEqual(evidence["remote_addresses"], "10.10.0.0/16")
        self.assertEqual(evidence["program"], "svchost.exe")
        self.assertIn("firewall policy evidence only", evidence["risk_explanation"])
        self.assertNotIn("internet exposure", evidence["risk_explanation"].lower())
        self.assertFalse(finding["safe_to_auto_remediate"])
        validate_normalized_report(report)

    def test_windows_network_listener_findings_deduplicate_broad_ipv4_ipv6_endpoints(self):
        data = {
            "ToolName": "Get-WindowsNetworkExposureAudit",
            "ReportType": "windows-network-exposure",
            "GeneratedAtUtc": "2026-06-15T09:00:00Z",
            "ComputerName": "ADSRV-2018-PR",
            "Summary": {"FindingCount": 3},
            "ListeningTcpPorts": [
                {"LocalAddress": "::", "LocalPort": 3389, "OwningProcess": 1200, "ProcessName": "svchost"},
                {"LocalAddress": "0.0.0.0", "LocalPort": 3389, "OwningProcess": 1200, "ProcessName": "svchost"},
                {"LocalAddress": "::", "LocalPort": 5985, "OwningProcess": 4, "ProcessName": "System"},
            ],
            "Findings": [
                {
                    "FindingType": "RiskyListeningPort",
                    "Severity": "High",
                    "Title": "Sensitive TCP port is listening",
                    "Evidence": "TCP 3389 is listening on all interfaces by process svchost.",
                    "Recommendation": "Confirm the listener is required and restricted by host and network firewall policy.",
                },
                {
                    "FindingType": "RiskyListeningPort",
                    "Severity": "High",
                    "Title": "Sensitive TCP port is listening",
                    "Evidence": "TCP 3389 is listening on all interfaces by process svchost.",
                    "Recommendation": "Confirm the listener is required and restricted by host and network firewall policy.",
                },
                {
                    "FindingType": "RiskyListeningPort",
                    "Severity": "High",
                    "Title": "Sensitive TCP port is listening",
                    "Evidence": "TCP 5985 is listening on all interfaces by process System.",
                    "Recommendation": "Confirm the listener is required and restricted by host and network firewall policy.",
                },
            ],
        }

        report = normalize_windows_network_exposure(data, "windows-network-exposure.json")
        risky_findings = [
            finding
            for finding in report["findings"]
            if finding["evidence"].get("finding_type") == "RiskyListeningPort"
        ]
        tcp_3389_findings = [finding for finding in risky_findings if finding["evidence"].get("port") == 3389]

        self.assertEqual(len(tcp_3389_findings), 1)
        self.assertEqual(len(risky_findings), 2)
        rdp = tcp_3389_findings[0]
        self.assertEqual(rdp["finding_id"], "NETWORK-EXPOSURE-RISKYLISTENINGPORT-TCP-3389")
        self.assertEqual(rdp["evidence"]["bind_addresses"], ["::", "0.0.0.0"])
        self.assertEqual(rdp["evidence"]["source_endpoints"], [":::3389 svchost", "0.0.0.0:3389 svchost"])
        self.assertEqual(rdp["evidence"]["bind_scope"], "All interfaces")
        self.assertIn("Actual reachability depends on firewall rules", rdp["evidence"]["bind_scope_explanation"])
        self.assertNotIn("Listening on all interfaces", rdp["evidence"]["risk_explanation"])
        self.assertEqual(rdp["evidence"]["common_service"], "Remote Desktop Protocol")
        self.assertEqual(rdp["evidence"]["common_name"], "RDP")
        self.assertFalse(rdp["safe_to_auto_remediate"])

        winrm = next(finding for finding in risky_findings if finding["evidence"].get("port") == 5985)
        self.assertEqual(winrm["finding_id"], "NETWORK-EXPOSURE-RISKYLISTENINGPORT-TCP-5985")
        self.assertEqual(winrm["evidence"]["common_service"], "Windows Remote Management")
        self.assertEqual(winrm["evidence"]["common_name"], "WinRM over HTTP")

    def test_windows_network_listener_summary_preserves_all_specific_bind_addresses(self):
        addresses = ["192.168.176.1", "192.168.56.1", "192.168.1.65", "10.10.10.2"]
        data = {
            "ToolName": "Get-WindowsNetworkExposureAudit",
            "ReportType": "windows-network-exposure",
            "GeneratedAtUtc": "2026-07-17T16:24:22Z",
            "ComputerName": "MH-LAPTOP",
            "Summary": {"FindingCount": len(addresses)},
            "ListeningTcpPorts": [
                {"LocalAddress": address, "LocalPort": 139, "OwningProcess": 4, "ProcessName": "System"}
                for address in addresses
            ],
            "Findings": [
                {
                    "FindingType": "RiskyListeningPort",
                    "Severity": "High",
                    "Title": "Sensitive TCP port is listening",
                    "Evidence": f"TCP 139 is listening on {address} by process System.",
                    "Recommendation": "Confirm the listener is required and restricted by firewall policy.",
                }
                for address in addresses
            ],
        }

        report = normalize_windows_network_exposure(data, "windows-network-exposure.json")
        findings = [
            finding for finding in report["findings"]
            if finding["evidence"].get("finding_type") == "RiskyListeningPort"
        ]
        self.assertEqual(len(findings), 1)
        evidence = findings[0]["evidence"]
        self.assertEqual(evidence["bind_addresses"], addresses)
        self.assertIn("4 specific addresses", evidence["summary"])
        for address in addresses:
            self.assertIn(address, evidence["summary"])

    def test_windows_network_sample_uses_port_context(self):
        data = load_json_file(WINDOWS_SAMPLE_ROOT / "sample-windows-network-exposure.json")
        report = normalize_windows_network_exposure(data, WINDOWS_SAMPLE_ROOT / "sample-windows-network-exposure.json")
        rdp = next(finding for finding in report["findings"] if finding["evidence"].get("port") == 3389)

        self.assertEqual(rdp["evidence"]["common_name"], "RDP")
        self.assertIn("Remote Desktop Protocol", rdp["evidence"]["summary"])
        self.assertIn("customer_question: Who requires RDP access", rdp["evidence"]["details"])
        self.assertFalse(rdp["safe_to_auto_remediate"])

    def test_windows_public_network_profile_finding_uses_profile_context(self):
        data = load_json_file(WINDOWS_SAMPLE_ROOT / "sample-windows-network-exposure.json")
        report = normalize_windows_network_exposure(data, WINDOWS_SAMPLE_ROOT / "sample-windows-network-exposure.json")
        profile = next(finding for finding in report["findings"] if finding["evidence"].get("finding_type") == "PublicNetworkProfileActive")

        self.assertEqual(profile["affected_object"], "Ethernet0 / Public network profile / Lab Guest Network")
        self.assertEqual(profile["evidence"]["network_configuration_finding"], "network_profile_classification")
        self.assertEqual(profile["evidence"]["interface_alias"], "Ethernet0")
        self.assertEqual(profile["evidence"]["network_category"], "Public")
        self.assertEqual(profile["evidence"]["network_profile_name"], "Lab Guest Network")
        self.assertIn("classified as Public", profile["evidence"]["summary"])
        self.assertIn("network category", profile["evidence"]["safe_next_step"])
        self.assertNotIn("port", profile["evidence"]["customer_question"].lower())
        self.assertFalse(profile["safe_to_auto_remediate"])

    def test_windows_multiple_public_network_profiles_have_stable_unique_ids(self):
        data = {
            "ToolName": "Get-WindowsNetworkExposureAudit",
            "ReportType": "windows-network-exposure",
            "GeneratedAtUtc": "2026-07-20T11:00:00Z",
            "ComputerName": "LAB-WKS01",
            "NetworkProfiles": [
                {
                    "Name": "Guest Network",
                    "InterfaceAlias": "Ethernet 1",
                    "NetworkCategory": "Public",
                },
                {
                    "Name": "Isolated Network",
                    "InterfaceAlias": "Ethernet 2",
                    "NetworkCategory": "Public",
                },
            ],
            "Findings": [
                {
                    "FindingType": "PublicNetworkProfileActive",
                    "Severity": "Medium",
                    "Title": "Public network profile is active",
                    "Evidence": "Ethernet 1 is using the Public network category.",
                    "Recommendation": "Confirm the network classification is intended.",
                },
                {
                    "FindingType": "PublicNetworkProfileActive",
                    "Severity": "Medium",
                    "Title": "Public network profile is active",
                    "Evidence": "Ethernet 2 is using the Public network category.",
                    "Recommendation": "Confirm the network classification is intended.",
                },
            ],
        }

        first = normalize_windows_network_exposure(data, "windows-network-exposure.json")
        second = normalize_windows_network_exposure(data, "windows-network-exposure.json")
        first_ids = [finding["finding_id"] for finding in first["findings"]]
        second_ids = [finding["finding_id"] for finding in second["findings"]]

        self.assertEqual(len(first_ids), 2)
        self.assertEqual(len(first_ids), len(set(first_ids)))
        self.assertEqual(first_ids, second_ids)
        self.assertTrue(all(item.startswith("NETWORK-EXPOSURE-PUBLICNETWORKPROFILEACTIVE-") for item in first_ids))
        self.assertTrue(all(len(item.rsplit("-", 1)[-1]) == 8 for item in first_ids))
        validate_normalized_report(first)

    def test_windows_server_unquoted_service_path_suppresses_service_host_noise(self):
        def unquoted_row(name: str, path_name: str) -> dict:
            return {
                "FindingType": "UnquotedServicePath",
                "Severity": "High",
                "Name": name,
                "Title": "Service path is unquoted and contains spaces",
                "Evidence": f"{name} PathName={path_name}.",
                "Recommendation": "Validate the executable path and quote it during approved maintenance if required.",
            }

        data = {
            "ToolName": "Get-WindowsServerSecurityInventory",
            "ReportType": "windows-server-security-inventory",
            "GeneratedAtUtc": "2026-06-15T09:00:00Z",
            "ComputerName": "LAB-SRV01",
            "Summary": {"FindingCount": 7},
            "Findings": [
                unquoted_row("RpcSs", "svchost.exe -k LocalServiceNetworkRestricted -p"),
                unquoted_row("NetSvcHost", "svchost.exe -k netsvcs -p"),
                unquoted_row("FullSvchost", r"C:\Windows\System32\svchost.exe -k netsvcs -p"),
                unquoted_row("RelativeSvchost", r"system32\svchost.exe -k DcomLaunch -p"),
                unquoted_row("RealUnquotedA", r"C:\Program Files\Vendor App\Service.exe -service"),
                unquoted_row("RealUnquotedB", r"C:\Program Files (x86)\Some App\daemon.exe /run"),
                unquoted_row("QuotedVendor", r'"C:\Program Files\Vendor App\Service.exe" -service'),
            ],
        }

        report = normalize_windows_server_audit(data, "windows-server-security.json")
        emitted_names = {finding["affected_object"] for finding in report["findings"]}
        unquoted = [
            finding
            for finding in report["findings"]
            if finding["evidence"].get("finding_type") == "UnquotedServicePath"
        ]
        high_unquoted = [finding for finding in unquoted if finding["severity"] == "High"]
        source_unquoted_count = sum(1 for row in data["Findings"] if row["FindingType"] == "UnquotedServicePath")

        self.assertNotIn("RpcSs", emitted_names)
        self.assertNotIn("NetSvcHost", emitted_names)
        self.assertNotIn("FullSvchost", emitted_names)
        self.assertNotIn("RelativeSvchost", emitted_names)
        self.assertNotIn("QuotedVendor", emitted_names)
        self.assertEqual({finding["affected_object"] for finding in unquoted}, {"RealUnquotedA", "RealUnquotedB"})
        self.assertEqual(len(high_unquoted), 2)
        self.assertLess(len(high_unquoted), source_unquoted_count)
        self.assertTrue(
            all(
                "Confirmed unquoted executable path" in finding["evidence"].get("path_parsing_status", "")
                for finding in unquoted
            )
        )
        self.assertTrue(
            all(finding["evidence"].get("executable_path", "").endswith(".exe") for finding in unquoted)
        )
        finding_ids = [finding["finding_id"] for finding in report["findings"]]
        self.assertEqual(len(finding_ids), len(set(finding_ids)))
        self.assertTrue(all("UNQUOTEDSERVICEPATH" in finding["finding_id"] for finding in unquoted))
        self.assertTrue(all(finding["safe_to_auto_remediate"] is False for finding in report["findings"]))

    def test_windows_server_broad_smb_share_access_ids_are_unique(self):
        data = {
            "ToolName": "Get-WindowsServerSecurityInventory",
            "ReportType": "windows-server-security-inventory",
            "GeneratedAtUtc": "2026-06-15T09:00:00Z",
            "ComputerName": "DEMO-SERVER",
            "Summary": {"FindingCount": 3},
            "Findings": [
                {
                    "FindingType": "BroadSmbShareAccess",
                    "Severity": "High",
                    "Name": "Projects",
                    "Title": "SMB share grants broad access",
                    "Evidence": "Projects grants Change to Everyone.",
                    "Recommendation": "Validate business need and narrow share permissions.",
                },
                {
                    "FindingType": "BroadSmbShareAccess",
                    "Severity": "Medium",
                    "Name": "Projects",
                    "Title": "SMB share grants broad access",
                    "Evidence": "Projects grants Read to Authenticated Users.",
                    "Recommendation": "Validate business need and narrow share permissions.",
                },
                {
                    "FindingType": "BroadSmbShareAccess",
                    "Severity": "Medium",
                    "Name": "Finance",
                    "Title": "SMB share grants broad access",
                    "Evidence": "Finance grants Change to Domain Users.",
                    "Recommendation": "Validate business need and narrow share permissions.",
                },
            ],
        }

        report = normalize_windows_server_audit(data, "windows-server-security.json")

        finding_ids = [finding["finding_id"] for finding in report["findings"]]
        self.assertEqual(len(finding_ids), 3)
        self.assertEqual(len(finding_ids), len(set(finding_ids)))
        self.assertTrue(all(finding_id.startswith("SERVER-SECURITY-BROADSMBSHAREACCESS-") for finding_id in finding_ids))
        validate_normalized_report(report)

    def test_windows_server_uncertain_service_path_is_not_high_unquoted_service_path(self):
        data = {
            "ToolName": "Get-WindowsServerSecurityInventory",
            "ReportType": "windows-server-security-inventory",
            "GeneratedAtUtc": "2026-06-15T09:00:00Z",
            "ComputerName": "LAB-SRV01",
            "Summary": {"FindingCount": 1},
            "Findings": [
                {
                    "FindingType": "UnquotedServicePath",
                    "Severity": "High",
                    "Name": "LegacyLauncher",
                    "Title": "Service path is unquoted and contains spaces",
                    "Evidence": "LegacyLauncher PathName=LegacyLauncher -service.",
                    "Recommendation": "Validate the executable path and quote it during approved maintenance if required.",
                }
            ],
        }

        report = normalize_windows_server_audit(data, "windows-server-security.json")
        finding = report["findings"][0]

        self.assertEqual(finding["severity"], "Info")
        self.assertEqual(finding["evidence"]["finding_type"], "ServicePathNeedsValidation")
        self.assertIn("Needs validation", finding["evidence"]["path_parsing_status"])
        self.assertNotEqual(finding["finding_id"], "SERVER-SECURITY-UNQUOTEDSERVICEPATH")
        self.assertFalse(finding["safe_to_auto_remediate"])

    def test_windows_host_aggregate_network_finding_includes_exposed_port_context(self):
        data = {
            "ToolName": "Invoke-WindowsSecurityAudit.ps1",
            "ReportType": "windows-security-audit",
            "GeneratedAtUtc": "2026-06-15T09:00:00Z",
            "ComputerName": "LAB-SRV01",
            "Summary": {"FindingCount": 1},
            "Findings": [
                {
                    "Id": "WIN-NET-001",
                    "Severity": "Medium",
                    "Area": "Network exposure",
                    "Title": "High-value Windows management or file-sharing ports are listening broadly",
                    "WhyItMatters": "Broadly listening management and file-sharing ports should be limited to trusted networks.",
                    "Recommendation": "Confirm firewall rules restrict these ports to required management, domain, or application networks.",
                    "Evidence": ":::135 svchost; 0.0.0.0:135 svchost; :::445 System; :::3389 svchost; 0.0.0.0:3389 svchost; :::5985 System",
                }
            ],
        }

        report = normalize_windows_host_audit(data, "windows-security-audit.json")
        finding = report["findings"][0]
        evidence = finding["evidence"]
        exposed_by_port = {item["port"]: item for item in evidence["exposed_ports"]}

        self.assertEqual(len(evidence["exposed_ports"]), 4)
        self.assertEqual(exposed_by_port[135]["common_service"], "RPC Endpoint Mapper")
        self.assertEqual(exposed_by_port[445]["common_service"], "SMB")
        self.assertEqual(exposed_by_port[3389]["common_name"], "RDP")
        self.assertEqual(exposed_by_port[5985]["common_service"], "Windows Remote Management")
        self.assertEqual(exposed_by_port[5985]["common_name"], "WinRM over HTTP")
        self.assertEqual(exposed_by_port[135]["bind_addresses"], ["::", "0.0.0.0"])
        self.assertEqual(exposed_by_port[3389]["bind_addresses"], ["::", "0.0.0.0"])

        for item in evidence["exposed_ports"]:
            self.assertEqual(item["bind_scope"], "All interfaces")
            self.assertIn("Actual reachability depends on firewall rules", item["bind_scope_explanation"])
            self.assertNotIn("Listening on all interfaces", item["risk_explanation"])

        self.assertIn("TCP 135 RPC Endpoint Mapper", evidence["summary"])
        self.assertIn("TCP 445 SMB", evidence["summary"])
        self.assertIn("TCP 3389 RDP", evidence["summary"])
        self.assertIn("TCP 5985 WinRM over HTTP", evidence["summary"])
        self.assertIn("trusted domain, management, VPN, or application networks", evidence["summary"])
        self.assertNotIn("Listening on all interfaces", evidence["risk_explanation"])
        self.assertIn("Actual reachability depends on firewall rules", evidence["bind_scope_explanation"])
        self.assertIn("risk_explanation: Broadly listening Windows management", evidence["details"])
        self.assertIn("bind_scope_explanation: Listening on all interfaces means", evidence["details"])
        self.assertIn("aggregate_network_context:", evidence["details"])
        self.assertIn("does not prove internet exposure", evidence["details"])
        self.assertIn("source_report_type: windows-security-audit", evidence["details"])
        self.assertIn("machine_name: LAB-SRV01", evidence["details"])
        self.assertIn("source_script: Invoke-WindowsSecurityAudit.ps1", evidence["details"])
        self.assertIn("affected_object: WIN-NET-001", evidence["details"])
        self.assertEqual(evidence["evidence"], data["Findings"][0]["Evidence"])
        self.assertEqual(evidence["why_it_matters"], data["Findings"][0]["WhyItMatters"])
        self.assertFalse(finding["safe_to_auto_remediate"])
        self.assertNotIn("D:\\", json.dumps(report))

    def test_windows_strict_schema_rejects_missing_report_type_metadata(self):
        data = load_json_file(WINDOWS_SAMPLE_CASES[0]["path"])
        report = normalize_windows_host_audit(data, WINDOWS_SAMPLE_CASES[0]["path"])
        del report["report_type_metadata"]

        with self.assertRaisesRegex(SchemaValidationError, r"\$\.report_type_metadata"):
            validate_normalized_report(report)

    def test_windows_markdown_reports_are_generated(self):
        for case in WINDOWS_SAMPLE_CASES:
            with self.subTest(report_type=case["report_type"]):
                data = load_json_file(case["path"])
                report = case["normalizer"](data, case["path"])

                with tempfile.TemporaryDirectory() as tmp:
                    output_dir = Path(tmp)
                    paths = generate_markdown_reports(report, output_dir)

                    self.assertEqual({path.name for path in paths}, {"executive-summary.md", "technical-findings.md", "remediation-plan.md"})
                    executive = (output_dir / "executive-summary.md").read_text(encoding="utf-8")
                    self.assertIn("Windows Scope Coverage", executive)
                    self.assertIn("beta", executive)
                    technical = (output_dir / "technical-findings.md").read_text(encoding="utf-8")
                    self.assertIn("Technical Findings", technical)

    def test_windows_cli_supports_all_new_report_types(self):
        for case in WINDOWS_SAMPLE_CASES:
            with self.subTest(report_type=case["report_type"]):
                with tempfile.TemporaryDirectory() as tmp:
                    output_dir = Path(tmp)
                    with contextlib.redirect_stdout(io.StringIO()):
                        exit_code = secureinfra_analyzer.main(
                            [
                                "--input",
                                str(case["path"]),
                                "--type",
                                case["report_type"],
                                "--output",
                                str(output_dir),
                            ]
                        )

                    self.assertEqual(exit_code, 0)
                    normalized_path = output_dir / "normalized-report.json"
                    self.assertTrue(normalized_path.exists())
                    self.assertTrue((output_dir / "executive-summary.md").exists())
                    normalized = json.loads(normalized_path.read_text(encoding="utf-8"))
                    self.assertEqual(normalized["report_type"], case["report_type"])
                    self.assertEqual(normalized["report_type_metadata"]["normalizer_status"], "beta")

    def test_host_smb_winrm_and_firewall_baseline_findings_include_structured_context(self):
        data = {
            "ToolName": "Invoke-WindowsSecurityAudit",
            "ReportType": "windows-host-audit",
            "GeneratedAtUtc": "2026-06-15T09:00:00Z",
            "ComputerName": "LAB-SRV01",
            "FirewallProfiles": [
                {
                    "Name": "Domain",
                    "Enabled": False,
                    "DefaultInboundAction": "Allow",
                    "DefaultOutboundAction": "Allow",
                    "AllowInboundRules": True,
                    "LogAllowed": False,
                    "LogBlocked": True,
                }
            ],
            "RemoteAccess": {"WinRmService": "Running"},
            "Defender": {
                "AMServiceEnabled": True,
                "AntivirusEnabled": True,
                "RealTimeProtectionEnabled": False,
                "BehaviorMonitorEnabled": True,
                "IoavProtectionEnabled": False,
                "AntivirusSignatureLastUpdated": "2026-06-15T08:00:00Z",
            },
            "CoreSettings": {
                "Smb1ServerEnabled": True,
                "Smb1ClientDriverStart": 2,
                "InsecureGuestAuthPolicy": 1,
                "DefenderDisableAntiSpywarePolicy": 1,
                "UacEnabled": 0,
                "UacConsentPromptBehaviorAdmin": 5,
                "UacPromptOnSecureDesktop": 0,
            },
            "PowerShellLogging": {
                "ScriptBlockLoggingEnabled": 0,
                "TranscriptionEnabled": 0,
            },
            "WinRmPolicy": {
                "ClientAllowBasic": 1,
                "ClientAllowUnencryptedTraffic": 1,
                "ServiceDisableRunAs": 0,
            },
            "Findings": [
                {
                    "Id": "WIN-SMB-001",
                    "Severity": "Critical",
                    "Area": "Legacy protocols",
                    "Title": "SMBv1 server protocol is enabled",
                    "Evidence": "Smb1ServerEnabled=True",
                    "Recommendation": "Disable SMBv1 server protocol unless approved.",
                },
                {
                    "Id": "WIN-WINRM-003",
                    "Severity": "Medium",
                    "Area": "Remote management",
                    "Title": "WinRM client unencrypted traffic is allowed",
                    "Evidence": "Client AllowUnencryptedTraffic=1",
                    "Recommendation": "Disable unencrypted WinRM client traffic.",
                },
                {
                    "Id": "WIN-WINRM-008",
                    "Severity": "Medium",
                    "Area": "Remote management",
                    "Title": "WinRM RunAs credential storage is not disallowed by policy",
                    "Evidence": "Service DisableRunAs=0; expected 1",
                    "Recommendation": "Set WinRM service DisableRunAs to 1.",
                },
                {
                    "Id": "WIN-FW-001",
                    "Severity": "High",
                    "Area": "Firewall",
                    "Title": "Windows Firewall profile is disabled",
                    "Evidence": "Domain profile Enabled=False",
                    "Recommendation": "Enable Windows Firewall for the Domain profile.",
                },
                {
                    "Id": "WIN-DEF-002",
                    "Severity": "High",
                    "Area": "Endpoint protection",
                    "Title": "Microsoft Defender protection components are disabled",
                    "Evidence": "RealTimeProtectionEnabled=False; IoavProtectionEnabled=False",
                    "Recommendation": "Validate endpoint protection ownership.",
                },
                {
                    "Id": "WIN-DEF-003",
                    "Severity": "High",
                    "Area": "Endpoint protection",
                    "Title": "Microsoft Defender Antivirus is disabled by policy",
                    "Evidence": "DisableAntiSpyware=1",
                    "Recommendation": "Validate approved EDR ownership.",
                },
                {
                    "Id": "WIN-UAC-001",
                    "Severity": "High",
                    "Area": "Privilege control",
                    "Title": "User Account Control is disabled",
                    "Evidence": "EnableLUA=0",
                    "Recommendation": "Enable UAC after validation.",
                },
                {
                    "Id": "WIN-UAC-002",
                    "Severity": "Medium",
                    "Area": "Privilege control",
                    "Title": "Administrator elevation prompt is not set to a secure desktop prompt",
                    "Evidence": "ConsentPromptBehaviorAdmin=5",
                    "Recommendation": "Validate UAC prompt behavior.",
                },
                {
                    "Id": "WIN-UAC-003",
                    "Severity": "Medium",
                    "Area": "Privilege control",
                    "Title": "UAC secure desktop prompting is not enabled",
                    "Evidence": "PromptOnSecureDesktop=0",
                    "Recommendation": "Enable secure desktop prompting after validation.",
                },
                {
                    "Id": "WIN-PS-001",
                    "Severity": "Medium",
                    "Area": "PowerShell logging",
                    "Title": "PowerShell script block logging is not enabled by policy",
                    "Evidence": "EnableScriptBlockLogging=0",
                    "Recommendation": "Validate PowerShell logging coverage.",
                },
                {
                    "Id": "WIN-PS-002",
                    "Severity": "Medium",
                    "Area": "PowerShell logging",
                    "Title": "PowerShell transcription is not enabled by policy",
                    "Evidence": "EnableTranscripting=0",
                    "Recommendation": "Validate protected transcription path.",
                },
            ],
        }

        findings = normalize_client_source_file("host_windows_security_audit", data, Path("windows-security-audit.json"))
        by_id = {finding["finding_id"]: finding for finding in findings}

        smb = by_id["HOST-WIN-WIN-SMB-001"]
        self.assertEqual(smb["evidence"]["control_family"], "SMB baseline")
        self.assertEqual(smb["evidence"]["protocol_family"], "SMB")
        self.assertEqual(smb["evidence"]["setting_key"], "Smb1ServerEnabled")
        self.assertIs(smb["evidence"]["current_value"], True)
        self.assertIn("not proof that TCP 445 is reachable", smb["evidence"]["risk_explanation"])
        self.assertIn("legacy SMB dependency", smb["evidence"]["customer_question"])

        winrm = by_id["HOST-WIN-WIN-WINRM-003"]
        self.assertEqual(winrm["evidence"]["control_family"], "WinRM baseline")
        self.assertEqual(winrm["evidence"]["winrm_policy_name"], "ClientAllowUnencryptedTraffic")
        self.assertEqual(winrm["evidence"]["current_value"], 1)
        self.assertIn("does not prove internet reachability", winrm["evidence"]["risk_explanation"])

        winrm_runas = by_id["HOST-WIN-WIN-WINRM-008"]
        self.assertEqual(winrm_runas["evidence"]["winrm_policy_name"], "ServiceDisableRunAs")
        self.assertEqual(winrm_runas["evidence"]["expected_value"], "1 / Enabled")

        firewall = by_id["HOST-WIN-WIN-FW-001"]
        self.assertEqual(firewall["evidence"]["control_family"], "Windows Firewall baseline")
        self.assertEqual(firewall["evidence"]["firewall_profile"], "Domain")
        self.assertIs(firewall["evidence"]["firewall_enabled"], False)
        self.assertEqual(firewall["evidence"]["default_inbound_action"], "Allow")
        self.assertIn("not a claim of internet exposure", firewall["evidence"]["risk_explanation"])

        defender = by_id["HOST-WIN-WIN-DEF-002"]
        self.assertEqual(defender["evidence"]["control_family"], "Endpoint protection baseline")
        self.assertFalse(defender["evidence"]["defender_realtime_protection_enabled"])
        self.assertIn("IoavProtectionEnabled", defender["evidence"]["disabled_defender_components"])
        self.assertIn("approved third-party EDR", defender["evidence"]["risk_explanation"])

        defender_policy = by_id["HOST-WIN-WIN-DEF-003"]
        self.assertEqual(defender_policy["evidence"]["setting_key"], "DefenderDisableAntiSpywarePolicy")
        self.assertEqual(defender_policy["evidence"]["current_value"], 1)
        self.assertIn("approved endpoint protection", defender_policy["evidence"]["summary"])

        uac = by_id["HOST-WIN-WIN-UAC-001"]
        self.assertEqual(uac["evidence"]["control_family"], "Windows privilege control baseline")
        self.assertEqual(uac["evidence"]["registry_name"], "EnableLUA")
        self.assertEqual(uac["evidence"]["current_value"], 0)
        self.assertIn("legacy application", uac["evidence"]["customer_question"])

        powershell = by_id["HOST-WIN-WIN-PS-001"]
        self.assertEqual(powershell["evidence"]["control_family"], "PowerShell logging baseline")
        self.assertEqual(powershell["evidence"]["policy_name"], "PowerShell Script Block Logging")
        self.assertEqual(powershell["evidence"]["current_value"], 0)
        self.assertIn("centrally", powershell["evidence"]["customer_question"])

        transcription = by_id["HOST-WIN-WIN-PS-002"]
        self.assertIn("sensitive command content", transcription["evidence"]["data_sensitivity_note"])

    def test_host_password_audit_local_and_llmnr_findings_include_structured_context(self):
        data = {
            "ToolName": "Invoke-WindowsSecurityAudit",
            "ReportType": "windows-host-audit",
            "GeneratedAtUtc": "2026-06-15T09:00:00Z",
            "ComputerName": "LAB-SRV01",
            "PasswordPolicy": {
                "Minimum password length": 8,
                "Lockout threshold": 0,
                "Lockout duration (minutes)": 0,
            },
            "LocalAccounts": {
                "Guest": {
                    "Name": "Guest",
                    "Disabled": False,
                    "SID": "S-1-5-21-111-222-333-501",
                    "LocalAccount": True,
                }
            },
            "AuditPolicy": [
                {
                    "Subcategory": "Logon",
                    "Subcategory GUID": "{0CCE9215-69AE-11D9-BED3-505054503030}",
                    "Inclusion Setting": "Success",
                },
                {
                    "Subcategory": "Process Creation",
                    "Subcategory GUID": "{0CCE922B-69AE-11D9-BED3-505054503030}",
                    "Inclusion Setting": "No Auditing",
                },
            ],
            "CoreSettings": {
                "LlmnrEnabledPolicy": 1,
            },
            "Findings": [
                {
                    "Id": "WIN-PWD-001",
                    "Severity": "Medium",
                    "Area": "Password policy",
                    "Title": "Minimum password length is below 14 characters",
                    "Evidence": "Minimum password length=8",
                    "Recommendation": "Use at least 14 characters.",
                },
                {
                    "Id": "WIN-PWD-002",
                    "Severity": "High",
                    "Area": "Password policy",
                    "Title": "Account lockout threshold is disabled",
                    "Evidence": "Lockout threshold=0",
                    "Recommendation": "Set a nonzero account lockout threshold.",
                },
                {
                    "Id": "WIN-AUDIT-LOGON",
                    "Severity": "High",
                    "Area": "Audit policy",
                    "Title": "Logon auditing is incomplete",
                    "Evidence": "Logon Inclusion Setting=Success; missing Failure",
                    "Recommendation": "Enable Success and Failure auditing for Logon.",
                },
                {
                    "Id": "WIN-AUDIT-PROC",
                    "Severity": "Medium",
                    "Area": "Audit policy",
                    "Title": "Process Creation auditing is incomplete",
                    "Evidence": "Process Creation Inclusion Setting=No Auditing; missing Success",
                    "Recommendation": "Enable Success auditing for Process Creation.",
                },
                {
                    "Id": "WIN-LOCAL-002",
                    "Severity": "High",
                    "Area": "Local accounts",
                    "Title": "Built-in Guest account is enabled",
                    "Evidence": "Guest Disabled=False",
                    "Recommendation": "Disable the built-in Guest account.",
                },
                {
                    "Id": "WIN-LLMNR-001",
                    "Severity": "Medium",
                    "Area": "Name resolution",
                    "Title": "LLMNR disable policy is not enforced",
                    "Evidence": "EnableMulticast=1",
                    "Recommendation": "Set EnableMulticast to 0 through policy if LLMNR is not required.",
                },
            ],
        }

        findings = normalize_client_source_file("host_windows_security_audit", data, Path("windows-security-audit.json"))
        by_id = {finding["finding_id"]: finding for finding in findings}

        min_length = by_id["HOST-WIN-WIN-PWD-001"]
        self.assertEqual(min_length["evidence"]["control_family"], "Windows password policy baseline")
        self.assertEqual(min_length["evidence"]["setting_key"], "Minimum password length")
        self.assertEqual(min_length["evidence"]["current_value"], 8)
        self.assertIn("domain, Entra ID, MFA", min_length["evidence"]["risk_explanation"])
        self.assertIn("Which identity policy owns", min_length["evidence"]["customer_question"])

        lockout = by_id["HOST-WIN-WIN-PWD-002"]
        self.assertEqual(lockout["evidence"]["policy_name"], "Account lockout threshold")
        self.assertEqual(lockout["evidence"]["current_value"], 0)
        self.assertIn("identity change control", lockout["evidence"]["safe_next_step"])

        audit = by_id["HOST-WIN-WIN-AUDIT-LOGON"]
        self.assertEqual(audit["evidence"]["control_family"], "Windows audit policy baseline")
        self.assertEqual(audit["evidence"]["audit_subcategory"], "Logon")
        self.assertEqual(audit["evidence"]["current_inclusion_setting"], "Success")
        self.assertEqual(audit["evidence"]["required_inclusion"], ["Success", "Failure"])
        self.assertIn("central log collection", audit["evidence"]["safe_next_step"])

        process_creation = by_id["HOST-WIN-WIN-AUDIT-PROC"]
        self.assertEqual(process_creation["evidence"]["audit_subcategory"], "Process Creation")
        self.assertEqual(process_creation["evidence"]["current_inclusion_setting"], "No Auditing")

        guest = by_id["HOST-WIN-WIN-LOCAL-002"]
        self.assertEqual(guest["evidence"]["control_family"], "Windows local account baseline")
        self.assertEqual(guest["evidence"]["account_name"], "Guest")
        self.assertFalse(guest["evidence"]["current_value"])
        self.assertIn("temporary support exception", guest["evidence"]["customer_question"])

        llmnr = by_id["HOST-WIN-WIN-LLMNR-001"]
        self.assertEqual(llmnr["evidence"]["control_family"], "Windows name resolution baseline")
        self.assertEqual(llmnr["evidence"]["protocol_family"], "LLMNR")
        self.assertEqual(llmnr["evidence"]["current_value"], 1)
        self.assertIn("not proof of active exploitation", llmnr["evidence"]["risk_explanation"])

    def test_windows_samples_do_not_include_sensitive_or_customer_looking_data(self):
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
            "172.16.",
            "8.8.8.8",
            "1.1.1.1",
            "api_key",
            "secret=",
            "token=",
            "password=",
        ]

        for path in WINDOWS_SAMPLE_ROOT.glob("*.json"):
            text = path.read_text(encoding="utf-8").lower()
            for fragment in blocked_fragments:
                self.assertNotIn(fragment, text, f"{fragment} found in {path}")
            self.assertTrue(
                any(marker in text for marker in ["lab-", "corp.example.test", "10.10.10.0/24"]),
                f"No fictional marker found in {path}",
            )


if __name__ == "__main__":
    unittest.main()

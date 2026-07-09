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

    def test_windows_network_sample_uses_port_context(self):
        data = load_json_file(WINDOWS_SAMPLE_ROOT / "sample-windows-network-exposure.json")
        report = normalize_windows_network_exposure(data, WINDOWS_SAMPLE_ROOT / "sample-windows-network-exposure.json")
        rdp = next(finding for finding in report["findings"] if finding["evidence"].get("port") == 3389)

        self.assertEqual(rdp["evidence"]["common_name"], "RDP")
        self.assertIn("Remote Desktop Protocol", rdp["evidence"]["summary"])
        self.assertIn("customer_question: Who requires RDP access", rdp["evidence"]["details"])
        self.assertFalse(rdp["safe_to_auto_remediate"])

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

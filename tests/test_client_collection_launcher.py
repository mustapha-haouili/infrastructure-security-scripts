import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ClientCollectionLauncherTests(unittest.TestCase):
    def read_text(self, relative_path: str) -> str:
        return (ROOT / relative_path).read_text(encoding="utf-8")

    def test_client_collection_launcher_is_registered(self):
        launcher = self.read_text("scripts/windows/Start-WindowsSecurity.ps1")

        self.assertIn('New-ToolDefinition -Id "CLIENT-COLLECTION"', launcher)
        self.assertIn('RelativePath "Start-SecureInfraClientCollection.ps1"', launcher)
        self.assertIn("-IncludeInRunAll $false", launcher)
        self.assertIn('New-ToolDefinition -Id "SERVER-LOCAL-ADMINS"', launcher)
        self.assertIn('New-ToolDefinition -Id "SERVER-SECURITY-INVENTORY"', launcher)
        self.assertIn('New-ToolDefinition -Id "SERVER-RDP-EXPOSURE"', launcher)
        self.assertIn('New-ToolDefinition -Id "WORKSTATION-LOCAL-ADMINS"', launcher)
        self.assertIn('New-ToolDefinition -Id "WORKSTATION-SECURITY-INVENTORY"', launcher)
        self.assertIn('New-ToolDefinition -Id "WORKSTATION-RDP-EXPOSURE"', launcher)
        self.assertIn('New-ToolDefinition -Id "NETWORK-EXPOSURE"', launcher)
        self.assertIn('New-ToolDefinition -Id "BACKUP-READINESS"', launcher)

    def test_client_collection_launcher_has_safe_default_contract(self):
        collector = self.read_text("scripts/windows/Start-SecureInfraClientCollection.ps1")

        self.assertIn("SafetyMode", collector)
        self.assertIn("Audit and dry-run only", collector)
        self.assertIn("ad-shared", collector)
        self.assertIn("manifest.json", collector)
        self.assertIn("collection-summary.json", collector)
        self.assertIn("Compress-Archive", collector)
        self.assertNotIn("UpdateBaseline", collector)
        self.assertIsNone(re.search(r"\bApply\s*=", collector))
        self.assertIn("Get-WindowsLocalAdminInventory.ps1", collector)
        self.assertIn("Get-WindowsRDPExposureAudit.ps1", collector)
        self.assertIn("Get-WindowsServerSecurityInventory.ps1", collector)
        self.assertIn("Get-WindowsWorkstationSecurityInventory.ps1", collector)
        self.assertIn("Get-WindowsNetworkExposureAudit.ps1", collector)
        self.assertIn("Get-WindowsBackupReadinessAudit.ps1", collector)
        self.assertIn("The broad All scope includes AD/GPO only", collector)
        self.assertIn("CompatibilityProfile", collector)
        self.assertIn("compatibility-report.json", collector)
        self.assertIn("Scope compatibility preflight", collector)

    def test_client_collection_scope_values_document_current_coverage(self):
        collector = self.read_text("scripts/windows/Start-SecureInfraClientCollection.ps1")

        self.assertIn('$productTypeNumber -eq 1', collector)
        self.assertIn('$productTypeNumber -in @(2, 3)', collector)
        self.assertIn('$IsDomainController -ne $false', collector)
        self.assertIn('$roleScopes = @(', collector)
        self.assertIn('$directoryScopes = @(', collector)
        self.assertIn('$defaultAllScopes = @($directoryScopes) + @("Host") + @($roleScopes) + @("Network", "Backup")', collector)
        self.assertIn('OsProductType', collector)
        self.assertIn('ComputerDomainRole', collector)
        self.assertIn('IsDomainController', collector)
        self.assertIn('Resolve-CollectionScopes -OsProductType $clientInfo.OsProductType -IsDomainController $clientInfo.IsDomainController', collector)
        self.assertIn('@("AD", "GPO", "Host", "Server", "Workstation", "Network", "Backup")', collector)
        self.assertIn('SupportedToday     = @("AD", "GPO", "Host", "Server", "Workstation", "Network", "Backup")', collector)
        self.assertIn('NotYetImplemented  = @()', collector)

    def test_all_scope_resolution_preserves_domain_controller_scope_array(self):
        powershell = (
            shutil.which("powershell.exe")
            or shutil.which("powershell")
            or shutil.which("pwsh")
        )
        if powershell is None:
            self.skipTest("PowerShell is not installed")

        collector = self.read_text("scripts/windows/Start-SecureInfraClientCollection.ps1")
        start = collector.index("function Resolve-CollectionScopes")
        end = collector.index("function Add-SkippedTask", start)
        function_source = collector[start:end]
        command = f"""
{function_source}
$script:Scope = @("All")
[pscustomobject]@{{
    DomainController = @((Resolve-CollectionScopes -OsProductType 2 -IsDomainController $true))
    MemberServer = @((Resolve-CollectionScopes -OsProductType 3 -IsDomainController $false))
}} | ConvertTo-Json -Depth 4 -Compress
"""
        result = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-Command", command],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8-sig",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        resolved = json.loads(result.stdout)
        self.assertEqual(
            resolved["DomainController"],
            ["AD", "Host", "Server", "Network", "Backup"],
        )
        self.assertEqual(
            resolved["MemberServer"],
            ["Host", "Server", "Network", "Backup"],
        )

    def test_client_collection_restores_explicit_gpo_scope(self):
        collector = self.read_text("scripts/windows/Start-SecureInfraClientCollection.ps1")

        self.assertIn('"GPO" { Invoke-GPOCollection }', collector)
        self.assertIn('function Invoke-GPOCollection', collector)
        self.assertIn('Invoke-GPOHealthCollection -ScopeName "GPO"', collector)
        self.assertIn('Invoke-GPOHealthCollection -ScopeName "AD"', collector)
        self.assertIn('gpo\\Get-ADGPOHealthReport.ps1', collector)
        self.assertIn('gpo-health.json', collector)
        self.assertIn('gpo-review.md', collector)

    def test_client_collection_gpo_scope_is_documented(self):
        collector = self.read_text("scripts/windows/Start-SecureInfraClientCollection.ps1")
        readme = self.read_text("README.md")
        script_reference = self.read_text("docs/script-reference.md")
        windows_readme = self.read_text("scripts/windows/README.md")

        for document in [collector, readme, script_reference, windows_readme]:
            self.assertIn("-Scope GPO", document)
        self.assertIn("`All`, `AD`, `GPO`, `Host`, `Server`, `Workstation`, `Network`, `Backup`", script_reference)
        self.assertIn("The broad `AD`", readme)
        self.assertIn("GPO health", readme)

    def test_new_windows_collection_scripts_are_audit_only(self):
        for script in [
            "scripts/windows/host/Get-WindowsLocalAdminInventory.ps1",
            "scripts/windows/host/Get-WindowsRDPExposureAudit.ps1",
            "scripts/windows/network/Get-WindowsNetworkExposureAudit.ps1",
            "scripts/windows/backup/Get-WindowsBackupReadinessAudit.ps1",
            "scripts/windows/server/Get-WindowsServerSecurityInventory.ps1",
            "scripts/windows/workstation/Get-WindowsWorkstationSecurityInventory.ps1",
        ]:
            text = self.read_text(script)
            self.assertIn("does not change", text)
            self.assertNotIn("[switch]$Apply", text)
            self.assertNotIn("Set-ItemProperty", text)

    def test_builtin_group_inventory_supports_domain_controllers_and_localized_hosts(self):
        helper_path = "scripts/windows/common/Get-WindowsBuiltinGroupInventory.ps1"
        helper = self.read_text(helper_path)
        host_audit = self.read_text("scripts/windows/host/Invoke-WindowsSecurityAudit.ps1")
        local_admins = self.read_text("scripts/windows/host/Get-WindowsLocalAdminInventory.ps1")
        rdp = self.read_text("scripts/windows/host/Get-WindowsRDPExposureAudit.ps1")

        self.assertIn("[int]$domainRole -in @(4, 5)", helper)
        self.assertIn("Get-ADGroup -Identity $Sid", helper)
        self.assertIn("Get-ADGroupMember -Identity $Group.SourceObject", helper)
        self.assertIn("Get-SecureInfraLocalizedBuiltinGroupName", helper)
        self.assertIn('Provider     = "WinNT"', helper)
        self.assertIn("does not change group membership", helper)
        for collector in (host_audit, local_admins, rdp):
            self.assertIn("Get-WindowsBuiltinGroupInventory.ps1", collector)
            self.assertIn("Get-SecureInfraBuiltinGroup", collector)
            self.assertIn("Get-SecureInfraBuiltinGroupMembers", collector)

        self.assertIn('Sid "S-1-5-32-544"', host_audit)
        self.assertIn("LocalAdministratorCollection", host_audit)
        self.assertIn('MemberCount        = if ($status -eq "Complete")', host_audit)
        self.assertNotIn('Get-LocalGroupMember -Group "Administrators"', host_audit)
        self.assertNotIn('net localgroup Administrators', host_audit)
        self.assertIn('Sid "S-1-5-32-544"', local_admins)
        self.assertIn('"LocalAdminEvidenceUnavailable"', local_admins)
        self.assertIn("CollectionStatus", local_admins)
        self.assertNotIn('throw "Unable to find the local Administrators group."', local_admins)
        self.assertIn('Sid "S-1-5-32-555"', rdp)
        self.assertIn("GroupMembershipStatus", rdp)

    def test_windows_security_audit_accepts_textual_disabled_lockout_threshold(self):
        host_audit = self.read_text("scripts/windows/host/Invoke-WindowsSecurityAudit.ps1")

        self.assertIn("function ConvertTo-NullableInt", host_audit)
        self.assertIn('$lockoutThresholdText -eq "Never"', host_audit)
        self.assertIn("$null -ne $lockoutThresholdNumber -and $lockoutThresholdNumber -eq 0", host_audit)
        self.assertNotIn("([int]$lockoutThreshold -eq 0)", host_audit)


if __name__ == "__main__":
    unittest.main()

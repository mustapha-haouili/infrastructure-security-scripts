import re
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
        self.assertIn("The broad All scope includes Backup readiness", collector)

    def test_client_collection_scope_values_document_current_coverage(self):
        collector = self.read_text("scripts/windows/Start-SecureInfraClientCollection.ps1")

        self.assertIn('$defaultAllScopes = @("AD", "Host", "Server", "Workstation", "Network", "Backup")', collector)
        self.assertIn('@("AD", "GPO", "Host", "Server", "Workstation", "Network", "Backup")', collector)
        self.assertIn('SupportedToday     = @("AD", "GPO", "Host", "Server", "Workstation", "Network", "Backup")', collector)
        self.assertIn('NotYetImplemented  = @()', collector)

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
        self.assertIn("scope still includes GPO health evidence", readme)

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


if __name__ == "__main__":
    unittest.main()

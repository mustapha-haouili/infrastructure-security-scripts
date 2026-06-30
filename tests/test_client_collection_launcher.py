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
        self.assertIn("Backup is explicit and is not included in All", collector)

    def test_client_collection_scope_values_document_current_coverage(self):
        collector = self.read_text("scripts/windows/Start-SecureInfraClientCollection.ps1")

        self.assertIn('@("AD", "Host", "Server", "Workstation", "Network", "Backup")', collector)
        self.assertIn('SupportedToday     = @("AD", "Host", "Server", "Workstation", "Network", "Backup")', collector)
        self.assertIn('NotYetImplemented  = @()', collector)

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

from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = REPO_ROOT / "COLLECTOR_COVERAGE_MATRIX.md"
WINDOWS_LAUNCHER = REPO_ROOT / "scripts" / "windows" / "Start-SecureInfraClientCollection.ps1"
LINUX_LAUNCHER = REPO_ROOT / "scripts" / "linux" / "Start-SecureInfraLinuxCollection.sh"


def repo_path(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


class CollectorCoverageMatrixTests(unittest.TestCase):
    def setUp(self):
        self.matrix = MATRIX_PATH.read_text(encoding="utf-8")

    def test_windows_and_linux_scripts_are_documented(self):
        script_paths = [
            *sorted((REPO_ROOT / "scripts" / "windows").rglob("*.ps1")),
            *sorted((REPO_ROOT / "scripts" / "linux").glob("*.sh")),
        ]
        missing = [repo_path(path) for path in script_paths if repo_path(path) not in self.matrix]
        self.assertEqual(missing, [], "Every Windows/Linux collector script must be listed in COLLECTOR_COVERAGE_MATRIX.md")

    def test_automated_windows_collectors_are_called_by_launcher(self):
        launcher = WINDOWS_LAUNCHER.read_text(encoding="utf-8")
        expected_auto_scripts = [
            "Get-ADInactiveUserReport.ps1",
            "Get-ADPasswordNeverExpiresReport.ps1",
            "Get-ADSPNExposureAudit.ps1",
            "Get-ADServiceAccountAudit.ps1",
            "Get-ADStaleComputerReport.ps1",
            "Get-PrivilegedIdentityProtectionAudit.ps1",
            "Watch-ADPrivilegedGroupChanges.ps1",
            "Get-ADGPOHealthReport.ps1",
            "Invoke-WindowsSecurityAudit.ps1",
            "New-WindowsRemediationPlan.ps1",
            "Export-WindowsEventSecurityReport.ps1",
            "Set-WindowsBaselineHardening.ps1",
            "Get-WindowsLocalAdminInventory.ps1",
            "Get-WindowsRDPExposureAudit.ps1",
            "Get-WindowsServerSecurityInventory.ps1",
            "Clear-RDPUserProfileCache.ps1",
            "Get-WindowsWorkstationSecurityInventory.ps1",
            "Get-WindowsNetworkExposureAudit.ps1",
            "Get-WindowsBackupReadinessAudit.ps1",
        ]
        missing = [script for script in expected_auto_scripts if script not in launcher]
        self.assertEqual(missing, [], "Auto Windows collectors must be invoked by Start-SecureInfraClientCollection.ps1")

    def test_automated_linux_collectors_are_called_by_launcher(self):
        launcher = LINUX_LAUNCHER.read_text(encoding="utf-8")
        expected_auto_scripts = [
            "collect-linux-inventory.sh",
            "linux-security-audit.sh",
            "linux-network-exposure-audit.sh",
            "linux-service-inventory-audit.sh",
            "linux-log-audit.sh",
            "linux-hardening-baseline.sh",
            "backup-readiness-audit.sh",
        ]
        missing = [script for script in expected_auto_scripts if script not in launcher]
        self.assertEqual(missing, [], "Auto Linux collectors must be invoked by Start-SecureInfraLinuxCollection.sh")

    def test_manual_only_scripts_have_explicit_reason(self):
        self.assertIn("scripts/windows/host/Start-WindowsSecurityRemediation.ps1", self.matrix)
        self.assertIn("because it can change systems", self.matrix)
        self.assertIn("scripts/windows/Start-WindowsSecurity.ps1", self.matrix)
        self.assertIn("Interactive helper", self.matrix)

    def test_metadata_only_outputs_are_documented(self):
        self.assertIn("host/windows-remediation-plan.json", self.matrix)
        self.assertIn("host/windows-hardening-preview.json", self.matrix)
        self.assertIn("Metadata only", self.matrix)
        self.assertIn("Final metadata-only output contract", self.matrix)


if __name__ == "__main__":
    unittest.main()

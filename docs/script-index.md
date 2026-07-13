# Script Index

This index lists supported public entrypoints. Internal Python modules under
`SecureInfra_AI/scripts/reporting/secureinfra/` are implementation details and
are documented through the analyzer architecture and tests.

## Windows

- `scripts/windows/Start-WindowsSecurity.ps1`
- `scripts/windows/Start-SecureInfraClientCollection.ps1`
- `scripts/windows/ad/Get-ADInactiveUserReport.ps1`
- `scripts/windows/ad/Get-ADPasswordNeverExpiresReport.ps1`
- `scripts/windows/ad/Get-ADSPNExposureAudit.ps1`
- `scripts/windows/ad/Get-ADServiceAccountAudit.ps1`
- `scripts/windows/ad/Get-ADStaleComputerReport.ps1`
- `scripts/windows/ad/Get-PrivilegedIdentityProtectionAudit.ps1`
- `scripts/windows/ad/Watch-ADPrivilegedGroupChanges.ps1`
- `scripts/windows/backup/Get-WindowsBackupReadinessAudit.ps1`
- `scripts/windows/gpo/Get-ADGPOHealthReport.ps1`
- `scripts/windows/host/Export-WindowsEventSecurityReport.ps1`
- `scripts/windows/host/Get-WindowsLocalAdminInventory.ps1`
- `scripts/windows/host/Get-WindowsRDPExposureAudit.ps1`
- `scripts/windows/host/Invoke-WindowsSecurityAudit.ps1`
- `scripts/windows/host/New-WindowsRemediationPlan.ps1`
- `scripts/windows/host/Set-WindowsBaselineHardening.ps1`
- `scripts/windows/host/Start-WindowsSecurityRemediation.ps1`
- `scripts/windows/network/Get-WindowsNetworkExposureAudit.ps1`
- `scripts/windows/server/Clear-RDPUserProfileCache.ps1`
- `scripts/windows/server/Get-WindowsServerSecurityInventory.ps1`
- `scripts/windows/workstation/Get-WindowsWorkstationSecurityInventory.ps1`

## Linux

- `scripts/linux/Start-SecureInfraLinuxCollection.sh`
- `scripts/linux/collect-linux-inventory.sh`
- `scripts/linux/linux-security-audit.sh`
- `scripts/linux/linux-network-exposure-audit.sh`
- `scripts/linux/linux-service-inventory-audit.sh`
- `scripts/linux/linux-log-audit.sh`
- `scripts/linux/linux-hardening-baseline.sh`
- `scripts/linux/backup-readiness-audit.sh`

## Reporting and validation

- `SecureInfra_AI/scripts/reporting/secureinfra_analyzer.py`
- `scripts/reporting/generate-markdown-report.py`
- `scripts/reporting/validate_bundle.py`
- `scripts/reporting/validate_schema.py`

## Release integrity

- `scripts/release/create_release_bundle.sh`
- `scripts/release/New-SecureInfraReleaseBundle.ps1`

## Monitoring

- `scripts/monitoring/service-health-check.py`
- `scripts/monitoring/disk-space-monitor.sh`

## DevSecOps helpers

These remain standalone/manual tools until their collection and normalization
contracts are expanded after the Windows/Linux completion gate.

- `scripts/devsecops/secret-scan.py`
- `scripts/devsecops/docker-image-audit.sh`
- `scripts/devsecops/kubernetes-rbac-audit.sh`

See [script-reference.md](script-reference.md) for detailed parameters and
[../ROADMAP.md](../ROADMAP.md) for planned work.

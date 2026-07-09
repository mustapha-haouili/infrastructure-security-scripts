# SecureInfra Windows and Linux Collector Coverage Matrix

This matrix is the operating contract for Windows and Linux collection coverage.
Every Windows PowerShell collector and Linux shell collector in this repository must be listed here and must have one of these statuses:

- **Launcher**: primary entry point for a platform.
- **Auto**: invoked automatically by the platform launcher in a normal safe collection scope.
- **Auto dry-run/report-only**: invoked automatically, but only in report-only or dry-run mode.
- **Interactive launcher**: user-facing menu or helper launcher; not executed by client bundle collection.
- **Manual-only**: intentionally excluded from default collection because it is remediation, monitoring, or operationally sensitive.

New collectors must either be added to the platform launcher or marked manual-only here with a clear reason. Do not add orphan scripts.

## End-to-end collection flow

```text
Windows host or domain controller
  -> scripts/windows/Start-SecureInfraClientCollection.ps1
  -> ZIP bundle
  -> customer-projects/<project>/03-input-bundles
  -> validate_bundle.py
  -> secureinfra_analyzer.py --type multi-bundle
  -> validate_schema.py
  -> downstream-reporting-workspace reporting pipeline

Linux host
  -> scripts/linux/Start-SecureInfraLinuxCollection.sh
  -> ZIP bundle
  -> customer-projects/<project>/03-input-bundles
  -> validate_bundle.py
  -> secureinfra_analyzer.py --type multi-bundle
  -> validate_schema.py
  -> downstream-reporting-workspace reporting pipeline
```

## Windows collectors

| Script | Status | Launcher scope / path | Primary evidence outputs | Analyzer support | Notes |
|---|---|---|---|---|---|
| `scripts/windows/Start-SecureInfraClientCollection.ps1` | Launcher | Windows client bundle entry point | `client-info.json`, `collection-summary.json`, `manifest.json`, ZIP bundle | Yes | Safe report-only collector bundle launcher. `All` includes AD, Host, Server, Workstation, Network, and Backup. |
| `scripts/windows/Start-WindowsSecurity.ps1` | Interactive launcher | Manual menu launcher | User-selected child script outputs | Indirect | Interactive helper for local admins; not part of automated customer bundle pipeline. |
| `scripts/windows/ad/Get-ADInactiveUserReport.ps1` | Auto | `AD` / `All` | AD inactive user JSON/CSV/MD | Yes | Read-only AD account lifecycle evidence. |
| `scripts/windows/ad/Get-ADPasswordNeverExpiresReport.ps1` | Auto | `AD` / `All` | PasswordNeverExpires JSON/CSV/MD | Yes | Read-only account password policy exception evidence. |
| `scripts/windows/ad/Get-ADSPNExposureAudit.ps1` | Auto | `AD` / `All` | SPN exposure JSON/CSV/MD | Yes | Defensive SPN exposure review; no offensive actions. |
| `scripts/windows/ad/Get-ADServiceAccountAudit.ps1` | Auto | `AD` / `All` | Service account JSON/CSV/MD | Yes | Service account governance evidence. |
| `scripts/windows/ad/Get-ADStaleComputerReport.ps1` | Auto | `AD` / `All` | Stale computer JSON/CSV/MD | Yes | Computer lifecycle evidence; do not use service-account wording. |
| `scripts/windows/ad/Get-PrivilegedIdentityProtectionAudit.ps1` | Auto | `AD` / `All` | Privileged identity JSON/CSV/MD | Yes | Privileged account protection and lifecycle evidence. |
| `scripts/windows/ad/Watch-ADPrivilegedGroupChanges.ps1` | Auto | `AD` / `All` | Privileged group snapshot/change JSON/CSV/MD | Yes | Uses baseline for review; default collection does not update baseline unless explicitly requested. |
| `scripts/windows/gpo/Get-ADGPOHealthReport.ps1` | Auto | `AD`, `GPO` | GPO health JSON/CSV/MD | Yes | GPO health, stale policy, link/filter/version evidence. |
| `scripts/windows/host/Invoke-WindowsSecurityAudit.ps1` | Auto | `Host` / `All` | `host/windows-security-audit.json` | Yes | Local host baseline and configuration evidence. |
| `scripts/windows/host/New-WindowsRemediationPlan.ps1` | Auto dry-run/report-only | `Host` / `All` after host audit | `host/windows-remediation-plan.json`, `.md`, `.csv` | Metadata only | Generates a plan from audit evidence; does not apply remediation. |
| `scripts/windows/host/Export-WindowsEventSecurityReport.ps1` | Auto | `Host` / `All` | `host/windows-events/summary.json`, `.txt`, `events.csv` | Yes | Local Windows event/security summary evidence. |
| `scripts/windows/host/Set-WindowsBaselineHardening.ps1` | Auto dry-run/report-only | `Host` / `All` without apply flags | `host/windows-hardening-preview.json` | Metadata only | Preview/report mode only in bundle collection. Do not apply changes in client collection. |
| `scripts/windows/host/Get-WindowsLocalAdminInventory.ps1` | Auto | `Server`, `Workstation` | `windows-local-admins.json`, `.csv`, `.md` | Yes | Local administrator membership evidence. |
| `scripts/windows/host/Get-WindowsRDPExposureAudit.ps1` | Auto | `Server`, `Workstation` | `windows-rdp-exposure.json`, `.csv`, `.md` | Yes | RDP configuration/listener/firewall evidence. |
| `scripts/windows/host/Start-WindowsSecurityRemediation.ps1` | Manual-only | Manual remediation workflow | Remediation execution output | No | Explicitly excluded from bundle collection because it can change systems. |
| `scripts/windows/server/Get-WindowsServerSecurityInventory.ps1` | Auto | `Server` / `All` | `server/windows-server-security.json`, `.csv`, `.md` | Yes | Server services, shares, firewall, SMB/RDP/WinRM, and configuration evidence. |
| `scripts/windows/server/Clear-RDPUserProfileCache.ps1` | Auto dry-run/report-only | `Server` / `All` | `server/rdp-profile-cache-cleanup.json` | Yes | Report-only cache cleanup candidate evidence; no deletion in client collection. |
| `scripts/windows/workstation/Get-WindowsWorkstationSecurityInventory.ps1` | Auto | `Workstation` / `All` | `workstation/windows-workstation-security.json`, `.csv`, `.md` | Yes | Workstation baseline, local configuration, and exposure evidence. |
| `scripts/windows/network/Get-WindowsNetworkExposureAudit.ps1` | Auto | `Network` / `All` | `network/windows-network-exposure.json`, `.csv`, `.md` | Yes | Local TCP/UDP listener, process, Windows service, bind scope, sensitive inbound firewall allow rule, firewall profile, and network profile evidence. Does not prove internet exposure. |
| `scripts/windows/backup/Get-WindowsBackupReadinessAudit.ps1` | Auto | `Backup` / `All` | `backup/backup-readiness.json`, `.csv`, `.md` | Yes | Metadata-only backup readiness evidence. |

## Linux collectors

| Script | Status | Launcher scope / path | Primary evidence outputs | Analyzer support | Notes |
|---|---|---|---|---|---|
| `scripts/linux/Start-SecureInfraLinuxCollection.sh` | Launcher | Linux platform bundle entry point | `client-info.json`, `collection-summary.json`, `manifest.json`, `bundle-manifest.json`, ZIP bundle | Yes | Safe read-only Linux collector launcher. |
| `scripts/linux/collect-linux-inventory.sh` | Auto | Linux launcher | `linux/linux-inventory.json` | Inventory metadata | Host OS, CPU, memory, disks, mounts, network interface metadata. |
| `scripts/linux/linux-security-audit.sh` | Auto | Linux launcher | `linux/linux-security-summary.json`, text detail log | Yes | SSH, sudoers, UID 0, firewall evidence, sysctl/kernel hardening, patch evidence, filesystem permissions, audit coverage. |
| `scripts/linux/linux-network-exposure-audit.sh` | Auto | Linux launcher | `linux/linux-network-exposure-summary.json` | Yes | Local listening TCP/UDP services, bind scope, service/process hints, and firewall evidence. No active network scan. |
| `scripts/linux/linux-service-inventory-audit.sh` | Auto | Linux launcher | `linux/linux-service-inventory-summary.json` | Yes | systemd services, failed/enabled/running services, writable unit files, custom root-run service paths, startup persistence locations. |
| `scripts/linux/linux-log-audit.sh` | Auto | Linux launcher | `linux/linux-log-audit-summary.json` | Yes | Auth/audit/journald/rsyslog/Wazuh/OSSEC presence and event count metadata. Does not package raw logs. |
| `scripts/linux/linux-hardening-baseline.sh` | Auto dry-run/report-only | Linux launcher dry-run | hardening plan log under `linux/` | Metadata only | Preview/dry-run only in collection. Do not apply system changes in client collection. |
| `scripts/linux/backup-readiness-audit.sh` | Auto | Linux launcher | `backup/backup-readiness.json`, `.csv` | Yes | Metadata-only backup readiness evidence. |

## Manual-only and future platform notes

- DevSecOps, Docker, and Kubernetes scripts are not part of this Windows/Linux completion gate yet. They will receive dedicated launchers and normalizers before being treated as automated platform collectors.
- Wazuh SCA/rule content must not be copied into this repository. Use selected rule files only as reference material for a SecureInfra-owned mapping document or controls catalog.
- Active network scanning is not part of default Linux or Windows collection. Local listening socket inventory is allowed; remote scanning requires explicit customer authorization and a separate opt-in workflow.

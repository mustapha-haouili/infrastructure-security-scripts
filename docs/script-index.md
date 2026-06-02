# Script Index

For full parameter documentation and examples for every argument, see
[script-reference.md](script-reference.md).

## Windows

Expansion roadmap and category structure: [windows-roadmap.md](windows-roadmap.md).

Start Windows work from the root menu launcher. The implementation scripts stay
in organized category folders for advanced or direct use.

| Script | Purpose | Default mode |
|---|---|---|
| `Start-WindowsSecurity.ps1` | Interactive menu for AD/GPO, host, server, and workstation scripts | Menu |
| `host/Invoke-WindowsSecurityAudit.ps1` | Collect Windows baseline security information and export JSON | Audit |
| `host/Set-WindowsBaselineHardening.ps1` | Apply selected Windows baseline hardening controls | Dry run |
| `host/New-WindowsRemediationPlan.ps1` | Create remediation plans from Windows audit reports | Audit |
| `host/Start-WindowsSecurityRemediation.ps1` | Guided audit, approval, preview, and apply workflow | Dry run until final approval |
| `host/Export-WindowsEventSecurityReport.ps1` | Export important Windows Security and System event log activity | Audit |
| `server/Clear-RDPUserProfileCache.ps1` | Audit and optionally clean safe per-user cache locations on RDP/Terminal Server hosts | Dry run |

### Windows AD

| Script | Purpose | Default mode |
|---|---|---|
| `ad/Get-ADInactiveUserReport.ps1` | Report inactive Active Directory users with last logon evidence | Audit |
| `ad/Get-ADStaleComputerReport.ps1` | Report stale Active Directory computers with cleanup-readiness guidance | Audit |
| `ad/Watch-ADPrivilegedGroupChanges.ps1` | Compare privileged AD group membership against a saved baseline | Audit |
| `ad/Get-ADServiceAccountAudit.ps1` | Audit service account candidates, SPNs, password age, delegation, ownership, and privilege risk | Audit |
| `ad/Get-ADSPNExposureAudit.ps1` | Audit SPN-bearing user accounts for defensive Kerberos exposure indicators | Audit |
| `ad/Get-ADPasswordNeverExpiresReport.ps1` | Report PasswordNeverExpires accounts with exception and rotation guidance | Audit |

### Windows GPO

| Script | Purpose | Default mode |
|---|---|---|
| `gpo/Get-ADGPOHealthReport.ps1` | Audit Group Policy inventory, links, stale policies, filters, and common health risks | Audit |

## Linux

| Script | Purpose | Default mode |
|---|---|---|
| `linux-security-audit.sh` | Collect Linux security baseline information | Audit |
| `linux-hardening-baseline.sh` | Apply selected Linux baseline hardening controls | Dry run |
| `collect-linux-inventory.sh` | Export host inventory in JSON format | Audit |

## DevSecOps

| Script | Purpose | Default mode |
|---|---|---|
| `secret-scan.py` | Scan source code and configuration files for common secret patterns | Audit with failing exit code |
| `docker-image-audit.sh` | Inspect Docker image metadata and optional runtime characteristics | Audit |
| `kubernetes-rbac-audit.sh` | Review Kubernetes RBAC, privileged pods, host paths, and network policy coverage | Audit |

## Monitoring

| Script | Purpose | Default mode |
|---|---|---|
| `service-health-check.py` | Check HTTP and TCP service health from a JSON config file | Audit |
| `disk-space-monitor.sh` | Check filesystem usage and return a monitoring-friendly exit code | Audit |

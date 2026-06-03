# Windows Security Roadmap

This roadmap tracks the Windows expansion after version `1.0.0`.

The root of `scripts/windows/` contains one interactive launcher. Script
implementations live under the category folders below, and new feature work
should be added there before it is connected to the launcher or guided
remediation workflow.

## Target Structure

```text
scripts/windows/
|-- ad/             # Active Directory identity and computer-account audits
|-- gpo/            # Group Policy and policy-baseline comparison scripts
|-- host/           # Cross-host audit, hardening, workflow, and event scripts
|-- server/         # Server role and remote-management security scripts
|-- workstation/    # Workstation endpoint posture scripts
|-- shared/         # Shared PowerShell helpers used by Windows scripts
`-- Start-WindowsSecurity.ps1  # Main menu launcher
```

## Implementation Rules

- Every new script must be audit or dry-run by default.
- Any change must require `-Apply`, a saved remediation plan, or explicit admin confirmation.
- Reports must write to `reports/` by default.
- Apply mode must write backups or explain why a backup is not possible.
- Script output should be readable for normal IT administrators, not only security engineers.
- Domain and Entra/Azure checks must fail safely when required modules or permissions are missing.
- Controls that can break remote access must require explicit approval.

## Tasks

| ID | Area | Problem | Script idea | Platform | Priority | Status | Target folder | Proposed script |
|---:|---|---|---|---|---|---|---|---|
| 1 | Windows / AD | Inactive user accounts | Report inactive users with last logon evidence | Windows/AD | High | Implemented | `scripts/windows/ad/` | `Get-ADInactiveUserReport.ps1` |
| 2 | Windows / AD | Old devices in AD | Detect stale computer accounts | Windows/AD | High | Implemented | `scripts/windows/ad/` | `Get-ADStaleComputerReport.ps1` |
| 3 | Windows / AD | AD privileged group memberships not monitored | Monitor changes to Domain Admins and other privileged AD groups | Windows/AD | High | Implemented | `scripts/windows/ad/` | `Watch-ADPrivilegedGroupChanges.ps1` |
| 4 | Windows / AD | Service accounts without review | Discover service accounts and risky security properties | Windows/AD | High | Implemented | `scripts/windows/ad/` | `Get-ADServiceAccountAudit.ps1` |
| 5 | Windows / AD | High-risk SPN accounts | Kerberoasting exposure audit without offensive actions | Windows/AD | High | Implemented | `scripts/windows/ad/` | `Get-ADSPNExposureAudit.ps1` |
| 6 | Windows / AD | Passwords never expire | Report `PasswordNeverExpires` accounts | Windows/AD | High | Implemented | `scripts/windows/ad/` | `Get-ADPasswordNeverExpiresReport.ps1` |
| 7 | Windows / AD | Accounts without MFA or Conditional Access | Audit privileged accounts missing extra protection | AD/Entra ID | High | Partial: on-prem AD implemented | `scripts/windows/ad/` | `Get-PrivilegedIdentityProtectionAudit.ps1` |
| 8 | Windows | SMBv1 / guest access | Audit SMBv1, guest authentication, and signing | Windows | High | Existing / expand | `scripts/windows/server/` and `scripts/windows/workstation/` | Extend `Invoke-WindowsSecurityAudit.ps1` |
| 9 | Windows | RDP enabled on many devices | RDP exposure audit with allowed users | Windows | High | Expand | `scripts/windows/server/` and `scripts/windows/workstation/` | `Get-WindowsRDPExposureAudit.ps1` |
| 10 | Windows | WinRM open without need | WinRM listener and security audit | Windows | Medium | Expand | `scripts/windows/server/` | `Get-WindowsWinRMSecurityAudit.ps1` |
| 11 | Windows | LLMNR/NBNS enabled | Audit and safely disable after approval | Windows | High | Existing / expand | `scripts/windows/workstation/` | Extend audit and hardening controls |
| 12 | Windows | Defender not updated | Microsoft Defender status and signature audit | Windows | High | Existing / expand | `scripts/windows/workstation/` and `scripts/windows/server/` | Extend `Invoke-WindowsSecurityAudit.ps1` |
| 13 | Windows | Firewall profiles disabled | Audit Domain, Private, and Public firewall state | Windows | High | Existing / expand | `scripts/windows/workstation/` and `scripts/windows/server/` | Extend audit and hardening controls |
| 14 | Windows | Weak audit policy | Compare audit policy against baseline | Windows | High | Existing / expand | `scripts/windows/gpo/` | `Compare-WindowsAuditPolicyBaseline.ps1` |
| 15 | Windows | PowerShell logging disabled | Audit and enable Script Block Logging | Windows | High | Existing / expand | `scripts/windows/gpo/` and `scripts/windows/workstation/` | Extend audit and hardening controls |
| 16 | Windows | Local admins undocumented | Inventory local administrators per host | Windows | High | New | `scripts/windows/server/` and `scripts/windows/workstation/` | `Get-WindowsLocalAdminInventory.ps1` |
| 17 | Windows | Services with dangerous permissions | Detect unquoted service paths and weak service permissions | Windows | High | New | `scripts/windows/server/` and `scripts/windows/workstation/` | `Get-WindowsServiceRiskAudit.ps1` |
| 18 | Windows | Risky scheduled tasks | Audit scheduled tasks running with high privileges | Windows | Medium | New | `scripts/windows/server/` and `scripts/windows/workstation/` | `Get-WindowsScheduledTaskRiskAudit.ps1` |
| 19 | Windows | Pending reboot after patching | Detect machines needing reboot | Windows | Medium | New | `scripts/windows/server/` and `scripts/windows/workstation/` | `Test-WindowsPendingReboot.ps1` |
| 20 | Windows | Certificates near expiry | Audit Local Machine certificate store expiration | Windows | Medium | New | `scripts/windows/server/` and `scripts/windows/workstation/` | `Get-WindowsCertificateExpiryReport.ps1` |
| 21 | Windows / GPO | GPO sprawl, conflicts, missing links, and legacy policies | Inventory all GPOs, map links, and flag health risks | Windows/AD | High | Implemented | `scripts/windows/gpo/` | `Get-ADGPOHealthReport.ps1` |

## Suggested Build Order

1. Create AD audit scripts first because they cover the highest-risk identity findings.
2. Expand existing Windows host audit controls for SMB, RDP, WinRM, LLMNR/NBNS, Defender, firewall, audit policy, and PowerShell logging.
3. Add local admin, service-risk, scheduled-task, pending-reboot, and certificate-expiry scripts.
4. Connect stable scripts into `Start-WindowsSecurity.ps1`; connect remediation-capable controls into `Start-WindowsSecurityRemediation.ps1` only after each script has safe output and tests.

## Next Candidate For Implementation

Continue with an Entra/Microsoft Graph design for `Get-PrivilegedIdentityProtectionAudit.ps1`, or move to `Get-WindowsRDPExposureAudit.ps1` if the next milestone should stay purely on-prem Windows.

Reason: the on-prem privileged identity checks are implemented, but MFA,
Conditional Access, and cloud role verification need Microsoft Graph
permissions and a deliberate authentication model before implementation.

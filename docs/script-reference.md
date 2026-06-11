# Script Reference

This page documents every operational script in the repository, including
purpose, safety mode, parameters, outputs, and examples.

Use [script-documentation-standard.md](script-documentation-standard.md) when
adding or updating script documentation so purpose, requirements, permissions,
safety notes, limitations, and next steps stay consistent across script
families.

Use this workflow before production changes:

1. Run audit or dry-run mode first.
2. Review the generated report.
3. Confirm operational impact with the server owner.
4. Use `--apply` or `-Apply` only during an approved change window.

Generated `reports/`, `backups/`, and `logs/` directories are ignored by Git.

## Windows Scripts

Run PowerShell as Administrator for complete audit results and for any script
that applies changes.

For a temporary execution policy bypass:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### `scripts/windows/Start-WindowsSecurity.ps1`

Interactive menu launcher for Windows scripts. It is the recommended starting
point for normal IT administrators. It does not change the system by itself;
child scripts still keep their own audit, dry-run, `-Apply`, or final approval
behavior.

Default mode: menu.

Outputs:

- No report from the launcher itself
- Child scripts write their normal reports under `reports/` unless a custom path is provided

Parameters:

| Parameter | Type | Default | Description |
|---|---:|---|---|
| `-ListScripts` | switch | off | Print every menu tool and exit. |
| `-Group` | string | empty | Open one group directly, such as `AD`, `Host`, `Server`, or `Workstation`. |
| `-ToolId` | string | empty | Run one menu tool directly by ID. Use `-ListScripts` to see IDs. |
| `-RunAll` | switch | off | With `-Group`, run the default-safe scripts in that group. |
| `-UseDefaults` | switch | off | Use child-script defaults instead of prompting for optional parameters. Required parameters are still prompted. |
| `-ConfigPath` | string | empty | Optional JSON file with shared child-script parameter defaults. |

Examples:

```powershell
.\scripts\windows\Start-WindowsSecurity.ps1
```

```powershell
.\scripts\windows\Start-WindowsSecurity.ps1 -ListScripts
```

```powershell
.\scripts\windows\Start-WindowsSecurity.ps1 -Group AD -RunAll
```

```powershell
.\scripts\windows\Start-WindowsSecurity.ps1 -ToolId AD-GPO-HEALTH
```

```powershell
Copy-Item .\examples\windows-security.config.example.json .\windows-security.config.local.json
.\scripts\windows\Start-WindowsSecurity.ps1 -Group AD -RunAll -UseDefaults -ConfigPath .\windows-security.config.local.json
```

Use the menu when an admin should choose a group, review available scripts, and
enter parameters without editing PowerShell commands manually. Direct paths in
the sections below remain supported for automation and advanced use.

Shared launcher config values are read from `Defaults`, then `Groups.<GroupId>`,
then `Tools.<ToolId>`. The most specific value wins. Credential parameters are
not loaded from config, and high-impact switches are not automatically enabled
by `-UseDefaults`.

### `scripts/windows/host/Invoke-WindowsSecurityAudit.ps1`

Collects Windows security posture information and writes a JSON report. It does
not change the system.

Default mode: audit only.

Outputs:

- JSON report at `-OutputPath`
- Console summary unless `-Quiet` is used

Parameters:

| Parameter | Type | Default | Description |
|---|---:|---|---|
| `-OutputPath` | string | `.\reports\windows-security-audit-COMPUTER-TIMESTAMP.json` | JSON report path. |
| `-IncludeHotfixes` | switch | off | Include recent installed hotfix records. |
| `-Quiet` | switch | off | Suppress console summary. |

Examples:

```powershell
.\scripts\windows\host\Invoke-WindowsSecurityAudit.ps1
```

```powershell
.\scripts\windows\host\Invoke-WindowsSecurityAudit.ps1 -IncludeHotfixes
```

```powershell
.\scripts\windows\host\Invoke-WindowsSecurityAudit.ps1 -OutputPath .\reports\server01-audit.json
```

```powershell
.\scripts\windows\host\Invoke-WindowsSecurityAudit.ps1 -OutputPath .\reports\server01-audit.json -IncludeHotfixes -Quiet
```

Start reading the report at:

- `Summary.Posture`
- `Summary.SeverityCounts`
- `Findings`

### `scripts/windows/ad/Get-ADInactiveUserReport.ps1`

Reports inactive Active Directory user accounts with last logon evidence,
review priority, account category, lifecycle stage, and deletion-readiness
guidance. It does not change Active Directory.

Default mode: audit only.

Outputs:

- `inactive-users.json` under `-OutputDirectory`
- `inactive-users.csv` under `-OutputDirectory`
- `inactive-users-review.md` under `-OutputDirectory`

Parameters:

| Parameter | Type | Default | Description |
|---|---:|---|---|
| `-DaysInactive` | int | `90` | Days since last logon before a user is reported. |
| `-SearchBase` | string | empty | Optional OU or domain distinguished name to search. |
| `-Server` | string | empty | Optional domain controller to query. |
| `-Credential` | PSCredential | current user | Optional credential for the AD query. |
| `-IncludeDisabled` | switch | off | Include disabled accounts. By default, only enabled users are scanned. |
| `-ExcludeNeverLoggedOn` | switch | off | Exclude accounts that never logged on. |
| `-OutputDirectory` | string | `.\reports\ad-inactive-users-COMPUTER-TIMESTAMP` | Directory for JSON and CSV reports. |
| `-Quiet` | switch | off | Suppress console summary. |

Examples:

```powershell
.\scripts\windows\ad\Get-ADInactiveUserReport.ps1
```

```powershell
.\scripts\windows\ad\Get-ADInactiveUserReport.ps1 -DaysInactive 180
```

```powershell
.\scripts\windows\ad\Get-ADInactiveUserReport.ps1 -SearchBase "OU=Users,DC=example,DC=com"
```

```powershell
.\scripts\windows\ad\Get-ADInactiveUserReport.ps1 -IncludeDisabled -OutputDirectory .\reports\ad-users
```

Start reading the report at:

- `Summary.HighPriorityReviewUsers`
- `Summary.CriticalPriorityUsers`
- `Summary.HoldSystemManagedUsers`
- `Summary.PotentialDeletionCandidates`
- `Summary.MailEnabledInactiveUsers`
- `Summary.PrivilegedGroupMembers`
- `InactiveUsers[].ReviewPriority`
- `InactiveUsers[].AccountCategory`
- `InactiveUsers[].DeletionReadiness`
- `InactiveUsers[].DependencySignalsText`
- `InactiveUsers[].NextReviewStep`
- `InactiveUsers[].LastLogonDateUtc`
- `InactiveUsers[].RecommendedAction`
- `InactiveUsers[].DeletionGuidance`

The script uses `LastLogonDate`, which is based on replicated
`lastLogonTimestamp`. Use a conservative threshold and confirm ownership before
disabling accounts. `CanDeleteNow` is always `false`; even potential deletion
candidates require owner approval, disabled quarantine, dependency checks, and
rollback planning.

### `scripts/windows/ad/Get-ADStaleComputerReport.ps1`

Reports stale Active Directory computer accounts with last logon evidence,
review priority, computer category, lifecycle stage, and cleanup-readiness
guidance. It does not change Active Directory.

Default mode: audit only.

Outputs:

- `stale-computers.json` under `-OutputDirectory`
- `stale-computers.csv` under `-OutputDirectory`
- `stale-computers-review.md` under `-OutputDirectory`

Parameters:

| Parameter | Type | Default | Description |
|---|---:|---|---|
| `-DaysInactive` | int | `90` | Days since last logon before a computer is reported. |
| `-SearchBase` | string | empty | Optional OU or domain distinguished name to search. |
| `-Server` | string | empty | Optional domain controller to query. |
| `-Credential` | PSCredential | current user | Optional credential for the AD query. |
| `-IncludeDisabled` | switch | off | Include disabled computer accounts. By default, only enabled computers are scanned. |
| `-ExcludeNeverLoggedOn` | switch | off | Exclude computers that never logged on. |
| `-OutputDirectory` | string | `.\reports\ad-stale-computers-COMPUTER-TIMESTAMP` | Directory for JSON, CSV, and Markdown reports. |
| `-Quiet` | switch | off | Suppress console summary. |

Examples:

```powershell
.\scripts\windows\ad\Get-ADStaleComputerReport.ps1
```

```powershell
.\scripts\windows\ad\Get-ADStaleComputerReport.ps1 -DaysInactive 180
```

```powershell
.\scripts\windows\ad\Get-ADStaleComputerReport.ps1 -SearchBase "OU=Computers,DC=example,DC=com"
```

```powershell
.\scripts\windows\ad\Get-ADStaleComputerReport.ps1 -IncludeDisabled -OutputDirectory .\reports\ad-computers
```

Start reading the report at:

- `Summary.CriticalPriorityComputers`
- `Summary.HighPriorityReviewComputers`
- `Summary.PotentialCleanupCandidates`
- `StaleComputers[].ReviewPriority`
- `StaleComputers[].ActionPriority`
- `StaleComputers[].ComputerCategory`
- `StaleComputers[].CleanupReadiness`
- `StaleComputers[].RiskFlagsText`
- `StaleComputers[].NextReviewStep`
- `StaleComputers[].RecommendedAction`
- `StaleComputers[].CleanupGuidance`

The script uses `LastLogonDate`, which is based on replicated
`lastLogonTimestamp`. Domain controllers are marked Critical and must not be
handled as stale cleanup. `CanDeleteNow` is always `false`; even cleanup
candidates require owner approval, disabled quarantine, dependency checks, and
rollback planning.

### `scripts/windows/ad/Watch-ADPrivilegedGroupChanges.ps1`

Audits privileged Active Directory groups against a saved direct-membership
baseline. It does not change Active Directory membership. The first run creates
the baseline if it does not exist; later runs report membership differences and
current structural risks such as nested groups in privileged groups.

Default mode: audit only.

Outputs:

- `privileged-groups.json` under `-OutputDirectory`
- `privileged-groups.csv` under `-OutputDirectory`
- `privileged-group-members.csv` under `-OutputDirectory`
- `privileged-group-changes.csv` under `-OutputDirectory`
- `privileged-groups-review.md` under `-OutputDirectory`
- Baseline JSON at `-BaselinePath`

Parameters:

| Parameter | Type | Default | Description |
|---|---:|---|---|
| `-BaselinePath` | string | `.\reports\ad-privileged-groups-baseline.json` | Stable JSON baseline used for comparison. |
| `-OutputDirectory` | string | `.\reports\ad-privileged-groups-COMPUTER-TIMESTAMP` | Directory for JSON, CSV, and Markdown reports. |
| `-GroupName` | string array | empty | Extra group identities to audit in addition to the built-in privileged group set. |
| `-Server` | string | empty | Optional domain controller to query. |
| `-Credential` | PSCredential | current user | Optional credential for the AD query. |
| `-IncludeRecursiveMembers` | switch | off | Also collect recursive/effective members for visibility. |
| `-UpdateBaseline` | switch | off | Replace the baseline with the current snapshot after review. |
| `-Quiet` | switch | off | Suppress console summary. |

Examples:

```powershell
.\scripts\windows\ad\Watch-ADPrivilegedGroupChanges.ps1
```

```powershell
.\scripts\windows\ad\Watch-ADPrivilegedGroupChanges.ps1 -IncludeRecursiveMembers
```

```powershell
.\scripts\windows\ad\Watch-ADPrivilegedGroupChanges.ps1 -GroupName "DnsAdmins","Custom Tier0 Admins"
```

```powershell
.\scripts\windows\ad\Watch-ADPrivilegedGroupChanges.ps1 -UpdateBaseline
```

Start reading the report at:

- `Summary.BaselineStatus`
- `Summary.AddedMembers`
- `Summary.RemovedMembers`
- `Summary.NestedGroupFindings`
- `Changes[].ChangeType`
- `Changes[].Severity`
- `Changes[].AdminAction`
- `Changes[].VerificationStep`
- `Members[].RiskFlagsText`

Review `Added` changes first. Confirm owner approval, ticket/change record,
expected duration, and rollback decision before accepting the new state with
`-UpdateBaseline`.

### `scripts/windows/ad/Get-ADServiceAccountAudit.ps1`

Audits user service account candidates, SPN-bearing accounts, gMSA, and sMSA
objects. It does not change Active Directory.

Default mode: audit only.

Outputs:

- `service-accounts.json` under `-OutputDirectory`
- `service-accounts.csv` under `-OutputDirectory`
- `service-accounts-review.md` under `-OutputDirectory`

Parameters:

| Parameter | Type | Default | Description |
|---|---:|---|---|
| `-SearchBase` | string | empty | Optional OU or domain distinguished name to search. |
| `-Server` | string | empty | Optional domain controller to query. |
| `-Credential` | PSCredential | current user | Optional credential for the AD query. |
| `-IncludeDisabled` | switch | off | Include disabled user accounts. |
| `-StaleDays` | int | `90` | Days since last logon before an enabled service account is considered stale. |
| `-MaxPasswordAgeDays` | int | `180` | Password age threshold used for review. |
| `-OutputDirectory` | string | `.\reports\ad-service-accounts-COMPUTER-TIMESTAMP` | Directory for JSON, CSV, and Markdown reports. |
| `-Quiet` | switch | off | Suppress console summary. |

Examples:

```powershell
.\scripts\windows\ad\Get-ADServiceAccountAudit.ps1
```

```powershell
.\scripts\windows\ad\Get-ADServiceAccountAudit.ps1 -SearchBase "OU=Service Accounts,DC=example,DC=com"
```

Start reading the report at:

- `Summary.CriticalAccounts`
- `Summary.HighAccounts`
- `ServiceAccounts[].ReviewPriority`
- `ServiceAccounts[].AccountType`
- `ServiceAccounts[].RiskFlagsText`
- `ServiceAccounts[].RecommendedAction`
- `ServiceAccounts[].NextReviewStep`

Prioritize privileged access, delegation, pre-authentication disabled,
`PasswordNeverExpires`, old passwords, and missing owner evidence. Prefer gMSA
where applications support it.

### `scripts/windows/ad/Get-ADSPNExposureAudit.ps1`

Audits user accounts with SPNs for defensive Kerberos exposure indicators. It
does not request tickets, test passwords, or change Active Directory.

Default mode: audit only.

Outputs:

- `spn-exposure.json` under `-OutputDirectory`
- `spn-exposure.csv` under `-OutputDirectory`
- `spn-exposure-review.md` under `-OutputDirectory`

Parameters:

| Parameter | Type | Default | Description |
|---|---:|---|---|
| `-SearchBase` | string | empty | Optional OU or domain distinguished name to search. |
| `-Server` | string | empty | Optional domain controller to query. |
| `-Credential` | PSCredential | current user | Optional credential for the AD query. |
| `-IncludeDisabled` | switch | off | Include disabled SPN-bearing accounts. |
| `-MaxPasswordAgeDays` | int | `180` | Password age threshold used for exposure review. |
| `-OutputDirectory` | string | `.\reports\ad-spn-exposure-COMPUTER-TIMESTAMP` | Directory for JSON, CSV, and Markdown reports. |
| `-Quiet` | switch | off | Suppress console summary. |

Examples:

```powershell
.\scripts\windows\ad\Get-ADSPNExposureAudit.ps1
```

```powershell
.\scripts\windows\ad\Get-ADSPNExposureAudit.ps1 -IncludeDisabled -MaxPasswordAgeDays 365
```

Start reading the report at:

- `Summary.CriticalAccounts`
- `Summary.HighAccounts`
- `Summary.EncryptionReviewAccounts`
- `SPNAccounts[].ExposurePriority`
- `SPNAccounts[].EncryptionRisk`
- `SPNAccounts[].RiskFlagsText`
- `SPNAccounts[].RecommendedAction`

Prioritize SPN accounts with privileged access, delegation,
pre-authentication disabled, `PasswordNeverExpires`, old passwords, or weak and
unknown encryption settings.

### `scripts/windows/ad/Get-ADPasswordNeverExpiresReport.ps1`

Reports Active Directory users where `PasswordNeverExpires` is set and
classifies privilege, service-account, SPN, exception, disabled, and
system-managed hold cases. It does not change Active Directory.

Default mode: audit only.

Outputs:

- `password-never-expires.json` under `-OutputDirectory`
- `password-never-expires.csv` under `-OutputDirectory`
- `password-never-expires-review.md` under `-OutputDirectory`

Parameters:

| Parameter | Type | Default | Description |
|---|---:|---|---|
| `-SearchBase` | string | empty | Optional OU or domain distinguished name to search. |
| `-Server` | string | empty | Optional domain controller to query. |
| `-Credential` | PSCredential | current user | Optional credential for the AD query. |
| `-IncludeDisabled` | switch | off | Include disabled accounts. |
| `-MaxPasswordAgeDays` | int | `180` | Password age threshold used for review. |
| `-OutputDirectory` | string | `.\reports\ad-password-never-expires-COMPUTER-TIMESTAMP` | Directory for JSON, CSV, and Markdown reports. |
| `-Quiet` | switch | off | Suppress console summary. |

Examples:

```powershell
.\scripts\windows\ad\Get-ADPasswordNeverExpiresReport.ps1
```

```powershell
.\scripts\windows\ad\Get-ADPasswordNeverExpiresReport.ps1 -IncludeDisabled
```

Start reading the report at:

- `Summary.CriticalAccounts`
- `Summary.HighAccounts`
- `Summary.ExceptionRequiredAccounts`
- `PasswordNeverExpiresAccounts[].ReviewPriority`
- `PasswordNeverExpiresAccounts[].AccountCategory`
- `PasswordNeverExpiresAccounts[].RotationReadiness`
- `PasswordNeverExpiresAccounts[].RecommendedAction`

Do not remove `PasswordNeverExpires` blindly. Confirm owner, service
dependency, maintenance window, rollback, and exception status first.

### `scripts/windows/ad/Get-PrivilegedIdentityProtectionAudit.ps1`

Audits effective user members of privileged AD groups for on-prem protection
gaps. This version does not check Entra ID MFA or Conditional Access. It does
not change Active Directory.

Default mode: audit only.

Outputs:

- `privileged-identity-protection.json` under `-OutputDirectory`
- `privileged-identities.csv` under `-OutputDirectory`
- `privileged-group-memberships.csv` under `-OutputDirectory`
- `privileged-identity-findings.csv` under `-OutputDirectory`
- `privileged-identity-protection-review.md` under `-OutputDirectory`

Parameters:

| Parameter | Type | Default | Description |
|---|---:|---|---|
| `-GroupName` | string array | empty | Extra privileged group identities to audit. |
| `-Server` | string | empty | Optional domain controller to query. |
| `-Credential` | PSCredential | current user | Optional credential for the AD query. |
| `-StaleDays` | int | `90` | Days since last logon before an enabled privileged identity is considered stale. |
| `-MaxCredentialAgeDays` | int | `180` | Credential age threshold used for privileged account review. |
| `-OutputDirectory` | string | `.\reports\ad-privileged-identity-protection-COMPUTER-TIMESTAMP` | Directory for JSON, CSV, and Markdown reports. |
| `-Quiet` | switch | off | Suppress console summary. |

Examples:

```powershell
.\scripts\windows\ad\Get-PrivilegedIdentityProtectionAudit.ps1
```

```powershell
.\scripts\windows\ad\Get-PrivilegedIdentityProtectionAudit.ps1 -GroupName "Tier 0 Admins"
```

Start reading the report at:

- `Summary.CriticalIdentities`
- `Summary.HighIdentities`
- `Summary.CloudProtectionNotChecked`
- `PrivilegedIdentities[].ReviewPriority`
- `PrivilegedIdentities[].RiskFlagsText`
- `PrivilegedIdentities[].MFAConditionalAccessStatus`
- `Findings[].FindingType`

Treat MFA and Conditional Access as not verified until the future
Entra/Microsoft Graph expansion is added.

### `scripts/windows/gpo/Get-ADGPOHealthReport.ps1`

Audits Active Directory Group Policy inventory, links, and common health risks.
It does not change Group Policy or Active Directory.

Default mode: audit only.

Outputs:

- `gpo-health.json` under `-OutputDirectory`
- `gpos.csv` under `-OutputDirectory`
- `gpo-links.csv` under `-OutputDirectory`
- `gpo-findings.csv` under `-OutputDirectory`
- `gpo-review.md` under `-OutputDirectory`

Parameters:

| Parameter | Type | Default | Description |
|---|---:|---|---|
| `-OutputDirectory` | string | `.\reports\ad-gpo-health-COMPUTER-TIMESTAMP` | Directory for JSON, CSV, and Markdown reports. |
| `-Domain` | string | empty | Optional DNS domain name to query. |
| `-Server` | string | empty | Optional domain controller to query. |
| `-StaleDays` | int | `365` | Days since last GPO modification before a stale finding is created. |
| `-MaxGposPerTarget` | int | `10` | Number of enabled direct GPO links on one target before a review finding is created. |
| `-LegacyKeyword` | string array | old Windows, IE, Office terms | Keywords used to flag possible legacy policy references. |
| `-SkipTargetInventory` | switch | off | Skip OU/domain target inventory and rely on GPO XML link evidence when available. |
| `-Quiet` | switch | off | Suppress console summary. |

Examples:

```powershell
.\scripts\windows\gpo\Get-ADGPOHealthReport.ps1
```

```powershell
.\scripts\windows\gpo\Get-ADGPOHealthReport.ps1 -Domain example.com -StaleDays 730
```

```powershell
.\scripts\windows\gpo\Get-ADGPOHealthReport.ps1 -SkipTargetInventory -OutputDirectory .\reports\gpo
```

Start reading the report at:

- `Summary.TotalFindings`
- `Summary.ActionPriorityCounts`
- `Summary.HighFindings`
- `Findings[].ActionPriority`
- `Findings[].Severity`
- `Findings[].FindingType`
- `Findings[].Evidence`
- `Findings[].AdminAction`
- `Findings[].VerificationStep`
- `Findings[].Recommendation`
- `GPOs[].DirectLinkCount`
- `GPOs[].IsStale`
- `GPOs[].VersionMismatch`
- `Targets[].DirectEnabledLinkCount`

The script highlights review risks. It cannot decide whether a GPO is still
business-required, so cleanup should still use ownership review, GPO backup,
change approval, and staged testing.

### `scripts/windows/host/Set-WindowsBaselineHardening.ps1`

Creates a Windows hardening plan and optionally applies selected controls. It is
dry-run by default.

Default mode: dry run.

Outputs:

- JSON hardening report at `-ReportPath`
- Registry backups under `-BackupDirectory` when `-Apply` is used

Parameters:

| Parameter | Type | Default | Description |
|---|---:|---|---|
| `-Apply` | switch | off | Apply selected controls. Without this switch, no changes are made. |
| `-ReportPath` | string | `.\reports\windows-hardening-plan-COMPUTER-TIMESTAMP.json` | JSON report path. |
| `-BackupDirectory` | string | `.\backups\windows-baseline-COMPUTER-TIMESTAMP` | Backup directory used when applying changes. |
| `-SkipDefender` | switch | off | Skip Microsoft Defender controls. |
| `-SkipAuditPolicy` | switch | off | Skip audit policy controls. |
| `-ExcludeControlId` | string array | empty | Exclude one or more control IDs from the run. |
| `-OnlyControlId` | string array | empty | Run only selected control IDs. |
| `-ListControls` | switch | off | List valid control IDs and exit. |

Examples:

```powershell
.\scripts\windows\host\Set-WindowsBaselineHardening.ps1
```

```powershell
.\scripts\windows\host\Set-WindowsBaselineHardening.ps1 -ListControls
```

```powershell
.\scripts\windows\host\Set-WindowsBaselineHardening.ps1 -ExcludeControlId WIN-HARDEN-FW-001
```

```powershell
.\scripts\windows\host\Set-WindowsBaselineHardening.ps1 -ExcludeControlId WIN-HARDEN-FW-001,WIN-HARDEN-DEF-001
```

```powershell
.\scripts\windows\host\Set-WindowsBaselineHardening.ps1 -OnlyControlId WIN-HARDEN-RDP-001
```

```powershell
.\scripts\windows\host\Set-WindowsBaselineHardening.ps1 -SkipDefender -SkipAuditPolicy -ReportPath .\reports\server01-hardening.json
```

```powershell
.\scripts\windows\host\Set-WindowsBaselineHardening.ps1 -Apply -BackupDirectory .\backups\server01-baseline -ReportPath .\reports\server01-hardening.json
```

If another product owns a control, exclude it by ID. Example: if ESET manages
the host firewall, use `-ExcludeControlId WIN-HARDEN-FW-001`.

Start reading the report at:

- `Summary.HighPriorityReview`
- `Results[].ControlId`
- `Results[].OperationalImpact`
- `Results[].Rollback`

### `scripts/windows/host/Export-WindowsEventSecurityReport.ps1`

Exports selected Windows Security and System event log activity to a readable
summary, JSON summary, and CSV evidence file.

Default mode: audit only.

Outputs:

- `summary.txt`: admin-readable verdict, findings, evidence, and actions
- `summary.json`: machine-readable summary with `InvestigationSummary`
- `events.csv`: one row per event with parsed fields and raw evidence

Parameters:

| Parameter | Type | Default | Description |
|---|---:|---|---|
| `-Days` | int | `7` | Number of days of event history to review. |
| `-OutputDirectory` | string | `.\reports\windows-events-COMPUTER-TIMESTAMP` | Directory for `summary.txt`, `summary.json`, and `events.csv`. |

Examples:

```powershell
.\scripts\windows\host\Export-WindowsEventSecurityReport.ps1
```

```powershell
.\scripts\windows\host\Export-WindowsEventSecurityReport.ps1 -Days 7
```

```powershell
.\scripts\windows\host\Export-WindowsEventSecurityReport.ps1 -Days 30 -OutputDirectory .\reports\server01-events
```

Start with `summary.txt`. A High item means "review first", not automatic proof
of an attack.

### `scripts/windows/server/Clear-RDPUserProfileCache.ps1`

Audits and optionally cleans safe per-user cache locations on RDP or Terminal
Server hosts. It is conservative by default and skips loaded profiles unless
requested.

Default mode: dry run.

Outputs:

- JSON cleanup report at `-ReportPath`
- Deleted files only when `-Apply` is used

Parameters:

| Parameter | Type | Default | Description |
|---|---:|---|---|
| `-ProfileRoot` | string | `C:\Users` | Root directory containing user profile folders. |
| `-MinimumAgeDays` | int | `14` | Only report or delete files older than this many days. |
| `-ReportPath` | string | `.\reports\rdp-profile-cache-cleanup-COMPUTER-TIMESTAMP.json` | JSON report path. |
| `-Apply` | switch | off | Delete eligible files. Without this switch, no files are deleted. |
| `-IncludeLoadedProfiles` | switch | off | Include currently loaded profiles. Use carefully on production RDP servers. |
| `-IncludeRecycleBin` | switch | off | Include each user's Recycle Bin when available. |
| `-IncludeTemp` | switch | off | Include per-user `AppData\Local\Temp`. |
| `-ExcludeProfileName` | string array | system/public defaults | Profile folder names to skip. |

Examples:

```powershell
.\scripts\windows\server\Clear-RDPUserProfileCache.ps1
```

```powershell
.\scripts\windows\server\Clear-RDPUserProfileCache.ps1 -MinimumAgeDays 30
```

```powershell
.\scripts\windows\server\Clear-RDPUserProfileCache.ps1 -MinimumAgeDays 30 -IncludeRecycleBin -IncludeTemp
```

```powershell
.\scripts\windows\server\Clear-RDPUserProfileCache.ps1 -ProfileRoot D:\Users -MinimumAgeDays 45 -ReportPath .\reports\terminal01-cache.json
```

```powershell
.\scripts\windows\server\Clear-RDPUserProfileCache.ps1 -ExcludeProfileName "Default","Public","admin-template"
```

```powershell
.\scripts\windows\server\Clear-RDPUserProfileCache.ps1 -Apply -MinimumAgeDays 30
```

```powershell
.\scripts\windows\server\Clear-RDPUserProfileCache.ps1 -Apply -MinimumAgeDays 30 -IncludeLoadedProfiles
```

Use `-IncludeLoadedProfiles` only during a maintenance window after checking
active sessions.

## Linux Scripts

Run audit scripts with `sudo` when possible for complete evidence. Hardening
requires root only when `--apply` is used.

### `scripts/linux/linux-security-audit.sh`

Collects Linux security posture evidence and writes a readable text report plus
a JSON summary.

Default mode: audit only.

Outputs:

- Text report under `--output-dir`
- JSON summary at `--summary-json` or next to the text report

Options:

| Option | Default | Description |
|---|---|---|
| `-o DIR`, `--output-dir DIR` | `reports` | Directory for the text report. |
| `--quick` | off | Skip slower filesystem permission checks. |
| `--summary-json FILE` | next to text report | JSON summary path. |
| `-h`, `--help` | n/a | Show built-in help. |

Examples:

```bash
bash scripts/linux/linux-security-audit.sh
```

```bash
sudo bash scripts/linux/linux-security-audit.sh --output-dir reports/linux
```

```bash
bash scripts/linux/linux-security-audit.sh --quick
```

```bash
bash scripts/linux/linux-security-audit.sh --summary-json reports/linux-summary.json
```

```bash
bash scripts/linux/linux-security-audit.sh --quick --output-dir reports --summary-json reports/linux-summary.json
```

### `scripts/linux/linux-hardening-baseline.sh`

Creates a Linux baseline hardening plan and optionally applies selected controls.
It is dry-run by default.

Default mode: dry run.

Outputs:

- Hardening log under `--report-dir`
- Backup files under `--backup-dir` when `--apply` is used

Options:

| Option | Default | Description |
|---|---|---|
| `--apply` | off | Apply hardening changes. Without this option, no changes are made. |
| `--backup-dir DIR` | `backups/linux-baseline-HOST-TIMESTAMP` | Backup directory used during apply mode. |
| `--report-dir DIR` | `reports` | Directory for the hardening log. |
| `--no-ssh` | off | Skip SSH daemon baseline changes. |
| `--disable-ssh-password` | off | Set `PasswordAuthentication no` in sshd config. |
| `-h`, `--help` | n/a | Show built-in help. |

Examples:

```bash
bash scripts/linux/linux-hardening-baseline.sh
```

```bash
bash scripts/linux/linux-hardening-baseline.sh --report-dir reports/linux-hardening
```

```bash
sudo bash scripts/linux/linux-hardening-baseline.sh --apply
```

```bash
sudo bash scripts/linux/linux-hardening-baseline.sh --apply --backup-dir /root/baseline-backups --report-dir /var/log/security-baseline
```

```bash
bash scripts/linux/linux-hardening-baseline.sh --no-ssh
```

```bash
sudo bash scripts/linux/linux-hardening-baseline.sh --apply --disable-ssh-password
```

### `scripts/linux/collect-linux-inventory.sh`

Collects basic Linux host inventory and writes JSON.

Default mode: audit only.

Outputs:

- JSON inventory under `--output-dir`

Options:

| Option | Default | Description |
|---|---|---|
| `-o DIR`, `--output-dir DIR` | `reports` | Directory for inventory JSON. |
| `-h`, `--help` | n/a | Show built-in help. |

Examples:

```bash
bash scripts/linux/collect-linux-inventory.sh
```

```bash
bash scripts/linux/collect-linux-inventory.sh -o /var/tmp/inventory
```

```bash
bash scripts/linux/collect-linux-inventory.sh --output-dir reports
```

## DevSecOps Scripts

### `scripts/devsecops/secret-scan.py`

Scans source and configuration files for common secret patterns. It is
dependency-free and suitable for local use or CI.

Default mode: audit; returns exit code `2` when findings exist unless
`--no-fail` is used.

Outputs:

- Text or JSON to stdout
- Optional output file with `--output`

Arguments:

| Argument | Default | Description |
|---|---|---|
| `path` | `.` | File or directory to scan. |
| `--format text\|json` | `text` | Output format. |
| `--output FILE` | stdout | Write results to a file. |
| `--allowlist FILE` | `.secret-scan-allowlist` | File containing finding fingerprints to ignore. |
| `--max-file-size BYTES` | `1048576` | Maximum file size to scan. |
| `--no-fail` | off | Return exit code 0 even when findings exist. |
| `--include-hidden` | off | Include hidden files and directories. |
| `-h`, `--help` | n/a | Show built-in help. |

Examples:

```bash
python3 scripts/devsecops/secret-scan.py
```

```bash
python3 scripts/devsecops/secret-scan.py scripts
```

```bash
python3 scripts/devsecops/secret-scan.py . --format json --output reports/secrets.json
```

```bash
python3 scripts/devsecops/secret-scan.py . --allowlist .secret-scan-allowlist
```

```bash
python3 scripts/devsecops/secret-scan.py . --max-file-size 2097152
```

```bash
python3 scripts/devsecops/secret-scan.py . --include-hidden
```

```bash
python3 scripts/devsecops/secret-scan.py . --no-fail
```

### `scripts/devsecops/docker-image-audit.sh`

Audits Docker image metadata and optionally runs a temporary container for
runtime checks.

Default mode: audit only. `--deep` starts a temporary container with
`docker run --rm`.

Outputs:

- Text report under `--output-dir`

Arguments:

| Argument | Default | Description |
|---|---|---|
| `IMAGE` | required | Docker image name or reference to audit. |
| `--deep` | off | Run a temporary container for extra runtime checks. |
| `--output-dir DIR` | `reports` | Directory for the report. |
| `-h`, `--help` | n/a | Show built-in help. |

Examples:

```bash
bash scripts/devsecops/docker-image-audit.sh nginx:latest
```

```bash
bash scripts/devsecops/docker-image-audit.sh nginx:latest --deep
```

```bash
bash scripts/devsecops/docker-image-audit.sh registry.example.com/app/api:1.2.3 --output-dir reports/docker
```

```bash
bash scripts/devsecops/docker-image-audit.sh nginx:latest --deep --output-dir reports/docker
```

### `scripts/devsecops/kubernetes-rbac-audit.sh`

Reviews Kubernetes RBAC and workload security signals with `kubectl`.

Default mode: audit only.

Outputs:

- Text report under `--output-dir`

Options:

| Option | Default | Description |
|---|---|---|
| `--context NAME` | current kubectl context | Context to audit. |
| `--output-dir DIR` | `reports` | Directory for the report. |
| `-h`, `--help` | n/a | Show built-in help. |

Examples:

```bash
bash scripts/devsecops/kubernetes-rbac-audit.sh
```

```bash
bash scripts/devsecops/kubernetes-rbac-audit.sh --context prod-admin
```

```bash
bash scripts/devsecops/kubernetes-rbac-audit.sh --output-dir reports/kubernetes
```

```bash
bash scripts/devsecops/kubernetes-rbac-audit.sh --context prod-admin --output-dir reports/kubernetes
```

## Monitoring Scripts

### `scripts/monitoring/service-health-check.py`

Checks HTTP and TCP services from a JSON configuration file.

Default mode: audit only.

Exit codes:

- `0`: every service is healthy
- `1`: configuration or runtime error
- `2`: one or more services failed

Outputs:

- Console table
- Optional JSON report with `--output`

Arguments:

| Argument | Default | Description |
|---|---|---|
| `--config FILE` | `examples/services.example.json` | JSON service configuration file. |
| `--output FILE` | stdout only | Optional JSON output path. |
| `--timeout SECONDS` | per-service config | Override timeout for all checks. |
| `-h`, `--help` | n/a | Show built-in help. |

Examples:

```bash
python3 scripts/monitoring/service-health-check.py
```

```bash
python3 scripts/monitoring/service-health-check.py --config examples/services.example.json
```

```bash
python3 scripts/monitoring/service-health-check.py --config examples/services.example.json --output reports/services-health.json
```

```bash
python3 scripts/monitoring/service-health-check.py --config examples/services.example.json --timeout 10
```

Configuration shape:

```json
{
  "services": [
    {
      "name": "Example HTTP",
      "type": "http",
      "url": "https://example.com",
      "expected_status": [200],
      "timeout": 5
    },
    {
      "name": "Example TCP",
      "type": "tcp",
      "host": "127.0.0.1",
      "port": 443,
      "timeout": 3
    }
  ]
}
```

### `scripts/monitoring/disk-space-monitor.sh`

Checks filesystem usage and returns a monitoring-friendly exit code.

Default mode: audit only.

Exit codes:

- `0`: all checked filesystems are below warning threshold
- `1`: one or more filesystems reached warning threshold
- `2`: one or more filesystems reached critical threshold

Options:

| Option | Default | Description |
|---|---|---|
| `--warn PERCENT` | `80` | Warning threshold. |
| `--crit PERCENT` | `90` | Critical threshold. Must be higher than warning. |
| `--exclude-types LIST` | `tmpfs,devtmpfs,squashfs,overlay` | Comma-separated filesystem types to exclude. |
| `--json` | off | Print one JSON object per checked filesystem. |
| `-h`, `--help` | n/a | Show built-in help. |

Examples:

```bash
bash scripts/monitoring/disk-space-monitor.sh
```

```bash
bash scripts/monitoring/disk-space-monitor.sh --warn 75 --crit 90
```

```bash
bash scripts/monitoring/disk-space-monitor.sh --exclude-types tmpfs,devtmpfs,squashfs,overlay,nfs
```

```bash
bash scripts/monitoring/disk-space-monitor.sh --json
```

```bash
bash scripts/monitoring/disk-space-monitor.sh --warn 75 --crit 90 --exclude-types tmpfs,devtmpfs --json
```

## Reporting Scripts

### `scripts/reporting/generate-markdown-report.py`

Converts one or more JSON audit result files into a Markdown assessment report.
It is report-only and does not change systems.

Default mode: report-only.

Requirements:

- Python 3
- Read access to JSON input files
- Write access to the output directory

Outputs:

- Markdown report under `reports/` by default
- Custom Markdown output path when `--output` is provided

Arguments:

| Argument | Default | Description |
|---|---|---|
| `json_files` | required | One or more JSON audit result files. |
| `--output FILE` | `reports/assessment-report-TIMESTAMP.md` | Markdown output path. |
| `--title TEXT` | `Infrastructure Security Assessment Report` | Custom report title. |
| `-h`, `--help` | n/a | Show built-in help. |

Examples:

```bash
python3 scripts/reporting/generate-markdown-report.py examples/sample-output/windows/windows-host-audit.example.json
```

```bash
python3 scripts/reporting/generate-markdown-report.py examples/sample-output/active-directory/ad-health-check.example.json examples/sample-output/group-policy/gpo-health.example.json --output reports/example-assessment.md
```

```bash
python3 scripts/reporting/generate-markdown-report.py reports/windows-audit.json --title "Example GmbH Infrastructure Security Review"
```

Start reading the generated report at:

- `Executive Summary`
- `Findings By Severity`
- `Technical Findings`

Review generated Markdown before sharing it outside the administrator team.
Input JSON may contain sensitive operational evidence even when the report
generator itself is safe and read-only.

## SecureInfra AI Scripts

### `SecureInfra_AI/scripts/reporting/secureinfra_analyzer.py`

Normalizes JSON audit output, applies deterministic risk rules, writes a
normalized JSON report, and generates Markdown reports. Phase 1 supports Active
Directory inactive user audit JSON. AI is not required.

Default mode: report-only.

Requirements:

- Python 3
- Read access to a JSON input file
- Write access to the output directory

Outputs:

- `normalized-report.json`
- `executive-summary.md`
- `technical-findings.md`
- `remediation-plan.md`

Arguments:

| Argument | Default | Description |
|---|---|---|
| `--input FILE` | required | JSON audit result file to analyze. |
| `--type TYPE` | required | Input report type. Supports `ad-inactive-users`, `ad-password-never-expires`, `ad-privileged-groups`, `ad-privileged-identity`, `ad-service-accounts`, `ad-spn-exposure`, `ad-stale-computers`, `gpo-health`, and `ad-shared`. |
| `--output DIR` | `SecureInfra_AI/reports` | Output directory for normalized JSON and Markdown reports. |
| `--language LANG` | `en` | Report language. Phase 1 supports `en`; `de` is reserved for future support. |
| `--format FORMAT` | `markdown` | Report format. Phase 1 supports `markdown`. |

Example:

```bash
python3 SecureInfra_AI/scripts/reporting/secureinfra_analyzer.py --input SecureInfra_AI/examples/sample-input/active-directory/sample-ad-inactive-users.json --type ad-inactive-users --output SecureInfra_AI/reports
```

```bash
python3 SecureInfra_AI/scripts/reporting/secureinfra_analyzer.py --input reports/ad-shared --type ad-shared --output reports/output --language en --format markdown
```

```bash
python3 SecureInfra_AI/scripts/reporting/secureinfra_analyzer.py --input reports/ad-shared/service-accounts.json --type ad-service-accounts --output reports/output
```

```bash
python3 SecureInfra_AI/scripts/reporting/secureinfra_analyzer.py --input reports/ad-shared/gpo-health.json --type gpo-health --output reports/output
```

Safety notes:

- The analyzer does not modify systems.
- The risk engine is deterministic and does not rely on AI.
- AI stubs are optional and do not make remediation decisions.
- Privileged, SPN-bearing, built-in, and system-managed accounts are not safe
  for automatic remediation.
- Human owner review and approved change control are required before account
  changes.

# Windows Scripts

These scripts support Windows Server and workstation audit, hardening, event
review, and safe RDP profile cache cleanup.

Run PowerShell as Administrator for complete results. Before running scripts on
a new host, you can use a temporary execution policy bypass:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Full cross-platform reference: [../../docs/script-reference.md](../../docs/script-reference.md)

Windows expansion roadmap: [../../docs/windows-roadmap.md](../../docs/windows-roadmap.md)

## Main Launcher

Use one root script for normal Windows administration:

```powershell
.\scripts\windows\Start-WindowsSecurity.ps1
```

The launcher shows group menus for AD/GPO, Windows Host, Server, and
Workstation scripts. After a script is selected, it displays the supported
parameters and lets the admin enter values before running it.

Useful direct launcher commands:

```powershell
.\scripts\windows\Start-WindowsSecurity.ps1 -ListScripts
.\scripts\windows\Start-WindowsSecurity.ps1 -Group AD -RunAll
.\scripts\windows\Start-WindowsSecurity.ps1 -ToolId AD-GPO-HEALTH
```

## Shared Parameter Config

Use a local JSON config when many Windows scripts need the same values, such as
domain controller, DNS domain, search base, or output directory:

```powershell
Copy-Item .\examples\windows-security.config.example.json .\windows-security.config.local.json
.\scripts\windows\Start-WindowsSecurity.ps1 -Group AD -RunAll -UseDefaults -ConfigPath .\windows-security.config.local.json
```

The launcher reads config values in this order:

1. `Defaults`
2. `Groups.<GroupId>`
3. `Tools.<ToolId>`

Tool-specific values override group values, and group values override global
defaults. Interactive input still wins when the admin chooses to customize a
script. High-impact switches such as `-Apply` are not silently enabled by
`-UseDefaults`; select that script directly when a change must be confirmed.

Do not put passwords or secrets in this file. `Credential` parameters are
intentionally ignored by the config loader.

## Category Folders

New Windows scripts should be added under these folders:

| Folder | Purpose |
|---|---|
| `ad/` | Active Directory identity, computer-account, privileged-group, service-account, and SPN audits. |
| `gpo/` | Group Policy and policy baseline comparison scripts. |
| `host/` | Cross-host audit, hardening, workflow, remediation plan, and event scripts. |
| `server/` | Server-focused exposure, remote-management, service, certificate, and patch state audits. |
| `workstation/` | Workstation endpoint posture scripts. |
| `shared/` | Reusable PowerShell helpers and modules. |

The root of `scripts/windows/` contains only the main launcher. Implementation
scripts stay in the category folders.

## Recommended Workflow

For day-to-day IT use, start with the guided workflow:

```powershell
.\scripts\windows\Start-WindowsSecurity.ps1
```

Choose `Windows Host`, then select `Guided audit and remediation workflow`.
That guided script runs the audit, creates a remediation plan, shows each
finding with the suggested fix, records admin decisions, and runs a hardening
dry-run preview. After reviewing the preview, run the same menu item again and
enable `-ApplyApproved`, or use the direct command:

```powershell
.\scripts\windows\host\Start-WindowsSecurityRemediation.ps1 -ApplyApproved
```

When a saved decision plan exists in the output directory, `-ApplyApproved`
resumes that plan instead of asking all questions again. The final apply still
requires typing `APPLY` after the dry-run preview.

## `Start-WindowsSecurityRemediation.ps1`

Runs the admin-friendly workflow over the lower-level audit, remediation plan,
and hardening scripts.

Parameters:

| Parameter | Description |
|---|---|
| `-AuditReportPath` | Use an existing audit report instead of running a new audit. |
| `-PlanPath` | Use an existing remediation plan and skip the audit/questions unless `-ReviewDecisions` is used. |
| `-OutputDirectory` | Directory for generated reports. |
| `-IncludeHotfixes` | Include hotfix records when running a new audit. |
| `-ApplyApproved` | Allow final apply confirmation after dry-run preview. |
| `-ReviewDecisions` | Re-open a saved plan and ask the admin to review decisions again. |
| `-NonInteractive` | Mark all findings skipped and generate preview reports without prompts. |
| `-Quiet` | Reduce console output. |

Examples:

```powershell
.\scripts\windows\host\Start-WindowsSecurityRemediation.ps1
.\scripts\windows\host\Start-WindowsSecurityRemediation.ps1 -ApplyApproved
.\scripts\windows\host\Start-WindowsSecurityRemediation.ps1 -AuditReportPath .\reports\server01-audit.json
.\scripts\windows\host\Start-WindowsSecurityRemediation.ps1 -PlanPath .\reports\server01-remediation-plan.json -ApplyApproved
```

Use this workflow when an admin should not edit JSON manually. The script writes
their decisions into the JSON remediation plan and uses that plan for the
hardening preview/apply step.

The guided prompt shows `Approve fix` only when the finding maps to a hardening
control that can run. Manual-only items, such as broad listening ports or
PowerShell transcription design, can still be recorded as skipped or exception
items.

## AD Scripts

Active Directory scripts are under `ad/`.

| Script | Purpose |
|---|---|
| `ad/Get-ADInactiveUserReport.ps1` | Reports inactive AD users with last logon evidence, priority, category, and deletion-readiness guidance. |
| `ad/Get-ADStaleComputerReport.ps1` | Reports stale AD computers with last logon evidence, priority, category, and cleanup-readiness guidance. |
| `ad/Watch-ADPrivilegedGroupChanges.ps1` | Compares privileged AD group membership against a saved baseline and reports added/removed members. |
| `ad/Get-ADServiceAccountAudit.ps1` | Audits service account candidates, gMSA/sMSA objects, SPNs, password age, delegation, ownership, and privilege risk. |
| `ad/Get-ADSPNExposureAudit.ps1` | Audits SPN-bearing user accounts for Kerberos exposure indicators without offensive actions. |
| `ad/Get-ADPasswordNeverExpiresReport.ps1` | Reports PasswordNeverExpires accounts with service, SPN, privilege, exception, and cleanup guidance. |
| `ad/Get-PrivilegedIdentityProtectionAudit.ps1` | Audits privileged AD identities for on-prem protection gaps; MFA and Conditional Access are not checked yet. |

Example:

```powershell
.\scripts\windows\ad\Get-ADInactiveUserReport.ps1 -DaysInactive 90
.\scripts\windows\ad\Get-ADStaleComputerReport.ps1 -DaysInactive 90
.\scripts\windows\ad\Watch-ADPrivilegedGroupChanges.ps1
.\scripts\windows\ad\Get-ADServiceAccountAudit.ps1
.\scripts\windows\ad\Get-ADSPNExposureAudit.ps1
.\scripts\windows\ad\Get-ADPasswordNeverExpiresReport.ps1
.\scripts\windows\ad\Get-PrivilegedIdentityProtectionAudit.ps1
```

## GPO Scripts

Group Policy scripts are under `gpo/`.

| Script | Purpose |
|---|---|
| `gpo/Get-ADGPOHealthReport.ps1` | Audits GPO inventory, links, stale policies, filters, version mismatches, and common policy health risks. |

Example:

```powershell
.\scripts\windows\gpo\Get-ADGPOHealthReport.ps1 -StaleDays 365
```

## `Invoke-WindowsSecurityAudit.ps1`

Collects local security posture evidence and writes a JSON report. It does not
change the system.

Parameters:

| Parameter | Description |
|---|---|
| `-OutputPath` | JSON report path. |
| `-IncludeHotfixes` | Include recent installed hotfix records. |
| `-Quiet` | Suppress console summary. |

Examples:

```powershell
.\scripts\windows\host\Invoke-WindowsSecurityAudit.ps1
.\scripts\windows\host\Invoke-WindowsSecurityAudit.ps1 -IncludeHotfixes
.\scripts\windows\host\Invoke-WindowsSecurityAudit.ps1 -OutputPath .\reports\server01-audit.json
.\scripts\windows\host\Invoke-WindowsSecurityAudit.ps1 -OutputPath .\reports\server01-audit.json -IncludeHotfixes -Quiet
```

Start reading the report at `Summary.Posture`, `Summary.SeverityCounts`, and
`Findings`.

## `New-WindowsRemediationPlan.ps1`

Creates a reviewable remediation plan from a Windows security audit report. It
does not change the system. The JSON output is the automation source of truth;
Markdown and CSV outputs are optional review copies.

Parameters:

| Parameter | Description |
|---|---|
| `-AuditReportPath` | JSON report created by `Invoke-WindowsSecurityAudit.ps1`. |
| `-OutputPath` | JSON remediation plan path. |
| `-IncludeMarkdown` | Write a Markdown review copy. |
| `-IncludeCsv` | Write a CSV review copy. |
| `-Quiet` | Suppress console summary. |

Examples:

```powershell
.\scripts\windows\host\New-WindowsRemediationPlan.ps1 -AuditReportPath .\reports\server01-audit.json
.\scripts\windows\host\New-WindowsRemediationPlan.ps1 -AuditReportPath .\reports\server01-audit.json -IncludeMarkdown -IncludeCsv
```

Every plan item starts as `ApprovalStatus = NotApproved`. Review and approve
items in the JSON plan before using it with the hardening script.

## `Set-WindowsBaselineHardening.ps1`

Creates a Windows hardening plan and applies controls only when `-Apply` is
used. Dry-run is the default. Apply mode writes selective registry backups and
`backup-manifest.json` before remediation.

Parameters:

| Parameter | Description |
|---|---|
| `-Apply` | Apply selected controls. |
| `-ReportPath` | JSON hardening report path. |
| `-BackupDirectory` | Directory for selective registry backups and `backup-manifest.json` used with `-Apply`. |
| `-PlanPath` | Apply only approved runnable controls from a remediation plan. |
| `-SkipDefender` | Skip Microsoft Defender controls. |
| `-SkipAuditPolicy` | Skip audit policy controls. |
| `-ExcludeControlId` | Exclude one or more control IDs. |
| `-OnlyControlId` | Run only selected control IDs. |
| `-ListControls` | List valid control IDs and exit. |

Examples:

```powershell
.\scripts\windows\host\Set-WindowsBaselineHardening.ps1
.\scripts\windows\host\Set-WindowsBaselineHardening.ps1 -ListControls
.\scripts\windows\host\Set-WindowsBaselineHardening.ps1 -ExcludeControlId WIN-HARDEN-FW-001
.\scripts\windows\host\Set-WindowsBaselineHardening.ps1 -ExcludeControlId WIN-HARDEN-FW-001,WIN-HARDEN-DEF-001
.\scripts\windows\host\Set-WindowsBaselineHardening.ps1 -OnlyControlId WIN-HARDEN-RDP-001
.\scripts\windows\host\Set-WindowsBaselineHardening.ps1 -PlanPath .\reports\server01-remediation-plan.json
.\scripts\windows\host\Set-WindowsBaselineHardening.ps1 -PlanPath .\reports\server01-remediation-plan.json -Apply
.\scripts\windows\host\Set-WindowsBaselineHardening.ps1 -SkipDefender -SkipAuditPolicy -ReportPath .\reports\server01-hardening.json
.\scripts\windows\host\Set-WindowsBaselineHardening.ps1 -Apply -BackupDirectory .\backups\server01-baseline -ReportPath .\reports\server01-hardening.json
```

If another product owns a control, exclude it by ID. Example: if ESET manages
the host firewall, use `-ExcludeControlId WIN-HARDEN-FW-001`.

With `-PlanPath`, the script selects only plan items marked
`ApprovalStatus = Approved` and only when the referenced hardening control is
runnable. Approved items marked `NotYetImplemented`, `NeedsAlignment`,
`ManualDesignRequired`, or `ManualOnly` are not applied. Controls that can break
remote administration, such as disabling RDP or WinRM, require a remediation
plan approval or explicit `-OnlyControlId` selection before they run.

Backups are tied to selected controls. For example, `dnsclient-policy.reg` is
written only when the LLMNR control is selected. The manifest lists every
backup file, the control IDs that required it, missing registry keys, and
controls where rollback is not fully represented by a `.reg` file.

## `Export-WindowsEventSecurityReport.ps1`

Exports selected Windows Security and System event log activity. It writes
`summary.txt`, `summary.json`, and `events.csv`.

Parameters:

| Parameter | Description |
|---|---|
| `-Days` | Number of days of event history to review. |
| `-OutputDirectory` | Directory for report files. |

Examples:

```powershell
.\scripts\windows\host\Export-WindowsEventSecurityReport.ps1
.\scripts\windows\host\Export-WindowsEventSecurityReport.ps1 -Days 7
.\scripts\windows\host\Export-WindowsEventSecurityReport.ps1 -Days 30 -OutputDirectory .\reports\server01-events
```

Review `summary.txt` first. It gives a verdict, findings, why each item
matters, and the evidence to check before opening the full CSV.

## `Clear-RDPUserProfileCache.ps1`

Audits and optionally cleans safe per-user cache locations on RDP or Terminal
Server hosts. Dry-run is the default.

Parameters:

| Parameter | Description |
|---|---|
| `-ProfileRoot` | Root directory containing user profile folders. |
| `-MinimumAgeDays` | Only report or delete files older than this many days. |
| `-ReportPath` | JSON cleanup report path. |
| `-Apply` | Delete eligible files. |
| `-IncludeLoadedProfiles` | Include currently loaded profiles. |
| `-IncludeRecycleBin` | Include each user's Recycle Bin when available. |
| `-IncludeTemp` | Include per-user `AppData\Local\Temp`. |
| `-ExcludeProfileName` | Profile folder names to skip. |

Examples:

```powershell
.\scripts\windows\server\Clear-RDPUserProfileCache.ps1
.\scripts\windows\server\Clear-RDPUserProfileCache.ps1 -MinimumAgeDays 30
.\scripts\windows\server\Clear-RDPUserProfileCache.ps1 -MinimumAgeDays 30 -IncludeRecycleBin -IncludeTemp
.\scripts\windows\server\Clear-RDPUserProfileCache.ps1 -ProfileRoot D:\Users -MinimumAgeDays 45 -ReportPath .\reports\terminal01-cache.json
.\scripts\windows\server\Clear-RDPUserProfileCache.ps1 -ExcludeProfileName "Default","Public","admin-template"
.\scripts\windows\server\Clear-RDPUserProfileCache.ps1 -Apply -MinimumAgeDays 30
.\scripts\windows\server\Clear-RDPUserProfileCache.ps1 -Apply -MinimumAgeDays 30 -IncludeLoadedProfiles
```

Use `-IncludeLoadedProfiles` only during a maintenance window after checking
active sessions.

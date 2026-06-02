# Windows AD Scripts

Active Directory scripts live here.

Use this folder for identity, computer-account, privileged-group, service
account, SPN exposure, and privileged access protection audits.

Planned scripts are tracked in [../../../docs/windows-roadmap.md](../../../docs/windows-roadmap.md).

## `Get-ADInactiveUserReport.ps1`

Reports Active Directory users inactive for a selected number of days. The
script is audit-only and writes `inactive-users.json`, `inactive-users.csv`, and
`inactive-users-review.md`.

The report includes admin-facing fields for `ReviewPriority`,
`AccountCategory`, `LifecycleStage`, `DeletionReadiness`, `ReviewReasonsText`,
`RecommendedAction`, `DeletionGuidance`, `DependencySignalsText`, and
`NextReviewStep`.

Parameters:

| Parameter | Description |
|---|---|
| `-DaysInactive` | Number of days since last logon before a user is reported. Default: `90`. |
| `-SearchBase` | Optional OU or domain distinguished name to search. |
| `-Server` | Optional domain controller to query. |
| `-Credential` | Optional credential for the AD query. |
| `-IncludeDisabled` | Include disabled accounts. By default, only enabled users are scanned. |
| `-ExcludeNeverLoggedOn` | Exclude accounts that never logged on. |
| `-OutputDirectory` | Directory for JSON and CSV reports. |
| `-Quiet` | Suppress console summary. |

Examples:

```powershell
.\scripts\windows\ad\Get-ADInactiveUserReport.ps1
.\scripts\windows\ad\Get-ADInactiveUserReport.ps1 -DaysInactive 180
.\scripts\windows\ad\Get-ADInactiveUserReport.ps1 -SearchBase "OU=Users,DC=example,DC=com"
.\scripts\windows\ad\Get-ADInactiveUserReport.ps1 -IncludeDisabled -OutputDirectory .\reports\ad-users
```

Start review with `Critical` accounts, then `High` accounts. Treat `Hold`
accounts separately; for example Exchange `HealthMailbox*` accounts are
system-managed and should not be deleted as normal inactive users.

`CanDeleteNow` is always `false`. A `PotentialDeletionCandidate` still requires
owner approval, disabled-account quarantine, dependency checks, and rollback
planning before deletion.

The Markdown report is the best first view for normal admins. Use the CSV for
sorting/filtering by `DependencySignalsText`, `PrivilegedGroupCount`,
`HasMailAttributes`, `DirectGroupCount`, or `DeletionReadiness`.

The report uses `LastLogonDate`, which is based on replicated
`lastLogonTimestamp`, so use a conservative threshold and confirm ownership
before disabling accounts.

## `Get-ADStaleComputerReport.ps1`

Reports Active Directory computers stale for a selected number of days. The
script is audit-only and writes `stale-computers.json`, `stale-computers.csv`,
and `stale-computers-review.md`.

The report includes admin-facing fields for `ReviewPriority`,
`ActionPriority`, `ComputerCategory`, `LifecycleStage`, `CleanupReadiness`,
`PotentialCleanupCandidate`, `RiskFlagsText`, `RecommendedAction`,
`CleanupGuidance`, and `NextReviewStep`.

Parameters:

| Parameter | Description |
|---|---|
| `-DaysInactive` | Number of days since last logon before a computer is reported. Default: `90`. |
| `-SearchBase` | Optional OU or domain distinguished name to search. |
| `-Server` | Optional domain controller to query. |
| `-Credential` | Optional credential for the AD query. |
| `-IncludeDisabled` | Include disabled computers. By default, only enabled computers are scanned. |
| `-ExcludeNeverLoggedOn` | Exclude computers that never logged on. |
| `-OutputDirectory` | Directory for JSON, CSV, and Markdown reports. |
| `-Quiet` | Suppress console summary. |

Examples:

```powershell
.\scripts\windows\ad\Get-ADStaleComputerReport.ps1
.\scripts\windows\ad\Get-ADStaleComputerReport.ps1 -DaysInactive 180
.\scripts\windows\ad\Get-ADStaleComputerReport.ps1 -SearchBase "OU=Computers,DC=example,DC=com"
.\scripts\windows\ad\Get-ADStaleComputerReport.ps1 -IncludeDisabled -OutputDirectory .\reports\ad-computers
```

Start review with `Critical` domain-controller or infrastructure computers,
then `High` server or SPN-bearing computers. Disabled stale workstations can be
cleanup candidates, but `CanDeleteNow` is always `false`.

For cleanup candidates, backup/export evidence, confirm owner, disable or
quarantine first, monitor for impact, then delete only after approved change
control.

## `Watch-ADPrivilegedGroupChanges.ps1`

Audits Domain Admins, Builtin Administrators, and other privileged AD groups
against a saved direct-membership baseline. The script is audit-only and writes
`privileged-groups.json`, `privileged-groups.csv`,
`privileged-group-members.csv`, `privileged-group-changes.csv`, and
`privileged-groups-review.md`.

The first run creates the baseline automatically at
`.\reports\ad-privileged-groups-baseline.json`. Later runs compare current
membership to that baseline and flag added members, removed members, nested
groups, foreign security principals, and computer accounts in privileged
groups.

Parameters:

| Parameter | Description |
|---|---|
| `-BaselinePath` | Stable JSON baseline path. |
| `-OutputDirectory` | Directory for JSON, CSV, and Markdown reports. |
| `-GroupName` | Optional extra group identities to audit. |
| `-Server` | Optional domain controller to query. |
| `-Credential` | Optional credential for the AD query. |
| `-IncludeRecursiveMembers` | Also collect recursive/effective members for visibility. |
| `-UpdateBaseline` | Replace the baseline with the current snapshot after review. |
| `-Quiet` | Suppress console summary. |

Examples:

```powershell
.\scripts\windows\ad\Watch-ADPrivilegedGroupChanges.ps1
.\scripts\windows\ad\Watch-ADPrivilegedGroupChanges.ps1 -IncludeRecursiveMembers
.\scripts\windows\ad\Watch-ADPrivilegedGroupChanges.ps1 -GroupName "DnsAdmins","Custom Tier0 Admins"
.\scripts\windows\ad\Watch-ADPrivilegedGroupChanges.ps1 -UpdateBaseline
```

Review `Added` changes first, especially in `Critical` groups. Use
`-UpdateBaseline` only after every change has an owner, approval/ticket,
expected duration, and rollback decision.

## `Get-ADServiceAccountAudit.ps1`

Audits user-based service account candidates, SPN-bearing accounts, gMSA, and
sMSA objects. The script is audit-only and writes `service-accounts.json`,
`service-accounts.csv`, and `service-accounts-review.md`.

It flags privileged access, old passwords, `PasswordNeverExpires`, stale enabled
accounts, delegation, pre-authentication disabled, and missing owner evidence.

Example:

```powershell
.\scripts\windows\ad\Get-ADServiceAccountAudit.ps1
.\scripts\windows\ad\Get-ADServiceAccountAudit.ps1 -SearchBase "OU=Service Accounts,DC=example,DC=com"
.\scripts\windows\ad\Get-ADServiceAccountAudit.ps1 -IncludeDisabled -StaleDays 180
```

Start with `Critical`, then `High`. Prefer gMSA where applications support it,
but do not rotate, disable, or migrate an account until owner, dependency,
maintenance window, and rollback are confirmed.

## `Get-ADSPNExposureAudit.ps1`

Audits user accounts with SPNs and highlights Kerberos exposure indicators. The
script is defensive inventory only; it does not request tickets, crack
passwords, or change AD. It writes `spn-exposure.json`, `spn-exposure.csv`, and
`spn-exposure-review.md`.

Example:

```powershell
.\scripts\windows\ad\Get-ADSPNExposureAudit.ps1
.\scripts\windows\ad\Get-ADSPNExposureAudit.ps1 -IncludeDisabled -MaxPasswordAgeDays 365
```

Review privileged SPN accounts, delegation, pre-authentication disabled,
`PasswordNeverExpires`, old passwords, and weak or unknown encryption settings
first.

## `Get-ADPasswordNeverExpiresReport.ps1`

Reports accounts with `PasswordNeverExpires` and classifies normal exceptions,
service accounts, SPN accounts, privileged accounts, disabled accounts, and
system-managed Exchange health mailboxes. The script is audit-only and writes
`password-never-expires.json`, `password-never-expires.csv`, and
`password-never-expires-review.md`.

Example:

```powershell
.\scripts\windows\ad\Get-ADPasswordNeverExpiresReport.ps1
.\scripts\windows\ad\Get-ADPasswordNeverExpiresReport.ps1 -IncludeDisabled
```

Do not remove `PasswordNeverExpires` blindly. Confirm owner, service dependency,
maintenance window, rollback, and exception status first.

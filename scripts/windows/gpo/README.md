# Windows GPO Scripts

Group Policy and policy-baseline scripts live here.

Use this folder for audit policy comparisons, PowerShell logging policy checks,
security baseline comparisons, and future GPO export/report helpers.

## `Get-ADGPOHealthReport.ps1`

Audits Active Directory Group Policy inventory, links, and common health risks.
It does not change Group Policy or Active Directory.

The report helps normal IT administrators review:

- unlinked, stale, disabled, empty, or duplicate-name GPOs
- disabled and enforced GPO links
- targets with many direct GPO links
- possible setting overlap on the same linked target
- WMI-filtered and security-filtered GPOs
- AD/SYSVOL version mismatches
- possible legacy references such as old Windows, Internet Explorer, or Office versions

Example:

```powershell
.\scripts\windows\gpo\Get-ADGPOHealthReport.ps1
```

Audit a specific domain and treat GPOs older than 730 days as stale:

```powershell
.\scripts\windows\gpo\Get-ADGPOHealthReport.ps1 -Domain example.com -StaleDays 730
```

If the Active Directory module is not available, or you only want GPO XML-based
link discovery, skip OU/domain target inventory:

```powershell
.\scripts\windows\gpo\Get-ADGPOHealthReport.ps1 -SkipTargetInventory
```

Outputs:

- `gpo-health.json`
- `gpos.csv`
- `gpo-links.csv`
- `gpo-findings.csv`
- `gpo-review.md`

Start with `gpo-review.md` for the readable admin summary, then use CSV/JSON
for evidence and filtering.

The Markdown report includes an Admin Action Plan. Use `ActionPriority`,
`AdminAction`, and `VerificationStep` to decide whether an item is urgent,
cleanup work, modernization work, or documentation-only review.

Planned scripts are tracked in [../../../docs/windows-roadmap.md](../../../docs/windows-roadmap.md).

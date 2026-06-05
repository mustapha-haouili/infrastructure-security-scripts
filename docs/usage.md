# Usage Notes

## Running scripts safely

Use the following workflow before running a script in production:

1. Read the script header and parameters.
2. Run the script in audit or dry-run mode.
3. Review the report output.
4. Confirm that the changes match your internal baseline.
5. Run with `--apply` or `-Apply` only when you are ready.

For complete parameter documentation and examples, use
[script-reference.md](script-reference.md). Each script also includes built-in
help:

```bash
bash scripts/linux/linux-security-audit.sh --help
python3 scripts/monitoring/service-health-check.py --help
```

```powershell
Get-Content .\scripts\windows\host\Set-WindowsBaselineHardening.ps1 -First 140
```

## Output locations

The repository uses these default output directories:

```text
reports/    audit and monitoring output
backups/    configuration backups before changes
logs/       optional runtime logs
```

These folders are ignored by Git.

Some audit scripts also write machine-readable summaries. For example:

```bash
bash scripts/linux/linux-security-audit.sh --quick --summary-json reports/linux-audit-summary.json
```

## Windows execution policy

For a temporary PowerShell session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

This does not change the machine-wide execution policy.

## Windows menu launcher

For normal IT administration, start with the Windows menu:

```powershell
.\scripts\windows\Start-WindowsSecurity.ps1
```

The menu lets the admin choose a group, choose one script or run the
default-safe scripts in that group, enter supported parameters, preview the
command, and confirm before the selected script starts.

List menu IDs for direct use:

```powershell
.\scripts\windows\Start-WindowsSecurity.ps1 -ListScripts
```

When multiple Windows scripts need the same environment values, copy the
example config and update it once:

```powershell
Copy-Item .\examples\windows-security.config.example.json .\windows-security.config.local.json
.\scripts\windows\Start-WindowsSecurity.ps1 -Group AD -RunAll -UseDefaults -ConfigPath .\windows-security.config.local.json
```

The local `.local.json` copy is ignored by Git. Do not store credentials or
secrets in it; the launcher ignores `Credential` parameters from config.

## Reading Windows reports

The Windows audit and hardening reports include summary sections before the raw evidence:

- `Summary.Posture`: quick overall triage result for audit reports.
- `Summary.SeverityCounts`: count of Critical, High, Medium, Low, and Info items.
- `Findings`: audit findings with severity, evidence, reason, and recommendation.
- `Summary.HighPriorityReview`: hardening controls to review first before using `-Apply`.
- `Results`: full hardening plan with action, rationale, risk, operational impact, recommendation, and rollback note.

Severity is a triage helper, not a compliance certificate. Review operational impact before applying changes on production RDP servers.

The Windows event export writes:

- `events.csv`: one event per row, with `EventLabel`, `TriageSeverity`, `WhyItMatters`, and message evidence.
- `summary.txt`: readable administrator summary with verdict, findings, evidence, and recommended review actions.
- `summary.json`: event counts, `InvestigationSummary`, failed logon summaries, privileged logon summaries, recent high-severity events, and service installations.

Start with `summary.txt` or `summary.json` -> `InvestigationSummary.Verdict`. A High item means "review first", not automatic proof of an attack.

If another approved product owns a control, exclude that control by ID instead of editing the script. For example, on a server where ESET manages the firewall:

```powershell
.\scripts\windows\host\Set-WindowsBaselineHardening.ps1 -ExcludeControlId WIN-HARDEN-FW-001
```

Use `-ListControls` to see available control IDs.

## RDP profile cache cleanup

Use dry-run mode first on production RDP or Terminal Server hosts:

```powershell
.\scripts\windows\server\Clear-RDPUserProfileCache.ps1 -MinimumAgeDays 30
```

Review the JSON report under `reports/` before applying cleanup. By default, the script skips loaded profiles and does not clean user Recycle Bin or Temp folders unless those options are explicitly enabled.

## Linux permissions

Audit scripts can run as a normal user, but some checks return more detail when run with `sudo`.

Hardening scripts require root only when using `--apply`.

## CI usage

The secret scanner can be used in a pipeline:

```bash
python3 scripts/devsecops/secret-scan.py . --format json --output reports/secrets.json
```

The scanner returns exit code `2` when findings are detected unless `--no-fail` is used.

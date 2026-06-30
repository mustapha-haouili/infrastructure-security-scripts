# Windows Backup Readiness Audit

`Get-WindowsBackupReadinessAudit.ps1` collects metadata-only backup readiness
evidence for defensive review.

It is audit-only. It does not delete backups, modify backups, run restore
operations, enumerate backup folders, read backup contents, collect
credentials, or collect secrets.

## Usage

```powershell
.\scripts\windows\backup\Get-WindowsBackupReadinessAudit.ps1
```

```powershell
.\scripts\windows\backup\Get-WindowsBackupReadinessAudit.ps1 `
  -ExpectedBackupPaths "E:\ExampleBackups" `
  -ExpectedBackupSoftware "Windows Server Backup" `
  -WarningAgeDays 14 `
  -CriticalAgeDays 30 `
  -OutputDirectory .\reports\backup `
  -Quiet
```

## Outputs

- `backup-readiness.json`
- `backup-readiness-findings.csv`
- `backup-readiness-review.md`

## Evidence Boundary

The collector checks visible service names, backup-related event metadata,
Volume Shadow Copy / restore point metadata where available, and optional
expected backup path metadata with `Test-Path` and `Get-Item`.

Service presence is not treated as proof of healthy backups. If backup job
history, restore testing, monitoring, or centralized platform evidence is not
available locally, the report records that as an evidence gap for owner review.

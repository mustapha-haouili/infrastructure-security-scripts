# Script Reference

This page documents every operational script in the repository, including
purpose, safety mode, parameters, outputs, and examples.

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

### `scripts/windows/Invoke-WindowsSecurityAudit.ps1`

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
.\scripts\windows\Invoke-WindowsSecurityAudit.ps1
```

```powershell
.\scripts\windows\Invoke-WindowsSecurityAudit.ps1 -IncludeHotfixes
```

```powershell
.\scripts\windows\Invoke-WindowsSecurityAudit.ps1 -OutputPath .\reports\server01-audit.json
```

```powershell
.\scripts\windows\Invoke-WindowsSecurityAudit.ps1 -OutputPath .\reports\server01-audit.json -IncludeHotfixes -Quiet
```

Start reading the report at:

- `Summary.Posture`
- `Summary.SeverityCounts`
- `Findings`

### `scripts/windows/Set-WindowsBaselineHardening.ps1`

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
.\scripts\windows\Set-WindowsBaselineHardening.ps1
```

```powershell
.\scripts\windows\Set-WindowsBaselineHardening.ps1 -ListControls
```

```powershell
.\scripts\windows\Set-WindowsBaselineHardening.ps1 -ExcludeControlId WIN-HARDEN-FW-001
```

```powershell
.\scripts\windows\Set-WindowsBaselineHardening.ps1 -ExcludeControlId WIN-HARDEN-FW-001,WIN-HARDEN-DEF-001
```

```powershell
.\scripts\windows\Set-WindowsBaselineHardening.ps1 -OnlyControlId WIN-HARDEN-RDP-001
```

```powershell
.\scripts\windows\Set-WindowsBaselineHardening.ps1 -SkipDefender -SkipAuditPolicy -ReportPath .\reports\server01-hardening.json
```

```powershell
.\scripts\windows\Set-WindowsBaselineHardening.ps1 -Apply -BackupDirectory .\backups\server01-baseline -ReportPath .\reports\server01-hardening.json
```

If another product owns a control, exclude it by ID. Example: if ESET manages
the host firewall, use `-ExcludeControlId WIN-HARDEN-FW-001`.

Start reading the report at:

- `Summary.HighPriorityReview`
- `Results[].ControlId`
- `Results[].OperationalImpact`
- `Results[].Rollback`

### `scripts/windows/Export-WindowsEventSecurityReport.ps1`

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
.\scripts\windows\Export-WindowsEventSecurityReport.ps1
```

```powershell
.\scripts\windows\Export-WindowsEventSecurityReport.ps1 -Days 7
```

```powershell
.\scripts\windows\Export-WindowsEventSecurityReport.ps1 -Days 30 -OutputDirectory .\reports\server01-events
```

Start with `summary.txt`. A High item means "review first", not automatic proof
of an attack.

### `scripts/windows/Clear-RDPUserProfileCache.ps1`

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
.\scripts\windows\Clear-RDPUserProfileCache.ps1
```

```powershell
.\scripts\windows\Clear-RDPUserProfileCache.ps1 -MinimumAgeDays 30
```

```powershell
.\scripts\windows\Clear-RDPUserProfileCache.ps1 -MinimumAgeDays 30 -IncludeRecycleBin -IncludeTemp
```

```powershell
.\scripts\windows\Clear-RDPUserProfileCache.ps1 -ProfileRoot D:\Users -MinimumAgeDays 45 -ReportPath .\reports\terminal01-cache.json
```

```powershell
.\scripts\windows\Clear-RDPUserProfileCache.ps1 -ExcludeProfileName "Default","Public","admin-template"
```

```powershell
.\scripts\windows\Clear-RDPUserProfileCache.ps1 -Apply -MinimumAgeDays 30
```

```powershell
.\scripts\windows\Clear-RDPUserProfileCache.ps1 -Apply -MinimumAgeDays 30 -IncludeLoadedProfiles
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

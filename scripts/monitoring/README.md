# Monitoring Scripts

These scripts provide simple infrastructure monitoring checks that can be used
manually, with cron, or inside lightweight automation.

Full cross-platform reference: [../../docs/script-reference.md](../../docs/script-reference.md)

## `service-health-check.py`

Checks HTTP and TCP services from a JSON config file.

Exit codes:

| Code | Meaning |
|---:|---|
| `0` | Every service is healthy. |
| `1` | Configuration or runtime error. |
| `2` | One or more services failed. |

Arguments:

| Argument | Description |
|---|---|
| `--config FILE` | JSON service configuration file. |
| `--output FILE` | Optional JSON output path. |
| `--timeout SECONDS` | Override timeout for all checks. |
| `-h`, `--help` | Show built-in help. |

Examples:

```bash
python3 scripts/monitoring/service-health-check.py
python3 scripts/monitoring/service-health-check.py --config examples/services.example.json
python3 scripts/monitoring/service-health-check.py --config examples/services.example.json --output reports/services-health.json
python3 scripts/monitoring/service-health-check.py --config examples/services.example.json --timeout 10
```

## `disk-space-monitor.sh`

Checks filesystem usage and exits with monitoring-friendly status codes.

Exit codes:

| Code | Meaning |
|---:|---|
| `0` | All checked filesystems are below warning threshold. |
| `1` | One or more filesystems reached warning threshold. |
| `2` | One or more filesystems reached critical threshold. |

Options:

| Option | Description |
|---|---|
| `--warn PERCENT` | Warning threshold. |
| `--crit PERCENT` | Critical threshold. Must be higher than warning. |
| `--exclude-types LIST` | Comma-separated filesystem types to exclude. |
| `--json` | Print one JSON object per checked filesystem. |
| `-h`, `--help` | Show built-in help. |

Examples:

```bash
bash scripts/monitoring/disk-space-monitor.sh
bash scripts/monitoring/disk-space-monitor.sh --warn 75 --crit 90
bash scripts/monitoring/disk-space-monitor.sh --exclude-types tmpfs,devtmpfs,squashfs,overlay,nfs
bash scripts/monitoring/disk-space-monitor.sh --json
bash scripts/monitoring/disk-space-monitor.sh --warn 75 --crit 90 --exclude-types tmpfs,devtmpfs --json
```

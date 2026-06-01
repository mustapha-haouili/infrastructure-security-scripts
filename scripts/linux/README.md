# Linux Scripts

These scripts support Linux audit, hardening, and inventory collection.

Run audit scripts with `sudo` for complete evidence. Hardening scripts require
root only when `--apply` is used.

Full cross-platform reference: [../../docs/script-reference.md](../../docs/script-reference.md)

## `linux-security-audit.sh`

Collects host security posture information, writes a readable report, and writes
a JSON summary.

Options:

| Option | Description |
|---|---|
| `-o DIR`, `--output-dir DIR` | Directory for the text report. |
| `--quick` | Skip slower filesystem permission checks. |
| `--summary-json FILE` | JSON summary path. |
| `-h`, `--help` | Show built-in help. |

Examples:

```bash
bash scripts/linux/linux-security-audit.sh
sudo bash scripts/linux/linux-security-audit.sh --output-dir reports/linux
bash scripts/linux/linux-security-audit.sh --quick
bash scripts/linux/linux-security-audit.sh --summary-json reports/linux-summary.json
bash scripts/linux/linux-security-audit.sh --quick --output-dir reports --summary-json reports/linux-summary.json
```

## `linux-hardening-baseline.sh`

Runs in dry-run mode by default and applies selected baseline controls only with
`--apply`.

Options:

| Option | Description |
|---|---|
| `--apply` | Apply hardening changes. |
| `--backup-dir DIR` | Backup directory used during apply mode. |
| `--report-dir DIR` | Directory for the hardening log. |
| `--no-ssh` | Skip SSH daemon baseline changes. |
| `--disable-ssh-password` | Set `PasswordAuthentication no` in sshd config. |
| `-h`, `--help` | Show built-in help. |

Examples:

```bash
bash scripts/linux/linux-hardening-baseline.sh
bash scripts/linux/linux-hardening-baseline.sh --report-dir reports/linux-hardening
sudo bash scripts/linux/linux-hardening-baseline.sh --apply
sudo bash scripts/linux/linux-hardening-baseline.sh --apply --backup-dir /root/baseline-backups --report-dir /var/log/security-baseline
bash scripts/linux/linux-hardening-baseline.sh --no-ssh
sudo bash scripts/linux/linux-hardening-baseline.sh --apply --disable-ssh-password
```

## `collect-linux-inventory.sh`

Exports host inventory in JSON format. It does not change the system.

Options:

| Option | Description |
|---|---|
| `-o DIR`, `--output-dir DIR` | Directory for inventory JSON. |
| `-h`, `--help` | Show built-in help. |

Examples:

```bash
bash scripts/linux/collect-linux-inventory.sh
bash scripts/linux/collect-linux-inventory.sh -o /var/tmp/inventory
bash scripts/linux/collect-linux-inventory.sh --output-dir reports
```

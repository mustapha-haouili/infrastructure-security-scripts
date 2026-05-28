# Linux Scripts

These scripts support Linux audit, hardening, and inventory collection.

## Scripts

- `linux-security-audit.sh`: Collects host security posture information.
- `linux-hardening-baseline.sh`: Runs in dry-run mode by default and applies selected baseline controls only with `--apply`.
- `collect-linux-inventory.sh`: Exports host inventory in JSON format.

Run audit scripts with `sudo` for complete results. Review hardening changes before using `--apply`.

# Usage Notes

## Running scripts safely

Use the following workflow before running a script in production:

1. Read the script header and parameters.
2. Run the script in audit or dry-run mode.
3. Review the report output.
4. Confirm that the changes match your internal baseline.
5. Run with `--apply` or `-Apply` only when you are ready.

## Output locations

The repository uses these default output directories:

```text
reports/    audit and monitoring output
backups/    configuration backups before changes
logs/       optional runtime logs
```

These folders are ignored by Git.

## Windows execution policy

For a temporary PowerShell session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

This does not change the machine-wide execution policy.

## Linux permissions

Audit scripts can run as a normal user, but some checks return more detail when run with `sudo`.

Hardening scripts require root only when using `--apply`.

## CI usage

The secret scanner can be used in a pipeline:

```bash
python3 scripts/devsecops/secret-scan.py . --format json --output reports/secrets.json
```

The scanner returns exit code `2` when findings are detected unless `--no-fail` is used.

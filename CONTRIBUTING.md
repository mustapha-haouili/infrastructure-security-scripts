# Contributing

Contributions should be practical, readable, and safe by default.

## Script standards

- Use audit or dry-run mode by default when a script can change a system.
- Use clear parameter names and helpful usage output.
- Avoid hard-coded production values.
- Validate input before using it.
- Write reports to `reports/` and backups to `backups/`.
- Do not commit secrets, tokens, private keys, or customer data.
- Keep dependencies minimal and document any requirement.

## Commit style

Use clear commit messages:

```text
Add Linux SSH baseline hardening script
Improve Windows event report filtering
Fix secret scanner allowlist handling
```

## Testing

Run the static checks before opening a pull request:

```bash
bash tests/run_static_checks.sh
```

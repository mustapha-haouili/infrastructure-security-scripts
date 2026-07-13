# Contributing

Contributions should be practical, readable, portable, and safe by default.
Read [AGENTS.md](AGENTS.md) before changing collectors, analyzers, schemas,
validators, or release tooling.

## Script standards

- Use audit or dry-run mode by default when a script can change a system.
- Require an explicit `--apply` or `-Apply` flag for changes.
- Use clear parameter names and helpful usage output.
- Avoid hard-coded production values, local workstation paths, and
  environment-specific repository locations.
- Validate input before using it.
- Keep dependencies minimal and document any requirement.
- Any new production script must have an explicit caller or a documented
  manual-only reason.

## Data and examples

- Do not commit secrets, credentials, tokens, private keys, customer data, real
  domains, real host names, or internal workflow details.
- Use fictional, synthetic fixtures only.
- Preserve unknown values instead of converting them to safe-looking defaults.
- Treat bundles and imported reports as untrusted data.

## Documentation

- Keep `README.md` focused on project use and navigation.
- Keep `ARCHITECTURE.md` focused on components and data flow.
- Keep `DATA_CONTRACT.md` as the human-readable normalized data contract.
- Keep detailed collection layout rules in `COLLECTION_BUNDLE_CONTRACT.md`.
- Update documentation, examples, tests, and `CHANGELOG.md` when public behavior
  or a schema changes.
- Keep technical severity limited to `Critical`, `High`, `Medium`, `Low`, and
  `Info`; represent `Hold` only in workflow or review fields.

## Testing

Run the static checks and unit tests before opening a pull request:

```bash
bash tests/run_static_checks.sh
python -m unittest discover -s tests -p "test_*.py"
```

On Windows, run the public quality gate from the repository root:

```powershell
.\quality-gate.ps1 -Fast
```

Before release or public handoff, run the full gate:

```powershell
.\quality-gate.ps1
```

Also run `git diff --check` and review staged paths explicitly.

## Git safety

Use targeted staging commands such as:

```text
git add -- path/to/file1 path/to/file2
```

Do not use `git add .`. Do not commit generated reports, archives, spreadsheets,
local evidence, or customer-like project folders.

## Commit style

Use clear commit messages, for example:

```text
Add Linux SSH baseline audit
Improve Windows event normalization
Fix bundle path validation
```

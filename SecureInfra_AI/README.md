# SecureInfra AI

SecureInfra AI is the AI-ready analysis and reporting layer for the
infrastructure security scripts toolkit.

This public layer is defensive and audit-first. It normalizes existing JSON
audit outputs, applies deterministic risk rules, and generates Markdown reports.
It prepares the project for future local or private AI support, but Phase 1 does
not require an AI model.

## Current Capabilities

- Read JSON audit output files.
- Normalize Active Directory inactive user reports into a common finding format.
- Apply transparent rule-based risk classification.
- Generate executive summary, technical findings, and remediation plan
  Markdown reports.
- Provide AI provider interfaces and deterministic local stubs for future use.
- Analyze an AD shared report folder with `--type ad-shared`, normalizing known
  AD/GPO JSON reports for inactive users, password-never-expires accounts,
  service accounts, SPN exposure, stale computers, privileged groups,
  privileged identity protection, and GPO health.

## Safety Boundary

- No offensive automation.
- No autonomous remediation.
- No password, secret, token, private key, or customer data collection.
- No destructive decision-making by AI.
- Human review and approved change control are required before remediation.

## Example

```bash
python3 SecureInfra_AI/scripts/reporting/secureinfra_analyzer.py \
  --input SecureInfra_AI/examples/sample-input/active-directory/sample-ad-inactive-users.json \
  --type ad-inactive-users \
  --output SecureInfra_AI/reports
```

Analyze an AD shared bundle:

```bash
python3 SecureInfra_AI/scripts/reporting/secureinfra_analyzer.py \
  --input reports/ad-shared \
  --type ad-shared \
  --output reports/output \
  --language en \
  --format markdown
```

Run one supported AD/GPO report directly:

```bash
python3 SecureInfra_AI/scripts/reporting/secureinfra_analyzer.py \
  --input reports/ad-shared/service-accounts.json \
  --type ad-service-accounts \
  --output reports/output
```

Generated runtime reports are written to `SecureInfra_AI/reports/`, which is
ignored by Git.

See [docs/ad-shared-bundle-analysis.md](docs/ad-shared-bundle-analysis.md) for
bundle behavior, supported files, and safety notes.

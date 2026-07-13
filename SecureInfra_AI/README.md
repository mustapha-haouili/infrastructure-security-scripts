# SecureInfra AI

SecureInfra AI is the AI-ready analysis and reporting layer for the
infrastructure security scripts toolkit.

This public layer is defensive and audit-first. It normalizes existing JSON
audit outputs, applies deterministic risk rules, and generates Markdown reports.
It prepares the project for future local or private AI support, but Phase 1 does
not require an AI model.

Technical severity is limited to `Critical`, `High`, `Medium`, `Low`, and `Info`.
`Hold` is a separate workflow state and remediation priority, not a severity.

## Current Capabilities

- Read JSON audit output files.
- Normalize Active Directory inactive user reports into a common finding format.
- Apply transparent rule-based risk classification.
- Validate normalized reports against the local SecureInfra AI JSON schemas
  before writing output.
- Add deterministic cross-source correlation groups to normalized reports.
- Add deterministic broad control-reference metadata to normalized reports under
  `metadata.control_references_by_finding_id` and
  `metadata.control_mapping_summary`.
- Compare current normalized reports with a previous `normalized-report.json`
  to identify new, persistent, and resolved findings.
- Generate deterministic monthly KPI summaries with `--monthly-summary`,
  including baseline or month-over-month trend output from normalized reports.
- Generate executive summary, technical findings, and remediation plan
  Markdown reports.
- Review JSON outputs in a local static dashboard with severity metrics,
  filtering, evidence detail, official related-finding links, and historical
  comparison counts.
- Provide AI provider interfaces and deterministic local stubs for future use.
- Analyze a full SecureInfra client collection folder or zip with
  `--type client-bundle`, combining supported AD, host, server, workstation,
  network, and optional backup readiness evidence into one normalized
  dashboard report.
- Analyze many SecureInfra client collection folders or zips with
  `--type multi-bundle`, producing one fleet report with machine inventory,
  per-host coverage, scope totals, and top risky machines.
- Analyze an AD shared report folder with `--type ad-shared`, normalizing known
  AD/GPO JSON reports for inactive users, password-never-expires accounts,
  service accounts, SPN exposure, stale computers, privileged groups,
  privileged identity protection, and GPO health.
- Analyze individual Windows JSON reports with beta standalone analyzer types:
  `windows-host-audit`, `windows-server-audit`,
  `windows-workstation-audit`, and `windows-network-exposure`.
- Analyze backup readiness JSON reports with beta standalone analyzer type
  `backup-readiness` for metadata-only Windows or Linux backup evidence.

## Safety Boundary

- No offensive automation.
- No autonomous remediation.
- No password, secret, token, private key, or customer data collection.
- No backup content collection or restore execution.
- No destructive decision-making by AI.
- Human review and approved change control are required before remediation.
- Client collection zip files are treated as untrusted input. The analyzer
  validates every entry before extraction, rejects traversal and absolute paths,
  limits archives to 512 entries, limits each uncompressed file to 25 MiB, and
  allows only `.json`, `.csv`, `.md`, `.txt`, and `.log` report artifacts.
- Bundle content is never executed; it is loaded only as report evidence.
- Control references are broad informational mappings only. They do not claim
  compliance, certification, audit attestation, or official control coverage.

## Control Mapping

SecureInfra AI adds deterministic control-reference metadata after findings and
correlations are produced and before schema validation. Findings are not
modified; the output stays under report metadata:

```json
{
  "metadata": {
    "control_references_by_finding_id": {
      "AD-INACTIVE-0001": [
        {
          "framework": "CIS Controls IG1",
          "control_id": "CIS-IG1-05",
          "label": "Account Management",
          "mapping_confidence": "medium"
        }
      ]
    },
    "control_mapping_summary": {
      "CIS Controls IG1:CIS-IG1-05": 1
    }
  }
}
```

The catalog uses public-safe, broad references such as `CIS Controls IG1`,
`NIST CSF 2.0`, and `BSI SMB Security Guidance`. These mappings help readers
understand defensive themes; they are not evidence of compliance status.

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

Analyze a full client collection bundle:

```bash
python3 SecureInfra_AI/scripts/reporting/secureinfra_analyzer.py \
  --input reports/secureinfra-client-collection-CLIENT-20260619-120000.zip \
  --type client-bundle \
  --output reports/client-output
```

Analyze many client collection bundles:

```bash
python3 SecureInfra_AI/scripts/reporting/secureinfra_analyzer.py \
  --input reports/client-bundles \
  --type multi-bundle \
  --output reports/fleet-output
```

Compare the current run with a previous normalized report:

```bash
python3 SecureInfra_AI/scripts/reporting/secureinfra_analyzer.py \
  --input reports/ad-shared \
  --type ad-shared \
  --output reports/output \
  --previous-normalized-report reports/previous/normalized-report.json
```

Generate a baseline monthly KPI summary:

```bash
python3 SecureInfra_AI/scripts/reporting/secureinfra_analyzer.py \
  --input reports/ad-shared \
  --type ad-shared \
  --output reports/monthly-current \
  --monthly-summary
```

Generate a month-over-month KPI summary:

```bash
python3 SecureInfra_AI/scripts/reporting/secureinfra_analyzer.py \
  --input reports/ad-shared \
  --type ad-shared \
  --output reports/monthly-current \
  --previous-normalized-report reports/monthly-previous/normalized-report.json \
  --monthly-summary
```

Run one supported AD/GPO report directly:

```bash
python3 SecureInfra_AI/scripts/reporting/secureinfra_analyzer.py \
  --input reports/ad-shared/service-accounts.json \
  --type ad-service-accounts \
  --output reports/output
```

Run one supported Windows report directly. These standalone Windows analyzer
types are beta and report-only:

```bash
python3 SecureInfra_AI/scripts/reporting/secureinfra_analyzer.py \
  --input reports/windows-security-audit.json \
  --type windows-host-audit \
  --output reports/windows-host-output

python3 SecureInfra_AI/scripts/reporting/secureinfra_analyzer.py \
  --input reports/windows-server-security.json \
  --type windows-server-audit \
  --output reports/windows-server-output

python3 SecureInfra_AI/scripts/reporting/secureinfra_analyzer.py \
  --input reports/windows-workstation-security.json \
  --type windows-workstation-audit \
  --output reports/windows-workstation-output

python3 SecureInfra_AI/scripts/reporting/secureinfra_analyzer.py \
  --input reports/windows-network-exposure.json \
  --type windows-network-exposure \
  --output reports/windows-network-output
```

Analyze a backup readiness report:

```bash
python3 SecureInfra_AI/scripts/reporting/secureinfra_analyzer.py \
  --input reports/backup/backup-readiness.json \
  --type backup-readiness \
  --output reports/backup-output
```

Generated runtime reports are written to `SecureInfra_AI/reports/`, which is
ignored by Git.

Open the local dashboard:

```text
SecureInfra_AI/dashboard/index.html
```

The dashboard is a static, local report viewer. It includes a Content Security
Policy and renders report-controlled values as text instead of executable HTML.
The CSP keeps inline styles enabled for current local UI compatibility; do not
treat the dashboard as a hardened hosted portal.

See [docs/ad-shared-bundle-analysis.md](docs/ad-shared-bundle-analysis.md) for
AD bundle behavior, supported files, and safety notes. See
[docs/multi-bundle-fleet-analysis.md](docs/multi-bundle-fleet-analysis.md) for
many-host fleet analysis.


## Related documentation

- [Public architecture](../ARCHITECTURE.md)
- [Data contract](../DATA_CONTRACT.md)
- [Assessment methodology](../docs/methodology.md)
- [Roadmap](../ROADMAP.md)

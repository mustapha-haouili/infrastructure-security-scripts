# Infrastructure Security Scripts

![CI](https://github.com/mustapha-haouili/infrastructure-security-scripts/actions/workflows/static-checks.yml/badge.svg)
![Release](https://img.shields.io/github/v/release/mustapha-haouili/infrastructure-security-scripts?include_prereleases)
![License](https://img.shields.io/github/license/mustapha-haouili/infrastructure-security-scripts)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue)

A practical defensive infrastructure security toolkit for enterprise Windows, Linux, Active Directory, DevSecOps, monitoring, hardening, evidence collection, and local security reporting.

SecureInfra helps reviewers turn raw infrastructure evidence into normalized findings, local reports, control context, and monthly improvement summaries without sending data to external services.

This repository is designed for defensive security operations, infrastructure administration, repeatable baseline checks, and audit-first infrastructure security assessments across enterprise environments.

It includes the SecureInfra_AI layer for deterministic, local, AI-ready analysis of infrastructure evidence. This layer can normalize security findings, generate JSON and Markdown reports, compare historical runs, analyze client bundles, review fleet evidence, and display reports in a local dashboard. The default reporting workflow is deterministic and local: it does not require an AI provider and does not upload evidence to a cloud service.

Development status: beta. See [CHANGELOG.md](CHANGELOG.md) for release history and the current development baseline.

## Try it in 2 minutes

Run the local SecureInfra_AI analyzer against fictional sample evidence already
included in this repository. The demo does not contact Active Directory, require
admin rights, collect live customer data, use external services, or require
credentials. After the repository is present on your machine, the analyzer demo
runs offline.

Prerequisites:

- Python 3.10+
- PowerShell on Windows, or a shell with Python on Linux/macOS
- No administrator rights required for the sample demo

PowerShell:

```powershell
# Optional: clone once if you do not already have the repository locally.
git clone https://github.com/mustapha-haouili/infrastructure-security-scripts.git
cd .\infrastructure-security-scripts

# Analyze fictional backup readiness sample output and write local demo reports.
python .\SecureInfra_AI\scripts\reporting\secureinfra_analyzer.py `
  --input .\examples\sample-output\backup\backup-readiness.example.json `
  --type backup-readiness `
  --output .\demo-output

# Show generated files and preview the executive summary.
Get-ChildItem .\demo-output
Get-Content .\demo-output\executive-summary.md -TotalCount 40
```

If your Windows Python launcher is `py`, replace `python` with `py -3`.

Expected generated files in the current beta demo:

```text
demo-output/
|-- normalized-report.json
|-- executive-summary.md
|-- technical-findings.md
`-- remediation-plan.md
```

If your local branch differs, use `Get-ChildItem .\demo-output` to inspect the exact generated files.

Sample output preview from the fictional demo report:

```markdown
## Number Of Findings

| Severity | Count |
|---|---:|
| Critical | 0 |
| High | 1 |
| Medium | 2 |
| Low | 0 |
| Info | 1 |
```

## Who is this for?

- Infrastructure admins
- Windows / Active Directory admins
- Linux admins
- Blue team / defensive security teams
- IT consultants
- SMB infrastructure support teams

## What this project does

- Defensive evidence collection for Windows, Active Directory, Linux, backup,
  monitoring, and DevSecOps review workflows
- Normalized reporting from collected or imported evidence
- Account and privilege review, including AD account classification signals
- Backup readiness evidence review
- Control mapping metadata for reviewer context
- Monthly KPI trend summaries for recurring review conversations

## What this project does not do

- No offensive exploitation
- No credential theft
- No password spraying
- No destructive automation
- No customer data in the public repo
- No compliance certification claim
- No cloud upload or AI provider requirement in the default local reporting workflow

## Quality gate

Before publishing changes or handing normalized output to another workflow, run
the public quality gate from the repository root:

```powershell
.\quality-gate.ps1 -Fast
```

For release-level validation, run the full gate:

```powershell
.\quality-gate.ps1
```

The gate runs public tests, performs a synthetic analyzer smoke test, validates
the generated `normalized-report.json` with strict safety checks, and checks git
status for generated or customer-like artifacts that should not be committed.

## Release and integrity links

- [Release history](CHANGELOG.md)
- [Release integrity documentation](docs/release-integrity.md)
- [Repository guardrails](AGENTS.md)

## Feedback wanted

- Are the AD account classifications useful?
- Is the backup readiness audit practical?
- Are the monthly KPI summaries useful for recurring reviews?
- Are findings too noisy or too conservative?
- What would make this more useful in a real infrastructure assessment?

## Public/private boundary

This repository is the public defensive infrastructure security engine. It is
intended for audit-first checks, deterministic local reporting, safe evidence
normalization, and defensive remediation workflows.

Customer-specific reporting, presentation, exception handling, pricing,
branding, and customer data belong outside this repository. Keep public examples
fictional and follow the repository guardrails in [AGENTS.md](AGENTS.md).

## Focus areas

- Infrastructure hardening
- PowerShell automation
- Linux administration
- Security auditing
- DevSecOps operations
- Monitoring and automation
- Enterprise operational scripting

## Technologies

- Windows Server
- Linux
- PowerShell
- Python
- Bash
- Docker
- Kubernetes

## Repository structure

```text
infrastructure-security-scripts/
|-- .github/workflows/          # CI checks for scripts
|-- SecureInfra_AI/             # AI-ready deterministic analysis and reporting layer
|-- docs/                       # Methodology, usage, integrity, KPI, and script references
|-- examples/                   # Fictional configuration and machine-readable sample outputs
|-- schemas/                    # JSON schemas for findings, reports, and remediation plans
|-- scripts/
|   |-- windows/                # Windows audit and hardening scripts
|   |-- linux/                  # Linux audit, hardening, and inventory scripts
|   |-- devsecops/              # Docker, Kubernetes, and secret scanning scripts
|   |-- monitoring/             # Service and disk monitoring scripts
|   |-- reporting/              # Markdown report generation helpers
|   `-- release/                # Public release bundle and integrity helpers
`-- tests/                      # Lightweight static checks and unit tests
```

## Safety model

Most scripts use one of these patterns:

- Audit mode by default
- Dry-run mode by default
- Explicit `--apply` or `-Apply` required before making changes
- Report files written under `reports/`
- Backups written under `backups/` when a script changes configuration

Review each script before running it in production. Test changes in a lab or staging environment first.

## Quick start

```bash
git clone https://github.com/mustapha-haouili/infrastructure-security-scripts.git
cd infrastructure-security-scripts
bash tests/run_static_checks.sh
```

Windows / PowerShell test check when Bash is not available:

```powershell
python -m unittest discover -s tests -p "test_*.py"
```

### Linux audit

```bash
sudo bash scripts/linux/linux-security-audit.sh -o reports
```

### Linux backup readiness audit

```bash
bash scripts/linux/backup-readiness-audit.sh --output-dir reports/backup --expected-backup-path /mnt/example-backups
```

### Linux hardening dry run

```bash
sudo bash scripts/linux/linux-hardening-baseline.sh
```

Apply selected baseline changes only after review:

```bash
sudo bash scripts/linux/linux-hardening-baseline.sh --apply
```

### Windows audit

Run PowerShell as Administrator:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\windows\Start-WindowsSecurity.ps1
```

Choose `Windows Host` from the menu, then select `Windows security audit`.

### Windows backup readiness audit

```powershell
.\scripts\windows\backup\Get-WindowsBackupReadinessAudit.ps1 -ExpectedBackupPaths "E:\ExampleBackups" -OutputDirectory .\reports\backup
```

### Client evidence collection

For client-side collection, run the safe bundle launcher. It runs supported
audit/dry-run checks, writes a structured result folder, and creates a zip file
the client can send back for analysis.

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\windows\Start-SecureInfraClientCollection.ps1
```

Run selected scopes only:

```powershell
.\scripts\windows\Start-SecureInfraClientCollection.ps1 -Scope AD,Host,Server
```

Collect only Group Policy evidence:

```powershell
.\scripts\windows\Start-SecureInfraClientCollection.ps1 -Scope GPO
```

Collect backup readiness explicitly:

```powershell
.\scripts\windows\Start-SecureInfraClientCollection.ps1 -Scope Backup -ExpectedBackupPaths "E:\ExampleBackups" -ExpectedBackupSoftware "Windows Server Backup"
```

The current collector supports AD, GPO, Windows host, server, workstation,
local network exposure, and backup readiness evidence. The broad `All` scope includes Backup readiness so the default client bundle is
complete. The broad `AD` scope still includes GPO health evidence for
compatibility, while `GPO` can be requested alone when only Group Policy
evidence is needed.

Analyze the full client collection folder or zip:

```powershell
python .\SecureInfra_AI\scripts\reporting\secureinfra_analyzer.py --input .\reports\secureinfra-client-collection-CLIENT-20260619-120000.zip --type client-bundle --output .\reports\secureinfra-ai-client
```

Client collection zip files are treated as untrusted input. SecureInfra AI
validates entries before extraction, rejects traversal or absolute paths,
limits archives to 512 entries, limits each uncompressed file to 25 MiB, and
accepts only current report-output extensions: `.json`, `.csv`, `.md`, `.txt`,
and `.log`. Bundle content is parsed as evidence only and is never executed.

Analyze many client bundles from many servers or workstations:

```powershell
python .\SecureInfra_AI\scripts\reporting\secureinfra_analyzer.py --input .\reports\client-bundles --type multi-bundle --output .\reports\secureinfra-ai-fleet
```

Put every returned collection folder or `.zip` file under one parent folder
such as `reports\client-bundles`. The fleet analyzer creates one normalized
report with machine inventory, per-host coverage, and unique finding IDs.

Optional shared Windows parameters:

```powershell
Copy-Item .\examples\windows-security.config.example.json .\windows-security.config.local.json
.\scripts\windows\Start-WindowsSecurity.ps1 -Group AD -RunAll -UseDefaults -ConfigPath .\windows-security.config.local.json
```

### Windows baseline dry run

```powershell
.\scripts\windows\Start-WindowsSecurity.ps1 -ToolId HOST-HARDENING
```

Apply baseline changes only after review:

```powershell
.\scripts\windows\Start-WindowsSecurity.ps1 -ToolId HOST-HARDENING
```

When prompted for parameters, enable `-Apply` only during an approved change
window.

### Secret scan before pushing code

```bash
python3 scripts/devsecops/secret-scan.py . --format text
```

### Release integrity bundle

Create a public release bundle with `SHA256SUMS.txt` and
`RELEASE-MANIFEST.json`:

```bash
bash scripts/release/create_release_bundle.sh --output-dir dist
```

PowerShell users can run:

```powershell
.\scripts\release\New-SecureInfraReleaseBundle.ps1 -OutputDirectory .\dist
```

See [docs/release-integrity.md](docs/release-integrity.md) for included files,
exclusions, verification commands, and optional signing guidance.

### Docker image audit

```bash
bash scripts/devsecops/docker-image-audit.sh nginx:latest
```

### Kubernetes RBAC audit

```bash
bash scripts/devsecops/kubernetes-rbac-audit.sh --output-dir reports
```

### Service health checks

```bash
python3 scripts/monitoring/service-health-check.py --config examples/services.example.json
```

### Markdown report generation

```bash
python3 scripts/reporting/generate-markdown-report.py examples/sample-output/windows/windows-host-audit.example.json --output reports/example-assessment.md
```

### SecureInfra AI analyzer

```bash
python3 SecureInfra_AI/scripts/reporting/secureinfra_analyzer.py --input SecureInfra_AI/examples/sample-input/active-directory/sample-ad-inactive-users.json --type ad-inactive-users --output SecureInfra_AI/reports
```

Full client bundle:

```bash
python3 SecureInfra_AI/scripts/reporting/secureinfra_analyzer.py --input reports/secureinfra-client-collection-CLIENT-20260619-120000.zip --type client-bundle --output reports/secureinfra-ai-client
```

Fleet of client bundles:

```bash
python3 SecureInfra_AI/scripts/reporting/secureinfra_analyzer.py --input reports/client-bundles --type multi-bundle --output reports/secureinfra-ai-fleet
```

Beta standalone Windows report analyzers:

```bash
python3 SecureInfra_AI/scripts/reporting/secureinfra_analyzer.py --input reports/windows-security-audit.json --type windows-host-audit --output reports/secureinfra-ai-host
python3 SecureInfra_AI/scripts/reporting/secureinfra_analyzer.py --input reports/windows-server-security.json --type windows-server-audit --output reports/secureinfra-ai-server
python3 SecureInfra_AI/scripts/reporting/secureinfra_analyzer.py --input reports/windows-workstation-security.json --type windows-workstation-audit --output reports/secureinfra-ai-workstation
python3 SecureInfra_AI/scripts/reporting/secureinfra_analyzer.py --input reports/windows-network-exposure.json --type windows-network-exposure --output reports/secureinfra-ai-network
```

These analyzer types are report-only and normalize existing JSON evidence from
the corresponding Windows audit scripts. The `windows-network-exposure`
normalizer adds deterministic port context for common listeners such as RDP,
SMB, HTTP, and WinRM. This context explains common service use, why the
listener may matter, what the customer should validate, and safe next steps
without claiming a port is exploitable or recommending automatic service
disablement.

Backup readiness analyzer:

```bash
python3 SecureInfra_AI/scripts/reporting/secureinfra_analyzer.py --input reports/backup/backup-readiness.json --type backup-readiness --output reports/secureinfra-ai-backup
```

Normalized SecureInfra AI reports can also include broad control-reference
metadata under `metadata.control_references_by_finding_id` and
`metadata.control_mapping_summary`. These deterministic mappings are
informational only and do not claim compliance, certification, audit
attestation, or official control coverage.

Use `--monthly-summary` with the SecureInfra AI analyzer to generate a
deterministic monthly KPI summary from normalized reports. See
[docs/monthly-kpi-methodology.md](docs/monthly-kpi-methodology.md)
for baseline and month-over-month examples.

### SecureInfra Dashboard

Open `SecureInfra_AI/dashboard/index.html` in a browser to review JSON reports
locally with severity metrics, filtering, evidence detail, and related-finding
links. Normalized reports generated with `--previous-normalized-report` also
show new, persistent, and resolved findings. Normalized `multi-bundle` reports
add machine filtering and fleet collection coverage.

The dashboard is a local static viewer. It uses a Content Security Policy and
renders report-controlled values as text, not executable HTML. The CSP allows
inline styles for compatibility with the current static UI, so keep using it as
a local report viewer for trusted operators rather than as a hosted multi-user
portal.

## Script index

See [docs/script-index.md](docs/script-index.md) for a complete list of scripts and their purpose.
See [docs/script-reference.md](docs/script-reference.md) for every script argument, output file, safety mode, and copy-ready examples.
See [SecureInfra_AI/README.md](SecureInfra_AI/README.md) for the AI-ready deterministic reporting layer.
See [docs/methodology.md](docs/methodology.md) for the audit-first assessment workflow.
See [docs/monthly-kpi-methodology.md](docs/monthly-kpi-methodology.md) for deterministic monthly trend reporting.
See [ROADMAP.md](ROADMAP.md) for planned Windows, Linux, container, Kubernetes, and cloud work.

Every script also has built-in help:

```bash
bash scripts/linux/linux-security-audit.sh --help
python3 scripts/devsecops/secret-scan.py --help
```

PowerShell scripts include comment-based help at the top of each file. If your
PowerShell session does not load script help with `Get-Help`, view the header
directly:

```powershell
Get-Content .\scripts\windows\Start-WindowsSecurity.ps1 -First 120
```


## Author

Mustapha Haouili

Infrastructure Security Architect

## Responsible use

These scripts are intended for systems you own or are authorized to administer. Do not run them against third-party environments without written permission.

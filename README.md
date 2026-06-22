# Infrastructure Security Scripts

A practical defensive infrastructure security toolkit for enterprise Windows, Linux, Active Directory, DevSecOps, monitoring, hardening, evidence collection, and local security reporting.

This repository is designed for defensive security operations, infrastructure administration, repeatable baseline checks, and audit-first infrastructure security assessments across enterprise environments.

It includes the SecureInfra_AI layer for deterministic, local, AI-ready analysis of infrastructure evidence. This layer can normalize security findings, generate JSON and Markdown reports, compare historical runs, analyze client bundles, review fleet evidence, and display reports in a local dashboard.

Current version: `1.2.0-beta.1`. See [CHANGELOG.md](CHANGELOG.md) and
[v1.2.0-beta.1 release notes](docs/releases/v1.2.0-beta.1.md) for the current beta release baseline.

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
|-- docs/                       # Methodology, usage notes, service model, and script index
|-- examples/                   # Example configuration, sample reports, and sample outputs
|-- schemas/                    # JSON schemas for findings, reports, and remediation plans
|-- scripts/
|   |-- windows/                # Windows audit and hardening scripts
|   |-- linux/                  # Linux audit, hardening, and inventory scripts
|   |-- devsecops/              # Docker, Kubernetes, and secret scanning scripts
|   |-- monitoring/             # Service and disk monitoring scripts
|   `-- reporting/              # Markdown report generation helpers
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

### Linux audit

```bash
sudo bash scripts/linux/linux-security-audit.sh -o reports
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

The current collector supports AD/GPO, Windows host, server, workstation, and
local network exposure evidence.

Analyze the full client collection folder or zip:

```powershell
python .\SecureInfra_AI\scripts\reporting\secureinfra_analyzer.py --input .\reports\secureinfra-client-collection-CLIENT-20260619-120000.zip --type client-bundle --output .\reports\secureinfra-ai-client
```

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
the corresponding Windows audit scripts.

### SecureInfra Dashboard

Open `SecureInfra_AI/dashboard/index.html` in a browser to review JSON reports
locally with severity metrics, filtering, evidence detail, and related-finding
links. Normalized reports generated with `--previous-normalized-report` also
show new, persistent, and resolved findings. Normalized `multi-bundle` reports
add machine filtering and fleet collection coverage.

## Script index

See [docs/script-index.md](docs/script-index.md) for a complete list of scripts and their purpose.
See [docs/script-reference.md](docs/script-reference.md) for every script argument, output file, safety mode, and copy-ready examples.
See [SecureInfra_AI/README.md](SecureInfra_AI/README.md) for the AI-ready deterministic reporting layer.
See [docs/methodology.md](docs/methodology.md) for the audit-first assessment workflow.
See [docs/service-model/secureinfra-check-overview.md](docs/service-model/secureinfra-check-overview.md) for the infrastructure health check model.
See [ROADMAP.md](ROADMAP.md) for planned toolkit improvements.
See [docs/windows-roadmap.md](docs/windows-roadmap.md) for the Windows AD, GPO, server, and workstation expansion plan.

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

## Recommended GitHub description

Enterprise infrastructure security scripts for Windows, Linux, DevSecOps, hardening, audit, monitoring, and automation.

## Suggested repository topics

```text
infrastructure-security windows-server linux powershell bash python devsecops hardening security-audit docker kubernetes automation cybersecurity
```

## Author

Mustapha Haouili

Infrastructure Security Architect

## Responsible use

These scripts are intended for systems you own or are authorized to administer. Do not run them against third-party environments without written permission.

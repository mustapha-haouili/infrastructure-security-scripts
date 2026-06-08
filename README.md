# Infrastructure Security Scripts

A practical collection of enterprise infrastructure security, automation, hardening, and DevSecOps scripts focused on Windows and Linux environments.

This repository is designed for defensive security operations, infrastructure administration, and repeatable baseline checks across enterprise environments.

Current version: `1.1.0`. See [CHANGELOG.md](CHANGELOG.md) and
[v1.1.0 release notes](docs/releases/v1.1.0.md) for the release baseline.

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

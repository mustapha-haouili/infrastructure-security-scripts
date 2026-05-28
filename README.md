# Infrastructure Security Scripts

A practical collection of enterprise infrastructure security, automation, hardening, and DevSecOps scripts focused on Windows and Linux environments.

This repository is designed for defensive security operations, infrastructure administration, and repeatable baseline checks across enterprise environments.

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
├── .github/workflows/          # CI checks for scripts
├── docs/                       # Usage notes and script index
├── examples/                   # Example configuration files
├── scripts/
│   ├── windows/                # Windows audit and hardening scripts
│   ├── linux/                  # Linux audit, hardening, and inventory scripts
│   ├── devsecops/              # Docker, Kubernetes, and secret scanning scripts
│   └── monitoring/             # Service and disk monitoring scripts
└── tests/                      # Lightweight static checks and unit tests
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
.\scripts\windows\Invoke-WindowsSecurityAudit.ps1 -IncludeHotfixes
```

### Windows baseline dry run

```powershell
.\scripts\windows\Set-WindowsBaselineHardening.ps1
```

Apply baseline changes only after review:

```powershell
.\scripts\windows\Set-WindowsBaselineHardening.ps1 -Apply
```

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

## Script index

See [docs/script-index.md](docs/script-index.md) for a complete list of scripts and their purpose.

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

# Script Index

## Windows

| Script | Purpose | Default mode |
|---|---|---|
| `Invoke-WindowsSecurityAudit.ps1` | Collect Windows baseline security information and export JSON | Audit |
| `Set-WindowsBaselineHardening.ps1` | Apply selected Windows baseline hardening controls | Dry run |
| `Export-WindowsEventSecurityReport.ps1` | Export important Windows Security and System event log activity | Audit |

## Linux

| Script | Purpose | Default mode |
|---|---|---|
| `linux-security-audit.sh` | Collect Linux security baseline information | Audit |
| `linux-hardening-baseline.sh` | Apply selected Linux baseline hardening controls | Dry run |
| `collect-linux-inventory.sh` | Export host inventory in JSON format | Audit |

## DevSecOps

| Script | Purpose | Default mode |
|---|---|---|
| `secret-scan.py` | Scan source code and configuration files for common secret patterns | Audit with failing exit code |
| `docker-image-audit.sh` | Inspect Docker image metadata and optional runtime characteristics | Audit |
| `kubernetes-rbac-audit.sh` | Review Kubernetes RBAC, privileged pods, host paths, and network policy coverage | Audit |

## Monitoring

| Script | Purpose | Default mode |
|---|---|---|
| `service-health-check.py` | Check HTTP and TCP service health from a JSON config file | Audit |
| `disk-space-monitor.sh` | Check filesystem usage and return a monitoring-friendly exit code | Audit |

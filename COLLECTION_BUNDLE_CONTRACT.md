# SecureInfra Collection Bundle Contract

This repository is the public defensive collector and analyzer layer. Collection bundles are the handoff format between platform-specific read-only collectors and `secureinfra_analyzer.py`.

A bundle is a ZIP archive or directory containing evidence collected from one asset, host, domain, cluster, or platform scope. The public analyzer can process one bundle or a directory of multiple bundles and emit `normalized-report.json`.

## Core principles

- Collection is read-only by default.
- Bundles contain evidence and summaries, not remediation actions.
- Missing evidence remains unknown; it must not be converted to false or zero.
- Listening on all interfaces is bind-scope evidence only; it is not proof of internet exposure.
- No customer secrets, non-public prompts, credentials, tokens, local workstation paths, or internal workflow paths belong in a bundle.
- Every collector script must be invoked by a platform launcher or explicitly documented as manual-only.

## Standard bundle layout

```text
secureinfra-<platform>-bundle-<asset>-<timestamp>/
  client-info.json
  collection-summary.json
  manifest.json
  bundle-manifest.json
  logs/
  linux/
  backup/
  host/
  server/
  workstation/
  network/
  ad-shared/
  docker/
  kubernetes/
```

Not every platform uses every directory. A Linux-only bundle, for example, normally contains `linux/`, `backup/`, and `logs/`.

## Required root metadata

### `client-info.json`

Describes the collected asset or platform.

Recommended fields:

```json
{
  "ComputerName": "linux-app01",
  "Platform": "Linux",
  "CollectorLauncher": "Start-SecureInfraLinuxCollection.sh",
  "GeneratedAtUtc": "2026-07-09T12:00:00Z"
}
```

### `collection-summary.json`

Summarizes the launcher run and collector statuses.

Recommended fields:

```json
{
  "CollectionId": "secureinfra-linux-bundle-linux-app01-20260709-120000",
  "GeneratedAtUtc": "2026-07-09T12:00:00Z",
  "SafetyMode": "Read-only collection. No remediation or configuration changes are applied by this launcher.",
  "ScopeResolved": ["Linux", "Backup"],
  "Collectors": [
    {"name": "linux-security-audit", "status": "completed", "output": "linux/linux-security-summary.json"}
  ]
}
```

### `manifest.json` and `bundle-manifest.json`

`manifest.json` is the primary analyzer metadata file. `bundle-manifest.json` is an alias used by human operators and external bundle tooling. When both exist, they should describe the same bundle.

## Linux evidence contract

Linux platform bundles should be produced by:

```bash
scripts/linux/Start-SecureInfraLinuxCollection.sh
```

Expected Linux files:

```text
linux/linux-security-summary.json
linux/linux-network-exposure-summary.json
linux/linux-log-audit-summary.json
linux/linux-service-inventory-summary.json
linux/linux-inventory.json
linux/linux-security-audit-<host>-<timestamp>.txt
linux/linux-hardening-plan-<host>-<timestamp>.log
backup/backup-readiness.json
backup/backup-readiness-findings.csv
logs/*.log
```

`linux/linux-security-summary.json`, `linux/linux-network-exposure-summary.json`, `linux/linux-log-audit-summary.json`, and `linux/linux-service-inventory-summary.json` are normalized inputs for Linux host findings. The network exposure file is local listener/firewall evidence only; it is not an active subnet scan. It should contain:

```json
{
  "host": "linux-app01",
  "generated_at_utc": "2026-07-09T12:00:00Z",
  "root_context": false,
  "quick_mode": true,
  "finding_counts": {"high": 1, "medium": 2, "info": 1},
  "findings": [
    {
      "id": "LINUX-SSH-001",
      "severity": "high",
      "title": "SSH root login is enabled",
      "recommendation": "Set PermitRootLogin no and use named administrative accounts with sudo.",
      "evidence": "PermitRootLogin=yes"
    }
  ]
}
```

The Linux normalizer currently supports findings in these families:

- `LINUX-AUDIT-*` for audit coverage limitations.
- `LINUX-IDENTITY-*` for local identity controls.
- `LINUX-SUDO-*` for sudoers and privilege configuration.
- `LINUX-SSH-*` for OpenSSH daemon settings.
- `LINUX-FIREWALL-*` for host firewall evidence.
- `LINUX-NETWORK-*` for listening service evidence.
- `LINUX-LOG-*` for logging and audit coverage.
- `LINUX-PACKAGE-*` for package and patch evidence.
- `LINUX-FILESYSTEM-*` for filesystem permissions.
- `LINUX-KERNEL-*` for sysctl and kernel hardening settings.

## Docker and Kubernetes planned contract

Docker and Kubernetes bundles should follow the same launcher pattern later:

```text
scripts/docker/Start-SecureInfraDockerCollection.sh
scripts/kubernetes/Start-SecureInfraKubernetesCollection.sh
```

Planned evidence folders:

```text
docker/docker-summary.json
docker/docker-containers.json
docker/docker-risk-findings.json
kubernetes/kubernetes-summary.json
kubernetes/kubernetes-rbac.json
kubernetes/kubernetes-workloads.json
kubernetes/kubernetes-risk-findings.json
```

Until Docker and Kubernetes normalizers are added, these folders are allowed by `validate_bundle.py` but are not converted into normalized findings.

## Validation sequence

For commercial delivery, the private repository should run:

```text
<folder-containing-bundles>
→ validate_bundle.py
→ secureinfra_analyzer.py --type multi-bundle
→ validate_schema.py
→ customer-specific reporting pipeline
```

For public-only testing:

```bash
python scripts/reporting/validate_bundle.py --input <bundle.zip> --strict-safety
python SecureInfra_AI/scripts/reporting/secureinfra_analyzer.py --input <bundle.zip> --type client-bundle --output <output-dir>
python scripts/reporting/validate_schema.py --input <output-dir> --strict-safety
```

## Safety restrictions

Bundle validation rejects:

- path traversal entries such as `../evil.json`;
- absolute paths such as `C:\...` or `/tmp/...`;
- unsupported file extensions;
- oversized members or archive bombs;
- obvious secret, credential, token, or private prompt paths in strict mode.

## Commit safety

Do not commit real customer bundles or generated report outputs. Use only safe synthetic fixtures for tests.

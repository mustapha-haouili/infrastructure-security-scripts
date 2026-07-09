# SecureInfra Linux Collectors

This directory contains Linux read-only collectors and the Linux platform launcher.

## Recommended launcher

Use the launcher instead of running each collector manually:

```bash
bash scripts/linux/Start-SecureInfraLinuxCollection.sh --quick
```

The launcher runs the available Linux collectors, writes a standard bundle layout, and creates a ZIP archive that can be copied to:

```text
downstream-reporting-workspace/customer-projects/<project>/03-input-bundles
```

Typical output:

```text
reports/secureinfra-linux/
  secureinfra-linux-bundle-<host>-<timestamp>/
    client-info.json
    collection-summary.json
    manifest.json
    bundle-manifest.json
    linux/
      linux-security-summary.json
      linux-network-exposure-summary.json
      linux-log-audit-summary.json
      linux-service-inventory-summary.json
      linux-inventory.json
      linux-security-audit-<host>-<timestamp>.txt
      linux-hardening-plan-<host>-<timestamp>.log
    backup/
      backup-readiness.json
      backup-readiness-findings.csv
    logs/
  secureinfra-linux-bundle-<host>-<timestamp>.zip
```

## Scope

The launcher is read-only. It does not apply remediation. `linux-hardening-baseline.sh` is called in its default dry-run mode only.

Linux evidence currently covers:

- local identity and UID 0 evidence;
- sudoers file permission evidence;
- SSH daemon configuration evidence;
- firewall coverage evidence;
- sysctl/kernel hardening evidence;
- listening TCP service evidence for common risky services;
- authentication log and auditd coverage evidence;
- package update/patch evidence from local metadata where safe;
- filesystem permission checks for sensitive paths;
- inventory metadata;
- backup readiness metadata.

## Useful commands

Quick collection:

```bash
bash scripts/linux/Start-SecureInfraLinuxCollection.sh --quick
```

Full collection with expected backup path metadata:

```bash
bash scripts/linux/Start-SecureInfraLinuxCollection.sh \
  --expected-backup-path /mnt/backups
```

Directory-only collection without ZIP:

```bash
bash scripts/linux/Start-SecureInfraLinuxCollection.sh --quick --skip-archive
```

Validate the generated ZIP from the public repo root:

```bash
python scripts/reporting/validate_bundle.py \
  --input reports/secureinfra-linux/<bundle>.zip \
  --strict-safety
```

Analyze the generated ZIP:

```bash
python SecureInfra_AI/scripts/reporting/secureinfra_analyzer.py \
  --input reports/secureinfra-linux/<bundle>.zip \
  --type client-bundle \
  --output reports/secureinfra-linux-output

python scripts/reporting/validate_schema.py \
  --input reports/secureinfra-linux-output \
  --strict-safety
```


## Local network and log coverage

`Start-SecureInfraLinuxCollection.sh` also runs `linux-network-exposure-audit.sh`, `linux-log-audit.sh`, and `linux-service-inventory-audit.sh` by default. The network collector inventories local listening sockets, bind scope, service names, process names where available, and host firewall evidence. It does not run active network scans. The log collector packages counts and coverage metadata only, not raw authentication log lines. The service inventory collector records local service/startup metadata and does not change service state.

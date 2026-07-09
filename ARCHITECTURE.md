# Public Repository Architecture

## Purpose

This document describes the architecture of the public SecureInfra defensive collector/analyzer repository.

## High-level architecture

```text
Collectors / source scripts
        |
        v
Input bundles / JSON / CSV / Markdown evidence
        |
        v
SecureInfra analyzer entrypoint
        |
        v
Bundle discovery and safe loaders
        |
        v
Normalizers
        |
        v
Risk rules and public-safe context
        |
        v
Control mapping and technical correlations
        |
        v
normalized-report.json
```

## Main components

### Collectors

Collectors gather defensive evidence from systems and write local files. They should be read-only unless explicitly documented as dry-run/preview tools. They must not contain destructive remediation or exploitation behavior.

Collector families include:

- Active Directory evidence collectors,
- Windows host baseline collectors,
- Windows server inventory collectors,
- Windows workstation inventory collectors,
- Windows network exposure collectors,
- Group Policy health collectors,
- backup readiness collectors,
- Linux standalone audit scripts,
- DevSecOps standalone audit scripts,
- monitoring standalone helpers.

### Collector orchestration

`Start-SecureInfraClientCollection.ps1` orchestrates client collection scopes and creates structured bundle output. Scope handling must remain explicit and predictable. The broad `All` scope includes Backup readiness so default client bundles contain backup/recovery evidence; explicit scopes such as `Backup` and `GPO` remain available for targeted collection.

### Analyzer

`SecureInfra_AI/scripts/reporting/secureinfra_analyzer.py` is the public analyzer entrypoint. It discovers input type, loads bundle files, normalizes findings, attaches public-safe risk context and control mapping, and writes normalized reports.

### Bundle helpers

Bundle helpers identify supported report bundles and consolidate source files. They should not embed customer-specific assumptions.

### Loaders

Loaders read JSON and CSV safely. They should preserve unknown/missing values and avoid inventing evidence.

### Normalizers

Normalizers translate source evidence into a stable normalized finding contract. They are responsible for evidence-driven interpretation only.

Normalizers must not:

- infer missing evidence as false,
- convert unknown numeric values to zero,
- infer Internet exposure from listen state alone,
- infer network ports from control IDs,
- apply private customer approved exceptions,
- generate final commercial report language.

### Risk rules

Risk rules classify technical risk conservatively. They should be deterministic and public-safe.

### Network context

Network context may map known ports to common service names, for example:

- TCP 135: RPC Endpoint Mapper
- TCP 139: NetBIOS Session Service
- TCP 445: SMB / Server Message Block
- TCP 3389: RDP
- TCP 5985: WinRM over HTTP
- TCP 5986: WinRM over HTTPS

Network context must not claim Internet reachability unless explicit evidence exists.

### Correlation

Public correlation can identify technical relationships across normalized findings. Customer-facing grouping and management-level consolidation belong in the private commercial repository.

### Control mapping

Control mapping is broad and deterministic. It must not claim formal audit attestation, certification, or official compliance coverage.

## Output boundary

The primary public output is `normalized-report.json`. Private commercial rendering starts after this boundary.

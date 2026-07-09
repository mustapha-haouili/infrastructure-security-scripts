# Public Data Contract

## Purpose

This document defines the public data contract for SecureInfra collector and analyzer outputs.

## Input bundle contract

The public analyzer may consume bundles containing JSON, CSV, and Markdown evidence from supported collectors. Input bundles may originate from customer environments, but real customer bundles must not be committed to this public repository.

Supported evidence families include:

- Active Directory security,
- Windows host baseline,
- Windows server inventory,
- Windows workstation inventory,
- Windows network exposure,
- Group Policy health,
- backup/recovery readiness,
- Linux host audit scripts; `linux/linux-security-summary.json`, `linux/linux-network-exposure-summary.json`, `linux/linux-log-audit-summary.json`, `linux/linux-service-inventory-summary.json`, and generated `*.summary.json` variants are normalized when present,
- DevSecOps helper scripts where supported,
- monitoring helper scripts where supported.

For detailed bundle layout rules, see `COLLECTION_BUNDLE_CONTRACT.md`.

## Input bundle validation

Use `scripts\reporting\validate_bundle.py` to preflight ZIP archives or
expanded collection folders before analyzer import:

```powershell
python .\scripts\reporting\validate_bundle.py --input <bundle.zip-or-folder> --strict-safety
python .\scripts\reporting\validate_bundle.py --input <multi-bundle-folder> --expected-bundle-count <n> --strict-safety
```

The validator checks archive readability, path traversal/absolute path safety,
allowed file extensions, conservative size limits, recognizable SecureInfra
bundle structure, basic JSON readability, and optional strict filename/path
safety. It recognizes supported evidence folders such as `linux/` for Linux
security audit summaries, `backup/` for Linux/Windows backup readiness, and
planned `docker/` and `kubernetes/` folders. It does not execute bundle content.

## Output contract

The public analyzer output contract is `normalized-report.json` and related normalized public analysis files.

The normalized output should include:

- schema/version metadata,
- source/input metadata safe for public processing,
- normalized findings,
- evidence summaries,
- categories,
- severity or technical severity where supported,
- source script references,
- source host/asset fields where available,
- public-safe risk context,
- optional monthly summary or trend data,
- optional technical correlation metadata,
- optional broad control mappings.

## Evidence rules

Evidence must remain evidence-driven.

- Missing evidence remains missing or unknown.
- Unknown values remain unknown.
- Missing boolean values must not become false by default.
- Missing numeric values must not become zero by default.
- Derived fields should identify their derivation source where appropriate.

## Network evidence rules

Listening on all interfaces means bind scope. It does not prove external or Internet reachability. Actual reachability depends on firewall rules, routing, segmentation, and allowed source networks.

Valid network port values should come from:

- explicit `evidence.port`,
- explicit text such as `TCP 3389`,
- a reliable service evidence mapping.

Do not infer ports from control IDs such as `WIN-SMB-001`, `WIN-SMB-002`, or `WIN-RDP-002`.

## Commercial boundary

The public data contract ends at normalized technical output. Commercial fields such as customer-facing report status, approved exceptions, grouping for management presentation, and final report wording belong in `downstream-reporting-workspace`.

## Public contract validation

`normalized-report.json` should be validated before it is treated as a stable
public analyzer output:

```powershell
python .\scripts\reporting\validate_schema.py --input <output-dir-or-normalized-report.json>
```

Use `--strict-safety` for release or handoff scenarios where private/commercial
paths and private prompt markers must be rejected before downstream import.


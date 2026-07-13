# Public Data Contract

## Purpose

This document defines the human-readable public contract for collection bundles
and normalized analyzer output. The JSON schemas under `SecureInfra_AI/schemas/`
are the machine-readable source of truth.

## Input bundle contract

The analyzer may consume ZIP archives or expanded directories containing JSON,
CSV, text, and Markdown evidence from supported collectors. Real environment
bundles must not be committed to this repository.

Supported evidence families include:

- Active Directory and Group Policy;
- Windows host, server, workstation, network, and backup readiness;
- Linux security, network, logging, service inventory, host inventory, and
  backup readiness;
- supported monitoring or DevSecOps helpers.

Detailed layout rules are defined in
[COLLECTION_BUNDLE_CONTRACT.md](COLLECTION_BUNDLE_CONTRACT.md).

## Input validation

Validate a bundle before analyzer import:

```powershell
python .\scripts\reporting\validate_bundle.py --input <bundle.zip-or-folder> --strict-safety
python .\scripts\reporting\validate_bundle.py --input <folder-containing-bundles> --expected-bundle-count <n> --strict-safety
```

The validator checks archive readability, path traversal, absolute paths,
allowed extensions, conservative size and file-count limits, recognizable
bundle structure, JSON readability, and strict filename/path safety. It does not
execute bundle content.

## Normalized report contract

The primary analyzer output is `normalized-report.json`. A normalized report
contains version metadata, source metadata, findings, evidence summaries,
categories, technical severity, source references, optional trend data,
technical correlations, and broad control mappings where supported.

A normalized finding should provide stable fields for:

```json
{
  "finding_id": "...",
  "finding_type": "...",
  "category": "...",
  "severity": "...",
  "asset": {},
  "target": {},
  "evidence": {},
  "risk": {},
  "workflow": {},
  "extensions": {}
}
```

Domain-specific data belongs under documented extension objects rather than in
ad-hoc top-level fields.

## Evidence rules

- Missing evidence remains missing or unknown.
- Unknown values remain unknown.
- Missing booleans must not become `false` by default.
- Missing numbers must not become `0` by default.
- Derived fields should identify their source or derivation where practical.
- Findings must preserve stable identifiers and source references.

## Network evidence rules

Listening on all interfaces describes bind scope. It does not prove external or
Internet reachability. Reachability depends on firewall rules, routing,
segmentation, allowed sources, and other explicit evidence.

Port values must come from explicit evidence such as `evidence.port`, explicit
text such as `TCP 3389`, or a reliable service-evidence mapping. Do not infer
ports from control identifiers.

## Severity and workflow

Technical severity uses exactly `Critical`, `High`, `Medium`, `Low`, or `Info`.
Workflow and review fields are separate. `Hold` is valid for fields such as
`status` or `remediation_priority`, but it is not valid technical severity.

Legacy source reports may use labels such as `Informational` or may place `Hold`
in a review-priority field. Normalizers map `Informational` to `Info` and preserve
a source `Hold` as `severity: Info` plus an explicit Hold workflow state.

## Output boundary

This contract ends at normalized technical evidence and findings. Downstream
customer-specific presentation, exception handling, ownership, packaging, and
delivery fields are outside the public contract.

## Schema validation

Validate analyzer output with:

```powershell
python .\scripts\reporting\validate_schema.py --input <output-directory-or-normalized-report.json>
```

For release or handoff validation, enable strict safety checks:

```powershell
python .\scripts\reporting\validate_schema.py --input <output-directory-or-normalized-report.json> --strict-safety
```

Strict safety validation rejects local workstation paths, customer-project
folder markers, private prompt labels, and environment-file paths. It is a
public output safety check, not a replacement for downstream validation.

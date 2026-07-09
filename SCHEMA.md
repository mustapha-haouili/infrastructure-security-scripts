# Public Normalized Schema

## Purpose

This document describes the intended public normalized schema strategy for SecureInfra analyzer output.

## Primary schema concept

The public schema should support current and future infrastructure findings without becoming tied to a single technology domain.

A stable normalized finding should support this conceptual structure:

```json
{
  "schema_version": "...",
  "finding_id": "...",
  "finding_type": "...",
  "category": "...",
  "severity": "...",
  "asset": {},
  "target": {},
  "evidence": {},
  "risk": {},
  "workflow": {},
  "extensions": {
    "ad": {},
    "windows": {},
    "linux": {},
    "cloud": {},
    "network": {},
    "backup": {}
  }
}
```

## Current supported domains

The schema should cover current normalized findings for:

- Active Directory security,
- Host Security Baseline,
- Server Security Inventory,
- Workstation Security Inventory,
- Network Exposure,
- Group Policy Health,
- Backup / Recovery readiness,
- Windows configuration findings.

## Planned domains

The schema should be able to extend to:

- Linux SSH/sudoers/filesystem/listening services,
- Cloud identity findings,
- AWS/Azure/GCP resource findings,
- container/Kubernetes findings if needed later.

## Severity rules

The public schema may expose technical severity, but commercial report status and workflow interpretation belong in the private commercial repository.

Allowed severity values should remain predictable and validated:

- `Critical`
- `High`
- `Medium`
- `Low`
- `Info`

## Evidence confidence

When evidence is incomplete, represent uncertainty explicitly. Do not silently convert unknown values into false, zero, or safe states.

## Network schema rules

Network findings should distinguish:

- listening state,
- local bind address,
- firewall rule context,
- routing/segmentation evidence if available,
- allowed source networks if available,
- explicit external reachability evidence if available.

Do not claim Internet exposure without explicit evidence.

## Unquoted service path rule

A finding should be flagged as UnquotedServicePath only when:

- executable path contains spaces,
- path is not quoted,
- path points to a real executable,
- it is not a normal `svchost.exe` command such as `svchost.exe -k netsvcs -p` or `C:\Windows\System32\svchost.exe -k netsvcs -p`.

## Schema validation expectation

The public repository should include or evolve toward a `validate_schema.py` or equivalent schema validation command that can validate synthetic fixtures and analyzer outputs against the public normalized contract.

## Schema validation command

Use the repository-local validator to check analyzer output before handing a
`normalized-report.json` file to downstream tooling:

```powershell
python .\scripts\reporting\validate_schema.py --input .\SecureInfra_AI\reports\normalized-report.json
```

The command accepts either the report file itself or a directory containing
`normalized-report.json`.

For release or handoff validation, enable strict safety checks:

```powershell
python .\scripts\reporting\validate_schema.py --input .\SecureInfra_AI\reports --strict-safety
```

Strict safety validation fails if the normalized report contains private
commercial repository markers, customer-project folders, private prompt labels,
`.env` paths, or local Windows drive paths. This does not replace private
commercial deliverable validation; it is the public output contract check before
commercial import.


# Public Repository Testing Strategy

## Purpose

This document defines testing expectations for the public SecureInfra defensive collector/analyzer repository.

## Primary test command

Run from repository root:

```powershell
cd <local-workspace>\infrastructure-security-scripts
python -m unittest discover -s tests -p "test_*.py"
```

On Unix-like systems, static shell checks may also be run where supported:

```bash
./tests/run_static_checks.sh
```

## Test scope

Public tests should cover:

- collector launch behavior,
- bundle discovery,
- input bundle preflight validation,
- JSON/CSV loading,
- AD normalizers,
- Windows normalizers,
- backup readiness normalizer,
- Linux collection launcher contract,
- Linux security audit normalizer,
- network exposure context,
- risk rule behavior,
- control mapping,
- monthly KPI summaries,
- release bundle metadata,
- secret scanning,
- public/private boundary safety.

## Required negative tests

Tests should confirm the analyzer does not:

- infer ports from control IDs,
- claim Internet exposure from listen state alone,
- convert unknown/missing evidence to false or zero,
- flag normal `svchost.exe` service commands as UnquotedServicePath,
- generate fake network group names such as `NETWORK-TCP-1` or `NETWORK-TCP-2`,
- include customer-project paths or private commercial logic.

## Fixture strategy

Use safe synthetic fixtures only. Fixtures should cover:

- AD inactive users,
- AD password never expires,
- AD service account audit,
- AD SPN exposure,
- AD privileged identity,
- AD stale computers,
- Windows host baseline,
- Windows server inventory,
- Windows workstation inventory,
- Windows network exposure,
- Group Policy health,
- backup readiness,
- Linux launcher bundle examples,
- Linux audit examples and planned cloud/container examples.

## Quality gate expectation

The public repository includes `quality-gate.ps1`. It should run:

- unit tests,
- schema validation,
- fixture analyzer runs,
- leak scan for private paths in generated normalized output,
- release packaging checks where applicable,
- static script checks where possible.

## Before/after expectations

For every change, provide:

- focused scope,
- tests run,
- before/after sample where relevant,
- `git diff --stat`,
- no commit unless explicitly requested,
- no push unless explicitly requested.

## Input bundle validation

Before running the analyzer on client ZIPs or expanded collection folders, use:

```powershell
python .\scripts\reporting\validate_bundle.py --input <bundle.zip-or-folder> --strict-safety
```

For a folder containing multiple returned customer bundles, use:

```powershell
python .\scripts\reporting\validate_bundle.py --input <bundle-folder> --expected-bundle-count <n> --strict-safety
```

The public quality gate includes `tests.test_validate_bundle` and a bundle
validation smoke test so `validate_bundle.py` is not an orphan script.

## Normalized schema validation

After generating a public analyzer output, validate the public contract with:

```powershell
python .\scripts\reporting\validate_schema.py --input .\SecureInfra_AI\reports\normalized-report.json
```

For release-quality checks or before passing output into the private commercial
repo, include strict safety scanning:

```powershell
python .\scripts\reporting\validate_schema.py --input .\SecureInfra_AI\reports --strict-safety
```

The validator performs dependency-free JSON schema validation and focused
contract checks, including unique finding IDs, evidence contract fields, summary
count consistency, and optional private path leakage detection.


## Public quality gate

Run the repository quality gate before publishing, handing off normalized output,
or asking the private commercial repository to consume public analyzer results.

Fast development check:

```powershell
.\quality-gate.ps1 -Fast
```

Full public check:

```powershell
.\quality-gate.ps1
```

The gate verifies key script integration contracts, runs public tests, runs an
input bundle validation smoke test, generates a synthetic sample
`normalized-report.json`, validates it with
`scripts\reporting\validate_schema.py --strict-safety`, and checks git status
for generated or customer-like artifacts that should not be committed.

If a new production script is added, the quality gate or tests must prove that
it is either called automatically or documented as manual-only.


## Linux coverage checks

Linux tests must cover the launcher, `linux-security-audit.sh`, `linux-network-exposure-audit.sh`, `linux-log-audit.sh`, `linux-service-inventory-audit.sh`, `linux-service-inventory-audit.sh`, bundle validation, and client-bundle normalization for all Linux summary JSON files.

## Collector coverage matrix

Windows and Linux collectors are tracked in `COLLECTOR_COVERAGE_MATRIX.md`. The test `tests/test_collector_coverage_matrix.py` fails if a Windows/Linux collector script is not documented or if an automated collector is no longer invoked by its platform launcher. This prevents orphan collector scripts and protects the rule that every new script must be automatically invoked or explicitly documented as manual-only.


# Multi-Bundle Fleet Analysis

`multi-bundle` analysis combines many SecureInfra client collection bundles into
one normalized fleet report. Use it when a client sends evidence from many
servers, workstations, or collection hosts.

## Input Layout

Place returned collection folders and zip archives under one parent directory:

```text
reports/client-bundles/
  secureinfra-client-collection-DC01-20260619-120000.zip
  secureinfra-client-collection-FS01-20260619-121500/
  secureinfra-client-collection-WS01-20260619-123000.zip
```

The analyzer discovers:

- `.zip` files below the input directory
- collection folders with `manifest.json`, `client-info.json`, or
  `collection-summary.json`
- collection folders that contain `ad-shared/`

## Command

```bash
python3 SecureInfra_AI/scripts/reporting/secureinfra_analyzer.py \
  --input reports/client-bundles \
  --type multi-bundle \
  --output reports/secureinfra-ai-fleet
```

## Output

The output folder contains:

- `normalized-report.json`
- `executive-summary.md`
- `technical-findings.md`
- `remediation-plan.md`

The normalized report includes:

- `summary.scope_finding_counts` for AD, Host, Server, Workstation, and Network
- `summary.machine_finding_counts`
- `summary.top_risky_machines`
- `report_type_metadata.machine_inventory`
- `report_type_metadata.coverage_matrix`
- `report_type_metadata.skipped_bundles`
- `report_type_metadata.failed_bundles`

Each finding keeps the original source finding ID in
`evidence.original_finding_id`. The fleet finding ID is prefixed with the
machine identifier so repeated IDs from different hosts do not collide.

## Dashboard

Open `SecureInfra_AI/dashboard/index.html` and load the fleet
`normalized-report.json`. The dashboard shows:

- machine filter
- per-scope fleet coverage
- top machine cards
- missing or failed collection items per host
- normal severity, source, object type, and status filters

## Collection Guidance

For clean fleet counts, collect AD/GPO evidence once per domain and collect
Host, Server, Workstation, or Network evidence per machine. If the same AD
bundle is included in many host bundles, the fleet analyzer preserves the
evidence but AD findings can appear once per bundle.

If the input folder contains both a collection zip and its extracted folder, the
analyzer skips the duplicate collection ID so findings are not counted twice.

This analysis is report-only. Missing or failed bundles do not stop analysis of
other bundles. Remediation still requires human owner review and approved
change control.

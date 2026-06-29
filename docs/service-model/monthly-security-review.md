# Monthly Security Review

The monthly security review workflow uses existing SecureInfra AI
`normalized-report.json` files to show repeatable improvement trends. It is
deterministic, local/offline, and does not require AI, external services, paid
tools, private templates, customer data, pricing, or branding.

This workflow does not claim compliance, certification, audit attestation, or
official audit status. The KPI values are operational trend indicators for
defensive review.

## Workflow

1. Run the normal SecureInfra collection and analyzer workflow for the current
   month.
2. Keep the prior month's `normalized-report.json` if month-over-month trend
   reporting is needed.
3. Run the analyzer with `--monthly-summary`.
4. Review `normalized-report.json`, `executive-summary.md`, and
   `monthly-kpi-summary.md`.

Baseline monthly summary without a previous report:

```bash
python3 SecureInfra_AI/scripts/reporting/secureinfra_analyzer.py \
  --input reports/ad-shared \
  --type ad-shared \
  --output reports/monthly-current \
  --monthly-summary
```

Month-over-month summary with a previous normalized report:

```bash
python3 SecureInfra_AI/scripts/reporting/secureinfra_analyzer.py \
  --input reports/ad-shared \
  --type ad-shared \
  --output reports/monthly-current \
  --previous-normalized-report reports/monthly-previous/normalized-report.json \
  --monthly-summary
```

## KPI Fields

The analyzer adds `monthly_kpi_summary` to the normalized report when
`--monthly-summary` is used. It includes:

- Current finding totals by severity.
- New, persistent, and resolved findings.
- A simple risk reduction score.
- Top current risks and recommended actions.
- Coverage grouped by source script, report type, analyzer type, and source
  host when available.
- Evidence gaps and limitations.

## Matching Logic

Trend matching is deterministic:

- Findings are matched by stable `finding_id` first.
- If IDs changed, the analyzer uses a conservative fallback fingerprint built
  from category, title, affected object, and source script/type.
- Fallback matches are used only when unique. Ambiguous fingerprints are not
  overmatched and are listed as limitations.

## Risk Reduction Score

The risk reduction score is intentionally simple:

- Resolved Critical and High findings add points.
- New Critical and High findings subtract points.
- Persistent Critical and High findings subtract smaller points.

The score is not a formal risk score. It helps reviewers discuss whether the
current month shows improvement pressure, new high-severity work, or persistent
high-severity backlog.

## Review Questions

- Which Critical or High findings were resolved since the last monthly report?
- Which Critical or High findings are new?
- Which risks stayed open and need owner decisions?
- Are any source scripts, hosts, scopes, or evidence files missing?
- What small set of owner-approved actions should be prioritized next month?

## Limitations

- Results depend on the supplied normalized reports and their coverage.
- A baseline summary without a previous report cannot show trend movement.
- Fallback matching is conservative and should be reviewed when used.
- The summary is operational guidance, not a compliance, certification, or
  audit-attestation result.

# SecureInfra Dashboard

The dashboard is a local, static report viewer for SecureInfra JSON output. It
runs fully in the browser and does not upload report data.

Open `index.html` in a browser, then select a report folder or one or more JSON
files. The dashboard reads normalized SecureInfra AI reports and common source
JSON outputs, then shows severity metrics, source inventory, findings, evidence,
recommendations, safety notes, related findings, scope filters, collection
coverage, machine filters, and historical comparison counts when available.

When a normalized report includes a top-level `correlations` array, the
dashboard uses those official analyzer-generated links first. For raw source
JSON, it falls back to local in-browser relationship inference.

When a normalized report includes a top-level `history_comparison` object, the
dashboard shows new, persistent, and resolved finding counts and marks current
findings as `New` or `Persistent`.

When a normalized `client-bundle` report includes coverage metadata, the
dashboard shows loaded files, missing scope files, failed files, per-scope
finding counts for AD, Host, Server, Workstation, and Network, and a collection
quality status of `Complete`, `Partial`, `Failed`, or `Needs rerun`.

When a normalized `multi-bundle` report includes fleet metadata, the dashboard
shows per-scope fleet coverage, machine cards, host-level quality status, and a
machine filter so large server and workstation collections remain readable.

Supported inputs include:

- `normalized-report.json`
- normalized `client-bundle` reports generated from a SecureInfra client
  collection folder or zip
- normalized `multi-bundle` reports generated from a folder containing many
  client collection folders or zip files
- AD shared source JSON files such as `inactive-users.json`,
  `service-accounts.json`, `spn-exposure.json`, `privileged-groups.json`,
  `privileged-identity-protection.json`, and `gpo-health.json`
- Any JSON file with a top-level `Findings` or `findings` array

This dashboard is read-only. Remediation still requires human owner review and
approved change control.

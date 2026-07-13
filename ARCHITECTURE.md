# Public Repository Architecture

## Purpose

This document describes the architecture of the public defensive collector and
analyzer repository.

## High-level architecture

```text
Collectors and source scripts
        |
        v
Local evidence files and collection bundles
        |
        v
Bundle validation and safe loaders
        |
        v
Public analyzer entrypoint
        |
        v
Normalizers and conservative risk rules
        |
        v
Technical correlations and broad control mappings
        |
        v
Schema validation and report generation
        |
        v
normalized-report.json
```

## Main components

### Collectors

Collectors gather authorized defensive evidence and write local files. They are
read-only unless explicitly documented as dry-run or preview tools. Production
collection must not include exploitation or destructive remediation behavior.

Current collector families include:

- Active Directory and Group Policy evidence;
- Windows host, server, workstation, network, and backup evidence;
- Linux inventory, security, network, logging, service, and backup evidence;
- standalone monitoring and DevSecOps helpers.

### Platform launchers

Tracked launchers orchestrate supported collectors and create predictable bundle
layouts. Scope handling must remain explicit. Any collector that is not invoked
by a launcher must be documented as manual-only.

### Bundle validation and loaders

Bundle validation rejects unsafe paths, unsupported file types, excessive file
sizes or counts, malformed JSON, and unrecognized layouts. Loaders parse bundle
content as data only and preserve missing or unknown values.

### Analyzer

`SecureInfra_AI/scripts/reporting/secureinfra_analyzer.py` is the primary public
analyzer entrypoint. It discovers supported input types, loads evidence,
normalizes findings, attaches public-safe technical context, validates the
result, and writes normalized outputs.

The analyzer pipeline is deterministic:

```text
validated input
  -> report-type loader
  -> normalizer
  -> conservative risk classification
  -> technical correlation and control mapping
  -> optional history comparison and monthly KPI summary
  -> JSON Schema validation
  -> normalized-report.json and optional Markdown reports
```

Language-generation interfaces are not part of the risk-decision path. Any
future language assistance must remain evidence-grounded and human-reviewed.

### Normalizers

Normalizers translate source evidence into a stable finding contract. They must
not:

- infer missing evidence as false;
- convert unknown numeric values to zero;
- infer Internet exposure from listening state alone;
- infer ports from control identifiers;
- apply customer-specific exceptions or presentation rules;
- generate unsupported business-impact claims.

Technical severity uses `Critical`, `High`, `Medium`, `Low`, or `Info`. Workflow
states such as `Hold` are represented separately and must not be stored as
severity.

### Risk rules and network context

Risk rules are deterministic and conservative. Network context may map explicit
ports to common service names, but reachability claims require firewall,
routing, segmentation, allowed-source, or other explicit evidence.

### Correlation

Public correlation may identify technical relationships across evidence sources.
It must preserve source finding identifiers, source scripts, evidence, and
technical severity. Correlation is a review aid and does not authorize
remediation.

### History and monthly summaries

Optional history comparison matches stable finding identifiers and reports new,
persistent, and resolved findings. Monthly KPI output is a deterministic trend
aid, not a formal risk score or compliance result.

### Schema validation

Machine-readable JSON Schemas under `schemas/` and `SecureInfra_AI/schemas/`
are the executable contract. `DATA_CONTRACT.md` explains the same contract for
human reviewers. Validators must fail closed on unsupported severities,
duplicate identifiers, malformed evidence, and unsafe path leakage.

### Control mapping

Control mappings are broad defensive references. They do not assert formal
compliance, certification, or audit attestation.

## Output boundary

The primary public output is `normalized-report.json`. Downstream tools may
consume this normalized output, but customer-specific interpretation,
exceptions, packaging, and delivery workflows are outside this repository.

See also:

- [DATA_CONTRACT.md](DATA_CONTRACT.md)
- [COLLECTION_BUNDLE_CONTRACT.md](COLLECTION_BUNDLE_CONTRACT.md)
- [docs/methodology.md](docs/methodology.md)
- [AGENTS.md](AGENTS.md)

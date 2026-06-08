# Sample GPO Health Report

Company: Example GmbH  
Domain: `example.local`  
Assessment date: 2026-06-07

All policies, links, and values in this sample report are fictional.

## Executive Summary

The Group Policy review identified stale policies, unlinked policies, disabled
links, and possible legacy references. These items should be reviewed for
cleanup and modernization, but none should be deleted without backup and owner
approval.

## Scope

- 42 Group Policy Objects.
- Domain and OU direct links.
- Stale threshold: 365 days since last modification.
- WMI filter and security filter visibility.

## Key Findings

| Finding | Count | Risk level | Priority |
|---|---:|---|---|
| Stale GPOs older than 365 days | 8 | Medium | P2 |
| Unlinked GPOs | 5 | Low | P3 |
| Disabled GPO links | 4 | Low | P3 |
| Possible legacy policy references | 3 | Medium | P2 |
| AD/SYSVOL version mismatch | 1 | High | P1 |

## Risk Level

Overall risk level: Medium.

The highest-priority item is the version mismatch because it can indicate
replication or policy consistency problems.

## Operational Impact

GPO changes can affect authentication, endpoint configuration, browser settings,
scripting behavior, update behavior, and administrative access. Cleanup should
be staged and tested with pilot OUs.

## Suggested Remediation

- Investigate the AD/SYSVOL version mismatch first.
- Export and back up GPOs before cleanup.
- Confirm owners for stale and unlinked policies.
- Review legacy references for modernization.
- Pilot link or policy changes before broad rollout.

## Priority

Priority: P1 for version mismatch investigation. P2 for stale and legacy policy
review. P3 for unlinked or disabled cleanup after backup and owner approval.

## Notes for IT Administrators

A stale or unlinked GPO may still be kept for rollback, audit history, or future
use. Treat findings as review prompts, not automatic delete instructions.

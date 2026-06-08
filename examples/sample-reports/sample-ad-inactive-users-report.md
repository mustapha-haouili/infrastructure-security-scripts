# Sample AD Inactive Users Report

Company: Example GmbH  
Domain: `example.local`  
Assessment date: 2026-06-07  
Inactive threshold: 90 days

All users and values in this sample report are fictional.

## Executive Summary

The inactive user review found 18 enabled accounts that have not logged on for
at least 90 days. Four accounts should be reviewed first because they have group
memberships or lifecycle signals that could create risk if ignored or changed
without validation.

## Scope

- Enabled user accounts in `example.local`.
- Disabled accounts excluded.
- Never-logged-on accounts included for review.
- Privileged group membership signals reviewed.

## Key Findings

| User | Last logon age | Risk level | Priority | Suggested action |
|---|---:|---|---|---|
| `EXAMPLE\julia.reed` | 184 days | High | P1 | Confirm owner and disable after approval. |
| `EXAMPLE\temp.project01` | Never | High | P1 | Validate project status and remove if unused. |
| `EXAMPLE\svc-reporting-old` | 147 days | Medium | P2 | Confirm service dependency before change. |
| `EXAMPLE\mark.sommer` | 123 days | Medium | P2 | Confirm employment status with HR process owner. |
| `EXAMPLE\training-user07` | 116 days | Low | P3 | Review for cleanup during next maintenance cycle. |

## Risk Level

Overall risk level: High.

Inactive enabled accounts increase exposure because unused credentials can
remain available after role changes, project closure, or employee departure.

## Operational Impact

Disabling accounts can affect scheduled tasks, service access, delegated
administration, mailbox access, or application integrations. Service-like
accounts require dependency review before any change.

## Suggested Remediation

- Review high-priority accounts with HR, application, and system owners.
- Disable confirmed unused human accounts before deletion.
- Move confirmed cleanup candidates to a quarantine OU where appropriate.
- Monitor for access failures during the quarantine period.
- Delete only after approval and rollback planning are complete.

## Priority

Priority: P1 for high-risk inactive enabled accounts, P2 for accounts with
service or group dependency signals, P3 for low-risk cleanup candidates.

## Notes for IT Administrators

Use the Markdown report for review and the CSV output for sorting by owner,
last logon age, group count, and recommended action. Do not use inactivity alone
as a deletion decision.

# Executive Summary

Company: Example GmbH  
Domain: `example.local`  
Report type: Active Directory inactive user analysis

All data in this sample output is fictional.

## Overall Risk Summary

The sample analysis found inactive accounts that require human review before any
remediation. The highest risks are inactive privileged access, stale service
account evidence, and a built-in Administrator account that requires
break-glass policy review.

## Finding Counts

| Severity | Count |
|---|---:|
| Critical | 2 |
| High | 2 |
| Medium | 1 |
| Low | 0 |
| Info | 0 |
| Hold | 1 |

## Top 5 Risks

1. Enabled inactive privileged account detected: `alex.admin`.
2. Built-in Administrator enabled and inactive: `Administrator`.
3. Enabled stale service account candidate: `svc-reporting-old`.
4. Inactive account with SPN requires owner review: `app.sql.legacy`.
5. Disabled inactive account requires owner and mailbox review: `julia.reed`.

## Business Impact

Inactive privileged or service-related accounts can increase identity exposure
and complicate incident response. Account cleanup without owner validation can
also disrupt applications, mailboxes, and administrative access.

## Recommended First Actions

- Review Critical findings with identity and system owners.
- Validate privileged access and break-glass policy requirements.
- Confirm service dependencies before changing SPN-bearing accounts.
- Keep system-managed accounts on hold unless product owners approve action.

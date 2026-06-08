# SecureInfra Check Overview

SecureInfra Check is a defensive infrastructure security assessment model. The
SecureInfra AI layer supports it by turning audit evidence into normalized
findings and readable reports.

## Assessment Areas

- Active Directory security hygiene.
- Windows Server baseline security.
- Group Policy health and security risks.
- Linux host security posture.
- Backup and monitoring readiness.
- Privileged account exposure.
- Legacy protocol exposure.
- Patch and configuration visibility.

## SecureInfra AI Role

SecureInfra AI does not scan systems directly in Phase 1. It reads JSON reports
created by existing audit scripts, applies deterministic risk rules, and creates
Markdown reports for human review.

## Safety Positioning

The public toolkit is not a penetration testing framework. It is a practical
infrastructure security assessment and hardening support toolkit. It should not
include offensive exploitation automation, autonomous remediation, or customer
data.

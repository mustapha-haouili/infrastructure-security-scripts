"""Static public-safe control mapping catalog.

Mappings are broad defensive references only. They do not assert compliance,
certification, audit attestation, or official control coverage.
"""

from __future__ import annotations

from typing import Any


ControlReference = dict[str, Any]


CONTROL_CATALOG: dict[str, list[ControlReference]] = {
    "account_management_access_review": [
        {
            "framework": "CIS Controls IG1",
            "control_id": "CIS-IG1-05",
            "label": "Account Management",
            "mapping_confidence": "medium",
        },
        {
            "framework": "NIST CSF 2.0",
            "control_id": "PR.AA",
            "label": "Identity Management, Authentication, and Access Control",
            "mapping_confidence": "medium",
        },
    ],
    "asset_inventory_attack_surface": [
        {
            "framework": "CIS Controls IG1",
            "control_id": "CIS-IG1-01",
            "label": "Inventory and Control of Enterprise Assets",
            "mapping_confidence": "medium",
        },
        {
            "framework": "NIST CSF 2.0",
            "control_id": "ID.AM",
            "label": "Asset Management",
            "mapping_confidence": "medium",
        },
    ],
    "account_management_authentication": [
        {
            "framework": "CIS Controls IG1",
            "control_id": "CIS-IG1-05",
            "label": "Account Management",
            "mapping_confidence": "medium",
        },
        {
            "framework": "NIST CSF 2.0",
            "control_id": "PR.AA",
            "label": "Identity Management, Authentication, and Access Control",
            "mapping_confidence": "medium",
        },
    ],
    "privileged_access_management": [
        {
            "framework": "CIS Controls IG1",
            "control_id": "CIS-IG1-06",
            "label": "Access Control Management",
            "mapping_confidence": "medium",
        },
        {
            "framework": "NIST CSF 2.0",
            "control_id": "PR.AA",
            "label": "Identity Management, Authentication, and Access Control",
            "mapping_confidence": "medium",
        },
    ],
    "service_account_credential_hygiene": [
        {
            "framework": "CIS Controls IG1",
            "control_id": "CIS-IG1-05",
            "label": "Account Management",
            "mapping_confidence": "medium",
        },
        {
            "framework": "BSI SMB Security Guidance",
            "control_id": "BSI-SMB-IDENTITY",
            "label": "Identity and Credential Hygiene",
            "mapping_confidence": "medium",
        },
    ],
    "secure_configuration_management": [
        {
            "framework": "CIS Controls IG1",
            "control_id": "CIS-IG1-04",
            "label": "Secure Configuration of Enterprise Assets and Software",
            "mapping_confidence": "medium",
        },
        {
            "framework": "NIST CSF 2.0",
            "control_id": "PR.PS",
            "label": "Platform Security",
            "mapping_confidence": "medium",
        },
    ],
    "network_exposure_secure_configuration": [
        {
            "framework": "CIS Controls IG1",
            "control_id": "CIS-IG1-12",
            "label": "Network Infrastructure Management",
            "mapping_confidence": "medium",
        },
        {
            "framework": "NIST CSF 2.0",
            "control_id": "PR.IR",
            "label": "Technology Infrastructure Resilience",
            "mapping_confidence": "medium",
        },
    ],
    "linux_account_secure_configuration": [
        {
            "framework": "CIS Controls IG1",
            "control_id": "CIS-IG1-05",
            "label": "Account Management",
            "mapping_confidence": "medium",
        },
        {
            "framework": "CIS Controls IG1",
            "control_id": "CIS-IG1-04",
            "label": "Secure Configuration of Enterprise Assets and Software",
            "mapping_confidence": "medium",
        },
    ],
    "workload_hardening": [
        {
            "framework": "CIS Controls IG1",
            "control_id": "CIS-IG1-04",
            "label": "Secure Configuration of Enterprise Assets and Software",
            "mapping_confidence": "medium",
        },
        {
            "framework": "NIST CSF 2.0",
            "control_id": "PR.PS",
            "label": "Platform Security",
            "mapping_confidence": "medium",
        },
    ],
    "secret_management": [
        {
            "framework": "CIS Controls IG1",
            "control_id": "CIS-IG1-03",
            "label": "Data Protection",
            "mapping_confidence": "medium",
        },
        {
            "framework": "NIST CSF 2.0",
            "control_id": "PR.DS",
            "label": "Data Security",
            "mapping_confidence": "medium",
        },
    ],
    "resilience_recovery_readiness": [
        {
            "framework": "CIS Controls IG1",
            "control_id": "CIS-IG1-11",
            "label": "Data Recovery",
            "mapping_confidence": "medium",
        },
        {
            "framework": "NIST CSF 2.0",
            "control_id": "RC.RP",
            "label": "Incident Recovery Plan Execution",
            "mapping_confidence": "medium",
        },
    ],
    "backup_readiness_operational_continuity": [
        {
            "framework": "CIS Controls IG1",
            "control_id": "CIS-IG1-11",
            "label": "Data Recovery",
            "mapping_confidence": "medium",
        },
        {
            "framework": "NIST CSF 2.0",
            "control_id": "RC.RP",
            "label": "Recovery Readiness",
            "mapping_confidence": "medium",
        },
        {
            "framework": "NIST CSF 2.0",
            "control_id": "PR.DS",
            "label": "Data Protection",
            "mapping_confidence": "medium",
        },
        {
            "framework": "BSI SMB Security Guidance",
            "control_id": "BSI-SMB-RESILIENCE",
            "label": "Operational Continuity",
            "mapping_confidence": "medium",
        },
    ],
    "vulnerability_update_management": [
        {
            "framework": "CIS Controls IG1",
            "control_id": "CIS-IG1-07",
            "label": "Continuous Vulnerability Management",
            "mapping_confidence": "medium",
        },
        {
            "framework": "NIST CSF 2.0",
            "control_id": "ID.RA",
            "label": "Risk Assessment",
            "mapping_confidence": "medium",
        },
    ],
}


THEME_ORDER = [
    "account_management_access_review",
    "asset_inventory_attack_surface",
    "account_management_authentication",
    "privileged_access_management",
    "service_account_credential_hygiene",
    "secure_configuration_management",
    "network_exposure_secure_configuration",
    "linux_account_secure_configuration",
    "workload_hardening",
    "secret_management",
    "backup_readiness_operational_continuity",
    "resilience_recovery_readiness",
    "vulnerability_update_management",
]

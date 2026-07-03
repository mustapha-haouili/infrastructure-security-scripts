"""Public-safe deterministic context for common listening network ports."""

from __future__ import annotations

from typing import Any


UNKNOWN_PORT_CONTEXT = {
    "common_service": "Unknown or custom service",
    "common_name": "Unknown or custom service",
    "exposure_type": "Listening service requiring validation",
    "risk_explanation": "A listening service was detected, but SecureInfra does not have a specific service mapping for this port. Validate owner, purpose, firewall scope, and monitoring.",
    "acceptable_when": "May be acceptable when the owning application, approved business purpose, allowed source networks, and monitoring are documented.",
    "customer_question": "Which application owns this port, why is it required, and which source networks should reach it?",
    "safe_next_step": "Identify the owning application and validate firewall/routing exposure before changing the service.",
    "mapping_confidence": "low",
}


PORT_CONTEXT: dict[tuple[str, int], dict[str, str]] = {
    ("tcp", 20): {
        "common_service": "FTP data",
        "common_name": "File Transfer Protocol data channel",
        "exposure_type": "Legacy file transfer service",
        "risk_explanation": "FTP data channels are associated with legacy file transfer workflows. Validate whether FTP is still required, how data transfer is protected, and which networks should reach it.",
        "acceptable_when": "May be acceptable for a documented legacy transfer workflow that is restricted to approved systems and monitored.",
        "customer_question": "Which transfer workflow uses FTP data traffic, who owns it, and what networks are allowed to connect?",
        "safe_next_step": "Confirm owner, transfer purpose, firewall scope, and replacement plan before changing the listener.",
        "mapping_confidence": "high",
    },
    ("tcp", 21): {
        "common_service": "FTP control",
        "common_name": "File Transfer Protocol",
        "exposure_type": "Legacy file transfer service",
        "risk_explanation": "FTP is commonly used for legacy file transfer and may expose authentication or data-transfer risk depending on configuration and network reachability. Validate ownership and approved scope.",
        "acceptable_when": "May be acceptable for a documented legacy transfer workflow with restricted sources, approved credentials handling, and monitoring.",
        "customer_question": "Which business workflow requires FTP, who owns it, and can access be restricted or modernized?",
        "safe_next_step": "Validate owner, allowed sources, authentication method, and monitoring before changing or replacing the service.",
        "mapping_confidence": "high",
    },
    ("tcp", 22): {
        "common_service": "SSH",
        "common_name": "Secure Shell",
        "exposure_type": "Remote administration service",
        "risk_explanation": "SSH is a remote administration service. It can be appropriate, but reachability should be limited to trusted management networks with approved authentication and logging.",
        "acceptable_when": "May be acceptable when restricted to approved administrators or management systems and monitored.",
        "customer_question": "Who administers this host through SSH, which source networks are approved, and how is access monitored?",
        "safe_next_step": "Validate allowed sources, authentication controls, and logging before changing SSH exposure.",
        "mapping_confidence": "high",
    },
    ("tcp", 23): {
        "common_service": "Telnet",
        "common_name": "Telnet",
        "exposure_type": "Legacy remote administration service",
        "risk_explanation": "Telnet is a legacy remote administration protocol. Validate whether it is still required and whether access can be removed, replaced, or tightly restricted.",
        "acceptable_when": "May be acceptable only for a documented legacy dependency isolated to approved management networks.",
        "customer_question": "Which legacy dependency requires Telnet, who owns it, and what replacement or isolation plan exists?",
        "safe_next_step": "Confirm owner, dependency, source restrictions, and migration plan before changing the service.",
        "mapping_confidence": "high",
    },
    ("tcp", 25): {
        "common_service": "SMTP",
        "common_name": "Simple Mail Transfer Protocol",
        "exposure_type": "Mail transfer service",
        "risk_explanation": "SMTP is commonly used for mail transfer or relay. Validate whether this host is an approved mail server or relay and whether sources are restricted.",
        "acceptable_when": "May be acceptable for approved mail servers or relays with documented routing, anti-abuse controls, and monitoring.",
        "customer_question": "Is this host an approved mail relay or server, who owns it, and which systems may submit mail?",
        "safe_next_step": "Validate mail ownership, relay restrictions, firewall scope, and monitoring before changing SMTP exposure.",
        "mapping_confidence": "high",
    },
    ("tcp", 53): {
        "common_service": "DNS",
        "common_name": "Domain Name System",
        "exposure_type": "Name resolution service",
        "risk_explanation": "DNS is a core name-resolution service. Validate whether this host is an approved resolver or authoritative server and whether queries are limited to intended clients.",
        "acceptable_when": "May be acceptable for approved DNS servers with restricted recursion or authoritative scope and monitoring.",
        "customer_question": "Is this host an approved DNS service, who owns it, and which clients should query it?",
        "safe_next_step": "Validate DNS role, allowed clients, recursion policy, firewall scope, and monitoring before changing the listener.",
        "mapping_confidence": "high",
    },
    ("udp", 53): {
        "common_service": "DNS",
        "common_name": "Domain Name System",
        "exposure_type": "Name resolution service",
        "risk_explanation": "DNS over UDP is commonly used for name resolution. Validate whether this host is an approved resolver or authoritative server and whether queries are limited to intended clients.",
        "acceptable_when": "May be acceptable for approved DNS servers with restricted recursion or authoritative scope and monitoring.",
        "customer_question": "Is this host an approved DNS service, who owns it, and which clients should query it?",
        "safe_next_step": "Validate DNS role, allowed clients, recursion policy, firewall scope, and monitoring before changing the listener.",
        "mapping_confidence": "high",
    },
    ("tcp", 80): {
        "common_service": "HTTP web service",
        "common_name": "Hypertext Transfer Protocol",
        "exposure_type": "Web or application service",
        "risk_explanation": "HTTP commonly represents a web or application service. It is context-dependent: public, internal, admin, and health-check endpoints have different risk and ownership requirements.",
        "acceptable_when": "May be acceptable for an approved web service with documented owner, route, monitoring, and access controls.",
        "customer_question": "Which web application owns this listener, who should reach it, and is plaintext HTTP approved?",
        "safe_next_step": "Validate application owner, expected clients, TLS or redirect design, firewall scope, and monitoring before changing the listener.",
        "mapping_confidence": "high",
    },
    ("tcp", 88): {
        "common_service": "Kerberos",
        "common_name": "Kerberos authentication",
        "exposure_type": "Directory authentication service",
        "risk_explanation": "Kerberos is commonly used by Active Directory domain controllers and other Kerberos services. Validate whether this host is expected to provide authentication services.",
        "acceptable_when": "May be acceptable on approved domain controllers or Kerberos infrastructure with expected network reachability.",
        "customer_question": "Is this host approved to provide Kerberos authentication, and which networks should reach it?",
        "safe_next_step": "Validate server role, domain ownership, firewall scope, and monitoring before changing the listener.",
        "mapping_confidence": "high",
    },
    ("tcp", 135): {
        "common_service": "RPC Endpoint Mapper",
        "common_name": "Microsoft RPC Endpoint Mapper",
        "exposure_type": "Windows RPC service",
        "risk_explanation": "RPC Endpoint Mapper supports Windows remote management and service discovery workflows. Validate whether this exposure is required and restricted to trusted networks.",
        "acceptable_when": "May be acceptable on Windows servers where RPC is required and network access is limited to approved management or domain networks.",
        "customer_question": "Which Windows management or application dependency requires RPC, and which sources should reach it?",
        "safe_next_step": "Validate owner, dependency, firewall profile, allowed sources, and monitoring before changing RPC exposure.",
        "mapping_confidence": "high",
    },
    ("tcp", 139): {
        "common_service": "NetBIOS Session Service",
        "common_name": "NetBIOS over TCP/IP",
        "exposure_type": "Legacy Windows file and name service",
        "risk_explanation": "NetBIOS is associated with legacy Windows file-sharing and name-service workflows. Validate whether it is still required and restricted.",
        "acceptable_when": "May be acceptable only for documented legacy Windows dependencies on trusted networks.",
        "customer_question": "Which legacy system requires NetBIOS, who owns it, and can it be disabled or restricted?",
        "safe_next_step": "Confirm dependency and allowed sources before changing NetBIOS exposure.",
        "mapping_confidence": "high",
    },
    ("tcp", 389): {
        "common_service": "LDAP",
        "common_name": "Lightweight Directory Access Protocol",
        "exposure_type": "Directory service",
        "risk_explanation": "LDAP is commonly used for directory queries and authentication integration. Validate whether this host is an approved directory service and whether clients are restricted.",
        "acceptable_when": "May be acceptable on approved directory servers with intended client reachability and monitoring.",
        "customer_question": "Is this host an approved LDAP directory service, and which systems should query it?",
        "safe_next_step": "Validate directory role, approved clients, firewall scope, and whether LDAPS is required before changing LDAP exposure.",
        "mapping_confidence": "high",
    },
    ("tcp", 443): {
        "common_service": "HTTPS web service",
        "common_name": "HTTP over TLS",
        "exposure_type": "Web or application service",
        "risk_explanation": "HTTPS commonly represents a web application, API, or management interface. Risk depends on owner, authentication, exposed functionality, and network reachability.",
        "acceptable_when": "May be acceptable for approved web services with documented owner, TLS configuration, access controls, and monitoring.",
        "customer_question": "Which application or management interface owns this HTTPS listener, and who should reach it?",
        "safe_next_step": "Validate application owner, certificate/TLS posture, expected clients, firewall scope, and monitoring before changing the listener.",
        "mapping_confidence": "high",
    },
    ("tcp", 445): {
        "common_service": "SMB",
        "common_name": "Server Message Block",
        "exposure_type": "File sharing and Windows administration service",
        "risk_explanation": "SMB supports Windows file sharing and administrative operations. It can be required internally, but reachability should be limited to trusted networks and approved clients.",
        "acceptable_when": "May be acceptable for approved file servers or domain workflows restricted to intended internal networks.",
        "customer_question": "Which file sharing or Windows management dependency requires SMB, and which clients should reach it?",
        "safe_next_step": "Validate share/server role, allowed source networks, firewall scope, SMB hardening, and monitoring before changing SMB exposure.",
        "mapping_confidence": "high",
    },
    ("tcp", 636): {
        "common_service": "LDAPS",
        "common_name": "LDAP over TLS",
        "exposure_type": "Directory service",
        "risk_explanation": "LDAPS is commonly used for encrypted directory queries and integrations. Validate directory role, client scope, certificate management, and monitoring.",
        "acceptable_when": "May be acceptable on approved directory servers with intended client reachability and certificate lifecycle controls.",
        "customer_question": "Is this host an approved LDAPS service, which systems should query it, and how are certificates managed?",
        "safe_next_step": "Validate directory role, approved clients, certificate status, firewall scope, and monitoring before changing LDAPS exposure.",
        "mapping_confidence": "high",
    },
    ("tcp", 1433): {
        "common_service": "Microsoft SQL Server",
        "common_name": "SQL Server database service",
        "exposure_type": "Database service",
        "risk_explanation": "Microsoft SQL Server is a database service. Database listeners should be reachable only by approved application, administration, or backup systems.",
        "acceptable_when": "May be acceptable for approved database servers restricted to intended application and management networks.",
        "customer_question": "Which application owns this SQL Server listener, and which systems should connect?",
        "safe_next_step": "Validate database owner, required clients, firewall scope, authentication model, backup dependencies, and monitoring before changing the listener.",
        "mapping_confidence": "high",
    },
    ("tcp", 3306): {
        "common_service": "MySQL/MariaDB",
        "common_name": "MySQL or MariaDB database service",
        "exposure_type": "Database service",
        "risk_explanation": "MySQL or MariaDB is a database service. Validate whether the listener is intended and restricted to approved application or administration systems.",
        "acceptable_when": "May be acceptable for approved database servers restricted to intended application and management networks.",
        "customer_question": "Which application owns this database listener, and which systems should connect?",
        "safe_next_step": "Validate database owner, required clients, firewall scope, authentication model, and monitoring before changing the listener.",
        "mapping_confidence": "high",
    },
    ("tcp", 3389): {
        "common_service": "Remote Desktop Protocol",
        "common_name": "RDP",
        "exposure_type": "Remote administration service",
        "risk_explanation": "RDP is a remote administration service. It may be required for operations, but exposure should be restricted to trusted management networks with approved authentication and monitoring.",
        "acceptable_when": "May be acceptable when Remote Desktop is approved, restricted to trusted administration sources, protected by policy, and monitored.",
        "customer_question": "Who requires RDP access, from which source networks, and how is access approved and monitored?",
        "safe_next_step": "Validate RDP owner, allowed source networks, NLA/policy controls, firewall scope, and monitoring before changing the listener.",
        "mapping_confidence": "high",
    },
    ("tcp", 5432): {
        "common_service": "PostgreSQL",
        "common_name": "PostgreSQL database service",
        "exposure_type": "Database service",
        "risk_explanation": "PostgreSQL is a database service. Validate whether the listener is intended and restricted to approved application or administration systems.",
        "acceptable_when": "May be acceptable for approved database servers restricted to intended application and management networks.",
        "customer_question": "Which application owns this PostgreSQL listener, and which systems should connect?",
        "safe_next_step": "Validate database owner, required clients, firewall scope, authentication model, and monitoring before changing the listener.",
        "mapping_confidence": "high",
    },
    ("tcp", 5900): {
        "common_service": "VNC",
        "common_name": "Virtual Network Computing",
        "exposure_type": "Remote administration service",
        "risk_explanation": "VNC is a remote console service. Validate whether it is approved, restricted, and monitored before making changes.",
        "acceptable_when": "May be acceptable only for documented administrative workflows restricted to trusted management networks.",
        "customer_question": "Who requires VNC access, from which networks, and how is access protected and monitored?",
        "safe_next_step": "Validate owner, approved sources, authentication controls, and monitoring before changing VNC exposure.",
        "mapping_confidence": "high",
    },
    ("tcp", 5985): {
        "common_service": "Windows Remote Management",
        "common_name": "WinRM over HTTP",
        "exposure_type": "Remote administration service",
        "risk_explanation": "WinRM over HTTP is commonly used for Windows remote administration and automation. It should be restricted to trusted management networks and validated before changes.",
        "acceptable_when": "May be acceptable when WinRM is approved, restricted to trusted management sources, uses approved authentication, and is monitored.",
        "customer_question": "Which management tools or administrators require WinRM over HTTP, from which source networks, and how is access monitored?",
        "safe_next_step": "Validate WinRM owner, management network scope, authentication policy, firewall rules, and monitoring before changing the listener.",
        "mapping_confidence": "high",
    },
    ("tcp", 5986): {
        "common_service": "Windows Remote Management",
        "common_name": "WinRM over HTTPS",
        "exposure_type": "Remote administration service",
        "risk_explanation": "WinRM over HTTPS is commonly used for Windows remote administration and automation. It should still be restricted to trusted management networks and validated before changes.",
        "acceptable_when": "May be acceptable when WinRM is approved, restricted to trusted management sources, uses managed certificates, and is monitored.",
        "customer_question": "Which management tools or administrators require WinRM over HTTPS, from which source networks, and how are certificates and access monitored?",
        "safe_next_step": "Validate WinRM owner, management network scope, certificate status, authentication policy, firewall rules, and monitoring before changing the listener.",
        "mapping_confidence": "high",
    },
    ("tcp", 6379): {
        "common_service": "Redis",
        "common_name": "Redis data store",
        "exposure_type": "Database or cache service",
        "risk_explanation": "Redis is commonly used as an application cache or data store. Validate whether the listener is intended and restricted to approved application systems.",
        "acceptable_when": "May be acceptable for approved application stacks restricted to intended clients and monitored.",
        "customer_question": "Which application owns this Redis listener, and which systems should connect?",
        "safe_next_step": "Validate application owner, required clients, firewall scope, authentication/TLS posture, and monitoring before changing the listener.",
        "mapping_confidence": "high",
    },
    ("tcp", 8080): {
        "common_service": "Alternate HTTP or app server",
        "common_name": "Alternate HTTP",
        "exposure_type": "Web or application service",
        "risk_explanation": "TCP 8080 commonly hosts alternate HTTP services, proxies, or application servers. Validate the owning application and intended access path.",
        "acceptable_when": "May be acceptable for approved internal web or application services with restricted reachability and monitoring.",
        "customer_question": "Which application owns this 8080 listener, and who should reach it?",
        "safe_next_step": "Validate application owner, expected clients, firewall scope, and monitoring before changing the listener.",
        "mapping_confidence": "medium",
    },
    ("tcp", 8443): {
        "common_service": "Alternate HTTPS or admin console",
        "common_name": "Alternate HTTPS",
        "exposure_type": "Web, application, or administration service",
        "risk_explanation": "TCP 8443 commonly hosts alternate HTTPS services or administrative consoles. Validate the owner, authentication, and intended source networks.",
        "acceptable_when": "May be acceptable for approved application or management interfaces with restricted reachability and monitoring.",
        "customer_question": "Which application or admin console owns this 8443 listener, and who should reach it?",
        "safe_next_step": "Validate application owner, authentication, certificate posture, firewall scope, and monitoring before changing the listener.",
        "mapping_confidence": "medium",
    },
    ("tcp", 9200): {
        "common_service": "Elasticsearch",
        "common_name": "Elasticsearch API",
        "exposure_type": "Search or data platform service",
        "risk_explanation": "Elasticsearch exposes search and data APIs. Validate whether this listener is intended and restricted to approved application or administration systems.",
        "acceptable_when": "May be acceptable for approved search clusters restricted to intended clients and monitored.",
        "customer_question": "Which application or data platform owns Elasticsearch, and which systems should connect?",
        "safe_next_step": "Validate platform owner, required clients, firewall scope, authentication/TLS posture, and monitoring before changing the listener.",
        "mapping_confidence": "high",
    },
    ("tcp", 11211): {
        "common_service": "Memcached",
        "common_name": "Memcached cache service",
        "exposure_type": "Cache service",
        "risk_explanation": "Memcached is commonly used as an application cache. Validate whether the listener is intended and restricted to approved application systems.",
        "acceptable_when": "May be acceptable for approved application stacks restricted to intended clients and monitored.",
        "customer_question": "Which application owns this Memcached listener, and which systems should connect?",
        "safe_next_step": "Validate application owner, required clients, firewall scope, and monitoring before changing the listener.",
        "mapping_confidence": "high",
    },
    ("tcp", 27017): {
        "common_service": "MongoDB",
        "common_name": "MongoDB database service",
        "exposure_type": "Database service",
        "risk_explanation": "MongoDB is a database service. Validate whether the listener is intended and restricted to approved application or administration systems.",
        "acceptable_when": "May be acceptable for approved database servers restricted to intended application and management networks.",
        "customer_question": "Which application owns this MongoDB listener, and which systems should connect?",
        "safe_next_step": "Validate database owner, required clients, firewall scope, authentication/TLS posture, and monitoring before changing the listener.",
        "mapping_confidence": "high",
    },
}


def lookup_port_context(protocol: Any, port: Any) -> dict[str, str]:
    normalized_protocol = normalize_protocol(protocol)
    normalized_port = normalize_port(port)
    if normalized_port is None:
        return dict(UNKNOWN_PORT_CONTEXT)

    context = PORT_CONTEXT.get((normalized_protocol, normalized_port))
    if context is None and normalized_protocol == "udp":
        context = PORT_CONTEXT.get(("tcp", normalized_port))
    if context is None:
        return dict(UNKNOWN_PORT_CONTEXT)
    return dict(context)


def normalize_protocol(protocol: Any) -> str:
    text = str(protocol or "tcp").strip().lower()
    if "udp" in text:
        return "udp"
    return "tcp"


def normalize_port(port: Any) -> int | None:
    if isinstance(port, bool) or port in (None, ""):
        return None
    try:
        return int(port)
    except (TypeError, ValueError):
        return None


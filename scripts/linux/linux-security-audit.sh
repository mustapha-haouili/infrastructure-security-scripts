#!/usr/bin/env bash
set -euo pipefail

OUTPUT_DIR="reports"
QUICK_MODE=0
SUMMARY_JSON_PATH=""

FINDING_IDS=()
FINDING_SEVERITIES=()
FINDING_TITLES=()
FINDING_RECOMMENDATIONS=()
FINDING_EVIDENCES=()

usage() {
    cat <<USAGE
Usage: $0 [-o output_dir] [--quick] [--summary-json file]

Collects Linux security baseline information and writes a structured text report.
The script does not change system configuration.

Options:
  -o, --output-dir DIR   Directory for the report. Default: reports
  --quick                Skip slower filesystem checks
  --summary-json FILE    JSON summary path. Default: next to the text report
  -h, --help             Show this help

Examples:
  $0
      Run a full audit and write text plus JSON reports under reports/.
  $0 -o /var/tmp/security-reports
      Write reports to a specific directory.
  $0 --quick
      Skip slower filesystem permission checks.
  $0 --summary-json reports/linux-summary.json
      Write the JSON summary to an explicit file.
  $0 --quick --output-dir reports --summary-json reports/linux-summary.json
      Combine quick mode, explicit text output directory, and explicit JSON path.
USAGE
}

require_value() {
    local option="$1"
    local value="${2:-}"
    if [[ -z "$value" || "$value" == -* ]]; then
        echo "Option $option requires a value." >&2
        usage
        exit 1
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -o|--output-dir)
            require_value "$1" "${2:-}"
            OUTPUT_DIR="${2:-}"
            shift 2
            ;;
        --quick)
            QUICK_MODE=1
            shift
            ;;
        --summary-json)
            require_value "$1" "${2:-}"
            SUMMARY_JSON_PATH="${2:-}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage
            exit 1
            ;;
    esac
done

mkdir -p "$OUTPUT_DIR"
HOSTNAME_VALUE="$(hostname 2>/dev/null || echo unknown)"
REPORT_FILE="$OUTPUT_DIR/linux-security-audit-${HOSTNAME_VALUE}-$(date -u +%Y%m%d-%H%M%S).txt"
if [[ -z "$SUMMARY_JSON_PATH" ]]; then
    SUMMARY_JSON_PATH="${REPORT_FILE%.txt}.summary.json"
fi

is_root() {
    [[ "${EUID:-$(id -u)}" -eq 0 ]]
}

have_cmd() {
    command -v "$1" >/dev/null 2>&1
}

json_escape() {
    python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().rstrip("\n")))'
}

add_finding() {
    local id="$1"
    local severity="$2"
    local title="$3"
    local recommendation="$4"
    local evidence="$5"

    FINDING_IDS+=("$id")
    FINDING_SEVERITIES+=("$severity")
    FINDING_TITLES+=("$title")
    FINDING_RECOMMENDATIONS+=("$recommendation")
    FINDING_EVIDENCES+=("$evidence")
}

count_findings_by_severity() {
    local target="$1"
    local count=0
    local severity

    for severity in "${FINDING_SEVERITIES[@]}"; do
        if [[ "$severity" == "$target" ]]; then
            count=$((count + 1))
        fi
    done

    echo "$count"
}

section() {
    {
        echo
        echo "================================================================"
        echo "$1"
        echo "================================================================"
    } >> "$REPORT_FILE"
}

run_check() {
    local title="$1"
    shift
    section "$title"
    {
        "$@"
    } >> "$REPORT_FILE" 2>&1 || {
        echo "Check failed: $title" >> "$REPORT_FILE"
    }
}

read_ssh_effective_config() {
    if have_cmd sshd; then
        sshd -T 2>/dev/null || true
    elif [[ -r /etc/ssh/sshd_config ]]; then
        grep -Ei '^[[:space:]]*(PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords)[[:space:]]+' /etc/ssh/sshd_config | awk '{print tolower($1) " " tolower($2)}' || true
    fi
}

ssh_setting_value() {
    local config="$1"
    local key="$2"
    awk -v wanted="$key" 'tolower($1) == wanted {print tolower($2); exit}' <<< "$config"
}

collect_sysctl_finding() {
    local key="$1"
    local expected="$2"
    local id="$3"
    local severity="$4"
    local title="$5"
    local recommendation="$6"
    local value

    value="$(sysctl -n "$key" 2>/dev/null || true)"
    if [[ -n "$value" && "$value" != "$expected" ]]; then
        add_finding "$id" "$severity" "$title" "$recommendation" "$key=$value, expected $expected"
    fi
}


known_linux_service_name() {
    case "$1" in
        21) echo "FTP" ;;
        22) echo "SSH" ;;
        23) echo "Telnet" ;;
        25) echo "SMTP" ;;
        53) echo "DNS" ;;
        111) echo "RPC bind" ;;
        139) echo "NetBIOS" ;;
        445) echo "SMB" ;;
        2049) echo "NFS" ;;
        3306) echo "MySQL" ;;
        5432) echo "PostgreSQL" ;;
        6379) echo "Redis" ;;
        9200) echo "Elasticsearch HTTP" ;;
        9300) echo "Elasticsearch transport" ;;
        11211) echo "Memcached" ;;
        27017) echo "MongoDB" ;;
        3389) echo "RDP/xrdp" ;;
        5900) echo "VNC" ;;
        *) echo "" ;;
    esac
}

linux_service_severity() {
    local port="$1"
    local bind_scope="$2"
    case "$port" in
        23|6379|9200|9300|11211|27017)
            [[ "$bind_scope" == "all interfaces" ]] && echo "high" || echo "medium"
            ;;
        21|111|139|445|2049|3306|5432|3389|5900)
            [[ "$bind_scope" == "all interfaces" ]] && echo "medium" || echo "low"
            ;;
        22)
            [[ "$bind_scope" == "all interfaces" ]] && echo "low" || echo "info"
            ;;
        *) echo "info" ;;
    esac
}

is_all_interface_address() {
    local address="$1"
    case "$address" in
        "0.0.0.0"|"*"|"::"|"[::]"|":::") return 0 ;;
    esac
    return 1
}

collect_listening_socket_findings() {
    local socket_file
    local socket
    local local_address
    local port
    local bind_scope
    local service_name
    local severity
    local emitted_ports=""

    socket_file="$(mktemp)"
    if have_cmd ss; then
        ss -H -ltn 2>/dev/null | awk '{print $4}' > "$socket_file" || true
    elif have_cmd netstat; then
        netstat -ltn 2>/dev/null | awk 'NR>2 {print $4}' > "$socket_file" || true
    else
        rm -f "$socket_file"
        add_finding \
            "LINUX-NETWORK-COVERAGE-001" \
            "info" \
            "Listening socket inventory command was not available" \
            "Install ss or netstat, or provide equivalent listener evidence for review." \
            "Neither ss nor netstat was available in the audit context"
        return
    fi

    while IFS= read -r socket; do
        [[ -z "$socket" ]] && continue
        port="${socket##*:}"
        [[ "$port" =~ ^[0-9]+$ ]] || continue
        service_name="$(known_linux_service_name "$port")"
        [[ -n "$service_name" ]] || continue
        if [[ " $emitted_ports " == *" $port "* ]]; then
            continue
        fi
        emitted_ports="$emitted_ports $port"
        local_address="${socket%:*}"
        local_address="${local_address#[}"
        local_address="${local_address%]}"
        bind_scope="specific local address"
        if is_all_interface_address "$local_address"; then
            bind_scope="all interfaces"
        fi
        severity="$(linux_service_severity "$port" "$bind_scope")"
        add_finding \
            "LINUX-NETWORK-PORT-${port}" \
            "$severity" \
            "Linux host is listening on TCP ${port} / ${service_name}" \
            "Validate the business need, allowed source networks, firewall policy, and service owner before changing the listener." \
            "TCP ${port} / ${service_name}; bind scope: ${bind_scope}; local listener: ${socket}. This is bind evidence, not proof of internet reachability."
    done < "$socket_file"
    rm -f "$socket_file"
}

collect_log_coverage_findings() {
    local auth_log_found=0
    if [[ -r /var/log/auth.log || -r /var/log/secure ]]; then
        auth_log_found=1
    elif have_cmd journalctl && journalctl -n 1 >/dev/null 2>&1; then
        auth_log_found=1
    fi

    if [[ "$auth_log_found" -eq 0 ]]; then
        add_finding \
            "LINUX-LOG-COVERAGE-001" \
            "info" \
            "Authentication log evidence was not available" \
            "Confirm whether authentication logs are forwarded, retained locally, or available through the customer logging platform." \
            "No readable /var/log/auth.log, /var/log/secure, or journalctl evidence was available."
    fi

    if have_cmd systemctl; then
        if ! systemctl is-active auditd >/dev/null 2>&1; then
            add_finding \
                "LINUX-LOG-AUDITD-001" \
                "medium" \
                "Linux audit service is not active or could not be verified" \
                "Validate whether auditd or an equivalent audit control is required for this host and enable or document compensating controls as appropriate." \
                "systemctl is-active auditd did not return active."
        fi
    elif ! have_cmd auditctl; then
        add_finding \
            "LINUX-LOG-AUDITD-002" \
            "info" \
            "Linux audit tooling was not available" \
            "Confirm whether auditd, auditctl, or an equivalent EDR/logging control is used on this host." \
            "Neither systemctl auditd status nor auditctl was available in the audit context."
    fi
}

collect_package_update_findings() {
    local updates
    local update_count
    if have_cmd apt; then
        updates="$(apt list --upgradable 2>/dev/null | awk 'NR>1 {count++} END {print count + 0}')"
        update_count="${updates:-0}"
        if [[ "$update_count" =~ ^[0-9]+$ && "$update_count" -gt 0 ]]; then
            add_finding \
                "LINUX-PACKAGE-UPDATES-001" \
                "medium" \
                "Linux package updates are available in local package metadata" \
                "Review pending package updates with the system owner and apply through the approved patch process." \
                "apt local metadata reports ${update_count} upgradable package(s). The audit did not refresh repositories."
        fi
    elif have_cmd dnf || have_cmd yum || have_cmd zypper || have_cmd apk; then
        add_finding \
            "LINUX-PACKAGE-COVERAGE-001" \
            "info" \
            "Package manager was detected but update status was not evaluated" \
            "Run the approved distribution-specific patch status command or provide vulnerability management evidence." \
            "A package manager was detected, but this read-only audit did not run commands that may contact repositories."
    else
        add_finding \
            "LINUX-PACKAGE-COVERAGE-002" \
            "info" \
            "Linux package manager was not detected" \
            "Confirm how this host receives package updates and provide patch management evidence if applicable." \
            "No supported package manager command was found in PATH."
    fi
}

collect_filesystem_permission_findings() {
    local writable_etc
    local writable_sensitive_dirs
    writable_etc="$(find /etc -xdev -type f -perm -0002 -print 2>/dev/null | sed -n '1,10p' | paste -sd ',' - || true)"
    if [[ -n "$writable_etc" ]]; then
        add_finding \
            "LINUX-FILESYSTEM-001" \
            "high" \
            "World-writable files exist under /etc" \
            "Remove world-writable permissions from system configuration files after validating ownership and application requirements." \
            "World-writable /etc files: ${writable_etc}"
    fi

    writable_sensitive_dirs="$(find /usr/local/bin /usr/local/sbin /opt -xdev -type d -perm -0002 ! -perm -1000 -print 2>/dev/null | sed -n '1,10p' | paste -sd ',' - || true)"
    if [[ -n "$writable_sensitive_dirs" ]]; then
        add_finding \
            "LINUX-FILESYSTEM-002" \
            "medium" \
            "World-writable sensitive directories without sticky bit were found" \
            "Review directory ownership and permissions before changing them through approved change control." \
            "Directories: ${writable_sensitive_dirs}"
    fi
}

collect_findings() {
    local uid_zero_accounts
    local uid_zero_count
    local empty_password_accounts
    local writable_sudoers
    local ssh_config
    local ssh_root_login
    local ssh_password_auth
    local ssh_empty_passwords

    if ! is_root; then
        add_finding \
            "LINUX-AUDIT-COVERAGE-001" \
            "info" \
            "Audit was not run as root" \
            "Run with sudo for complete shadow, service, and package evidence." \
            "Current user: $(id -un 2>/dev/null || echo unknown)"
    fi

    uid_zero_accounts="$(awk -F: '$3 == 0 {print $1}' /etc/passwd 2>/dev/null | paste -sd ',' -)"
    uid_zero_count="$(awk -F: '$3 == 0 {count++} END {print count + 0}' /etc/passwd 2>/dev/null || echo 0)"
    if (( uid_zero_count > 1 )); then
        add_finding \
            "LINUX-IDENTITY-001" \
            "high" \
            "Multiple UID 0 accounts exist" \
            "Review UID 0 accounts and remove or remap any account that should not have root-equivalent privileges." \
            "UID 0 accounts: $uid_zero_accounts"
    fi

    if is_root && [[ -r /etc/shadow ]]; then
        empty_password_accounts="$(awk -F: '$2 == "" {print $1}' /etc/shadow | paste -sd ',' -)"
        if [[ -n "$empty_password_accounts" ]]; then
            add_finding \
                "LINUX-IDENTITY-002" \
                "critical" \
                "Accounts with empty password fields exist" \
                "Lock the accounts or set strong passwords immediately." \
                "Accounts: $empty_password_accounts"
        fi
    else
        add_finding \
            "LINUX-AUDIT-COVERAGE-002" \
            "info" \
            "Shadow password file was not readable" \
            "Run with sudo to verify empty local password fields." \
            "/etc/shadow not readable in current context"
    fi

    writable_sudoers="$({ find /etc/sudoers /etc/sudoers.d -type f -perm /022 -print 2>/dev/null || true; } | sed -n '1,10p' | paste -sd ',' -)"
    if [[ -n "$writable_sudoers" ]]; then
        add_finding \
            "LINUX-SUDO-001" \
            "high" \
            "Sudoers files are writable by group or others" \
            "Restrict sudoers files to root-owned, non-world-writable permissions." \
            "Writable files: $writable_sudoers"
    fi

    ssh_config="$(read_ssh_effective_config)"
    if [[ -n "$ssh_config" ]]; then
        ssh_root_login="$(ssh_setting_value "$ssh_config" "permitrootlogin")"
        ssh_password_auth="$(ssh_setting_value "$ssh_config" "passwordauthentication")"
        ssh_empty_passwords="$(ssh_setting_value "$ssh_config" "permitemptypasswords")"

        if [[ "$ssh_root_login" == "yes" ]]; then
            add_finding \
                "LINUX-SSH-001" \
                "high" \
                "SSH root login is enabled" \
                "Set PermitRootLogin no and use named administrative accounts with sudo." \
                "PermitRootLogin=$ssh_root_login"
        elif [[ -n "$ssh_root_login" && "$ssh_root_login" != "no" ]]; then
            add_finding \
                "LINUX-SSH-002" \
                "medium" \
                "SSH root login is not fully disabled" \
                "Consider setting PermitRootLogin no unless an exception is documented." \
                "PermitRootLogin=$ssh_root_login"
        fi

        if [[ "$ssh_password_auth" == "yes" ]]; then
            add_finding \
                "LINUX-SSH-003" \
                "medium" \
                "SSH password authentication is enabled" \
                "Prefer key-based SSH authentication and disable password authentication where operationally safe." \
                "PasswordAuthentication=$ssh_password_auth"
        fi

        if [[ "$ssh_empty_passwords" == "yes" ]]; then
            add_finding \
                "LINUX-SSH-004" \
                "critical" \
                "SSH permits empty passwords" \
                "Set PermitEmptyPasswords no immediately." \
                "PermitEmptyPasswords=$ssh_empty_passwords"
        fi
    else
        add_finding \
            "LINUX-SSH-005" \
            "info" \
            "SSH server configuration was not found" \
            "Confirm whether OpenSSH server should be installed or audited on this host." \
            "No sshd effective config or readable /etc/ssh/sshd_config"
    fi

    if ! have_cmd ufw && ! have_cmd firewall-cmd && ! have_cmd nft && ! have_cmd iptables; then
        add_finding \
            "LINUX-FIREWALL-001" \
            "medium" \
            "Firewall status could not be verified" \
            "Install or expose a supported firewall tool, or document the host firewall control used by this system." \
            "No ufw, firewall-cmd, nft, or iptables command found"
    fi

    collect_sysctl_finding "net.ipv4.ip_forward" "0" "LINUX-KERNEL-001" "medium" "IPv4 forwarding is enabled" "Disable IP forwarding unless the host is intended to route traffic."
    collect_sysctl_finding "net.ipv4.conf.all.accept_redirects" "0" "LINUX-KERNEL-002" "medium" "IPv4 ICMP redirects are accepted" "Disable ICMP redirect acceptance through sysctl."
    collect_sysctl_finding "net.ipv4.conf.default.accept_redirects" "0" "LINUX-KERNEL-003" "medium" "Default IPv4 ICMP redirects are accepted" "Disable default ICMP redirect acceptance through sysctl."
    collect_sysctl_finding "net.ipv6.conf.all.accept_redirects" "0" "LINUX-KERNEL-004" "medium" "IPv6 ICMP redirects are accepted" "Disable IPv6 redirect acceptance through sysctl."
    collect_sysctl_finding "kernel.randomize_va_space" "2" "LINUX-KERNEL-005" "medium" "Full ASLR is not enabled" "Set kernel.randomize_va_space to 2."

    collect_listening_socket_findings
    collect_log_coverage_findings
    collect_package_update_findings
    if [[ "$QUICK_MODE" -eq 0 ]]; then
        collect_filesystem_permission_findings
    fi
}

write_findings_summary() {
    local total="${#FINDING_IDS[@]}"
    local index

    {
        echo
        echo "Finding summary"
        echo "---------------"
        echo "Total findings: $total"
        echo "Critical: $(count_findings_by_severity critical)"
        echo "High: $(count_findings_by_severity high)"
        echo "Medium: $(count_findings_by_severity medium)"
        echo "Info: $(count_findings_by_severity info)"
        echo
        echo "Recommended actions"
        echo "-------------------"
        if (( total == 0 )); then
            echo "No high-signal findings were identified by the built-in checks."
        else
            for index in "${!FINDING_IDS[@]}"; do
                echo "- [${FINDING_SEVERITIES[$index]}] ${FINDING_TITLES[$index]} (${FINDING_IDS[$index]})"
                echo "  Recommendation: ${FINDING_RECOMMENDATIONS[$index]}"
                echo "  Evidence: ${FINDING_EVIDENCES[$index]}"
            done
        fi
        echo
        echo "Evidence collected"
        echo "------------------"
        echo "Raw command output follows for review and manual validation."
    } >> "$REPORT_FILE"
}

write_summary_json() {
    local index

    if ! have_cmd python3; then
        echo "Summary JSON skipped because python3 is not installed." >> "$REPORT_FILE"
        return
    fi

    mkdir -p "$(dirname "$SUMMARY_JSON_PATH")"
    {
        echo "{"
        printf '  "host": %s,\n' "$(printf '%s' "$HOSTNAME_VALUE" | json_escape)"
        printf '  "generated_at_utc": %s,\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ | json_escape)"
        printf '  "root_context": %s,\n' "$(is_root && echo true || echo false)"
        printf '  "quick_mode": %s,\n' "$([[ "$QUICK_MODE" -eq 1 ]] && echo true || echo false)"
        echo '  "finding_counts": {'
        printf '    "critical": %s,\n' "$(count_findings_by_severity critical)"
        printf '    "high": %s,\n' "$(count_findings_by_severity high)"
        printf '    "medium": %s,\n' "$(count_findings_by_severity medium)"
        printf '    "info": %s\n' "$(count_findings_by_severity info)"
        echo '  },'
        echo '  "findings": ['
        for index in "${!FINDING_IDS[@]}"; do
            if (( index > 0 )); then
                echo ","
            fi
            echo "    {"
            printf '      "id": %s,\n' "$(printf '%s' "${FINDING_IDS[$index]}" | json_escape)"
            printf '      "severity": %s,\n' "$(printf '%s' "${FINDING_SEVERITIES[$index]}" | json_escape)"
            printf '      "title": %s,\n' "$(printf '%s' "${FINDING_TITLES[$index]}" | json_escape)"
            printf '      "recommendation": %s,\n' "$(printf '%s' "${FINDING_RECOMMENDATIONS[$index]}" | json_escape)"
            printf '      "evidence": %s\n' "$(printf '%s' "${FINDING_EVIDENCES[$index]}" | json_escape)"
            printf '    }'
        done
        echo
        echo '  ]'
        echo "}"
    } > "$SUMMARY_JSON_PATH"
}

write_header() {
    cat > "$REPORT_FILE" <<HEADER
Linux Security Audit Report
Host: $HOSTNAME_VALUE
Generated UTC: $(date -u +%Y-%m-%dT%H:%M:%SZ)
User: $(id -un 2>/dev/null || echo unknown)
Root context: $(is_root && echo yes || echo no)
Quick mode: $([[ "$QUICK_MODE" -eq 1 ]] && echo yes || echo no)
Summary JSON: $SUMMARY_JSON_PATH
HEADER
    write_findings_summary
}

check_system() {
    echo "Kernel: $(uname -a)"
    echo
    if [[ -r /etc/os-release ]]; then
        cat /etc/os-release
    fi
    echo
    echo "Uptime:"
    uptime || true
}

check_identity() {
    echo "Current identity:"
    id || true
    echo
    echo "UID 0 accounts:"
    awk -F: '$3 == 0 {print $1 ":" $3 ":" $6 ":" $7}' /etc/passwd 2>/dev/null || true
    echo
    echo "Accounts with empty password fields in /etc/shadow:"
    if is_root && [[ -r /etc/shadow ]]; then
        awk -F: '$2 == "" {print $1}' /etc/shadow || true
    else
        echo "Requires root access."
    fi
}

check_sudoers() {
    echo "Sudo group members:"
    getent group sudo 2>/dev/null || true
    getent group wheel 2>/dev/null || true
    echo
    echo "Sudoers files:"
    ls -la /etc/sudoers /etc/sudoers.d 2>/dev/null || true
    echo
    echo "Writable sudoers files by non-root:"
    find /etc/sudoers /etc/sudoers.d -type f -perm /022 -ls 2>/dev/null || true
}

check_ssh() {
    echo "sshd_config effective security settings:"
    if have_cmd sshd; then
        sshd -T 2>/dev/null | grep -Ei '^(permitrootlogin|passwordauthentication|pubkeyauthentication|x11forwarding|maxauthtries|logingracetime|allowtcpforwarding|permitemptypasswords|clientaliveinterval|clientalivecountmax)' || true
    elif [[ -r /etc/ssh/sshd_config ]]; then
        grep -Ei '^[[:space:]]*(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|X11Forwarding|MaxAuthTries|LoginGraceTime|AllowTcpForwarding|PermitEmptyPasswords|ClientAliveInterval|ClientAliveCountMax)' /etc/ssh/sshd_config || true
    else
        echo "OpenSSH server configuration not found."
    fi
    echo
    echo "SSH service status:"
    if have_cmd systemctl; then
        systemctl is-enabled sshd 2>/dev/null || systemctl is-enabled ssh 2>/dev/null || true
        systemctl is-active sshd 2>/dev/null || systemctl is-active ssh 2>/dev/null || true
    fi
}

check_network() {
    echo "Listening TCP and UDP sockets:"
    if have_cmd ss; then
        ss -tulpn || true
    elif have_cmd netstat; then
        netstat -tulpn || true
    else
        echo "Neither ss nor netstat is available."
    fi
    echo
    echo "Default routes:"
    ip route show 2>/dev/null || route -n 2>/dev/null || true
}

check_firewall() {
    echo "Firewall status:"
    if have_cmd ufw; then
        ufw status verbose || true
    fi
    if have_cmd firewall-cmd; then
        firewall-cmd --state || true
        firewall-cmd --list-all || true
    fi
    if have_cmd nft; then
        nft list ruleset 2>/dev/null | sed -n '1,160p' || true
    elif have_cmd iptables; then
        iptables -S || true
    else
        echo "No supported firewall command found."
    fi
}

check_auth_logs() {
    echo "Recent failed authentication attempts:"
    if have_cmd journalctl; then
        journalctl --since "24 hours ago" 2>/dev/null | grep -Ei 'failed password|authentication failure|invalid user' | tail -n 80 || true
    fi
    for log_file in /var/log/auth.log /var/log/secure; do
        if [[ -r "$log_file" ]]; then
            grep -Ei 'failed password|authentication failure|invalid user' "$log_file" | tail -n 80 || true
        fi
    done
    echo
    echo "Last successful logins:"
    last -n 20 2>/dev/null || true
}

check_packages() {
    echo "Available package updates:"
    if have_cmd apt-get; then
        apt-get -s upgrade 2>/dev/null | grep -E '^[0-9]+ upgraded|^Inst ' | sed -n '1,120p' || true
    elif have_cmd dnf; then
        dnf check-update --security 2>/dev/null | sed -n '1,120p' || true
    elif have_cmd yum; then
        yum check-update --security 2>/dev/null | sed -n '1,120p' || true
    elif have_cmd zypper; then
        zypper list-updates 2>/dev/null | sed -n '1,120p' || true
    else
        echo "No supported package manager found."
    fi
}

check_filesystem() {
    echo "World-writable directories without sticky bit, limited to local filesystems:"
    if have_cmd timeout; then
        timeout 60 find / -xdev -type d -perm -0002 ! -perm -1000 -print 2>/dev/null | sed -n '1,200p' || true
    else
        find / -xdev -type d -perm -0002 ! -perm -1000 -print 2>/dev/null | sed -n '1,200p' || true
    fi
    echo
    echo "SUID and SGID files, limited to local filesystems:"
    if have_cmd timeout; then
        timeout 60 find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -print 2>/dev/null | sed -n '1,250p' || true
    else
        find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -print 2>/dev/null | sed -n '1,250p' || true
    fi
}

check_sysctl() {
    echo "Selected kernel network settings:"
    for key in \
        net.ipv4.ip_forward \
        net.ipv4.conf.all.accept_redirects \
        net.ipv4.conf.default.accept_redirects \
        net.ipv4.conf.all.secure_redirects \
        net.ipv4.conf.default.secure_redirects \
        net.ipv4.conf.all.rp_filter \
        net.ipv4.conf.default.rp_filter \
        net.ipv6.conf.all.accept_redirects \
        kernel.randomize_va_space; do
        sysctl "$key" 2>/dev/null || true
    done
}

check_containers() {
    echo "Docker containers:"
    if have_cmd docker; then
        docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null || true
    else
        echo "Docker command not found."
    fi
    echo
    echo "Kubernetes client context:"
    if have_cmd kubectl; then
        kubectl config current-context 2>/dev/null || true
        kubectl get nodes 2>/dev/null || true
    else
        echo "kubectl command not found."
    fi
}

collect_findings
write_header
write_summary_json
run_check "System information" check_system
run_check "Identity and privileged accounts" check_identity
run_check "Sudoers review" check_sudoers
run_check "SSH configuration" check_ssh
run_check "Network listeners" check_network
run_check "Firewall status" check_firewall
run_check "Authentication log review" check_auth_logs
run_check "Package update review" check_packages
run_check "Kernel security settings" check_sysctl
run_check "Container tooling" check_containers

if [[ "$QUICK_MODE" -eq 0 ]]; then
    run_check "Filesystem permission review" check_filesystem
else
    section "Filesystem permission review"
    echo "Skipped because --quick was used." >> "$REPORT_FILE"
fi

echo "Linux security audit written to: $REPORT_FILE"

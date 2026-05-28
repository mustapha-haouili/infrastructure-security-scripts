#!/usr/bin/env bash
set -euo pipefail

OUTPUT_DIR="reports"
QUICK_MODE=0

usage() {
    cat <<USAGE
Usage: $0 [-o output_dir] [--quick]

Collects Linux security baseline information and writes a text report.
The script does not change system configuration.

Options:
  -o, --output-dir DIR   Directory for the report. Default: reports
  --quick                Skip slower filesystem checks
  -h, --help             Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -o|--output-dir)
            OUTPUT_DIR="${2:-}"
            shift 2
            ;;
        --quick)
            QUICK_MODE=1
            shift
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

is_root() {
    [[ "${EUID:-$(id -u)}" -eq 0 ]]
}

have_cmd() {
    command -v "$1" >/dev/null 2>&1
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

write_header() {
    cat > "$REPORT_FILE" <<HEADER
Linux Security Audit Report
Host: $HOSTNAME_VALUE
Generated UTC: $(date -u +%Y-%m-%dT%H:%M:%SZ)
User: $(id -un 2>/dev/null || echo unknown)
Root context: $(is_root && echo yes || echo no)
HEADER
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
        sshd -T 2>/dev/null | grep -Ei '^(permitrootlogin|passwordauthentication|pubkeyauthentication|x11forwarding|maxauthtries|logingracetime|allowtcpforwarding|permitempty passwords|clientaliveinterval|clientalivecountmax)' || true
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

write_header
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

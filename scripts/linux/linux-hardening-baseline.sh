#!/usr/bin/env bash
set -euo pipefail

APPLY=0
BACKUP_DIR="backups/linux-baseline-$(hostname 2>/dev/null || echo host)-$(date -u +%Y%m%d-%H%M%S)"
REPORT_DIR="reports"
HARDEN_SSH=1
DISABLE_SSH_PASSWORD=0

usage() {
    cat <<USAGE
Usage: $0 [--apply] [--backup-dir DIR] [--report-dir DIR] [--no-ssh] [--disable-ssh-password]

Applies selected Linux baseline hardening controls.
The default mode is dry run and does not change configuration.

Options:
  --apply                 Apply changes
  --backup-dir DIR        Backup directory. Default: $BACKUP_DIR
  --report-dir DIR        Report directory. Default: reports
  --no-ssh                Skip SSH baseline changes
  --disable-ssh-password  Set PasswordAuthentication no in sshd config
  -h, --help              Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --apply)
            APPLY=1
            shift
            ;;
        --backup-dir)
            BACKUP_DIR="${2:-}"
            shift 2
            ;;
        --report-dir)
            REPORT_DIR="${2:-}"
            shift 2
            ;;
        --no-ssh)
            HARDEN_SSH=0
            shift
            ;;
        --disable-ssh-password)
            DISABLE_SSH_PASSWORD=1
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

if [[ "$APPLY" -eq 1 && "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "Run as root when using --apply." >&2
    exit 1
fi

mkdir -p "$REPORT_DIR"
REPORT_FILE="$REPORT_DIR/linux-hardening-plan-$(hostname 2>/dev/null || echo host)-$(date -u +%Y%m%d-%H%M%S).log"

log() {
    echo "$*" | tee -a "$REPORT_FILE"
}

run_or_plan() {
    local description="$1"
    shift

    if [[ "$APPLY" -eq 1 ]]; then
        log "APPLY: $description"
        "$@" >> "$REPORT_FILE" 2>&1
    else
        log "DRY RUN: $description"
    fi
}

backup_file() {
    local file="$1"
    if [[ "$APPLY" -eq 1 && -e "$file" ]]; then
        mkdir -p "$BACKUP_DIR"
        local safe_name
        safe_name="$(echo "$file" | sed 's#/#_#g' | sed 's#^_##')"
        cp -a "$file" "$BACKUP_DIR/$safe_name"
    fi
}

write_sysctl_baseline() {
    local target="/etc/sysctl.d/99-infra-security.conf"
    backup_file "$target"
    cat > "$target" <<SYSCTL
# Managed baseline: infrastructure security
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
kernel.randomize_va_space = 2
SYSCTL
    sysctl --system >/dev/null
}

write_modprobe_baseline() {
    local target="/etc/modprobe.d/99-infra-security.conf"
    backup_file "$target"
    cat > "$target" <<MODPROBE
# Managed baseline: infrastructure security
install cramfs /bin/false
install freevxfs /bin/false
install jffs2 /bin/false
install hfs /bin/false
install hfsplus /bin/false
install udf /bin/false
MODPROBE
}

write_limits_baseline() {
    local target="/etc/security/limits.d/99-infra-security.conf"
    backup_file "$target"
    cat > "$target" <<LIMITS
# Managed baseline: infrastructure security
* hard core 0
* soft core 0
LIMITS
}

write_ssh_baseline() {
    local target="/etc/ssh/sshd_config.d/90-infra-security.conf"
    local service_name="sshd"

    if [[ ! -d /etc/ssh/sshd_config.d ]]; then
        target="/etc/ssh/sshd_config"
    fi

    backup_file "$target"

    if [[ "$target" == */sshd_config ]]; then
        local tmp_file
        tmp_file="$(mktemp)"
        awk '
            /^# BEGIN Managed baseline: infrastructure security$/ {skip=1; next}
            /^# END Managed baseline: infrastructure security$/ {skip=0; next}
            skip != 1 {print}
        ' "$target" > "$tmp_file"
        cat "$tmp_file" > "$target"
        rm -f "$tmp_file"
        cat >> "$target" <<SSHCFG

# BEGIN Managed baseline: infrastructure security
PermitRootLogin no
PermitEmptyPasswords no
MaxAuthTries 4
LoginGraceTime 30
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
SSHCFG
        if [[ "$DISABLE_SSH_PASSWORD" -eq 1 ]]; then
            echo "PasswordAuthentication no" >> "$target"
        fi
        echo "# END Managed baseline: infrastructure security" >> "$target"
    else
        cat > "$target" <<SSHCFG
# Managed baseline: infrastructure security
PermitRootLogin no
PermitEmptyPasswords no
MaxAuthTries 4
LoginGraceTime 30
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
SSHCFG
        if [[ "$DISABLE_SSH_PASSWORD" -eq 1 ]]; then
            echo "PasswordAuthentication no" >> "$target"
        fi
    fi

    chmod 600 /etc/ssh/sshd_config 2>/dev/null || true

    if command -v sshd >/dev/null 2>&1; then
        sshd -t
    fi

    if command -v systemctl >/dev/null 2>&1; then
        if systemctl list-unit-files | grep -q '^ssh\.service'; then
            service_name="ssh"
        fi
        systemctl reload "$service_name" 2>/dev/null || systemctl restart "$service_name" 2>/dev/null || true
    fi
}

set_basic_permissions() {
    chmod 644 /etc/passwd 2>/dev/null || true
    chmod 640 /etc/shadow 2>/dev/null || true
    chmod 644 /etc/group 2>/dev/null || true
    chmod 640 /etc/gshadow 2>/dev/null || true
    chmod 700 /root 2>/dev/null || true
}

log "Linux hardening baseline"
log "Generated UTC: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "Mode: $([[ "$APPLY" -eq 1 ]] && echo apply || echo dry-run)"
log "Report: $REPORT_FILE"
if [[ "$APPLY" -eq 1 ]]; then
    log "Backup directory: $BACKUP_DIR"
fi

run_or_plan "Write kernel network security baseline" write_sysctl_baseline
run_or_plan "Disable uncommon legacy filesystems through modprobe" write_modprobe_baseline
run_or_plan "Disable core dumps through limits.d" write_limits_baseline
run_or_plan "Set basic permissions on account databases" set_basic_permissions

if [[ "$HARDEN_SSH" -eq 1 ]]; then
    run_or_plan "Apply SSH daemon baseline" write_ssh_baseline
else
    log "SKIP: SSH baseline disabled by --no-ssh"
fi

if [[ "$APPLY" -eq 0 ]]; then
    log "Dry run complete. Re-run with --apply after review."
fi

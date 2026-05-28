#!/usr/bin/env bash
set -euo pipefail

OUTPUT_DIR="reports"

usage() {
    cat <<USAGE
Usage: $0 [-o output_dir]

Collects basic Linux host inventory and writes JSON.
This script does not change system configuration.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -o|--output-dir)
            OUTPUT_DIR="${2:-}"
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
OUTPUT_FILE="$OUTPUT_DIR/linux-inventory-${HOSTNAME_VALUE}-$(date -u +%Y%m%d-%H%M%S).json"

json_escape() {
    python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().rstrip("\n")))'
}

read_os_pretty_name() {
    if [[ -r /etc/os-release ]]; then
        . /etc/os-release
        echo "${PRETTY_NAME:-unknown}"
    else
        echo "unknown"
    fi
}

list_ip_addresses() {
    if command -v ip >/dev/null 2>&1; then
        ip -o -4 addr show scope global 2>/dev/null | awk '{print $2":"$4}' | paste -sd ',' -
    else
        hostname -I 2>/dev/null | tr ' ' ',' | sed 's/,$//'
    fi
}

list_mounts_json() {
    df -P -T 2>/dev/null | awk 'NR>1 {print $1"|"$2"|"$3"|"$4"|"$5"|"$6"|"$7}' | while IFS='|' read -r fs type blocks used avail pct mount; do
        printf '{"filesystem":%s,"type":%s,"blocks":%s,"used":%s,"available":%s,"use_percent":%s,"mount":%s}\n' \
            "$(printf '%s' "$fs" | json_escape)" \
            "$(printf '%s' "$type" | json_escape)" \
            "${blocks:-0}" \
            "${used:-0}" \
            "${avail:-0}" \
            "$(printf '%s' "$pct" | json_escape)" \
            "$(printf '%s' "$mount" | json_escape)"
    done | paste -sd ',' -
}

cat > "$OUTPUT_FILE" <<JSON
{
  "hostname": $(printf '%s' "$HOSTNAME_VALUE" | json_escape),
  "generated_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "os": $(read_os_pretty_name | json_escape),
  "kernel": $(uname -r | json_escape),
  "architecture": $(uname -m | json_escape),
  "uptime": $(uptime -p 2>/dev/null | json_escape),
  "ip_addresses": $(list_ip_addresses | json_escape),
  "cpu_count": $(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 0),
  "memory_kb": $(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0),
  "mounts": [$(list_mounts_json)]
}
JSON

echo "Linux inventory written to: $OUTPUT_FILE"

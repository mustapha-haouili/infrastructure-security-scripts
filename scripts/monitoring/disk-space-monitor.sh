#!/usr/bin/env bash
set -euo pipefail

WARN=80
CRIT=90
EXCLUDE_TYPES="tmpfs,devtmpfs,squashfs,overlay"
OUTPUT_FORMAT="text"

usage() {
    cat <<USAGE
Usage: $0 [--warn PERCENT] [--crit PERCENT] [--exclude-types LIST] [--json]

Checks filesystem usage and returns a monitoring-friendly exit code.
Exit codes: 0 OK, 1 warning, 2 critical.

Options:
  --warn PERCENT         Warning threshold. Default: 80
  --crit PERCENT         Critical threshold. Default: 90
  --exclude-types LIST   Comma-separated filesystem types to exclude
  --json                 Output JSON lines
  -h, --help             Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --warn)
            WARN="${2:-}"
            shift 2
            ;;
        --crit)
            CRIT="${2:-}"
            shift 2
            ;;
        --exclude-types)
            EXCLUDE_TYPES="${2:-}"
            shift 2
            ;;
        --json)
            OUTPUT_FORMAT="json"
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

if ! [[ "$WARN" =~ ^[0-9]+$ && "$CRIT" =~ ^[0-9]+$ ]]; then
    echo "Thresholds must be numeric." >&2
    exit 1
fi

if (( WARN >= CRIT )); then
    echo "Warning threshold must be lower than critical threshold." >&2
    exit 1
fi

json_escape() {
    python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().rstrip("\n")))'
}

is_excluded_type() {
    local type="$1"
    IFS=',' read -ra excluded <<< "$EXCLUDE_TYPES"
    for item in "${excluded[@]}"; do
        [[ "$type" == "$item" ]] && return 0
    done
    return 1
}

STATUS=0
OUTPUT_LINES=()

while read -r filesystem type size used avail pct mount; do
    [[ -z "${filesystem:-}" ]] && continue
    if is_excluded_type "$type"; then
        continue
    fi

    usage_percent="${pct%%%}"
    state="OK"
    if (( usage_percent >= CRIT )); then
        state="CRITICAL"
        STATUS=2
    elif (( usage_percent >= WARN )); then
        state="WARNING"
        if (( STATUS < 1 )); then
            STATUS=1
        fi
    fi

    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        line=$(printf '{"state":%s,"filesystem":%s,"type":%s,"used_percent":%s,"mount":%s,"size":%s,"used":%s,"available":%s}' \
            "$(printf '%s' "$state" | json_escape)" \
            "$(printf '%s' "$filesystem" | json_escape)" \
            "$(printf '%s' "$type" | json_escape)" \
            "$usage_percent" \
            "$(printf '%s' "$mount" | json_escape)" \
            "$(printf '%s' "$size" | json_escape)" \
            "$(printf '%s' "$used" | json_escape)" \
            "$(printf '%s' "$avail" | json_escape)")
    else
        line=$(printf '%-8s %3s%% %-12s %-12s %-12s %s' "$state" "$usage_percent" "$size" "$used" "$avail" "$mount")
    fi
    OUTPUT_LINES+=("$line")
done < <(df -P -T | awk 'NR>1 {print $1, $2, $3, $4, $5, $6, $7}')

if [[ "$OUTPUT_FORMAT" != "json" ]]; then
    printf '%-8s %-4s %-12s %-12s %-12s %s\n' "STATE" "USE" "SIZE" "USED" "AVAILABLE" "MOUNT"
fi

for line in "${OUTPUT_LINES[@]}"; do
    echo "$line"
done

exit "$STATUS"

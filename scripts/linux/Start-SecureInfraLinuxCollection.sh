#!/usr/bin/env bash
set -euo pipefail

OUTPUT_DIR="reports/secureinfra-linux"
QUICK_MODE=0
SKIP_ARCHIVE=0
QUIET=0
RUN_BACKUP=1
RUN_HARDENING_PLAN=1
EXPECTED_BACKUP_PATHS=()
COLLECTOR_TIMEOUT_SECONDS=180

usage() {
    cat <<USAGE
Usage: $0 [options]

Runs the SecureInfra Linux read-only collection launcher. The launcher calls
focused Linux collectors, writes a standard SecureInfra client bundle layout,
and creates a ZIP archive that can be copied to the reporting input bundles directory.

Options:
  -o, --output-dir DIR             Directory where the bundle directory and ZIP are written.
                                   Default: reports/secureinfra-linux
  --quick                          Skip slower checks in linux-security-audit.sh.
  --expected-backup-path PATH      Optional expected backup path for backup-readiness-audit.sh.
                                   May be supplied more than once.
  --skip-backup                    Do not run backup-readiness-audit.sh.
  --skip-hardening-plan            Do not generate the dry-run hardening plan log.
  --skip-archive                   Leave the bundle directory only; do not create ZIP.
  --collector-timeout-seconds N     Per-collector timeout. Default: 180. Use 0 to disable.
  -q, --quiet                      Reduce console output.
  -h, --help                       Show this help.

Examples:
  $0 --quick
  $0 -o /var/tmp/secureinfra-linux --expected-backup-path /mnt/backups
  $0 --quick --skip-archive
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
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --quick)
            QUICK_MODE=1
            shift
            ;;
        --expected-backup-path)
            require_value "$1" "${2:-}"
            EXPECTED_BACKUP_PATHS+=("$2")
            shift 2
            ;;
        --skip-backup)
            RUN_BACKUP=0
            shift
            ;;
        --skip-hardening-plan)
            RUN_HARDENING_PLAN=0
            shift
            ;;
        --skip-archive)
            SKIP_ARCHIVE=1
            shift
            ;;
        --collector-timeout-seconds)
            require_value "$1" "${2:-}"
            COLLECTOR_TIMEOUT_SECONDS="$2"
            shift 2
            ;;
        -q|--quiet)
            QUIET=1
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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOSTNAME_VALUE="$(hostname 2>/dev/null || echo linux-host)"
SAFE_HOST="$(printf '%s' "$HOSTNAME_VALUE" | tr -c 'A-Za-z0-9._-' '-' | sed 's/-\{2,\}/-/g' | sed 's/^-//;s/-$//' | cut -c1-64)"
if [[ -z "$SAFE_HOST" ]]; then
    SAFE_HOST="linux-host"
fi
TIMESTAMP="$(date -u +%Y%m%d-%H%M%S)"
GENERATED_AT_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
BUNDLE_NAME="secureinfra-linux-bundle-${SAFE_HOST}-${TIMESTAMP}"
mkdir -p "$OUTPUT_DIR"
BUNDLE_ROOT="$OUTPUT_DIR/$BUNDLE_NAME"
LINUX_DIR="$BUNDLE_ROOT/linux"
BACKUP_DIR="$BUNDLE_ROOT/backup"
LOG_DIR="$BUNDLE_ROOT/logs"
mkdir -p "$LINUX_DIR" "$BACKUP_DIR" "$LOG_DIR"
COLLECTOR_STATUS_FILE="$LOG_DIR/collector-status.txt"
: > "$COLLECTOR_STATUS_FILE"

log() {
    if [[ "$QUIET" -eq 0 ]]; then
        echo "$*"
    fi
}

json_escape() {
    python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().rstrip("\n")))'
}

record_status() {
    local name="$1"
    local status="$2"
    local output_path="$3"
    printf '%s\t%s\t%s\n' "$name" "$status" "$output_path" >> "$COLLECTOR_STATUS_FILE"
}

run_collector() {
    local name="$1"
    local output_hint="$2"
    shift 2
    local log_file="$LOG_DIR/${name}.log"
    log "Running ${name}..."
    local command_status=0
    if command -v timeout >/dev/null 2>&1 && [[ "$COLLECTOR_TIMEOUT_SECONDS" =~ ^[0-9]+$ ]] && [[ "$COLLECTOR_TIMEOUT_SECONDS" -gt 0 ]]; then
        timeout "$COLLECTOR_TIMEOUT_SECONDS" "$@" > "$log_file" 2>&1 || command_status=$?
    else
        "$@" > "$log_file" 2>&1 || command_status=$?
    fi

    if [[ "$command_status" -eq 0 ]]; then
        record_status "$name" "completed" "$output_hint"
        log "Completed ${name}"
    elif [[ "$command_status" -eq 124 ]]; then
        record_status "$name" "timeout" "$output_hint"
        echo "Collector timed out: ${name}. See ${log_file}" >&2
    else
        record_status "$name" "failed" "$output_hint"
        echo "Collector failed: ${name}. See ${log_file}" >&2
    fi
}

copy_latest_inventory_to_canonical() {
    local latest=""
    latest="$(ls -t "$LINUX_DIR"/linux-inventory-*.json 2>/dev/null | head -n 1 || true)"
    if [[ -n "$latest" && -f "$latest" ]]; then
        cp "$latest" "$LINUX_DIR/linux-inventory.json"
    fi
}

write_json_array_from_status() {
    python3 - "$COLLECTOR_STATUS_FILE" <<'PY'
import json
import sys
from pathlib import Path
rows = []
path = Path(sys.argv[1])
if path.exists():
    for line in path.read_text(encoding='utf-8').splitlines():
        parts = line.split('\t')
        if len(parts) >= 3:
            rows.append({'name': parts[0], 'status': parts[1], 'output': parts[2]})
print(json.dumps(rows, indent=2))
PY
}

write_bundle_metadata() {
    local collector_json
    collector_json="$(write_json_array_from_status)"
    cat > "$BUNDLE_ROOT/client-info.json" <<JSON
{
  "ComputerName": $(printf '%s' "$HOSTNAME_VALUE" | json_escape),
  "Platform": "Linux",
  "CollectorLauncher": "Start-SecureInfraLinuxCollection.sh",
  "GeneratedAtUtc": "$GENERATED_AT_UTC"
}
JSON

    cat > "$BUNDLE_ROOT/collection-summary.json" <<JSON
{
  "CollectionId": "$BUNDLE_NAME",
  "GeneratedAtUtc": "$GENERATED_AT_UTC",
  "SafetyMode": "Read-only collection. No remediation or configuration changes are applied by this launcher.",
  "ScopeResolved": ["Linux", "Backup"],
  "QuickMode": $([[ "$QUICK_MODE" -eq 1 ]] && echo true || echo false),
  "Collectors": $collector_json
}
JSON

    cat > "$BUNDLE_ROOT/manifest.json" <<JSON
{
  "SchemaVersion": "1.0",
  "BundleContract": "SecureInfra collection bundle contract v1",
  "CollectionId": "$BUNDLE_NAME",
  "BundleType": "secureinfra-linux-client-collection",
  "Platform": "Linux",
  "GeneratedAtUtc": "$GENERATED_AT_UTC",
  "SourceLauncher": "Start-SecureInfraLinuxCollection.sh",
  "SafetyMode": "Read-only collection; remediation is not applied.",
  "CanonicalEvidence": {
    "LinuxSecuritySummary": "linux/linux-security-summary.json",
    "LinuxInventory": "linux/linux-inventory.json",
    "BackupReadiness": "backup/backup-readiness.json"
  },
  "Collectors": $collector_json
}
JSON
    cp "$BUNDLE_ROOT/manifest.json" "$BUNDLE_ROOT/bundle-manifest.json"
}

create_zip_archive() {
    local archive_path="$OUTPUT_DIR/${BUNDLE_NAME}.zip"
    rm -f "$archive_path"
    if command -v zip >/dev/null 2>&1; then
        (cd "$OUTPUT_DIR" && zip -qr "$archive_path" "$BUNDLE_NAME")
    else
        python3 - "$OUTPUT_DIR" "$BUNDLE_NAME" "$archive_path" <<'PY'
import sys
import zipfile
from pathlib import Path
output_dir = Path(sys.argv[1])
bundle_name = sys.argv[2]
archive_path = Path(sys.argv[3])
bundle_root = output_dir / bundle_name
with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as archive:
    for path in sorted(bundle_root.rglob('*')):
        archive.write(path, path.relative_to(output_dir).as_posix())
PY
    fi
    echo "$archive_path"
}

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required for SecureInfra Linux collection JSON handling." >&2
    exit 1
fi

run_collector \
    "linux-inventory" \
    "linux/linux-inventory.json" \
    bash "$SCRIPT_DIR/collect-linux-inventory.sh" --output-dir "$LINUX_DIR"
copy_latest_inventory_to_canonical

SECURITY_ARGS=(bash "$SCRIPT_DIR/linux-security-audit.sh" --output-dir "$LINUX_DIR" --summary-json "$LINUX_DIR/linux-security-summary.json")
if [[ "$QUICK_MODE" -eq 1 ]]; then
    SECURITY_ARGS+=(--quick)
fi
run_collector "linux-security-audit" "linux/linux-security-summary.json" "${SECURITY_ARGS[@]}"

if [[ "$RUN_HARDENING_PLAN" -eq 1 ]]; then
    run_collector \
        "linux-hardening-baseline-dry-run" \
        "linux/linux-hardening-plan-*.log" \
        bash "$SCRIPT_DIR/linux-hardening-baseline.sh" --report-dir "$LINUX_DIR"
else
    record_status "linux-hardening-baseline-dry-run" "skipped" "linux/linux-hardening-plan-*.log"
fi

if [[ "$RUN_BACKUP" -eq 1 ]]; then
    BACKUP_ARGS=(sh "$SCRIPT_DIR/backup-readiness-audit.sh" --output-dir "$BACKUP_DIR" --quiet)
    for expected_path in "${EXPECTED_BACKUP_PATHS[@]}"; do
        BACKUP_ARGS+=(--expected-backup-path "$expected_path")
    done
    run_collector "linux-backup-readiness" "backup/backup-readiness.json" "${BACKUP_ARGS[@]}"
else
    record_status "linux-backup-readiness" "skipped" "backup/backup-readiness.json"
fi

write_bundle_metadata

log "Linux SecureInfra bundle directory: $BUNDLE_ROOT"
if [[ "$SKIP_ARCHIVE" -eq 0 ]]; then
    ARCHIVE_PATH="$(create_zip_archive)"
    log "Linux SecureInfra bundle ZIP: $ARCHIVE_PATH"
else
    log "Archive creation skipped."
fi

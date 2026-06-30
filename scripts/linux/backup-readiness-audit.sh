#!/usr/bin/env sh
set -eu

OUTPUT_DIR="reports/backup-readiness"
EXPECTED_BACKUP_PATHS=""
WARNING_AGE_DAYS=14
CRITICAL_AGE_DAYS=30
QUIET=0

usage() {
    cat <<USAGE
Usage: $0 [options]

Collects audit-only Linux backup readiness metadata. The script does not
delete, modify, restore, enumerate, or read backup contents.

Options:
  -o, --output-dir DIR             Directory for backup-readiness.json and findings CSV.
  --expected-backup-path PATH      Optional expected backup path to check with stat only.
                                   May be supplied more than once.
  --warning-age-days DAYS          Stale evidence warning threshold. Default: 14.
  --critical-age-days DAYS         Critical stale evidence threshold. Default: 30.
  -q, --quiet                      Suppress console summary.
  -h, --help                       Show this help.

Examples:
  $0 -o reports/backup
  $0 --expected-backup-path /mnt/example-backups --warning-age-days 14
USAGE
}

require_value() {
    option="$1"
    value="${2:-}"
    if [ -z "$value" ] || [ "${value#-}" != "$value" ]; then
        echo "Option $option requires a value." >&2
        usage
        exit 1
    fi
}

append_expected_path() {
    if [ -z "$EXPECTED_BACKUP_PATHS" ]; then
        EXPECTED_BACKUP_PATHS="$1"
    else
        EXPECTED_BACKUP_PATHS="${EXPECTED_BACKUP_PATHS}
$1"
    fi
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        -o|--output-dir)
            require_value "$1" "${2:-}"
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --expected-backup-path)
            require_value "$1" "${2:-}"
            append_expected_path "$2"
            shift 2
            ;;
        --warning-age-days)
            require_value "$1" "${2:-}"
            WARNING_AGE_DAYS="$2"
            shift 2
            ;;
        --critical-age-days)
            require_value "$1" "${2:-}"
            CRITICAL_AGE_DAYS="$2"
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

case "$WARNING_AGE_DAYS" in
    ''|*[!0-9]*)
        echo "--warning-age-days must be a positive integer." >&2
        exit 1
        ;;
esac
case "$CRITICAL_AGE_DAYS" in
    ''|*[!0-9]*)
        echo "--critical-age-days must be a positive integer." >&2
        exit 1
        ;;
esac
if [ "$WARNING_AGE_DAYS" -lt 1 ] || [ "$CRITICAL_AGE_DAYS" -lt "$WARNING_AGE_DAYS" ]; then
    echo "--critical-age-days must be greater than or equal to --warning-age-days." >&2
    exit 1
fi

mkdir -p "$OUTPUT_DIR"
JSON_PATH="$OUTPUT_DIR/backup-readiness.json"
CSV_PATH="$OUTPUT_DIR/backup-readiness-findings.csv"
TMP_FINDINGS="$OUTPUT_DIR/.backup-readiness-findings.tmp"
TMP_TOOLS="$OUTPUT_DIR/.backup-readiness-tools.tmp"
TMP_SERVICES="$OUTPUT_DIR/.backup-readiness-services.tmp"
TMP_TIMERS="$OUTPUT_DIR/.backup-readiness-timers.tmp"
TMP_CRON="$OUTPUT_DIR/.backup-readiness-cron.tmp"
TMP_PATHS="$OUTPUT_DIR/.backup-readiness-paths.tmp"

: > "$TMP_FINDINGS"
: > "$TMP_TOOLS"
: > "$TMP_SERVICES"
: > "$TMP_TIMERS"
: > "$TMP_CRON"
: > "$TMP_PATHS"

HOSTNAME_VALUE="$(hostname 2>/dev/null || echo unknown)"
GENERATED_AT_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
NOW_EPOCH="$(date -u +%s)"
LATEST_EVIDENCE_EPOCH=""
FINDING_COUNT=0
CRITICAL_COUNT=0
HIGH_COUNT=0
MEDIUM_COUNT=0
LOW_COUNT=0
INFO_COUNT=0
TOOL_COUNT=0
SERVICE_COUNT=0
TIMER_COUNT=0
CRON_COUNT=0
EXPECTED_PATH_COUNT=0
MISSING_PATH_COUNT=0
STALE_PATH_COUNT=0

have_cmd() {
    command -v "$1" >/dev/null 2>&1
}

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/\\t/g; s/\r/\\r/g' | tr '\n' ' '
}

csv_escape() {
    printf '%s' "$1" | sed 's/"/""/g'
}

iso_from_epoch() {
    epoch="$1"
    if date -u -d "@$epoch" +%Y-%m-%dT%H:%M:%SZ >/dev/null 2>&1; then
        date -u -d "@$epoch" +%Y-%m-%dT%H:%M:%SZ
    elif date -u -r "$epoch" +%Y-%m-%dT%H:%M:%SZ >/dev/null 2>&1; then
        date -u -r "$epoch" +%Y-%m-%dT%H:%M:%SZ
    else
        printf '%s' ""
    fi
}

path_mtime_epoch() {
    path="$1"
    if stat -c %Y "$path" >/dev/null 2>&1; then
        stat -c %Y "$path"
    elif stat -f %m "$path" >/dev/null 2>&1; then
        stat -f %m "$path"
    else
        printf '%s' ""
    fi
}

update_latest_evidence() {
    epoch="$1"
    if [ -z "$epoch" ]; then
        return
    fi
    if [ -z "$LATEST_EVIDENCE_EPOCH" ] || [ "$epoch" -gt "$LATEST_EVIDENCE_EPOCH" ]; then
        LATEST_EVIDENCE_EPOCH="$epoch"
    fi
}

severity_count_increment() {
    case "$1" in
        Critical|critical) CRITICAL_COUNT=$((CRITICAL_COUNT + 1)) ;;
        High|high) HIGH_COUNT=$((HIGH_COUNT + 1)) ;;
        Medium|medium) MEDIUM_COUNT=$((MEDIUM_COUNT + 1)) ;;
        Low|low) LOW_COUNT=$((LOW_COUNT + 1)) ;;
        *) INFO_COUNT=$((INFO_COUNT + 1)) ;;
    esac
}

add_finding() {
    finding_type="$1"
    severity="$2"
    title="$3"
    affected_object="$4"
    evidence="$5"
    recommendation="$6"
    source="$7"
    confidence="$8"
    last_timestamp="$9"
    restore_status="${10}"
    monitoring_status="${11}"
    limitation="${12}"

    FINDING_COUNT=$((FINDING_COUNT + 1))
    severity_count_increment "$severity"
    if [ "$FINDING_COUNT" -gt 1 ]; then
        printf ',\n' >> "$TMP_FINDINGS"
    fi
    {
        printf '    {\n'
        printf '      "FindingType": "%s",\n' "$(json_escape "$finding_type")"
        printf '      "Severity": "%s",\n' "$(json_escape "$severity")"
        printf '      "Title": "%s",\n' "$(json_escape "$title")"
        printf '      "AffectedObject": "%s",\n' "$(json_escape "$affected_object")"
        printf '      "Evidence": "%s",\n' "$(json_escape "$evidence")"
        printf '      "Recommendation": "%s",\n' "$(json_escape "$recommendation")"
        printf '      "BackupEvidenceSource": "%s",\n' "$(json_escape "$source")"
        printf '      "BackupEvidenceConfidence": "%s",\n' "$(json_escape "$confidence")"
        printf '      "LastBackupEvidenceTimestamp": "%s",\n' "$(json_escape "$last_timestamp")"
        printf '      "RestoreTestEvidenceStatus": "%s",\n' "$(json_escape "$restore_status")"
        printf '      "MonitoringEvidenceStatus": "%s",\n' "$(json_escape "$monitoring_status")"
        printf '      "Limitations": ["%s"],\n' "$(json_escape "$limitation")"
        printf '      "RequiresOwnerReview": true,\n'
        printf '      "SafeToAutoRemediate": false\n'
        printf '    }'
    } >> "$TMP_FINDINGS"
}

add_json_object_line() {
    file_path="$1"
    object_text="$2"
    if [ -s "$file_path" ]; then
        printf ',\n' >> "$file_path"
    fi
    printf '%s' "$object_text" >> "$file_path"
}

for tool in rsync borg restic duplicity rclone veeam; do
    if have_cmd "$tool"; then
        TOOL_COUNT=$((TOOL_COUNT + 1))
        tool_path="$(command -v "$tool" 2>/dev/null || true)"
        add_json_object_line "$TMP_TOOLS" "    {\"name\":\"$(json_escape "$tool")\",\"path\":\"$(json_escape "$tool_path")\"}"
    fi
done

if have_cmd systemctl; then
    systemctl list-unit-files --type=service --no-legend 2>/dev/null |
        grep -Ei 'backup|borg|restic|duplicity|rclone|veeam|snapshot' |
        sed -n '1,50p' |
        while read -r unit state rest; do
            [ -n "$unit" ] || continue
            printf '%s|%s\n' "$unit" "$state" >> "$TMP_SERVICES"
        done

    systemctl list-timers --all --no-legend 2>/dev/null |
        grep -Ei 'backup|borg|restic|duplicity|rclone|veeam|snapshot' |
        sed -n '1,50p' |
        while read -r line; do
            [ -n "$line" ] || continue
            unit="$(printf '%s\n' "$line" | awk '{print $(NF-1)}')"
            [ -n "$unit" ] || unit="$line"
            printf '%s\n' "$unit" >> "$TMP_TIMERS"
        done
fi

if [ -s "$TMP_SERVICES" ]; then
    SERVICE_COUNT="$(wc -l < "$TMP_SERVICES" | tr -d ' ')"
fi
if [ -s "$TMP_TIMERS" ]; then
    TIMER_COUNT="$(wc -l < "$TMP_TIMERS" | tr -d ' ')"
fi

for cron_path in /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    if [ -e "$cron_path" ]; then
        find "$cron_path" -maxdepth 1 -type f 2>/dev/null |
            grep -Ei 'backup|borg|restic|duplicity|rclone|veeam|snapshot' |
            sed -n '1,50p' >> "$TMP_CRON" || true
    fi
done
if [ -s "$TMP_CRON" ]; then
    CRON_COUNT="$(wc -l < "$TMP_CRON" | tr -d ' ')"
fi

if [ -n "$EXPECTED_BACKUP_PATHS" ]; then
    printf '%s\n' "$EXPECTED_BACKUP_PATHS" | while IFS= read -r expected_path; do
        [ -n "$expected_path" ] || continue
        if [ -e "$expected_path" ]; then
            mtime="$(path_mtime_epoch "$expected_path")"
            last_write="$(iso_from_epoch "$mtime")"
            age_days=0
            if [ -n "$mtime" ]; then
                age_days=$(( (NOW_EPOCH - mtime) / 86400 ))
            fi
            status="recent"
            if [ "$age_days" -ge "$WARNING_AGE_DAYS" ]; then
                status="stale"
            fi
            printf 'exists|%s|%s|%s|%s\n' "$expected_path" "$last_write" "$age_days" "$status" >> "$TMP_PATHS"
        else
            printf 'missing|%s|||\n' "$expected_path" >> "$TMP_PATHS"
        fi
    done
fi

if [ -s "$TMP_PATHS" ]; then
    EXPECTED_PATH_COUNT="$(wc -l < "$TMP_PATHS" | tr -d ' ')"
    while IFS='|' read -r status path last_write age_days path_status; do
        if [ "$status" = "missing" ]; then
            MISSING_PATH_COUNT=$((MISSING_PATH_COUNT + 1))
            add_finding "ExpectedBackupPathMissing" "High" "Expected backup path is missing" "$path" "The expected backup path was not present. Contents were not enumerated." "Confirm the expected backup target, mount state, permissions, and backup job ownership." "expected_backup_path" "high" "" "not_provided" "not_provided" "Only path metadata was checked."
        else
            mtime="$(path_mtime_epoch "$path")"
            update_latest_evidence "$mtime"
            if [ "$age_days" -ge "$WARNING_AGE_DAYS" ]; then
                STALE_PATH_COUNT=$((STALE_PATH_COUNT + 1))
                add_finding "ExpectedBackupPathStale" "High" "Expected backup path is stale" "$path" "LastWriteTimeUtc=$last_write; AgeDays=$age_days; WarningAgeDays=$WARNING_AGE_DAYS; CriticalAgeDays=$CRITICAL_AGE_DAYS." "Validate the backup job, schedule, storage target, and monitoring alerts before relying on this evidence." "expected_backup_path" "medium" "$last_write" "not_provided" "not_provided" "Directory or file contents were not enumerated or read."
            fi
        fi
    done < "$TMP_PATHS"
fi

LATEST_EVIDENCE_UTC=""
if [ -n "$LATEST_EVIDENCE_EPOCH" ]; then
    LATEST_EVIDENCE_UTC="$(iso_from_epoch "$LATEST_EVIDENCE_EPOCH")"
fi

if [ "$SERVICE_COUNT" -gt 0 ] || [ "$TOOL_COUNT" -gt 0 ] || [ "$TIMER_COUNT" -gt 0 ] || [ "$CRON_COUNT" -gt 0 ]; then
    add_finding "BackupServicePresentHealthUnverified" "Info" "Backup-related tool or schedule signal is present but health is unverified" "$HOSTNAME_VALUE" "Visible backup-related tools/services/timers/cron names were found. Presence does not prove successful or recoverable backups." "Review backup job history, alerts, recent successful backup evidence, and restore test evidence with the system owner." "tool_and_scheduler_inventory" "low" "$LATEST_EVIDENCE_UTC" "not_provided" "not_provided" "Tool and schedule inventory does not prove backup success or restoreability."
fi

recent_cutoff=$((NOW_EPOCH - WARNING_AGE_DAYS * 86400))
if [ -z "$LATEST_EVIDENCE_EPOCH" ] || [ "$LATEST_EVIDENCE_EPOCH" -lt "$recent_cutoff" ]; then
    severity="Medium"
    if [ "$EXPECTED_PATH_COUNT" -gt 0 ]; then
        severity="High"
    fi
    add_finding "NoRecentBackupEvidenceFound" "$severity" "No recent backup evidence was found" "$HOSTNAME_VALUE" "No expected path timestamp or visible local backup evidence was observed within $WARNING_AGE_DAYS day(s)." "Collect backup job history or storage target evidence and confirm the most recent successful backup with the owner." "collector_summary" "low" "$LATEST_EVIDENCE_UTC" "not_provided" "not_provided" "Centralized backup platforms may hold authoritative job history outside this host."
fi

if [ "$TOOL_COUNT" -eq 0 ] && [ "$SERVICE_COUNT" -eq 0 ] && [ "$TIMER_COUNT" -eq 0 ] && [ "$CRON_COUNT" -eq 0 ] && [ "$EXPECTED_PATH_COUNT" -eq 0 ]; then
    add_finding "BackupEvidenceUnavailable" "Info" "Backup readiness evidence is unavailable or incomplete" "$HOSTNAME_VALUE" "No local backup tool, service, timer, cron filename, or expected backup path metadata was available." "Provide approved backup job history, monitoring evidence, or expected backup path metadata for review." "collector_summary" "low" "" "not_provided" "not_provided" "Absence of local metadata does not prove backups do not exist."
fi

add_finding "RestoreTestEvidenceMissing" "Medium" "Restore test evidence was not provided" "$HOSTNAME_VALUE" "This collector does not run restore operations and did not receive separate restore test evidence." "Confirm the date, scope, and result of the latest approved restore test." "governance_review" "low" "$LATEST_EVIDENCE_UTC" "missing" "not_provided" "Restore readiness cannot be proven without a documented restore test."
add_finding "BackupMonitoringEvidenceMissing" "Medium" "Backup monitoring evidence was not provided" "$HOSTNAME_VALUE" "No backup monitoring alert or success/failure notification evidence was collected." "Confirm backup monitoring ownership, alert routing, and failure escalation procedures." "governance_review" "low" "$LATEST_EVIDENCE_UTC" "not_provided" "missing" "Monitoring coverage should be validated in the backup or monitoring platform."

{
    printf '"FindingType","Severity","Title","AffectedObject","Evidence","Recommendation"\n'
    sed -n 's/.*"FindingType": "\([^"]*\)".*/\1/p' "$TMP_FINDINGS" | while IFS= read -r finding_type; do
        :
    done
} > "$CSV_PATH"

# Rewrite the CSV from the JSON source with simple field extraction. This keeps
# the script dependency-light while avoiding backup content reads.
awk '
    /"FindingType":/ {gsub(/^.*"FindingType": "/,""); gsub(/",$/,""); type=$0}
    /"Severity":/ {gsub(/^.*"Severity": "/,""); gsub(/",$/,""); sev=$0}
    /"Title":/ {gsub(/^.*"Title": "/,""); gsub(/",$/,""); title=$0}
    /"AffectedObject":/ {gsub(/^.*"AffectedObject": "/,""); gsub(/",$/,""); obj=$0}
    /"Evidence":/ {gsub(/^.*"Evidence": "/,""); gsub(/",$/,""); evidence=$0}
    /"Recommendation":/ {gsub(/^.*"Recommendation": "/,""); gsub(/",$/,""); rec=$0; printf "\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n", type, sev, title, obj, evidence, rec}
' "$TMP_FINDINGS" >> "$CSV_PATH"

tools_json="$(cat "$TMP_TOOLS")"
services_json=""
if [ -s "$TMP_SERVICES" ]; then
    first=1
    while IFS='|' read -r unit state; do
        if [ "$first" -eq 0 ]; then services_json="${services_json},
"; fi
        services_json="${services_json}    {\"name\":\"$(json_escape "$unit")\",\"state\":\"$(json_escape "$state")\"}"
        first=0
    done < "$TMP_SERVICES"
fi
timers_json=""
if [ -s "$TMP_TIMERS" ]; then
    first=1
    while IFS= read -r timer; do
        if [ "$first" -eq 0 ]; then timers_json="${timers_json},
"; fi
        timers_json="${timers_json}    {\"name\":\"$(json_escape "$timer")\"}"
        first=0
    done < "$TMP_TIMERS"
fi
cron_json=""
if [ -s "$TMP_CRON" ]; then
    first=1
    while IFS= read -r cron_file; do
        if [ "$first" -eq 0 ]; then cron_json="${cron_json},
"; fi
        cron_json="${cron_json}    {\"path\":\"$(json_escape "$cron_file")\"}"
        first=0
    done < "$TMP_CRON"
fi
paths_json=""
if [ -s "$TMP_PATHS" ]; then
    first=1
    while IFS='|' read -r status path last_write age_days path_status; do
        if [ "$first" -eq 0 ]; then paths_json="${paths_json},
"; fi
        exists=false
        if [ "$status" = "exists" ]; then exists=true; fi
        paths_json="${paths_json}    {\"path\":\"$(json_escape "$path")\",\"exists\":$exists,\"last_write_time_utc\":\"$(json_escape "$last_write")\",\"age_days\":\"$(json_escape "$age_days")\",\"status\":\"$(json_escape "$path_status")\",\"limitation\":\"Only path metadata was checked; backup contents were not enumerated or read.\"}"
        first=0
    done < "$TMP_PATHS"
fi

cat > "$JSON_PATH" <<JSON
{
  "ToolName": "backup-readiness-audit.sh",
  "ReportType": "backup-readiness",
  "Platform": "linux",
  "GeneratedAtUtc": "$GENERATED_AT_UTC",
  "HostName": "$(json_escape "$HOSTNAME_VALUE")",
  "WarningAgeDays": $WARNING_AGE_DAYS,
  "CriticalAgeDays": $CRITICAL_AGE_DAYS,
  "Summary": {
    "BackupHealthStatus": "Unverified",
    "DetectedToolCount": $TOOL_COUNT,
    "BackupServiceCount": $SERVICE_COUNT,
    "BackupTimerCount": $TIMER_COUNT,
    "BackupCronSignalCount": $CRON_COUNT,
    "ExpectedBackupPathCount": $EXPECTED_PATH_COUNT,
    "MissingExpectedPathCount": $MISSING_PATH_COUNT,
    "StaleExpectedPathCount": $STALE_PATH_COUNT,
    "LastBackupEvidenceTimestamp": "$LATEST_EVIDENCE_UTC",
    "RestoreTestEvidenceStatus": "missing",
    "MonitoringEvidenceStatus": "missing",
    "FindingCount": $FINDING_COUNT,
    "SeverityCounts": {
      "Critical": $CRITICAL_COUNT,
      "High": $HIGH_COUNT,
      "Medium": $MEDIUM_COUNT,
      "Low": $LOW_COUNT,
      "Info": $INFO_COUNT
    }
  },
  "BackupEvidence": {
    "Tools": [
$tools_json
    ],
    "Services": [
$services_json
    ],
    "Timers": [
$timers_json
    ],
    "CronSignals": [
$cron_json
    ],
    "ExpectedBackupPaths": [
$paths_json
    ]
  },
  "Findings": [
$(cat "$TMP_FINDINGS")
  ],
  "Limitations": [
    "This collector does not read backup contents.",
    "This collector does not run restore operations.",
    "Local tool, service, timer, or cron evidence may not include centralized backup platform status."
  ],
  "Notes": [
    "Audit-only backup readiness evidence. No backup data is deleted, modified, restored, enumerated, or read.",
    "Service or tool presence is not proof of healthy, successful, or recoverable backups.",
    "Owner review is required before relying on any backup readiness conclusion."
  ]
}
JSON

rm -f "$TMP_FINDINGS" "$TMP_TOOLS" "$TMP_SERVICES" "$TMP_TIMERS" "$TMP_CRON" "$TMP_PATHS"

if [ "$QUIET" -eq 0 ]; then
    echo "Linux backup readiness report written to: $JSON_PATH"
    echo "Backup health status: Unverified"
    echo "Findings: $FINDING_COUNT"
fi

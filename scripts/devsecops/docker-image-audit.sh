#!/usr/bin/env bash
set -euo pipefail

IMAGE=""
DEEP=0
OUTPUT_DIR="reports"

usage() {
    cat <<USAGE
Usage: $0 IMAGE [--deep] [--output-dir DIR]

Audits Docker image metadata and optional runtime characteristics.
The script does not modify the image.

Options:
  --deep              Run a temporary container to collect extra details
  --output-dir DIR    Directory for the report. Default: reports
  -h, --help          Show this help
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
        --deep)
            DEEP=1
            shift
            ;;
        --output-dir)
            require_value "$1" "${2:-}"
            OUTPUT_DIR="${2:-}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            if [[ -z "$IMAGE" ]]; then
                IMAGE="$1"
                shift
            else
                echo "Unknown argument: $1" >&2
                usage
                exit 1
            fi
            ;;
    esac
done

if [[ -z "$IMAGE" ]]; then
    usage
    exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "docker command not found." >&2
    exit 1
fi

mkdir -p "$OUTPUT_DIR"
SAFE_IMAGE_NAME="$(echo "$IMAGE" | tr '/:@' '___')"
REPORT_FILE="$OUTPUT_DIR/docker-image-audit-${SAFE_IMAGE_NAME}-$(date -u +%Y%m%d-%H%M%S).txt"

section() {
    {
        echo
        echo "================================================================"
        echo "$1"
        echo "================================================================"
    } >> "$REPORT_FILE"
}

run_section() {
    local title="$1"
    shift
    section "$title"
    "$@" >> "$REPORT_FILE" 2>&1 || echo "Check failed: $title" >> "$REPORT_FILE"
}

write_header() {
    cat > "$REPORT_FILE" <<HEADER
Docker Image Audit Report
Image: $IMAGE
Generated UTC: $(date -u +%Y-%m-%dT%H:%M:%SZ)
Host: $(hostname 2>/dev/null || echo unknown)
HEADER
}

inspect_summary() {
    docker image inspect "$IMAGE" --format \
'ID: {{.Id}}
Created: {{.Created}}
Architecture: {{.Architecture}}
OS: {{.Os}}
User: {{.Config.User}}
Entrypoint: {{json .Config.Entrypoint}}
Command: {{json .Config.Cmd}}
ExposedPorts: {{json .Config.ExposedPorts}}
Volumes: {{json .Config.Volumes}}
WorkingDir: {{.Config.WorkingDir}}
Labels: {{json .Config.Labels}}'
}

inspect_env() {
    docker image inspect "$IMAGE" --format '{{range .Config.Env}}{{println .}}{{end}}' | sort
}

inspect_history() {
    docker history --no-trunc "$IMAGE"
}

runtime_checks() {
    docker run --rm --entrypoint /bin/sh "$IMAGE" -c '
        echo "Runtime identity:"; id 2>/dev/null || true
        echo; echo "Writable root check:"; touch /tmp/docker-audit-write-test 2>/dev/null && echo "tmp writable: yes" || echo "tmp writable: no"
        echo; echo "Package manager commands present:"; command -v apk apt-get dnf yum microdnf rpm dpkg 2>/dev/null || true
        echo; echo "SUID files, limited output:"; find / -xdev -perm -4000 -type f 2>/dev/null | sed -n "1,80p" || true
    '
}

write_header
run_section "Image metadata" inspect_summary
run_section "Environment variables" inspect_env
run_section "Image history" inspect_history

USER_VALUE="$(docker image inspect "$IMAGE" --format '{{.Config.User}}' 2>/dev/null || true)"
section "Baseline observations"
if [[ -z "$USER_VALUE" || "$USER_VALUE" =~ ^(root|0)(:|$) ]]; then
    echo "Finding: image runs as root or does not define a non-root user." >> "$REPORT_FILE"
else
    echo "OK: image defines user: $USER_VALUE" >> "$REPORT_FILE"
fi

if docker image inspect "$IMAGE" --format '{{json .Config.Env}}' | grep -Eiq 'password|passwd|secret|token|apikey|api_key'; then
    echo "Finding: environment metadata contains credential-like variable names. Review values and build process." >> "$REPORT_FILE"
else
    echo "OK: no credential-like variable names detected in image metadata." >> "$REPORT_FILE"
fi

if [[ "$DEEP" -eq 1 ]]; then
    run_section "Runtime checks" runtime_checks
else
    section "Runtime checks"
    echo "Skipped. Use --deep to run a temporary container for extra checks." >> "$REPORT_FILE"
fi

echo "Docker image audit written to: $REPORT_FILE"

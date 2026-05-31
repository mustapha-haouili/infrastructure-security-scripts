#!/usr/bin/env bash
set -euo pipefail

OUTPUT_DIR="reports"
CONTEXT=""

usage() {
    cat <<USAGE
Usage: $0 [--context NAME] [--output-dir DIR]

Reviews Kubernetes RBAC and workload security signals using kubectl.
The script does not change cluster configuration.

Options:
  --context NAME      kubectl context to use
  --output-dir DIR    Directory for the report. Default: reports
  -h, --help          Show this help

Examples:
  $0
      Audit the current kubectl context.
  $0 --context prod-admin
      Audit a named kubectl context.
  $0 --output-dir reports/kubernetes
      Write the report to a specific directory.
  $0 --context prod-admin --output-dir reports/kubernetes
      Combine explicit context and output directory.
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
        --context)
            require_value "$1" "${2:-}"
            CONTEXT="${2:-}"
            shift 2
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
            echo "Unknown argument: $1" >&2
            usage
            exit 1
            ;;
    esac
done

if ! command -v kubectl >/dev/null 2>&1; then
    echo "kubectl command not found." >&2
    exit 1
fi

KUBECTL=(kubectl)
if [[ -n "$CONTEXT" ]]; then
    KUBECTL+=(--context "$CONTEXT")
fi

mkdir -p "$OUTPUT_DIR"
CURRENT_CONTEXT="$("${KUBECTL[@]}" config current-context 2>/dev/null || echo unknown)"
SAFE_CONTEXT="$(echo "$CURRENT_CONTEXT" | tr '/:@' '___')"
REPORT_FILE="$OUTPUT_DIR/kubernetes-rbac-audit-${SAFE_CONTEXT}-$(date -u +%Y%m%d-%H%M%S).txt"

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
Kubernetes RBAC and Workload Security Audit
Context: $CURRENT_CONTEXT
Generated UTC: $(date -u +%Y-%m-%dT%H:%M:%SZ)
HEADER
}

cluster_summary() {
    "${KUBECTL[@]}" version --short 2>/dev/null || "${KUBECTL[@]}" version 2>/dev/null || true
    echo
    "${KUBECTL[@]}" get nodes -o wide
}

cluster_admin_bindings() {
    "${KUBECTL[@]}" get clusterrolebinding -o jsonpath='{range .items[?(@.roleRef.name=="cluster-admin")]}{.metadata.name}{" | "}{range .subjects[*]}{.kind}{":"}{.namespace}{":"}{.name}{","}{end}{"\n"}{end}'
}

wildcard_cluster_roles() {
    "${KUBECTL[@]}" get clusterroles -o jsonpath='{range .items[*]}{.metadata.name}{" | "}{range .rules[*]}verbs={.verbs};resources={.resources};apiGroups={.apiGroups}{" || "}{end}{"\n"}{end}' | grep -E '\*|verbs=\[.*\*.*\]|resources=\[.*\*.*\]' || true
}

privileged_pods() {
    "${KUBECTL[@]}" get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{" | hostNetwork="}{.spec.hostNetwork}{" | "}{range .spec.containers[*]}{.name}{":privileged="}{.securityContext.privileged}{",allowPrivilegeEscalation="}{.securityContext.allowPrivilegeEscalation}{",runAsUser="}{.securityContext.runAsUser}{";"}{end}{"\n"}{end}' | grep -E 'privileged=true|allowPrivilegeEscalation=true|hostNetwork=true|runAsUser=0' || true
}

hostpath_pods() {
    "${KUBECTL[@]}" get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{" | "}{range .spec.volumes[*]}{.name}{":hostPath="}{.hostPath.path}{";"}{end}{"\n"}{end}' | grep 'hostPath=/' || true
}

default_service_account_usage() {
    "${KUBECTL[@]}" get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{" | serviceAccount="}{.spec.serviceAccountName}{"\n"}{end}' | grep 'serviceAccount=default' || true
}

network_policy_coverage() {
    local namespaces
    namespaces="$("${KUBECTL[@]}" get namespaces -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')"
    while IFS= read -r ns; do
        [[ -z "$ns" ]] && continue
        local count
        count="$("${KUBECTL[@]}" get networkpolicy -n "$ns" --no-headers 2>/dev/null | wc -l | tr -d ' ')"
        printf '%s | network policies: %s\n' "$ns" "$count"
    done <<< "$namespaces"
}

write_header
run_section "Cluster summary" cluster_summary
run_section "Cluster-admin bindings" cluster_admin_bindings
run_section "Wildcard cluster roles" wildcard_cluster_roles
run_section "Privileged or high-risk pod settings" privileged_pods
run_section "Pods using hostPath volumes" hostpath_pods
run_section "Pods using default service account" default_service_account_usage
run_section "Network policy coverage by namespace" network_policy_coverage

echo "Kubernetes audit written to: $REPORT_FILE"

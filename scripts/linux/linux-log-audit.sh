#!/usr/bin/env bash
set -euo pipefail

OUTPUT_DIR="reports"
SUMMARY_JSON_PATH=""
QUICK_MODE=0
MAX_LOG_LINES=5000

usage() {
    cat <<USAGE
Usage: $0 [-o output_dir] [--summary-json file] [--quick]

Collects local Linux logging and audit coverage evidence. The script records
counts and coverage metadata only; it does not package raw authentication logs.
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
        -o|--output-dir) require_value "$1" "${2:-}"; OUTPUT_DIR="$2"; shift 2 ;;
        --summary-json) require_value "$1" "${2:-}"; SUMMARY_JSON_PATH="$2"; shift 2 ;;
        --quick) QUICK_MODE=1; MAX_LOG_LINES=1000; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
    esac
done

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required for JSON output." >&2
    exit 1
fi

mkdir -p "$OUTPUT_DIR"
HOSTNAME_VALUE="$(hostname 2>/dev/null || echo unknown)"
REPORT_FILE="$OUTPUT_DIR/linux-log-audit-${HOSTNAME_VALUE}-$(date -u +%Y%m%d-%H%M%S).txt"
if [[ -z "$SUMMARY_JSON_PATH" ]]; then
    SUMMARY_JSON_PATH="${REPORT_FILE%.txt}.summary.json"
fi

python3 - "$SUMMARY_JSON_PATH" "$REPORT_FILE" "$QUICK_MODE" "$MAX_LOG_LINES" <<'PYCODE'
import datetime as dt
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from collections import deque
from pathlib import Path

summary_path=Path(sys.argv[1]); report_path=Path(sys.argv[2]); quick_mode=sys.argv[3]=="1"; max_log_lines=int(sys.argv[4])
host=socket.gethostname() or "unknown"
now=dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00","Z")
root_context=os.geteuid()==0 if hasattr(os,"geteuid") else False
AUTH_LOGS=[Path("/var/log/auth.log"),Path("/var/log/secure")]; SYSLOGS=[Path("/var/log/syslog"),Path("/var/log/messages")]; AUDIT_LOG=Path("/var/log/audit/audit.log")

def run_command(args, timeout=8):
    if not args or not shutil.which(args[0]):
        return {"available":False,"returncode":None,"stdout":"","stderr":f"{args[0]} not found"}
    try:
        proc=subprocess.run(args,text=True,capture_output=True,timeout=timeout,check=False)
        return {"available":True,"returncode":proc.returncode,"stdout":proc.stdout,"stderr":proc.stderr}
    except Exception as exc:
        return {"available":True,"returncode":None,"stdout":"","stderr":str(exc)}

def file_status(path):
    return {"path":str(path),"exists":path.exists(),"readable":os.access(path,os.R_OK),"size_bytes":path.stat().st_size if path.exists() else 0}

def tail_lines(path, limit):
    rows=deque(maxlen=limit)
    try:
        with path.open("r",encoding="utf-8",errors="ignore") as handle:
            for line in handle: rows.append(line.rstrip("\n"))
    except Exception:
        return []
    return list(rows)

def journal_sample():
    result=run_command(["journalctl","-n",str(max_log_lines),"--no-pager"],timeout=10)
    return result["stdout"].splitlines() if result["available"] and result["returncode"]==0 else []

def count_patterns(lines):
    joined="\n".join(lines).lower()
    return {"failed_password_events":len(re.findall(r"failed password|authentication failure|invalid user",joined)),"sudo_events":len(re.findall(r"\bsudo\b|pam_unix\(sudo",joined)),"su_events":len(re.findall(r"\bsu\b|pam_unix\(su",joined)),"ssh_accepted_events":len(re.findall(r"accepted password|accepted publickey",joined))}

def service_state(name):
    result=run_command(["systemctl","is-active",name])
    if result["available"]:
        return {"service":name,"checked_with":"systemctl","state":(result["stdout"].strip() or result["stderr"].strip() or "unknown"),"returncode":result["returncode"]}
    return {"service":name,"checked_with":"systemctl","state":"unknown","returncode":None}

def binary_present(*names):
    return any(shutil.which(name) for name in names)

log_files=[file_status(path) for path in AUTH_LOGS+SYSLOGS+[AUDIT_LOG]]
readable_auth_paths=[Path(item["path"]) for item in log_files if item["path"] in {str(p) for p in AUTH_LOGS} and item["readable"]]
lines=[]
for path in readable_auth_paths: lines.extend(tail_lines(path,max_log_lines))
if not lines: lines=journal_sample()
pattern_counts=count_patterns(lines)
auditd_state=service_state("auditd"); rsyslog_state=service_state("rsyslog"); journald_state=service_state("systemd-journald"); wazuh_state=service_state("wazuh-agent"); ossec_state=service_state("ossec")
wazuh_detected=Path("/var/ossec").exists() or binary_present("wazuh-control","ossec-control") or wazuh_state.get("state")=="active" or ossec_state.get("state")=="active"
audit_tooling_present=binary_present("auditctl","ausearch") or AUDIT_LOG.exists()
findings=[]
if not readable_auth_paths and not lines:
    findings.append({"id":"LINUX-LOG-AUTH-COVERAGE-001","severity":"info","title":"Linux authentication log evidence was not available locally","recommendation":"Confirm whether authentication logs are retained locally, available through journald, or forwarded to a central logging platform.","evidence":"No readable /var/log/auth.log or /var/log/secure evidence was collected, and journalctl did not provide a readable sample.","affected_object":f"{host}: authentication log coverage"})
if auditd_state.get("state") != "active":
    findings.append({"id":"LINUX-LOG-AUDITD-001","severity":"medium" if audit_tooling_present else "info","title":"Linux auditd service is not active or could not be verified","recommendation":"Validate whether auditd or an equivalent EDR/logging control is required for this host and document compensating controls if local auditd is not used.","evidence":f"auditd state: {auditd_state.get('state')}; audit tooling present: {audit_tooling_present}","affected_object":f"{host}: auditd coverage"})
if not wazuh_detected:
    findings.append({"id":"LINUX-LOG-WAZUH-COVERAGE-001","severity":"info","title":"Wazuh or OSSEC local agent was not detected","recommendation":"If Wazuh rules are used for this customer, validate that equivalent telemetry is collected by a local agent, forwarding layer, or central integration.","evidence":"No /var/ossec directory, wazuh-control, ossec-control, active wazuh-agent, or active ossec service was detected locally.","affected_object":f"{host}: Wazuh/OSSEC telemetry coverage"})
if pattern_counts["failed_password_events"] >= 20:
    findings.append({"id":"LINUX-LOG-AUTH-FAILURES-001","severity":"medium","title":"Linux authentication log sample contains repeated failed authentication events","recommendation":"Review authentication telemetry in the customer's logging platform and validate source addresses, accounts, and lockout/MFA controls.","evidence":f"Failed authentication indicators in local sample: {pattern_counts['failed_password_events']}. Raw log lines are not packaged.","affected_object":f"{host}: authentication failures"})
finding_counts={name:0 for name in ("critical","high","medium","low","info")}
for item in findings:
    sev=str(item.get("severity","info")).lower(); finding_counts[sev if sev in finding_counts else "info"]+=1
summary={"host":host,"generated_at_utc":now,"source_script":"linux-log-audit.sh","collector_type":"linux-log-audit","root_context":root_context,"quick_mode":quick_mode,"safety_note":"Counts and coverage metadata only. Raw authentication logs are not packaged.","log_files":log_files,"auth_log_sample_line_count":len(lines),"auth_log_event_counts":pattern_counts,"services":{"auditd":auditd_state,"rsyslog":rsyslog_state,"systemd_journald":journald_state,"wazuh_agent":wazuh_state,"ossec":ossec_state},"central_logging_hints":{"wazuh_or_ossec_detected":wazuh_detected,"rsyslog_state":rsyslog_state,"journald_state":journald_state},"finding_counts":finding_counts,"findings":findings}
summary_path.parent.mkdir(parents=True, exist_ok=True); summary_path.write_text(json.dumps(summary,indent=2,sort_keys=True),encoding="utf-8")
lines_out=["SecureInfra Linux Log and Audit Coverage Audit",f"Host: {host}",f"GeneratedAtUtc: {now}","Safety: metadata/counts only; raw log lines are not packaged.","",f"Authentication log sample lines counted: {len(lines)}",f"Event counts: {json.dumps(pattern_counts,sort_keys=True)}",f"auditd state: {auditd_state.get('state')}",f"Wazuh/OSSEC detected: {wazuh_detected}","","Findings:"]
for finding in findings: lines_out.append(f"- [{finding['severity']}] {finding['id']} {finding['title']} :: {finding['evidence']}")
report_path.write_text("\n".join(lines_out)+"\n",encoding="utf-8")
print(str(summary_path))
PYCODE

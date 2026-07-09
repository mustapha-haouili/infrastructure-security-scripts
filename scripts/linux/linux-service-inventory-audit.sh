#!/usr/bin/env bash
set -euo pipefail

OUTPUT_DIR="reports"
SUMMARY_JSON_PATH=""
QUICK_MODE=0
MAX_SERVICES=500

usage() {
    cat <<USAGE
Usage: $0 [-o output_dir] [--summary-json file] [--quick]

Collects local Linux service and persistence inventory evidence. This is a
read-only local inventory. It does not stop, start, enable, disable, or modify
services, unit files, cron entries, or startup configuration.
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
        --quick) QUICK_MODE=1; MAX_SERVICES=200; shift ;;
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
REPORT_FILE="$OUTPUT_DIR/linux-service-inventory-audit-${HOSTNAME_VALUE}-$(date -u +%Y%m%d-%H%M%S).txt"
if [[ -z "$SUMMARY_JSON_PATH" ]]; then
    SUMMARY_JSON_PATH="${REPORT_FILE%.txt}.summary.json"
fi

python3 - "$SUMMARY_JSON_PATH" "$REPORT_FILE" "$QUICK_MODE" "$MAX_SERVICES" <<'PYCODE'
import datetime as dt
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
from pathlib import Path

summary_path=Path(sys.argv[1]); report_path=Path(sys.argv[2]); quick_mode=sys.argv[3]=="1"; max_services=int(sys.argv[4])
host=socket.gethostname() or "unknown"
now=dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00","Z")
root_context=os.geteuid()==0 if hasattr(os,"geteuid") else False

SYSTEM_SERVICE_DIRS=[Path('/etc/systemd/system'),Path('/usr/lib/systemd/system'),Path('/lib/systemd/system')]
SENSITIVE_STARTUP_PATHS=[Path('/etc/cron.d'),Path('/etc/cron.daily'),Path('/etc/cron.hourly'),Path('/etc/cron.weekly'),Path('/etc/cron.monthly'),Path('/etc/init.d'),Path('/etc/rc.local')]
CUSTOM_EXEC_PREFIXES=('/opt/','/srv/','/home/','/tmp/','/var/www/','/var/tmp/')
TRUSTED_EXEC_PREFIXES=('/usr/bin/','/usr/sbin/','/bin/','/sbin/','/usr/lib/','/lib/','/snap/bin/')

def run_command(args, timeout=10):
    if not args or not shutil.which(args[0]):
        return {"available":False,"returncode":None,"stdout":"","stderr":f"{args[0]} not found"}
    try:
        proc=subprocess.run(args,text=True,capture_output=True,timeout=timeout,check=False)
        return {"available":True,"returncode":proc.returncode,"stdout":proc.stdout,"stderr":proc.stderr}
    except Exception as exc:
        return {"available":True,"returncode":None,"stdout":"","stderr":str(exc)}

def parse_unit_files():
    result=run_command(['systemctl','list-unit-files','--type=service','--no-pager','--no-legend'],timeout=20)
    rows=[]
    if not result['available'] or result['returncode'] not in (0,1):
        return rows,result
    for line in result['stdout'].splitlines():
        parts=line.split()
        if len(parts) >= 2 and parts[0].endswith('.service'):
            rows.append({'unit':parts[0],'enabled_state':parts[1]})
        if len(rows) >= max_services:
            break
    return rows,result

def parse_running_units():
    result=run_command(['systemctl','list-units','--type=service','--all','--no-pager','--no-legend'],timeout=20)
    states={}
    if not result['available'] or result['returncode'] not in (0,1):
        return states,result
    for line in result['stdout'].splitlines():
        parts=line.split(None,4)
        if len(parts) >= 4 and parts[0].endswith('.service'):
            states[parts[0]]={'load':parts[1],'active':parts[2],'sub':parts[3],'description':parts[4] if len(parts)>4 else ''}
    return states,result

def show_unit(unit):
    props='Id,Names,LoadState,ActiveState,SubState,UnitFileState,FragmentPath,User,Group,ExecStart,Description'
    result=run_command(['systemctl','show',unit,'--property',props,'--no-pager'],timeout=8)
    data={}
    if result['available'] and result['returncode']==0:
        for line in result['stdout'].splitlines():
            if '=' in line:
                k,v=line.split('=',1); data[k]=v
    return data

def exec_paths(exec_start):
    text=str(exec_start or '')
    # systemctl show ExecStart may contain { path=... ; argv[]=... }
    paths=re.findall(r'path=([^ ;}]+)', text)
    if paths:
        return paths
    candidates=[]
    for token in re.split(r'\s+', text):
        token=token.strip('"\'')
        if token.startswith('/'):
            candidates.append(token)
    return candidates[:5]

def path_mode_summary(path):
    try:
        st=Path(path).stat()
        return {'exists':True,'mode':oct(st.st_mode & 0o777),'owner_uid':st.st_uid,'group_gid':st.st_gid,'group_or_world_writable':bool(st.st_mode & (stat.S_IWGRP|stat.S_IWOTH))}
    except Exception as exc:
        return {'exists':False,'error':str(exc),'group_or_world_writable':False}

def startup_inventory():
    rows=[]
    for path in SENSITIVE_STARTUP_PATHS:
        if path.is_file():
            rows.append({'path':str(path),'type':'file','mode':path_mode_summary(path)})
        elif path.is_dir():
            try:
                count=sum(1 for item in path.iterdir() if item.is_file())
            except Exception:
                count=None
            rows.append({'path':str(path),'type':'directory','file_count':count,'mode':path_mode_summary(path)})
    return rows

unit_files,unit_file_cmd=parse_unit_files()
running_states,running_cmd=parse_running_units()
services=[]; findings=[]; failed_units=[]; writable_units=[]; custom_root_services=[]
for row in unit_files:
    unit=row['unit']; state=running_states.get(unit,{})
    detail=show_unit(unit)
    fragment=detail.get('FragmentPath') or ''
    user=detail.get('User') or 'root'
    active=detail.get('ActiveState') or state.get('active') or 'unknown'
    unit_file_state=detail.get('UnitFileState') or row.get('enabled_state') or 'unknown'
    execs=exec_paths(detail.get('ExecStart',''))
    service={'unit':unit,'enabled_state':unit_file_state,'active_state':active,'sub_state':detail.get('SubState') or state.get('sub') or 'unknown','user':user or 'root','fragment_path':fragment,'description':detail.get('Description') or state.get('description') or '', 'exec_paths':execs[:5]}
    if fragment:
        service['unit_file_mode']=path_mode_summary(fragment)
        if service['unit_file_mode'].get('group_or_world_writable'):
            writable_units.append(service)
    if active == 'failed':
        failed_units.append(service)
    if unit_file_state in {'enabled','static','generated'} and (user in {'','root'}):
        for path in execs:
            if path.startswith(CUSTOM_EXEC_PREFIXES):
                custom_root_services.append(service); break
    services.append(service)

if not unit_files:
    findings.append({'id':'LINUX-SERVICE-COVERAGE-001','severity':'info','title':'Linux systemd service inventory was not available','recommendation':'Provide equivalent service inventory evidence or run on a host with systemctl available.','evidence':'systemctl list-unit-files did not return service inventory. This may be expected in containers or non-systemd systems.','affected_object':f'{host}: service inventory coverage'})
if writable_units:
    sample='; '.join(f"{s['unit']}={s.get('fragment_path','')}" for s in writable_units[:10])
    findings.append({'id':'LINUX-SERVICE-UNIT-WRITABLE-001','severity':'high','title':'Linux service unit files are group- or world-writable','recommendation':'Restrict service unit files to root-owned, non-writable permissions for group/other after validating deployment ownership.','evidence':f'Writable service unit files: {sample}','affected_object':f'{host}: systemd unit file permissions'})
if failed_units:
    sample='; '.join(s['unit'] for s in failed_units[:10])
    findings.append({'id':'LINUX-SERVICE-FAILED-001','severity':'low','title':'Linux services are in failed state','recommendation':'Review failed services with the system owner to confirm whether they affect security monitoring, backup, patching, or business applications.','evidence':f'Failed services: {sample}','affected_object':f'{host}: failed systemd services'})
if custom_root_services:
    sample='; '.join(f"{s['unit']} -> {','.join(s.get('exec_paths',[])[:2])}" for s in custom_root_services[:10])
    findings.append({'id':'LINUX-SERVICE-CUSTOM-ROOT-001','severity':'medium','title':'Enabled root service executes from a custom application path','recommendation':'Validate service owner, file ownership, deployment process, monitoring, and whether the service should run as a less-privileged account.','evidence':f'Custom root service examples: {sample}','affected_object':f'{host}: root service execution paths'})
startup=startup_inventory()
writable_startup=[row for row in startup if row.get('mode',{}).get('group_or_world_writable')]
if writable_startup:
    sample='; '.join(row['path'] for row in writable_startup[:10])
    findings.append({'id':'LINUX-PERSISTENCE-STARTUP-WRITABLE-001','severity':'high','title':'Linux startup or cron path is group- or world-writable','recommendation':'Restrict startup and cron paths to approved administrative ownership and permissions.','evidence':f'Writable startup paths: {sample}','affected_object':f'{host}: startup persistence paths'})

finding_counts={name:0 for name in ('critical','high','medium','low','info')}
for item in findings:
    sev=str(item.get('severity','info')).lower(); finding_counts[sev if sev in finding_counts else 'info']+=1
summary={'host':host,'generated_at_utc':now,'source_script':'linux-service-inventory-audit.sh','collector_type':'linux-service-inventory','root_context':root_context,'quick_mode':quick_mode,'safety_note':'Read-only local service and startup inventory. No service or startup configuration was changed.','systemctl_available':bool(unit_file_cmd.get('available')),'service_count':len(services),'service_inventory_sample':services[:100],'startup_inventory':startup,'finding_counts':finding_counts,'findings':findings}
summary_path.parent.mkdir(parents=True,exist_ok=True); summary_path.write_text(json.dumps(summary,indent=2,sort_keys=True),encoding='utf-8')
lines=['SecureInfra Linux Service Inventory Audit',f'Host: {host}',f'GeneratedAtUtc: {now}','Safety: read-only; no service or startup configuration was changed.','',f'Services inventoried: {len(services)}',f'Startup paths reviewed: {len(startup)}','','Findings:']
for finding in findings:
    lines.append(f"- [{finding['severity']}] {finding['id']} {finding['title']} :: {finding['evidence']}")
report_path.write_text('\n'.join(lines)+'\n',encoding='utf-8')
print(str(summary_path))
PYCODE

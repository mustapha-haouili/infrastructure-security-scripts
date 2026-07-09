#!/usr/bin/env bash
set -euo pipefail

OUTPUT_DIR="reports"
SUMMARY_JSON_PATH=""
QUICK_MODE=0

usage() {
    cat <<USAGE
Usage: $0 [-o output_dir] [--summary-json file] [--quick]

Collects local Linux network exposure evidence. This is a read-only local
listener/firewall inventory, not an active network scan. It does not probe
remote hosts or subnets.
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
        --quick) QUICK_MODE=1; shift ;;
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
REPORT_FILE="$OUTPUT_DIR/linux-network-exposure-audit-${HOSTNAME_VALUE}-$(date -u +%Y%m%d-%H%M%S).txt"
if [[ -z "$SUMMARY_JSON_PATH" ]]; then
    SUMMARY_JSON_PATH="${REPORT_FILE%.txt}.summary.json"
fi

python3 - "$SUMMARY_JSON_PATH" "$REPORT_FILE" "$QUICK_MODE" <<'PYCODE'
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path

summary_path = Path(sys.argv[1])
report_path = Path(sys.argv[2])
quick_mode = sys.argv[3] == "1"
host = socket.gethostname() or "unknown"
now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
root_context = os.geteuid() == 0 if hasattr(os, "geteuid") else False

SERVICE_NAMES = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",111:"RPC bind",123:"NTP",135:"RPC Endpoint Mapper",139:"NetBIOS",143:"IMAP",389:"LDAP",443:"HTTPS",445:"SMB",636:"LDAPS",873:"rsync",1433:"MSSQL",1521:"Oracle DB",2049:"NFS",2375:"Docker API",2376:"Docker API TLS",3000:"Web application",3306:"MySQL",3389:"RDP/xrdp",5000:"Web/API service",5432:"PostgreSQL",5601:"Kibana",5900:"VNC",5985:"WinRM HTTP",5986:"WinRM HTTPS",6379:"Redis",8000:"Web/API service",8080:"HTTP alternate",8443:"HTTPS alternate",9000:"Web/API service",9200:"Elasticsearch HTTP",9300:"Elasticsearch transport",11211:"Memcached",15672:"RabbitMQ management",27017:"MongoDB"}
REMOTE_ADMIN_PORTS={22,3389,5900,5985,5986}
CLEAR_TEXT_OR_LEGACY_PORTS={21,23,110,143}
DATABASE_OR_CACHE_PORTS={1433,1521,3306,5432,6379,9200,9300,11211,27017}
FILE_SHARING_PORTS={111,139,445,873,2049}
CONTAINER_API_PORTS={2375,2376}
WEB_PORTS={80,443,3000,5000,5601,8000,8080,8443,9000,15672}

def run_command(args, timeout=12):
    if not args or not shutil.which(args[0]):
        return {"available": False, "returncode": None, "stdout": "", "stderr": f"{args[0]} not found"}
    try:
        proc = subprocess.run(args, text=True, capture_output=True, timeout=timeout, check=False)
        return {"available": True, "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}
    except Exception as exc:
        return {"available": True, "returncode": None, "stdout": "", "stderr": str(exc)}

def extract_process(raw):
    match = re.search(r'users:\(\("(?P<name>[^"]+)"', raw or "")
    if match:
        return match.group("name")
    match = re.search(r'program=(?P<name>[^,\s]+)', raw or "")
    return match.group("name") if match else ""

def split_host_port(value):
    text = str(value or "").strip().replace("[", "").replace("]", "")
    if "%" in text and text.count(":") > 1:
        left, _, right = text.rpartition(":")
        text = f"{left.split('%', 1)[0]}:{right}"
    if ":" not in text:
        return text, None
    address, _, port_text = text.rpartition(":")
    if not port_text.isdigit():
        return address, None
    return address or "*", int(port_text)

def bind_scope(address):
    addr = str(address or "").strip().lower()
    if addr in {"*", "0.0.0.0", "::", ":::", "[::]"}:
        return "all interfaces"
    if addr.startswith("127.") or addr in {"localhost", "::1"}:
        return "loopback only"
    return "specific local address"

def service_name_for(port, protocol):
    if port in SERVICE_NAMES:
        return SERVICE_NAMES[port]
    try:
        return socket.getservbyport(int(port), protocol.lower())
    except Exception:
        return "Unknown service"

def parse_ss(protocol):
    result = run_command(["ss", "-H", "-ltnp" if protocol == "tcp" else "-lunp"])
    listeners=[]
    if not result["available"] or result["returncode"] not in (0, None):
        return listeners, result
    for line in result["stdout"].splitlines():
        parts=line.split()
        if len(parts)<4:
            continue
        local = parts[3] if parts[0].upper() in {"LISTEN","UNCONN"} else (parts[4] if len(parts)>4 else "")
        address, port = split_host_port(local)
        if port is None:
            continue
        listeners.append({"protocol":protocol.upper(),"local_address":address,"port":port,"bind_scope":bind_scope(address),"service_name":service_name_for(port,protocol),"process_name":extract_process(" ".join(parts[5:])),"raw_listener":line[:500]})
    return listeners, result

def parse_netstat():
    result=run_command(["netstat","-lntup"])
    listeners=[]
    if not result["available"] or result["returncode"] not in (0, None):
        return listeners, result
    for line in result["stdout"].splitlines():
        parts=line.split()
        if len(parts)<4 or not parts[0].lower().startswith(("tcp","udp")):
            continue
        protocol="TCP" if parts[0].lower().startswith("tcp") else "UDP"
        address, port=split_host_port(parts[3])
        if port is None:
            continue
        raw_process=parts[-1] if "/" in parts[-1] else ""
        listeners.append({"protocol":protocol,"local_address":address,"port":port,"bind_scope":bind_scope(address),"service_name":service_name_for(port,protocol.lower()),"process_name":raw_process.split("/",1)[-1] if raw_process else "","raw_listener":line[:500]})
    return listeners,result

def collect_listeners():
    listeners=[]; commands=[]
    if shutil.which("ss"):
        for protocol in ("tcp","udp"):
            rows,result=parse_ss(protocol); listeners.extend(rows); commands.append({"command":f"ss {protocol}","available":result["available"],"returncode":result["returncode"],"stderr":result["stderr"][:300]})
    elif shutil.which("netstat"):
        rows,result=parse_netstat(); listeners.extend(rows); commands.append({"command":"netstat","available":result["available"],"returncode":result["returncode"],"stderr":result["stderr"][:300]})
    else:
        commands.append({"command":"ss/netstat","available":False,"returncode":None,"stderr":"Neither ss nor netstat was found"})
    deduped={}
    for row in listeners:
        deduped[(row["protocol"],row["local_address"],row["port"],row.get("process_name",""))]=row
    return sorted(deduped.values(), key=lambda r:(r["protocol"],r["port"],r["local_address"])), commands

def collect_firewall():
    checks=[]
    for name,args in [("ufw",["ufw","status"]),("firewalld",["firewall-cmd","--state"]),("nftables",["nft","list","ruleset"]),("iptables",["iptables","-S"] )]:
        result=run_command(args, timeout=8)
        if result["available"]:
            if name in {"nftables","iptables"}:
                summary=f"lines={len([line for line in result['stdout'].splitlines() if line.strip()])}"
            else:
                summary=(" ".join(result["stdout"].splitlines()[:3]) or result["stderr"].strip())[:500]
            checks.append({"tool":name,"available":True,"returncode":result["returncode"],"summary":summary})
    return {"checks":checks,"firewall_evidence_available":bool(checks)}

def listener_severity(listener):
    port=int(listener["port"]); scope=listener["bind_scope"]
    if port in {23,2375,6379,9200,9300,11211,27017} and scope=="all interfaces": return "high"
    if port in CONTAINER_API_PORTS and scope != "loopback only": return "high"
    if port in DATABASE_OR_CACHE_PORTS and scope=="all interfaces": return "high"
    if port in CLEAR_TEXT_OR_LEGACY_PORTS and scope=="all interfaces": return "medium"
    if port in FILE_SHARING_PORTS and scope=="all interfaces": return "medium"
    if port in REMOTE_ADMIN_PORTS and scope=="all interfaces": return "medium" if port != 22 else "low"
    return "info"

def stable_id(*parts):
    return hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()[:8].upper()

def finding_for_listener(listener):
    port=int(listener["port"]); protocol=listener["protocol"]; service=listener["service_name"]; process=listener.get("process_name") or "unknown process"; scope=listener["bind_scope"]
    object_text=f"{protocol} {port} / {service}"
    return {"id":f"LINUX-NETWORK-{protocol}-{port}-{stable_id(protocol,port,listener.get('local_address'),process)}","severity":listener_severity(listener),"title":f"Linux listening service review for {protocol} {port} / {service}","recommendation":"Validate the service owner, business purpose, allowed source networks, and host/network firewall policy before changing the listener.","evidence":f"{object_text}; bind scope: {scope}; local address: {listener.get('local_address')}; process: {process}. This is local bind evidence, not proof of internet reachability.","affected_object":object_text,"protocol":protocol,"port":port,"service_name":service,"bind_scope":scope,"local_address":listener.get("local_address"),"process_name":process}

def firewall_findings(firewall):
    checks=firewall.get("checks",[])
    if not checks:
        return [{"id":"LINUX-FIREWALL-COVERAGE-001","severity":"info","title":"Linux host firewall evidence was not available","recommendation":"Confirm whether host firewall policy is managed by ufw, firewalld, nftables, iptables, cloud controls, or another approved control plane.","evidence":"No ufw, firewall-cmd, nft, or iptables command was available in the audit context.","affected_object":f"{host}: host firewall"}]
    for check in checks:
        summary=check.get("summary","").lower()
        if check["tool"]=="ufw" and "inactive" in summary:
            return [{"id":"LINUX-FIREWALL-STATUS-001","severity":"medium","title":"Linux ufw firewall is inactive","recommendation":"Validate whether host firewall controls are required or whether network/cloud firewalls provide compensating controls.","evidence":check.get("summary","ufw reported inactive"),"affected_object":f"{host}: ufw firewall"}]
        if check["tool"]=="firewalld" and "not running" in summary:
            return [{"id":"LINUX-FIREWALL-STATUS-002","severity":"medium","title":"Linux firewalld is not running","recommendation":"Validate whether host firewall controls are required or whether network/cloud firewalls provide compensating controls.","evidence":check.get("summary","firewalld is not running"),"affected_object":f"{host}: firewalld"}]
    return []

listeners, listener_commands = collect_listeners()
firewall=collect_firewall()
ip_route=run_command(["ip","route","show"])
findings=[finding_for_listener(listener) for listener in listeners]
if not listeners:
    findings.append({"id":"LINUX-NETWORK-COVERAGE-001","severity":"info","title":"Linux listening socket inventory evidence was not available","recommendation":"Install ss or netstat, or provide equivalent local listener evidence for review.","evidence":"No local listening socket rows were collected. This does not prove that no services are listening.","affected_object":f"{host}: listening socket inventory"})
findings.extend(firewall_findings(firewall))
finding_counts={name:0 for name in ("critical","high","medium","low","info")}
for item in findings:
    sev=str(item.get("severity","info")).lower(); finding_counts[sev if sev in finding_counts else "info"]+=1
summary={"host":host,"generated_at_utc":now,"source_script":"linux-network-exposure-audit.sh","collector_type":"linux-network-exposure","root_context":root_context,"quick_mode":quick_mode,"safety_note":"Local read-only listener and firewall inventory. No active network scan was performed.","listener_count":len(listeners),"listeners":listeners,"listener_collection_commands":listener_commands,"firewall":firewall,"local_network_context":{"ip_route_available":bool(ip_route["available"] and ip_route["returncode"]==0),"ip_route_sample":ip_route["stdout"].splitlines()[:20] if ip_route["returncode"]==0 else []},"finding_counts":finding_counts,"findings":findings}
summary_path.parent.mkdir(parents=True, exist_ok=True); summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
lines=["SecureInfra Linux Network Exposure Audit",f"Host: {host}",f"GeneratedAtUtc: {now}","Safety: local read-only listener/firewall inventory; no active network scan was performed.","",f"Listeners collected: {len(listeners)}"]
for listener in listeners:
    lines.append(f"- {listener['protocol']} {listener['local_address']}:{listener['port']} {listener['service_name']} scope={listener['bind_scope']} process={listener.get('process_name') or 'unknown'}")
lines.append(""); lines.append("Findings:")
for finding in findings:
    lines.append(f"- [{finding['severity']}] {finding['id']} {finding['title']} :: {finding['evidence']}")
report_path.write_text("\n".join(lines)+"\n", encoding="utf-8")
print(str(summary_path))
PYCODE

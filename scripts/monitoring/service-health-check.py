#!/usr/bin/env python3
"""
Check HTTP and TCP services from a JSON configuration file.

The script returns:
  0 when every service is healthy
  2 when one or more services fail
  1 for configuration or runtime errors
"""

from __future__ import annotations

import argparse
import json
import socket
import ssl
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


@dataclass
class CheckResult:
    name: str
    type: str
    target: str
    ok: bool
    status: str
    latency_ms: int
    detail: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check HTTP and TCP service health.")
    parser.add_argument("--config", default="examples/services.example.json", help="Path to JSON config file")
    parser.add_argument("--output", help="Optional JSON output path")
    parser.add_argument("--timeout", type=float, default=None, help="Override timeout for all checks")
    return parser.parse_args()


def load_config(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    services = data.get("services")
    if not isinstance(services, list):
        raise ValueError("Config must contain a 'services' list")
    return services


def check_http(service: dict[str, Any], timeout_override: float | None) -> CheckResult:
    name = str(service.get("name", service.get("url", "http-service")))
    url = str(service["url"])
    timeout = float(timeout_override or service.get("timeout", 5))
    expected_status = set(int(code) for code in service.get("expected_status", [200]))
    start = time.monotonic()

    try:
        request = Request(url, headers={"User-Agent": "infra-service-health-check/1.0"})
        context = ssl.create_default_context()
        with urlopen(request, timeout=timeout, context=context) as response:
            status_code = int(response.status)
            latency_ms = int((time.monotonic() - start) * 1000)
            ok = status_code in expected_status
            return CheckResult(
                name=name,
                type="http",
                target=url,
                ok=ok,
                status=str(status_code),
                latency_ms=latency_ms,
                detail="expected" if ok else f"unexpected status, expected one of {sorted(expected_status)}",
            )
    except HTTPError as exc:
        latency_ms = int((time.monotonic() - start) * 1000)
        ok = int(exc.code) in expected_status
        return CheckResult(
            name=name,
            type="http",
            target=url,
            ok=ok,
            status=str(exc.code),
            latency_ms=latency_ms,
            detail="expected" if ok else str(exc.reason),
        )
    except (URLError, TimeoutError, OSError) as exc:
        latency_ms = int((time.monotonic() - start) * 1000)
        return CheckResult(name=name, type="http", target=url, ok=False, status="failed", latency_ms=latency_ms, detail=str(exc))


def check_tcp(service: dict[str, Any], timeout_override: float | None) -> CheckResult:
    name = str(service.get("name", "tcp-service"))
    host = str(service["host"])
    port = int(service["port"])
    timeout = float(timeout_override or service.get("timeout", 3))
    target = f"{host}:{port}"
    start = time.monotonic()

    try:
        with socket.create_connection((host, port), timeout=timeout):
            latency_ms = int((time.monotonic() - start) * 1000)
            return CheckResult(name=name, type="tcp", target=target, ok=True, status="open", latency_ms=latency_ms, detail="connected")
    except OSError as exc:
        latency_ms = int((time.monotonic() - start) * 1000)
        return CheckResult(name=name, type="tcp", target=target, ok=False, status="closed", latency_ms=latency_ms, detail=str(exc))


def run_check(service: dict[str, Any], timeout_override: float | None) -> CheckResult:
    service_type = str(service.get("type", "")).lower()
    if service_type == "http":
        if "url" not in service:
            raise ValueError("HTTP service requires 'url'")
        return check_http(service, timeout_override)
    if service_type == "tcp":
        if "host" not in service or "port" not in service:
            raise ValueError("TCP service requires 'host' and 'port'")
        return check_tcp(service, timeout_override)
    raise ValueError(f"Unsupported service type: {service_type}")


def print_table(results: list[CheckResult]) -> None:
    print(f"{'STATUS':<8} {'TYPE':<6} {'LATENCY':>8}  {'NAME':<28} TARGET")
    print("-" * 88)
    for item in results:
        status = "OK" if item.ok else "FAILED"
        print(f"{status:<8} {item.type:<6} {item.latency_ms:>6}ms  {item.name[:28]:<28} {item.target}")
        if not item.ok:
            print(f"         detail: {item.detail}")


def main() -> int:
    args = parse_args()
    try:
        services = load_config(Path(args.config))
        results = [run_check(service, args.timeout) for service in services]
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print_table(results)

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "results": [asdict(item) for item in results],
        }
        output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    return 0 if all(item.ok for item in results) else 2


if __name__ == "__main__":
    raise SystemExit(main())

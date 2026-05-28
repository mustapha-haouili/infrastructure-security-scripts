#!/usr/bin/env python3
"""
Scan files for common secret patterns before code is committed or deployed.

The scanner is intentionally dependency-free so it can run on developer
workstations and in CI jobs without extra setup.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Iterator, Pattern

DEFAULT_EXCLUDE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    "__pycache__",
    ".pytest_cache",
    "node_modules",
    "vendor",
    "venv",
    ".venv",
    "dist",
    "build",
    "reports",
    "backups",
}

DEFAULT_EXCLUDE_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".bmp",
    ".ico",
    ".pdf",
    ".zip",
    ".gz",
    ".tar",
    ".tgz",
    ".7z",
    ".exe",
    ".dll",
    ".so",
    ".bin",
    ".pyc",
}


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: Pattern[str]
    severity: str
    description: str


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    file: str
    line: int
    fingerprint: str
    evidence: str
    description: str


RULES = [
    Rule(
        "aws-access-key-id",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "high",
        "AWS access key identifier",
    ),
    Rule(
        "github-token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b"),
        "high",
        "GitHub token",
    ),
    Rule(
        "gitlab-token",
        re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b"),
        "high",
        "GitLab personal access token",
    ),
    Rule(
        "slack-token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{20,}\b"),
        "high",
        "Slack token",
    ),
    Rule(
        "private-key-block",
        re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
        "critical",
        "Private key material",
    ),
    Rule(
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "medium",
        "JSON Web Token",
    ),
    Rule(
        "generic-secret-assignment",
        re.compile(
            r"(?i)\b(password|passwd|pwd|secret|token|apikey|api_key|client_secret)\b\s*[:=]\s*['\"]?([A-Za-z0-9_./+=@!#$%\-]{12,})"
        ),
        "medium",
        "Generic credential-style assignment",
    ),
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scan files for common secret patterns.")
    parser.add_argument("path", nargs="?", default=".", help="File or directory to scan. Default: current directory")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="Output format")
    parser.add_argument("--output", help="Write results to a file instead of stdout")
    parser.add_argument("--allowlist", default=".secret-scan-allowlist", help="Allowlist file containing fingerprints")
    parser.add_argument("--max-file-size", type=int, default=1024 * 1024, help="Maximum file size in bytes")
    parser.add_argument("--no-fail", action="store_true", help="Return exit code 0 even when findings exist")
    parser.add_argument("--include-hidden", action="store_true", help="Scan hidden files and directories")
    return parser.parse_args()


def load_allowlist(path: Path) -> set[str]:
    if not path.exists():
        return set()
    values: set[str] = set()
    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if line and not line.startswith("#"):
            values.add(line)
    return values


def should_skip_path(path: Path, include_hidden: bool) -> bool:
    parts = set(path.parts)
    if parts & DEFAULT_EXCLUDE_DIRS:
        return True
    if not include_hidden and any(part.startswith(".") and part not in {".", ".."} for part in path.parts):
        return True
    return path.suffix.lower() in DEFAULT_EXCLUDE_EXTENSIONS


def iter_files(root: Path, include_hidden: bool, max_file_size: int) -> Iterator[Path]:
    if root.is_file():
        if not should_skip_path(root, include_hidden) and root.stat().st_size <= max_file_size:
            yield root
        return

    for current_root, dirs, files in os.walk(root):
        current = Path(current_root)
        dirs[:] = [d for d in dirs if not should_skip_path(current / d, include_hidden)]
        for file_name in files:
            candidate = current / file_name
            try:
                if should_skip_path(candidate, include_hidden):
                    continue
                if candidate.stat().st_size > max_file_size:
                    continue
                yield candidate
            except OSError:
                continue


def redact(value: str) -> str:
    value = value.strip()
    if len(value) <= 10:
        return "<redacted>"
    return f"{value[:4]}...{value[-4:]}"


def fingerprint(rule: Rule, path: Path, line_number: int, match_value: str) -> str:
    raw = f"{rule.name}:{path.as_posix()}:{line_number}:{match_value}".encode("utf-8", errors="ignore")
    return hashlib.sha256(raw).hexdigest()[:20]


def scan_file(path: Path, root: Path, allowlist: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return findings

    display_path = path.relative_to(root).as_posix() if root.is_dir() else path.as_posix()

    for line_number, line in enumerate(lines, start=1):
        if "nosec" in line.lower() or "secret-scan: ignore" in line.lower():
            continue
        for rule in RULES:
            for match in rule.pattern.finditer(line):
                matched_value = match.group(0)
                item_fingerprint = fingerprint(rule, Path(display_path), line_number, matched_value)
                if item_fingerprint in allowlist:
                    continue
                evidence = line.strip().replace(matched_value, redact(matched_value))
                findings.append(
                    Finding(
                        rule=rule.name,
                        severity=rule.severity,
                        file=display_path,
                        line=line_number,
                        fingerprint=item_fingerprint,
                        evidence=evidence[:240],
                        description=rule.description,
                    )
                )
    return findings


def scan(root: Path, allowlist: set[str], include_hidden: bool, max_file_size: int) -> list[Finding]:
    findings: list[Finding] = []
    root = root.resolve()
    for path in iter_files(root, include_hidden=include_hidden, max_file_size=max_file_size):
        findings.extend(scan_file(path.resolve(), root, allowlist))
    return findings


def render_text(findings: Iterable[Finding]) -> str:
    findings = list(findings)
    if not findings:
        return "No secrets detected."

    lines = [f"Secret scan findings: {len(findings)}"]
    for item in findings:
        lines.append("")
        lines.append(f"Rule: {item.rule}")
        lines.append(f"Severity: {item.severity}")
        lines.append(f"Location: {item.file}:{item.line}")
        lines.append(f"Fingerprint: {item.fingerprint}")
        lines.append(f"Evidence: {item.evidence}")
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    root = Path(args.path)
    if not root.exists():
        print(f"Path not found: {root}", file=sys.stderr)
        return 1

    allowlist = load_allowlist(Path(args.allowlist))
    findings = scan(
        root=root,
        allowlist=allowlist,
        include_hidden=args.include_hidden,
        max_file_size=args.max_file_size,
    )

    if args.format == "json":
        output = json.dumps([asdict(item) for item in findings], indent=2)
    else:
        output = render_text(findings)

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)

    if findings and not args.no_fail:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

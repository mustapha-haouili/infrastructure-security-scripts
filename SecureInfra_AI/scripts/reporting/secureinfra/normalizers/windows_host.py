"""Normalize standalone Windows host security audit reports."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from secureinfra.normalizers.windows_scope_common import normalize_windows_scope_report


def normalize_windows_host_audit(data: dict[str, Any], source_file: str | Path) -> dict[str, Any]:
    return normalize_windows_scope_report(data, source_file, "windows-host-audit")

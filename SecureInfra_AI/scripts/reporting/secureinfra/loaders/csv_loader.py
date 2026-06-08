"""CSV loading helpers for SecureInfra AI."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any


def load_csv_file(path: str | Path) -> list[dict[str, Any]]:
    """Load a CSV file into dictionaries with Windows BOM-safe encoding."""
    csv_path = Path(path)
    if not csv_path.exists():
        raise FileNotFoundError(f"Input CSV file not found: {csv_path}")
    if not csv_path.is_file():
        raise ValueError(f"Input path is not a file: {csv_path}")

    with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]

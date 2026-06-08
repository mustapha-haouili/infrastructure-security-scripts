"""JSON loading helpers for SecureInfra AI."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


JSON_ENCODINGS = ("utf-8-sig", "utf-8", "utf-16")


def load_json_file(path: str | Path) -> Any:
    """Load a JSON file and return parsed data."""
    json_path = Path(path)
    if not json_path.exists():
        raise FileNotFoundError(f"Input JSON file not found: {json_path}")
    if not json_path.is_file():
        raise ValueError(f"Input path is not a file: {json_path}")

    decode_errors: list[str] = []
    for encoding in JSON_ENCODINGS:
        try:
            return json.loads(json_path.read_text(encoding=encoding))
        except UnicodeDecodeError as exc:
            decode_errors.append(f"{encoding}: {exc}")
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in {json_path}: {exc}") from exc

    raise ValueError(f"Could not decode JSON file {json_path}. Tried: {', '.join(decode_errors)}")

"""Dependency-free JSON schema validation for SecureInfra AI report schemas."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any


class SchemaValidationError(ValueError):
    """Raised when a normalized report does not match the local schema."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__("Normalized report schema validation failed:\n- " + "\n- ".join(errors))


def default_schema_dir() -> Path:
    return Path(__file__).resolve().parents[4] / "schemas"


REPORT_TYPE_SCHEMA_NAMES = {
    "windows-host-audit": "windows-host-audit-normalized-report.schema.json",
    "windows-server-audit": "windows-server-audit-normalized-report.schema.json",
    "windows-workstation-audit": "windows-workstation-audit-normalized-report.schema.json",
    "windows-network-exposure": "windows-network-exposure-normalized-report.schema.json",
}


def load_schema(schema_name: str, schema_dir: str | Path | None = None) -> dict[str, Any]:
    root = Path(schema_dir) if schema_dir is not None else default_schema_dir()
    schema_path = root / schema_name
    with schema_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"Schema must be a JSON object: {schema_path}")
    return data


def validate_normalized_report(report: dict[str, Any], schema_dir: str | Path | None = None) -> None:
    root = Path(schema_dir) if schema_dir is not None else default_schema_dir()
    schemas = {
        "normalized-report.schema.json": load_schema("normalized-report.schema.json", root),
        "finding.schema.json": load_schema("finding.schema.json", root),
    }
    errors: list[str] = []
    _validate_instance(report, schemas["normalized-report.schema.json"], "$", schemas, errors)
    report_type = str(report.get("report_type") or "")
    report_type_schema_name = REPORT_TYPE_SCHEMA_NAMES.get(report_type)
    if report_type_schema_name:
        schemas[report_type_schema_name] = load_schema(report_type_schema_name, root)
        _validate_instance(report, schemas[report_type_schema_name], "$", schemas, errors)
    if errors:
        raise SchemaValidationError(errors)


def _validate_instance(
    instance: Any,
    schema: dict[str, Any],
    path: str,
    schemas: dict[str, dict[str, Any]],
    errors: list[str],
) -> None:
    ref = schema.get("$ref")
    if isinstance(ref, str):
        referenced = schemas.get(ref)
        if referenced is None:
            errors.append(f"{path}: unresolved schema reference {ref}")
            return
        _validate_instance(instance, referenced, path, schemas, errors)
        return

    expected_type = schema.get("type")
    if isinstance(expected_type, str) and not _type_matches(instance, expected_type):
        errors.append(f"{path}: expected {expected_type}, got {_json_type_name(instance)}")
        return

    if "enum" in schema and instance not in schema["enum"]:
        allowed = ", ".join(str(value) for value in schema["enum"])
        errors.append(f"{path}: expected one of [{allowed}], got {instance!r}")

    if isinstance(instance, str):
        min_length = schema.get("minLength")
        if isinstance(min_length, int) and len(instance) < min_length:
            errors.append(f"{path}: string is shorter than minLength {min_length}")
        if schema.get("format") == "date-time" and not _is_date_time(instance):
            errors.append(f"{path}: expected RFC3339 date-time string")

    if isinstance(instance, dict):
        properties = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
        for key in schema.get("required", []):
            if key not in instance:
                errors.append(f"{path}.{key}: required property is missing")
        if schema.get("additionalProperties") is False:
            for key in instance:
                if key not in properties:
                    errors.append(f"{path}.{key}: additional property is not allowed")
        for key, value in instance.items():
            child_schema = properties.get(key)
            if isinstance(child_schema, dict):
                _validate_instance(value, child_schema, f"{path}.{key}", schemas, errors)

    if isinstance(instance, list):
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(instance):
                _validate_instance(item, item_schema, f"{path}[{index}]", schemas, errors)


def _type_matches(instance: Any, expected_type: str) -> bool:
    if expected_type == "object":
        return isinstance(instance, dict)
    if expected_type == "array":
        return isinstance(instance, list)
    if expected_type == "string":
        return isinstance(instance, str)
    if expected_type == "boolean":
        return isinstance(instance, bool)
    if expected_type == "integer":
        return isinstance(instance, int) and not isinstance(instance, bool)
    if expected_type == "number":
        return isinstance(instance, (int, float)) and not isinstance(instance, bool)
    if expected_type == "null":
        return instance is None
    return True


def _json_type_name(value: Any) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    if isinstance(value, str):
        return "string"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if value is None:
        return "null"
    return type(value).__name__


def _is_date_time(value: str) -> bool:
    if "T" not in value:
        return False
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        datetime.fromisoformat(candidate)
    except ValueError:
        return False
    return True

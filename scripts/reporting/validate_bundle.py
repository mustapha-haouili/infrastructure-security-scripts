#!/usr/bin/env python3
"""Validate SecureInfra client collection bundles before analyzer import.

This helper performs a defensive preflight check for ZIP archives or expanded
client collection folders produced by Start-SecureInfraClientCollection.ps1. It
validates archive safety, expected file layout, basic JSON readability, and
obvious unsupported/sensitive file types before a bundle is passed to the public
analyzer or the private commercial reporting pipeline.
"""

from __future__ import annotations

import argparse
import json
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


# Allow this helper to run from the repository root without requiring callers to
# set PYTHONPATH. The secureinfra package lives under SecureInfra_AI.
REPO_ROOT = Path(__file__).resolve().parents[2]
SECUREINFRA_REPORTING_ROOT = REPO_ROOT / "SecureInfra_AI" / "scripts" / "reporting"
if str(SECUREINFRA_REPORTING_ROOT) not in sys.path:
    sys.path.insert(0, str(SECUREINFRA_REPORTING_ROOT))

from secureinfra.bundles.client_bundle import (  # noqa: E402
    ALLOWED_ZIP_EXTENSIONS,
    ALLOWED_ZIP_ROOT_FILES,
    CLIENT_FILE_DEFINITIONS,
    MAX_ZIP_ENTRIES,
    MAX_ZIP_MEMBER_SIZE_BYTES,
    discover_client_bundle,
    is_allowed_zip_path_without_wrapper,
    is_allowed_zip_relative_path,
    missing_client_files,
    validate_zip_member,
)
from secureinfra.bundles.multi_bundle import discover_bundle_inputs, looks_like_client_bundle  # noqa: E402


DANGEROUS_FILENAMES = {".env", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
DANGEROUS_EXTENSIONS = {
    ".7z",
    ".bak",
    ".cer",
    ".crt",
    ".db",
    ".der",
    ".gz",
    ".key",
    ".kdbx",
    ".p12",
    ".pem",
    ".pfx",
    ".rar",
    ".sqlite",
    ".tar",
    ".tgz",
    ".zip",
}
DANGEROUS_PATH_SEGMENTS = {"private-prompts", "private_prompts", "secrets", "credentials"}
RECOGNIZED_EVIDENCE_TOP_LEVEL_DIRS = {"linux", "devsecops", "docker", "kubernetes"}


@dataclass
class BundleValidationResult:
    input_path: Path
    bundle_count: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def add_error(self, message: str) -> None:
        self.errors.append(message)

    def add_warning(self, message: str) -> None:
        self.warnings.append(message)


class BundleValidationError(ValueError):
    """Raised when an input bundle violates the public bundle contract."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__("Input bundle validation failed:\n- " + "\n- ".join(errors))


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate SecureInfra client collection ZIP archives or expanded bundle folders.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s --input reports/secureinfra-client-collection-HOST-20260709-120000.zip
  %(prog)s --input reports/secureinfra-client-collection-HOST-20260709-120000
  %(prog)s --input customer-projects/CUST001/03-input-bundles --strict-safety
""",
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to a client collection .zip, expanded collection folder, or directory containing many bundles.",
    )
    parser.add_argument(
        "--expected-bundle-count",
        type=int,
        default=0,
        help="Optional minimum number of bundle candidates expected in the input.",
    )
    parser.add_argument(
        "--strict-safety",
        action="store_true",
        help="Fail on suspicious filenames/path segments in addition to structural checks.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Only print validation errors.",
    )
    return parser.parse_args(argv)


def validate_input_bundle(
    input_path: str | Path,
    *,
    expected_bundle_count: int = 0,
    strict_safety: bool = False,
) -> BundleValidationResult:
    path = Path(input_path)
    result = BundleValidationResult(input_path=path)

    if expected_bundle_count < 0:
        result.add_error("--expected-bundle-count cannot be negative")
        raise_if_errors(result)

    if not path.exists():
        result.add_error(f"Input path does not exist: {path}")
        raise_if_errors(result)

    candidates = resolve_bundle_candidates(path)
    if not candidates:
        result.add_error(f"No SecureInfra client bundle candidates were found under: {path}")
        raise_if_errors(result)

    result.bundle_count = len(candidates)
    if expected_bundle_count and result.bundle_count < expected_bundle_count:
        result.add_error(
            f"Expected at least {expected_bundle_count} bundle candidates but found {result.bundle_count} under: {path}"
        )

    for candidate in candidates:
        validate_candidate(candidate, result, strict_safety=strict_safety)

    raise_if_errors(result)
    return result


def raise_if_errors(result: BundleValidationResult) -> None:
    if result.errors:
        raise BundleValidationError(result.errors)


def resolve_bundle_candidates(input_path: Path) -> list[Path]:
    if input_path.is_file():
        return [input_path]
    if looks_like_client_bundle(input_path):
        return [input_path]
    return discover_bundle_inputs(input_path)


def validate_candidate(candidate: Path, result: BundleValidationResult, *, strict_safety: bool) -> None:
    if candidate.is_file():
        validate_zip_bundle(candidate, result, strict_safety=strict_safety)
        return
    if candidate.is_dir():
        validate_directory_bundle(candidate, result, strict_safety=strict_safety)
        return
    result.add_error(f"Unsupported bundle candidate type: {candidate}")


def validate_zip_bundle(zip_path: Path, result: BundleValidationResult, *, strict_safety: bool) -> None:
    if zip_path.suffix.lower() != ".zip":
        result.add_error(f"Bundle file must be a .zip archive: {zip_path}")
        return

    try:
        with zipfile.ZipFile(zip_path) as archive:
            bad_member = archive.testzip()
            if bad_member:
                result.add_error(f"{zip_path}: archive member failed integrity check: {bad_member}")
                return

            members = archive.infolist()
            if len(members) > MAX_ZIP_ENTRIES:
                result.add_error(f"{zip_path}: too many entries ({len(members)} > {MAX_ZIP_ENTRIES})")
                return

            content_paths: list[tuple[str, bool]] = []
            for member in members:
                try:
                    parts = validate_zip_member(member)
                except ValueError as exc:
                    result.add_error(f"{zip_path}: {exc}")
                    continue

                content_parts = unwrap_optional_zip_root(parts, is_directory=member.is_dir())
                relative_name = "/".join(content_parts)
                content_paths.append((relative_name, member.is_dir()))

                if strict_safety:
                    validate_strict_safety_parts(parts, f"{zip_path}!{member.filename}", result)
                    if content_parts != parts:
                        validate_strict_safety_parts(content_parts, f"{zip_path}!{relative_name}", result)

                if not member.is_dir() and Path(content_parts[-1]).suffix.lower() == ".json":
                    validate_json_zip_member(archive, member, f"{zip_path}!{relative_name}", result)

            validate_bundle_shape(content_paths, f"{zip_path}", result)
    except zipfile.BadZipFile as exc:
        result.add_error(f"{zip_path}: not a readable ZIP archive: {exc}")
    except OSError as exc:
        result.add_error(f"{zip_path}: cannot read archive: {exc}")


def unwrap_optional_zip_root(parts: list[str], *, is_directory: bool) -> list[str]:
    if is_allowed_zip_path_without_wrapper(parts, is_directory):
        return parts
    if len(parts) > 1 and is_allowed_zip_path_without_wrapper(parts[1:], is_directory):
        return parts[1:]
    return parts


def validate_json_zip_member(
    archive: zipfile.ZipFile,
    member: zipfile.ZipInfo,
    display_name: str,
    result: BundleValidationResult,
) -> None:
    try:
        with archive.open(member) as handle:
            payload = handle.read()
        json.loads(payload.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        result.add_error(f"{display_name}: invalid JSON: {exc}")
    except OSError as exc:
        result.add_error(f"{display_name}: cannot read JSON member: {exc}")


def validate_directory_bundle(bundle_dir: Path, result: BundleValidationResult, *, strict_safety: bool) -> None:
    try:
        detected = discover_client_bundle(bundle_dir)
    except (OSError, ValueError) as exc:
        result.add_error(f"{bundle_dir}: cannot inspect bundle directory: {exc}")
        return

    if not detected:
        result.add_error(f"{bundle_dir}: no recognized SecureInfra collection files were found")
        return

    for file_path in sorted(path for path in bundle_dir.rglob("*") if path.is_file()):
        try:
            relative_parts = list(file_path.relative_to(bundle_dir).parts)
        except ValueError:
            result.add_error(f"{file_path}: file is outside bundle root")
            continue

        display_name = str(file_path.relative_to(bundle_dir)).replace("\\", "/")
        suffix = file_path.suffix.lower()
        if suffix not in ALLOWED_ZIP_EXTENSIONS:
            result.add_error(f"{bundle_dir}/{display_name}: unsupported file extension")
        if not is_allowed_zip_relative_path(relative_parts, is_directory=False):
            result.add_error(f"{bundle_dir}/{display_name}: file path is not allowed in a client bundle")
        try:
            if file_path.stat().st_size > MAX_ZIP_MEMBER_SIZE_BYTES:
                result.add_error(
                    f"{bundle_dir}/{display_name}: file is too large "
                    f"({file_path.stat().st_size} > {MAX_ZIP_MEMBER_SIZE_BYTES} bytes)"
                )
        except OSError as exc:
            result.add_error(f"{bundle_dir}/{display_name}: cannot stat file: {exc}")

        if strict_safety:
            validate_strict_safety_parts(relative_parts, f"{bundle_dir}/{display_name}", result)

        if suffix == ".json":
            validate_json_file(file_path, f"{bundle_dir}/{display_name}", result)

    missing = missing_client_files(detected)
    if missing:
        result.add_warning(f"{bundle_dir}: optional/coverage files missing: {', '.join(missing)}")


def validate_json_file(path: Path, display_name: str, result: BundleValidationResult) -> None:
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            json.load(handle)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        result.add_error(f"{display_name}: invalid JSON: {exc}")
    except OSError as exc:
        result.add_error(f"{display_name}: cannot read JSON file: {exc}")


def validate_bundle_shape(content_paths: Iterable[tuple[str, bool]], label: str, result: BundleValidationResult) -> None:
    file_paths = {path for path, is_dir in content_paths if not is_dir}
    dir_paths = {path.rstrip("/") for path, is_dir in content_paths if is_dir}
    recognized_files = {definition["path"] for definition in CLIENT_FILE_DEFINITIONS.values()} | ALLOWED_ZIP_ROOT_FILES

    has_root_marker = bool(file_paths & ALLOWED_ZIP_ROOT_FILES)
    has_known_report = bool(file_paths & recognized_files)
    has_ad_shared = any(path == "ad-shared" or path.startswith("ad-shared/") for path in file_paths | dir_paths)
    has_known_evidence_dir = any(
        path.split("/", 1)[0] in RECOGNIZED_EVIDENCE_TOP_LEVEL_DIRS
        for path in file_paths | dir_paths
    )

    if not (has_root_marker or has_known_report or has_ad_shared or has_known_evidence_dir):
        result.add_error(f"{label}: archive does not contain recognized SecureInfra client collection files")


def validate_strict_safety_parts(parts: list[str], display_name: str, result: BundleValidationResult) -> None:
    lowered_parts = [part.lower() for part in parts]
    for part in lowered_parts:
        if part in DANGEROUS_FILENAMES:
            result.add_error(f"{display_name}: forbidden sensitive filename '{part}'")
        if part in DANGEROUS_PATH_SEGMENTS:
            result.add_error(f"{display_name}: forbidden sensitive path segment '{part}'")

    suffix = Path(parts[-1]).suffix.lower() if parts else ""
    # .zip is allowed only for the top-level candidate file itself, never inside a bundle.
    if suffix in DANGEROUS_EXTENSIONS and suffix not in ALLOWED_ZIP_EXTENSIONS:
        result.add_error(f"{display_name}: forbidden sensitive or nested archive extension '{suffix}'")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        result = validate_input_bundle(
            args.input,
            expected_bundle_count=args.expected_bundle_count,
            strict_safety=args.strict_safety,
        )
    except BundleValidationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if not args.quiet:
        strict_label = " with strict safety checks" if args.strict_safety else ""
        print(f"Input bundle validation passed{strict_label}: {Path(args.input)}")
        print(f"Bundles validated: {result.bundle_count}")
        for warning in result.warnings:
            print(f"WARNING: {warning}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: bash scripts/release/create_release_bundle.sh [options]

Creates a public SecureInfra release bundle with SHA256SUMS.txt and
RELEASE-MANIFEST.json.

Options:
  --output-dir DIR   Output directory. Defaults to ./dist under the repo root.
  --version VERSION  Release version. Defaults to the VERSION file when present.
  --force            Replace an existing release directory or archive.
  -h, --help         Show this help text.
USAGE
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
output_dir="$repo_root/dist"
version=""
force=0

is_windows_absolute_path() {
    local raw="$1"
    [[ "$raw" =~ ^[A-Za-z]:[\\/] || "$raw" =~ ^\\\\ ]]
}

normalize_output_dir() {
    local raw="$1"
    local path_for_conversion="$raw"

    if [[ "$raw" != /* ]] && ! is_windows_absolute_path "$raw"; then
        path_for_conversion="$repo_root/$raw"
    fi

    if command -v cygpath >/dev/null 2>&1; then
        cygpath -u -a "$path_for_conversion"
        return
    fi

    if is_windows_absolute_path "$raw"; then
        if command -v wslpath >/dev/null 2>&1; then
            wslpath -u "$raw"
            return
        fi
        echo "Windows absolute output paths require cygpath or wslpath: $raw" >&2
        exit 2
    fi

    printf '%s\n' "$path_for_conversion"
}

to_lower() {
    if [[ "${BASH_VERSINFO[0]}" -ge 4 ]]; then
        printf '%s\n' "${1,,}"
    else
        printf '%s\n' "$1" | tr '[:upper:]' '[:lower:]'
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-dir)
            if [[ $# -lt 2 ]]; then
                echo "Missing value for --output-dir" >&2
                exit 2
            fi
            output_dir="$(normalize_output_dir "$2")"
            shift 2
            ;;
        --version)
            if [[ $# -lt 2 ]]; then
                echo "Missing value for --version" >&2
                exit 2
            fi
            version="$2"
            shift 2
            ;;
        --force)
            force=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ -z "$version" ]]; then
    if [[ -f "$repo_root/VERSION" ]]; then
        version="$(awk 'NR == 1 { gsub(/\r/, "", $0); print; exit }' "$repo_root/VERSION")"
    else
        version="0.0.0-dev"
    fi
fi

version_safe="$(printf '%s' "$version" | sed 's/[^A-Za-z0-9._-]/-/g')"
release_name="secureinfra-release-$version_safe"
staging_dir="$output_dir/$release_name"
archive_path="$output_dir/$release_name.zip"

is_excluded_path() {
    local path="${1//\\//}"
    local lower
    lower="$(to_lower "$path")"
    local wrapped="/$lower/"

    case "$lower" in
        reports|reports/*|secureinfra_ai/reports|secureinfra_ai/reports/*)
            return 0
            ;;
    esac

    case "$wrapped" in
        */.git/*|*/.codex/*|*/.agents/*|*/.pytest_cache/*|*/.mypy_cache/*|*/.ruff_cache/*|*/__pycache__/*|*/node_modules/*|*/backups/*|*/.venv/*|*/venv/*|*/env/*|*/tmp/*|*/temp/*|*/customer-data/*|*/client-data/*|*/raw-evidence/*|*/private-files/*|*/commercial-deliverables/*|*/private/*|*/customers/*)
            return 0
            ;;
    esac

    local base="${lower##*/}"
    case "$base" in
        .env|.env.*|.envrc|id_rsa|id_dsa|id_ecdsa|id_ed25519|*.local|*.local.*|*.secret.*|*.token.*|*.cred.*|*.credential.*|*.credentials.*|*.zip|*.7z|*.rar|*.tar|*.tgz|*.tar.gz|*.gz|*.bz2|*.xz|*.pfx|*.p12|*.pem|*.key|*.der|*.kdbx|*.sqlite|*.db|*.bak|*.tmp|*.swp|*.swo|*.pyc)
            return 0
            ;;
    esac

    return 1
}

python_runs() {
    "$1" -c 'import sys; sys.exit(0)' >/dev/null 2>&1
}

resolve_python_bin() {
    local candidate

    if [[ -n "${PYTHON_BIN:-}" ]]; then
        if python_runs "$PYTHON_BIN"; then
            printf '%s\n' "$PYTHON_BIN"
            return
        fi
        echo "PYTHON_BIN does not point to a runnable Python interpreter: $PYTHON_BIN" >&2
        exit 1
    fi

    for candidate in python3 python; do
        if command -v "$candidate" >/dev/null 2>&1 && python_runs "$candidate"; then
            printf '%s\n' "$candidate"
            return
        fi
    done

    echo "python3 or python is required to write deterministic release metadata." >&2
    exit 1
}

python_bin="$(resolve_python_bin)"

mkdir -p "$output_dir"

if [[ -e "$staging_dir" || -e "$archive_path" ]]; then
    if [[ "$force" -ne 1 ]]; then
        echo "Release output already exists. Re-run with --force to replace it." >&2
        echo "  $staging_dir" >&2
        echo "  $archive_path" >&2
        exit 1
    fi
    rm -rf "$staging_dir"
    rm -f "$archive_path"
fi

mkdir -p "$staging_dir"

file_list="$(mktemp)"
sorted_list="$(mktemp)"
trap 'rm -f "$file_list" "$sorted_list"' EXIT

root_files=(
    "README.md"
    "LICENSE"
    "SECURITY.md"
    "CONTRIBUTING.md"
    "CHANGELOG.md"
    "ROADMAP.md"
    "VERSION"
    "AGENTS.md"
    "Makefile"
)
public_dirs=("docs" "examples" "schemas" "scripts" "SecureInfra_AI")

for root_file in "${root_files[@]}"; do
    if [[ -f "$repo_root/$root_file" ]] && ! is_excluded_path "$root_file"; then
        printf '%s\n' "$root_file" >> "$file_list"
    fi
done

for public_dir in "${public_dirs[@]}"; do
    if [[ ! -d "$repo_root/$public_dir" ]]; then
        continue
    fi
    while IFS= read -r -d '' file_path; do
        rel_path="${file_path#"$repo_root"/}"
        if ! is_excluded_path "$rel_path"; then
            printf '%s\n' "$rel_path" >> "$file_list"
        fi
    done < <(find "$repo_root/$public_dir" -type f -print0)
done

sort -u "$file_list" > "$sorted_list"

"$python_bin" - "$repo_root" "$staging_dir" "$sorted_list" <<'PY'
import shutil
import sys
from pathlib import Path

repo_root = Path(sys.argv[1])
staging_dir = Path(sys.argv[2])
sorted_list = Path(sys.argv[3])

for rel_path in sorted_list.read_text(encoding="utf-8").splitlines():
    if not rel_path:
        continue
    source = repo_root / rel_path
    destination = staging_dir / rel_path
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
PY

generated_at_utc="$("$python_bin" - <<'PY'
from datetime import datetime, timezone
print(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
PY
)"

"$python_bin" - "$staging_dir" "$release_name" "$version" "$generated_at_utc" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

staging_dir = Path(sys.argv[1])
release_name = sys.argv[2]
version = sys.argv[3]
generated_at_utc = sys.argv[4]

files = []
for path in sorted(staging_dir.rglob("*")):
    if not path.is_file():
        continue
    relative_path = path.relative_to(staging_dir).as_posix()
    if relative_path in {"RELEASE-MANIFEST.json", "SHA256SUMS.txt"}:
        continue
    payload = path.read_bytes()
    files.append(
        {
            "path": relative_path,
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
    )

manifest = {
    "schema_version": "1.0",
    "release_name": release_name,
    "version": version,
    "generated_at_utc": generated_at_utc,
    "file_count": len(files),
    "files": files,
}

with (staging_dir / "RELEASE-MANIFEST.json").open("w", encoding="utf-8", newline="\n") as handle:
    handle.write(json.dumps(manifest, indent=2, sort_keys=False) + "\n")
with (staging_dir / "SHA256SUMS.txt").open("w", encoding="ascii", newline="\n") as handle:
    handle.write("".join(f"{item['sha256']}  {item['path']}\n" for item in files))
PY

if command -v zip >/dev/null 2>&1; then
    (cd "$staging_dir" && zip -qr "$archive_path" .)
else
    "$python_bin" - "$staging_dir" "$archive_path" <<'PY'
import sys
import zipfile
from pathlib import Path

staging_dir = Path(sys.argv[1])
archive_path = Path(sys.argv[2])

with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
    for path in sorted(staging_dir.rglob("*")):
        if path.is_file():
            archive.write(path, path.relative_to(staging_dir).as_posix())
PY
fi

echo "Release bundle directory: $staging_dir"
echo "Release archive: $archive_path"
echo "Manifest: $staging_dir/RELEASE-MANIFEST.json"
echo "Checksums: $staging_dir/SHA256SUMS.txt"

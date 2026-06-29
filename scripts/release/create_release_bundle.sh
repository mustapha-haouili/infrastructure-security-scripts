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

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-dir)
            if [[ $# -lt 2 ]]; then
                echo "Missing value for --output-dir" >&2
                exit 2
            fi
            if [[ "$2" = /* ]]; then
                output_dir="$2"
            else
                output_dir="$repo_root/$2"
            fi
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
    lower="$(printf '%s' "$path" | tr '[:upper:]' '[:lower:]')"
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

python_bin="${PYTHON_BIN:-python3}"
if ! command -v "$python_bin" >/dev/null 2>&1; then
    echo "python3 is required to write deterministic release metadata." >&2
    exit 1
fi

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

while IFS= read -r rel_path; do
    [[ -z "$rel_path" ]] && continue
    mkdir -p "$staging_dir/$(dirname "$rel_path")"
    cp -p "$repo_root/$rel_path" "$staging_dir/$rel_path"
done < "$sorted_list"

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

(staging_dir / "RELEASE-MANIFEST.json").write_text(
    json.dumps(manifest, indent=2, sort_keys=False) + "\n",
    encoding="utf-8",
)
(staging_dir / "SHA256SUMS.txt").write_text(
    "".join(f"{item['sha256']}  {item['path']}\n" for item in files),
    encoding="ascii",
)
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

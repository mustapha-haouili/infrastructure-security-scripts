#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

printf 'Checking shell script syntax...\n'
while IFS= read -r -d '' script; do
    bash -n "$script"
    printf '  ok %s\n' "$script"
done < <(find scripts tests -type f -name '*.sh' -print0)

printf '\nChecking Python syntax...\n'
python3 -m compileall -q scripts tests
printf '  ok python compileall\n'

printf '\nRunning Python unit tests...\n'
python3 -m unittest discover -s tests -p 'test_*.py'

if command -v pwsh >/dev/null 2>&1; then
    printf '\nChecking PowerShell syntax with pwsh...\n'
    while IFS= read -r -d '' script; do
        pwsh -NoProfile -Command "\$tokens=\$null; \$errors=\$null; [System.Management.Automation.Language.Parser]::ParseFile('$script',[ref]\$tokens,[ref]\$errors) | Out-Null; if (\$errors.Count -gt 0) { \$errors | Format-List; exit 1 }"
        printf '  ok %s\n' "$script"
    done < <(find scripts -type f -name '*.ps1' -print0)
else
    printf '\nPowerShell syntax check skipped because pwsh is not installed.\n'
fi

printf '\nRunning repository secret scan...\n'
python3 scripts/devsecops/secret-scan.py . --no-fail >/tmp/infra-security-secret-scan.txt
cat /tmp/infra-security-secret-scan.txt

printf '\nAll static checks completed.\n'

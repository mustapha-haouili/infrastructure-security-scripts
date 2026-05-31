# DevSecOps Scripts

These scripts support CI checks, container review, Kubernetes review, and source
security hygiene.

Full cross-platform reference: [../../docs/script-reference.md](../../docs/script-reference.md)

## `secret-scan.py`

Scans files for common secret patterns and returns a non-zero exit code when
findings are detected.

Arguments:

| Argument | Description |
|---|---|
| `path` | File or directory to scan. Default: current directory. |
| `--format text\|json` | Output format. |
| `--output FILE` | Write results to a file. |
| `--allowlist FILE` | File containing finding fingerprints to ignore. |
| `--max-file-size BYTES` | Maximum file size to scan. |
| `--no-fail` | Return exit code 0 even when findings exist. |
| `--include-hidden` | Include hidden files and directories. |
| `-h`, `--help` | Show built-in help. |

Examples:

```bash
python3 scripts/devsecops/secret-scan.py
python3 scripts/devsecops/secret-scan.py scripts
python3 scripts/devsecops/secret-scan.py . --format json --output reports/secrets.json
python3 scripts/devsecops/secret-scan.py . --allowlist .secret-scan-allowlist
python3 scripts/devsecops/secret-scan.py . --max-file-size 2097152
python3 scripts/devsecops/secret-scan.py . --include-hidden
python3 scripts/devsecops/secret-scan.py . --no-fail
```

## `docker-image-audit.sh`

Reviews Docker image metadata and optional runtime details.

Arguments:

| Argument | Description |
|---|---|
| `IMAGE` | Docker image reference to audit. |
| `--deep` | Run a temporary container for runtime checks. |
| `--output-dir DIR` | Directory for the report. |
| `-h`, `--help` | Show built-in help. |

Examples:

```bash
bash scripts/devsecops/docker-image-audit.sh nginx:latest
bash scripts/devsecops/docker-image-audit.sh nginx:latest --deep
bash scripts/devsecops/docker-image-audit.sh registry.example.com/app/api:1.2.3 --output-dir reports/docker
bash scripts/devsecops/docker-image-audit.sh nginx:latest --deep --output-dir reports/docker
```

## `kubernetes-rbac-audit.sh`

Reviews RBAC and workload security signals using `kubectl`.

Options:

| Option | Description |
|---|---|
| `--context NAME` | kubectl context to audit. |
| `--output-dir DIR` | Directory for the report. |
| `-h`, `--help` | Show built-in help. |

Examples:

```bash
bash scripts/devsecops/kubernetes-rbac-audit.sh
bash scripts/devsecops/kubernetes-rbac-audit.sh --context prod-admin
bash scripts/devsecops/kubernetes-rbac-audit.sh --output-dir reports/kubernetes
bash scripts/devsecops/kubernetes-rbac-audit.sh --context prod-admin --output-dir reports/kubernetes
```

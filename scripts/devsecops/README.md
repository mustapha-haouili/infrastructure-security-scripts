# DevSecOps Scripts

These scripts support CI checks, container review, Kubernetes review, and source security hygiene.

## Scripts

- `secret-scan.py`: Scans files for common secret patterns and returns a non-zero exit code when findings are detected.
- `docker-image-audit.sh`: Reviews Docker image metadata and optional runtime details.
- `kubernetes-rbac-audit.sh`: Reviews RBAC and workload security signals using `kubectl`.

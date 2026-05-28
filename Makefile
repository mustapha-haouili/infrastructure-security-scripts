.PHONY: check secret-scan

check:
	bash tests/run_static_checks.sh

secret-scan:
	python3 scripts/devsecops/secret-scan.py . --format text

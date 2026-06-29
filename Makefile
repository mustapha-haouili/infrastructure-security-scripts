.PHONY: check secret-scan release-bundle

check:
	bash tests/run_static_checks.sh

secret-scan:
	python3 scripts/devsecops/secret-scan.py . --format text

release-bundle:
	bash scripts/release/create_release_bundle.sh

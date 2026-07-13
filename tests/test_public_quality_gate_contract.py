import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
QUALITY_GATE = ROOT / "quality-gate.ps1"


class PublicQualityGateContractTests(unittest.TestCase):
    def read_gate(self) -> str:
        self.assertTrue(QUALITY_GATE.exists(), "quality-gate.ps1 should exist in the public repo root")
        return QUALITY_GATE.read_text(encoding="utf-8")

    def test_quality_gate_runs_schema_validator_after_sample_analyzer(self):
        content = self.read_gate()

        analyzer_index = content.index("secureinfra_analyzer.py")
        validator_index = content.index("validate_schema.py")
        self.assertLess(analyzer_index, validator_index)
        self.assertIn("--strict-safety", content)
        self.assertIn("normalized-report.json", content)

    def test_quality_gate_runs_fast_and_full_public_tests(self):
        content = self.read_gate()

        self.assertIn("test_validate_schema", content)
        self.assertIn("test_validate_bundle", content)
        self.assertIn("test_linux_security_normalizer", content)
        self.assertIn("test_linux_collection_launcher", content)
        self.assertIn("linux-service-inventory-audit.sh", content)
        self.assertIn("test_client_collection_launcher", content)
        self.assertIn("test_secureinfra_backup_readiness", content)
        self.assertIn('"discover", "-s", "tests", "-p", "test_*.py"', content)

    def test_quality_gate_runs_input_bundle_validator_smoke_test(self):
        content = self.read_gate()

        self.assertIn("validate_bundle.py", content)
        self.assertIn("Invoke-SampleBundleValidationSmokeTest", content)
        self.assertIn("linux-security-summary.json", content)
        self.assertIn("linux-service-inventory-audit.sh", content)
        self.assertIn("bundle-manifest.json", content)
        self.assertIn("--expected-bundle-count", content)
        self.assertIn("--strict-safety", content)

    def test_quality_gate_checks_new_script_integration_contract(self):
        content = self.read_gate()

        self.assertIn("Any new production script must have an explicit caller", content)
        self.assertIn("Require-TextMarker", content)
        self.assertIn("AGENTS.md", content)
        self.assertIn("Start-SecureInfraLinuxCollection.sh", content)
        self.assertIn("COLLECTION_BUNDLE_CONTRACT.md", content)

    def test_quality_gate_avoids_powershell_variable_colon_parser_error(self):
        content = self.read_gate()

        bad_expansions = re.findall(r'\$[A-Za-z_][A-Za-z0-9_]*:', content)
        allowed_scoped_variables = {"$script:"}
        unexpected = [item for item in bad_expansions if item not in allowed_scoped_variables]
        self.assertEqual(unexpected, [])


if __name__ == "__main__":
    unittest.main()

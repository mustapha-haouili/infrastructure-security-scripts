import importlib.util
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SECUREINFRA_REPORTING = ROOT / "SecureInfra_AI" / "scripts" / "reporting"
SAMPLE_INPUT = ROOT / "SecureInfra_AI" / "examples" / "sample-input" / "active-directory" / "sample-ad-inactive-users.json"

sys.path.insert(0, str(SECUREINFRA_REPORTING))

from secureinfra.bundles.ad_shared_bundle import discover_ad_shared_bundle, normalize_ad_shared_bundle
from secureinfra.loaders.csv_loader import load_csv_file
from secureinfra.loaders.json_loader import load_json_file
from secureinfra.normalizers.ad_inactive_users import normalize_ad_inactive_users
from secureinfra.report_generator.markdown_report import generate_markdown_reports
from secureinfra.risk_engine.rules import classify_ad_inactive_user


ANALYZER_PATH = SECUREINFRA_REPORTING / "secureinfra_analyzer.py"
spec = importlib.util.spec_from_file_location("secureinfra_analyzer", ANALYZER_PATH)
secureinfra_analyzer = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = secureinfra_analyzer
spec.loader.exec_module(secureinfra_analyzer)


class SecureInfraAITests(unittest.TestCase):
    def create_ad_shared_bundle(self, root: Path, include_inactive_users: bool = True) -> Path:
        bundle_dir = root / "ad-shared"
        bundle_dir.mkdir()
        sample_data = load_json_file(SAMPLE_INPUT)
        if include_inactive_users:
            (bundle_dir / "inactive-users.json").write_text(json.dumps(sample_data), encoding="utf-8-sig")
        for file_name in [
            "password-never-expires.json",
            "service-accounts.json",
            "spn-exposure.json",
            "privileged-groups.json",
            "gpo-health.json",
        ]:
            (bundle_dir / file_name).write_text(
                json.dumps(
                    {
                        "GeneratedAtUtc": "2026-06-08T09:00:00Z",
                        "Domain": "example.local",
                        "Summary": {"SampleRecords": 1},
                    }
                ),
                encoding="utf-8-sig",
            )
        return bundle_dir

    def test_sample_json_loads_correctly(self):
        data = load_json_file(SAMPLE_INPUT)

        self.assertEqual(data["Domain"], "example.local")
        self.assertEqual(len(data["InactiveUsers"]), 6)

    def test_json_loader_supports_utf8_bom(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bom.json"
            path.write_text('{"Domain": "example.local"}', encoding="utf-8-sig")

            data = load_json_file(path)

            self.assertEqual(data["Domain"], "example.local")

    def test_csv_loader_supports_utf8_bom(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bom.csv"
            path.write_text("Name,Domain\nEXAMPLE-DC01,example.local\n", encoding="utf-8-sig")

            rows = load_csv_file(path)

            self.assertEqual(rows, [{"Name": "EXAMPLE-DC01", "Domain": "example.local"}])

    def test_normalizer_creates_findings(self):
        data = load_json_file(SAMPLE_INPUT)
        report = normalize_ad_inactive_users(data, SAMPLE_INPUT)

        self.assertEqual(report["metadata"]["ai_required"], False)
        self.assertEqual(len(report["findings"]), 6)
        self.assertEqual(report["findings"][0]["finding_id"], "AD-INACTIVE-0001")
        self.assertEqual(report["findings"][0]["safe_to_auto_remediate"], False)

    def test_critical_risk_rule_works(self):
        risk = classify_ad_inactive_user(
            {
                "SamAccountName": "tier0.example",
                "Enabled": True,
                "InactiveDays": 120,
                "PrivilegedGroups": ["Domain Admins"],
                "HasSPN": False,
            }
        )

        self.assertEqual(risk["severity"], "Critical")
        self.assertEqual(risk["remediation_priority"], "Immediate Review")
        self.assertTrue(risk["requires_owner_review"])
        self.assertFalse(risk["safe_to_auto_remediate"])

    def test_hold_rule_works(self):
        risk = classify_ad_inactive_user(
            {
                "SamAccountName": "HealthMailbox-EXAMPLE-02",
                "Enabled": True,
                "InactiveDays": 300,
                "AccountCategory": "Exchange HealthMailbox",
                "RiskFlags": ["SystemManaged"],
            }
        )

        self.assertEqual(risk["severity"], "Hold")
        self.assertEqual(risk["remediation_priority"], "Hold")
        self.assertEqual(risk["status"], "Hold")

    def test_markdown_reports_are_generated(self):
        data = load_json_file(SAMPLE_INPUT)
        report = normalize_ad_inactive_users(data, SAMPLE_INPUT)

        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            paths = generate_markdown_reports(report, output_dir)

            self.assertEqual({path.name for path in paths}, {"executive-summary.md", "technical-findings.md", "remediation-plan.md"})
            self.assertIn("Overall Risk Summary", (output_dir / "executive-summary.md").read_text(encoding="utf-8"))
            self.assertIn("Technical Findings", (output_dir / "technical-findings.md").read_text(encoding="utf-8"))
            self.assertIn("Items Not Safe For Auto-Remediation", (output_dir / "remediation-plan.md").read_text(encoding="utf-8"))

    def test_cli_generates_normalized_and_markdown_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            with contextlib.redirect_stdout(io.StringIO()):
                exit_code = secureinfra_analyzer.main(
                    [
                        "--input",
                        str(SAMPLE_INPUT),
                        "--type",
                        "ad-inactive-users",
                        "--output",
                        str(output_dir),
                    ]
                )

            self.assertEqual(exit_code, 0)
            self.assertTrue((output_dir / "normalized-report.json").exists())
            self.assertTrue((output_dir / "executive-summary.md").exists())
            normalized = json.loads((output_dir / "normalized-report.json").read_text(encoding="utf-8"))
            self.assertEqual(normalized["summary"]["severity_counts"]["Critical"], 2)

    def test_ad_shared_discovers_known_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle_dir = self.create_ad_shared_bundle(Path(tmp))

            detected = discover_ad_shared_bundle(bundle_dir)

            self.assertIn("inactive_users", detected)
            self.assertIn("password_never_expires", detected)
            self.assertIn("gpo_health", detected)

    def test_ad_shared_directory_input_includes_inactive_user_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle_dir = self.create_ad_shared_bundle(Path(tmp))
            output_dir = Path(tmp) / "output"

            with contextlib.redirect_stdout(io.StringIO()):
                exit_code = secureinfra_analyzer.main(
                    [
                        "--input",
                        str(bundle_dir),
                        "--type",
                        "ad-shared",
                        "--output",
                        str(output_dir),
                        "--language",
                        "en",
                        "--format",
                        "markdown",
                    ]
                )

            self.assertEqual(exit_code, 0)
            normalized = json.loads((output_dir / "normalized-report.json").read_text(encoding="utf-8"))
            self.assertEqual(normalized["report_type"], "ad-shared")
            self.assertEqual(normalized["summary"]["normalized_finding_count"], 6)
            self.assertEqual(normalized["summary"]["severity_counts"]["Critical"], 2)
            self.assertIn("inactive_users", normalized["metadata"]["detected_files"])
            self.assertIn("stale-computers.json", normalized["metadata"]["missing_files"])
            self.assertIn("File detected and loaded", " ".join(normalized["notes"]))
            self.assertTrue((output_dir / "executive-summary.md").exists())
            executive = (output_dir / "executive-summary.md").read_text(encoding="utf-8")
            self.assertIn("Detected AD Report Files", executive)
            self.assertIn("Limitations", executive)

    def test_ad_shared_missing_optional_files_do_not_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle_dir = self.create_ad_shared_bundle(Path(tmp), include_inactive_users=False)

            report = normalize_ad_shared_bundle(bundle_dir)

            self.assertEqual(report["summary"]["normalized_finding_count"], 0)
            self.assertIn("inactive-users.json", report["metadata"]["missing_files"])
            self.assertIn("inactive-users.json was not found", " ".join(report["notes"]))

    def test_ad_inactive_users_rejects_directory_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            with contextlib.redirect_stderr(io.StringIO()):
                exit_code = secureinfra_analyzer.main(
                    [
                        "--input",
                        tmp,
                        "--type",
                        "ad-inactive-users",
                        "--output",
                        str(Path(tmp) / "output"),
                    ]
                )

            self.assertEqual(exit_code, 1)

    def test_no_real_customer_data_in_secureinfra_ai_samples(self):
        sample_root = ROOT / "SecureInfra_AI" / "examples"
        allowed_terms = {
            "example.local",
            "example gmbh",
            "example-dc01",
            "example",
            "alex admin",
            "julia reed",
        }
        blocked_fragments = [
            "mustapha",
            "haouili",
            "mh_laptop",
            "terminal2019",
            "contoso",
            "corp.local",
            "production.local",
            "administrator@",
            "192.168.",
            "10.0.",
            "172.16.",
        ]

        for path in sample_root.rglob("*"):
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8").lower()
            for fragment in blocked_fragments:
                self.assertNotIn(fragment, text, f"{fragment} found in {path}")
            self.assertTrue(any(term in text for term in allowed_terms), f"No fictional marker found in {path}")


if __name__ == "__main__":
    unittest.main()

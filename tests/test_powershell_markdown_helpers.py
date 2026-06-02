import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read_script(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def function_body(script_text: str, function_name: str) -> str:
    pattern = re.compile(
        rf"function\s+{re.escape(function_name)}\s*\{{(?P<body>.*?)(?=^function\s|\Z)",
        re.MULTILINE | re.DOTALL,
    )
    match = pattern.search(script_text)
    if not match:
        raise AssertionError(f"{function_name} was not found")
    return match.group("body")


class PowerShellMarkdownHelperTests(unittest.TestCase):
    def assert_markdown_helper_is_not_collection_typed(self, relative_path: str):
        script = read_script(relative_path)
        body = function_body(script, "Add-MarkdownLine")
        self.assertIn("[object]$Lines", body)
        self.assertIn("[AllowEmptyString()]", body)
        self.assertNotIn("[System.Collections.Generic.List[string]]$Lines", body)

    def assert_table_rows_allow_empty_results(self, relative_path: str, function_name: str):
        script = read_script(relative_path)
        body = function_body(script, function_name)
        self.assertIn("[AllowEmptyCollection()]", body)
        self.assertIn("[object[]]$Rows", body)

    def test_ad_markdown_helpers_allow_blank_and_empty_reports(self):
        script = "scripts/windows/ad/Get-ADInactiveUserReport.ps1"
        self.assert_markdown_helper_is_not_collection_typed(script)
        self.assert_table_rows_allow_empty_results(script, "Add-MarkdownUserTable")

    def test_stale_computer_markdown_helpers_allow_blank_and_empty_reports(self):
        script = "scripts/windows/ad/Get-ADStaleComputerReport.ps1"
        self.assert_markdown_helper_is_not_collection_typed(script)
        self.assert_table_rows_allow_empty_results(script, "Add-MarkdownComputerTable")

    def test_gpo_markdown_helpers_allow_blank_and_empty_reports(self):
        script = "scripts/windows/gpo/Get-ADGPOHealthReport.ps1"
        self.assert_markdown_helper_is_not_collection_typed(script)
        self.assert_table_rows_allow_empty_results(script, "Add-MarkdownFindingTable")

    def test_privileged_group_markdown_helpers_allow_blank_and_empty_reports(self):
        script = "scripts/windows/ad/Watch-ADPrivilegedGroupChanges.ps1"
        self.assert_markdown_helper_is_not_collection_typed(script)
        self.assert_table_rows_allow_empty_results(script, "Add-MarkdownChangeTable")

    def test_privileged_group_risk_helper_allows_empty_members(self):
        script = read_script("scripts/windows/ad/Watch-ADPrivilegedGroupChanges.ps1")
        body = function_body(script, "Add-CurrentRiskRows")
        self.assertIn("[AllowEmptyCollection()]", body)
        self.assertIn("[object[]]$DirectMembers", body)

    def test_service_account_markdown_helpers_allow_blank_and_empty_reports(self):
        script = "scripts/windows/ad/Get-ADServiceAccountAudit.ps1"
        self.assert_markdown_helper_is_not_collection_typed(script)
        self.assert_table_rows_allow_empty_results(script, "Add-MarkdownServiceAccountTable")

    def test_spn_exposure_markdown_helpers_allow_blank_and_empty_reports(self):
        script = "scripts/windows/ad/Get-ADSPNExposureAudit.ps1"
        self.assert_markdown_helper_is_not_collection_typed(script)
        self.assert_table_rows_allow_empty_results(script, "Add-MarkdownSPNTable")

    def test_password_never_expires_markdown_helpers_allow_blank_and_empty_reports(self):
        script = "scripts/windows/ad/Get-ADPasswordNeverExpiresReport.ps1"
        self.assert_markdown_helper_is_not_collection_typed(script)
        self.assert_table_rows_allow_empty_results(script, "Add-MarkdownPasswordAccountTable")


if __name__ == "__main__":
    unittest.main()

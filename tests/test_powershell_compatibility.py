from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PROTECTED_AUTOMATIC_VARIABLES = (
    "PID",
    "Host",
    "HOME",
    "PSHOME",
    "PSVersionTable",
    "PSScriptRoot",
    "PSCommandPath",
    "ExecutionContext",
    "ShellId",
    "PWD",
    "Args",
    "Input",
    "Matches",
    "Error",
    "LASTEXITCODE",
    "MyInvocation",
    "StackTrace",
    "NestedPromptLevel",
    "OFS",
    "PSBoundParameters",
    "PSCmdlet",
)
PROTECTED_NAME = "(?:" + "|".join(PROTECTED_AUTOMATIC_VARIABLES) + ")"
ASSIGNMENT = re.compile(
    rf"^\s*\$(?:global:|script:|local:|private:)?{PROTECTED_NAME}\s*(?:=|\+=|-=|\+\+|--)",
    re.IGNORECASE | re.MULTILINE,
)
LOOP_VARIABLE = re.compile(
    rf"\b(?:for|foreach)\s*\(\s*\${PROTECTED_NAME}\b",
    re.IGNORECASE,
)
TYPED_DECLARATION = re.compile(
    rf"(?:\[[^\]\r\n]+\]\s*)+\${PROTECTED_NAME}\b(?=\s*(?:=|,|\)|\r?$))",
    re.IGNORECASE | re.MULTILINE,
)
POWERSHELL_7_ONLY = (
    re.compile(r"\?\?"),
    re.compile(r"\?\."),
    re.compile(r"\bForEach-Object\s+-Parallel\b", re.IGNORECASE),
    re.compile(r"\bConvertFrom-Json\b[^\r\n]*\b-AsHashtable\b", re.IGNORECASE),
    re.compile(r"\b(?:Join-String|Test-Json|Get-Error)\b", re.IGNORECASE),
    re.compile(r"\b-Encoding\s+['\"]?utf8NoBOM\b", re.IGNORECASE),
    re.compile(r"\[System\.IO\.Path\]::GetRelativePath\b", re.IGNORECASE),
    re.compile(r"\[Convert\]::ToHexString\b", re.IGNORECASE),
)


def powershell_files() -> list[Path]:
    files = sorted((REPO_ROOT / "scripts").rglob("*.ps1"))
    quality_gate = REPO_ROOT / "quality-gate.ps1"
    if quality_gate.is_file():
        files.append(quality_gate)
    return files


class PowerShellCompatibilityTests(unittest.TestCase):
    def test_scripts_do_not_overwrite_protected_automatic_variables(self):
        failures: list[str] = []
        for path in powershell_files():
            content = path.read_text(encoding="utf-8-sig")
            for pattern in (ASSIGNMENT, LOOP_VARIABLE, TYPED_DECLARATION):
                for match in pattern.finditer(content):
                    line = content.count("\n", 0, match.start()) + 1
                    failures.append(f"{path.relative_to(REPO_ROOT)}:{line}: {match.group(0).strip()}")
        self.assertEqual(failures, [], "PowerShell automatic-variable collision:\n" + "\n".join(failures))

    def test_scripts_avoid_known_powershell_7_only_syntax(self):
        failures: list[str] = []
        for path in powershell_files():
            content = path.read_text(encoding="utf-8-sig")
            for pattern in POWERSHELL_7_ONLY:
                match = pattern.search(content)
                if match:
                    line = content.count("\n", 0, match.start()) + 1
                    failures.append(f"{path.relative_to(REPO_ROOT)}:{line}: {match.group(0)}")
        self.assertEqual(failures, [], "Windows PowerShell 5.1 incompatibility:\n" + "\n".join(failures))

    def test_network_process_lookup_does_not_shadow_pid(self):
        path = REPO_ROOT / "scripts" / "windows" / "network" / "Get-WindowsNetworkExposureAudit.ps1"
        content = path.read_text(encoding="utf-8-sig")
        self.assertIn('$processIdKey = "$($service.ProcessId)"', content)
        self.assertIn("$matchingPorts = New-Object System.Collections.Generic.List[int]", content)
        self.assertNotRegex(content, re.compile(r"^\s*\$pid\s*=", re.IGNORECASE | re.MULTILINE))
        self.assertNotRegex(content, re.compile(r"^\s*\$matches\s*=", re.IGNORECASE | re.MULTILINE))


if __name__ == "__main__":
    unittest.main()

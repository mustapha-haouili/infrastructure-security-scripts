from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MARKDOWN_LINK_RE = re.compile(r"(?<!!)\[[^\]]*\]\(([^)]+)\)")
INDEXED_SCRIPT_RE = re.compile(r"^- `([^`]+\.(?:ps1|sh|py))`$", re.MULTILINE)
CANONICAL_SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]


class PublicDocumentationContractTests(unittest.TestCase):
    def test_canonical_documents_exist_and_retired_duplicates_do_not(self) -> None:
        required = [
            "README.md",
            "ARCHITECTURE.md",
            "DATA_CONTRACT.md",
            "CONTRIBUTING.md",
            "docs/methodology.md",
            "docs/monthly-kpi-methodology.md",
            "docs/script-index.md",
            "docs/script-reference.md",
        ]
        retired = [
            "PROJECT_CONTEXT.md",
            "PUBLIC_PRIVATE_BOUNDARY.md",
            "CODEX_WORKFLOW.md",
            "SCHEMA.md",
            "docs/windows-roadmap.md",
            "docs/script-documentation-standard.md",
            "docs/service-model/monthly-security-review.md",
            "SecureInfra_AI/docs/ai-reporting-architecture.md",
            "SecureInfra_AI/docs/methodology.md",
            "SecureInfra_AI/docs/secureinfra-ai-roadmap.md",
        ]

        for relative_path in required:
            self.assertTrue((ROOT / relative_path).is_file(), relative_path)
        for relative_path in retired:
            self.assertFalse((ROOT / relative_path).exists(), relative_path)

    def test_local_markdown_links_resolve(self) -> None:
        broken: list[str] = []
        for markdown_path in ROOT.rglob("*.md"):
            text = markdown_path.read_text(encoding="utf-8")
            for raw_target in MARKDOWN_LINK_RE.findall(text):
                target = raw_target.strip().split()[0].strip("<>")
                if not target or target.startswith(("#", "http://", "https://", "mailto:")):
                    continue
                target = target.split("#", 1)[0]
                if not target:
                    continue
                resolved = (markdown_path.parent / target).resolve()
                if not resolved.exists():
                    broken.append(f"{markdown_path.relative_to(ROOT)} -> {target}")

        self.assertEqual([], broken, "Broken local Markdown links:\n" + "\n".join(broken))

    def test_script_index_references_existing_files(self) -> None:
        index_text = (ROOT / "docs/script-index.md").read_text(encoding="utf-8")
        indexed_paths = INDEXED_SCRIPT_RE.findall(index_text)
        self.assertGreater(len(indexed_paths), 20)
        missing = [path for path in indexed_paths if not (ROOT / path).is_file()]
        self.assertEqual([], missing)

    def test_public_schemas_use_canonical_technical_severities(self) -> None:
        schema_paths = [
            ROOT / "SecureInfra_AI/schemas/finding.schema.json",
            ROOT / "schemas/finding.schema.json",
        ]
        for schema_path in schema_paths:
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            severity_enum = schema["properties"]["severity"]["enum"]
            self.assertEqual(CANONICAL_SEVERITIES, severity_enum, str(schema_path))
            self.assertNotIn("Hold", severity_enum)

        ai_schema = json.loads(schema_paths[0].read_text(encoding="utf-8"))
        remediation_enum = ai_schema["properties"]["remediation_priority"]["enum"]
        self.assertIn("Hold", remediation_enum)


if __name__ == "__main__":
    unittest.main()

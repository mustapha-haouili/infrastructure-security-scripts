"""Deterministic local AI stub.

This stub does not call a model. It returns placeholder text so Phase 1 can keep
working without AI dependencies.
"""

from __future__ import annotations

from typing import Any

from secureinfra.ai.provider_interface import AIProvider


class LocalAIStub(AIProvider):
    provider_name = "local-ai-stub"

    def summarize_findings(self, normalized_report: dict[str, Any], language: str = "en") -> str:
        count = len(normalized_report.get("findings", []))
        return f"Deterministic placeholder summary based on {count} provided finding(s)."

    def explain_remediation(self, finding: dict[str, Any], language: str = "en") -> str:
        title = str(finding.get("title") or "finding")
        return f"Deterministic placeholder remediation explanation for: {title}. Human approval is required."

    def translate_text(self, text: str, language: str) -> str:
        if language == "en":
            return text
        return f"[Placeholder translation for {language}] {text}"

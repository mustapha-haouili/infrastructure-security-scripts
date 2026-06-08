"""AI provider interface for future optional report assistance."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class AIProvider(ABC):
    """Interface for future local or private AI providers.

    AI providers may summarize findings, generate executive language, explain
    remediation, translate reports, and express risk in business language.
    They must use only provided evidence and must not decide remediation.
    """

    @abstractmethod
    def summarize_findings(self, normalized_report: dict[str, Any], language: str = "en") -> str:
        """Summarize findings using only supplied evidence."""

    @abstractmethod
    def explain_remediation(self, finding: dict[str, Any], language: str = "en") -> str:
        """Explain remediation context without approving or executing changes."""

    @abstractmethod
    def translate_text(self, text: str, language: str) -> str:
        """Translate report text when future language support is enabled."""

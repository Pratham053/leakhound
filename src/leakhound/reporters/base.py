from __future__ import annotations

from abc import ABC, abstractmethod

from leakhound.models import Finding


class Reporter(ABC):
    """Abstract base for all output formats."""

    @abstractmethod
    def report(self, findings: list[Finding]) -> None:
        """Render findings to this reporter's destination."""
        raise NotImplementedError
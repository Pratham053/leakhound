from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterator

from leakhound.models import Finding


class Detector(ABC):
    """Abstract base for all detection strategies."""

    name: str

    @abstractmethod
    def scan(self, file_path: str, content: str) -> Iterator[Finding]:
        """Inspect one file's text and yield any Findings."""
        raise NotImplementedError
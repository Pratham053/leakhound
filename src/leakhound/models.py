from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Severity(Enum):
    """Severity levels for a finding, least to most urgent."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class Finding:
    """A single potential secret discovered during a scan."""
    rule_id: str
    description: str
    severity: Severity
    file_path: str
    line_number: int
    secret: str
    entropy: Optional[float] = None
    commit: Optional[str] = None
    line_content: Optional[str] = None

    def redacted(self, visible: int = 4) -> str:
        """Mask the middle of the secret, keeping a few chars for triage."""
        if len(self.secret) <= visible * 2:
            return "*" * len(self.secret)
        masked = "*" * (len(self.secret) - visible * 2)
        return f"{self.secret[:visible]}{masked}{self.secret[-visible:]}"
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Iterator

from leakhound.detectors.base import Detector
from leakhound.models import Finding, Severity

TOKEN_PATTERN = re.compile(r"[A-Za-z0-9+/=_\-]{16,}")


def shannon_entropy(data: str) -> float:
    """Shannon entropy of a string, in bits per character."""
    if not data:
        return 0.0
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in Counter(data).values()
    )


class EntropyDetector(Detector):
    """Flags high-entropy strings that no named pattern caught."""

    name = "entropy"

    def __init__(self, threshold: float = 4.5, min_length: int = 20) -> None:
        self.threshold = threshold
        self.min_length = min_length

    def scan(self, file_path: str, content: str) -> Iterator[Finding]:
        for line_number, line in enumerate(content.splitlines(), start=1):
            for match in TOKEN_PATTERN.finditer(line):
                token = match.group(0)
                if len(token) < self.min_length:
                    continue
                entropy = shannon_entropy(token)
                if entropy >= self.threshold:
                    yield Finding(
                        rule_id="high-entropy-string",
                        description="High-Entropy String",
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_number=line_number,
                        secret=token,
                        entropy=round(entropy, 2),
                        line_content=line.strip(),
                    )
from __future__ import annotations

import json
import sys
from typing import IO, Optional

from leakhound.models import Finding
from leakhound.reporters.base import Reporter


class JSONReporter(Reporter):
    """Emits findings as a JSON array — machine-readable for piping into other tools.

    Secrets are redacted in the output: a report file is something people commit
    and share, so writing raw credentials into it would defeat the tool's purpose.
    """

    def __init__(self, stream: Optional[IO[str]] = None, indent: int = 2) -> None:
        self.stream = stream or sys.stdout
        self.indent = indent

    def report(self, findings: list[Finding]) -> None:
        payload = [self._serialise(f) for f in findings]
        json.dump(payload, self.stream, indent=self.indent)
        self.stream.write("\n")

    @staticmethod
    def _serialise(f: Finding) -> dict:
        return {
            "rule_id": f.rule_id,
            "description": f.description,
            "severity": str(f.severity),
            "file": f.file_path,
            "line": f.line_number,
            "secret": f.redacted(),
            "entropy": f.entropy,
            "commit": f.commit,
        }
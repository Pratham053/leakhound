from __future__ import annotations

import json
import sys
from typing import IO, Optional

from leakhound.models import Finding, Severity
from leakhound.reporters.base import Reporter

# SARIF only has three levels; map our five severities onto them.
_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


class SARIFReporter(Reporter):
    """Emits findings as SARIF 2.1.0 — the format GitHub code scanning ingests.

    Uploading this to GitHub surfaces each finding inline on the relevant line
    in the Security tab and in pull requests.
    """

    TOOL_NAME = "leakhound"
    TOOL_VERSION = "0.1.0"
    INFO_URI = "https://github.com/Pratham053/leakhound"

    def __init__(self, stream: Optional[IO[str]] = None) -> None:
        self.stream = stream or sys.stdout

    def report(self, findings: list[Finding]) -> None:
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.TOOL_NAME,
                            "version": self.TOOL_VERSION,
                            "informationUri": self.INFO_URI,
                            "rules": self._rules(findings),
                        }
                    },
                    "results": [self._result(f) for f in findings],
                }
            ],
        }
        json.dump(sarif, self.stream, indent=2)
        self.stream.write("\n")

    @staticmethod
    def _rules(findings: list[Finding]) -> list[dict]:
        seen: dict[str, dict] = {}
        for f in findings:
            if f.rule_id not in seen:
                seen[f.rule_id] = {
                    "id": f.rule_id,
                    "name": f.description,
                    "shortDescription": {"text": f.description},
                }
        return list(seen.values())

    @staticmethod
    def _result(f: Finding) -> dict:
        return {
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f"{f.description} detected"},
            "locations": [
                {
                    "physicalLocation": {
                        # SARIF expects forward-slash URIs, even on Windows.
                        "artifactLocation": {"uri": f.file_path.replace("\\", "/")},
                        "region": {"startLine": f.line_number},
                    }
                }
            ],
        }
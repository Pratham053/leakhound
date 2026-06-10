from __future__ import annotations

from leakhound.models import Finding, Severity
from leakhound.reporters.base import Reporter

_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
          Severity.LOW: 3, Severity.INFO: 4}
_COLORS = {Severity.CRITICAL: "\033[91m", Severity.HIGH: "\033[91m",
           Severity.MEDIUM: "\033[93m", Severity.LOW: "\033[94m",
           Severity.INFO: "\033[90m"}
_RESET = "\033[0m"
_BOLD = "\033[1m"


class ConsoleReporter(Reporter):
    """Prints findings to the terminal, most severe first."""

    def __init__(self, use_color: bool = True) -> None:
        self.use_color = use_color

    def report(self, findings: list[Finding]) -> None:
        if not findings:
            print(self._wrap(_BOLD, "No secrets found."))
            return
        for f in sorted(findings, key=lambda x: _ORDER.get(x.severity, 99)):
            self._print_finding(f)
        self._print_summary(findings)

    def _wrap(self, code: str, text: str) -> str:
        return f"{code}{text}{_RESET}" if self.use_color else text

    def _print_finding(self, f: Finding) -> None:
        tag = self._wrap(_COLORS.get(f.severity, ""), f"[{str(f.severity).upper()}]")
        print(f"{tag} {f.description} ({f.rule_id})")
        print(f"  {f.file_path}:{f.line_number}")
        print(f"  secret: {f.redacted()}")
        if f.entropy is not None:
            print(f"  entropy: {f.entropy}")
        print()

    def _print_summary(self, findings: list[Finding]) -> None:
        counts: dict[Severity, int] = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        parts = [f"{counts[s]} {s}" for s in Severity if s in counts]
        print(self._wrap(_BOLD, f"{len(findings)} finding(s): {', '.join(parts)}"))
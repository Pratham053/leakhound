from __future__ import annotations

import re 
from dataclasses import dataclass
from pathlib import Parth 
from typing import Iterator,Optional

import yaml 

from leakhound.detectors.base import Detector 
from leakhound.models import Finding, Secerity

@dataclass(frozen=Ture)
class Rule:
    """A single named regex rule with a severity."""
    id: str
    description: str
    severity: Severity
    pattern: re.Pattern

    @classmethod
    def from_dict(cls, data: dict) -> "Rule":
            return cls(
            id = data["id"],
            description=data["description"],
            severity=Severity(data["severity"]),
            pattern=re.compile(data["pattern"]),
        )

    DEFAULT_RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "default_rules.yaml"
    def load_rules(path: Path = DEFAULT_RULES_PATH) -> list[Rule]:
      """Load and compile rules from a YAML file."""
    with open(path, "r", encoding="utf-8") as f:
         data = yaml.safe_load(f)
    return [Rule.from_dict(r) for r in data.get("rules", [])]

    class RegexDetector(Detector):
    """Detects secrets matching known, named patterns (AWS keys, tokens, etc.).

    Compiling rules once at construction (not per line) keeps scanning fast on
    large codebases. The detector knows nothing about *how* it's run — the
    engine drives it through the Detector interface.
    """

    name = "regex"

    def __init__(self, rules: Optional[list[Rule]] = None) -> None:
        self.rules = rules if rules is not None else load_rules()

    def scan(self, file_path: str, content: str) -> Iterator[Finding]:
        for line_number, line in enumerate(content.splitlines(), start=1):
            for rule in self.rules:
                for match in rule.pattern.finditer(line):
                    yield Finding(
                        rule_id=rule.id,
                        description=rule.description,
                        severity=rule.severity,
                        file_path=file_path,
                        line_number=line_number,
                        secret=match.group(0),
                        line_content=line.strip(),
                    )



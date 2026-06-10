import re

from leakhound.detectors.regex_detector import RegexDetector, Rule, load_rules
from leakhound.models import Severity


def test_detects_aws_access_key():
    det = RegexDetector()
    findings = list(det.scan("f.py", 'key = "AKIAIOSFODNN7EXAMPLE"'))
    assert "aws-access-key" in {f.rule_id for f in findings}


def test_detects_github_pat():
    det = RegexDetector()
    token = "ghp_" + "a" * 36
    findings = list(det.scan("f.py", f'token = "{token}"'))
    assert any(f.rule_id == "github-pat" for f in findings)


def test_clean_content_yields_nothing():
    det = RegexDetector()
    findings = list(det.scan("f.py", "x = 1 + 2  # just math\n"))
    assert findings == []


def test_custom_rule_is_honoured():
    rule = Rule(
        id="test-rule", description="Test", severity=Severity.LOW,
        pattern=re.compile(r"SECRET-\d{4}"),
    )
    det = RegexDetector(rules=[rule])
    findings = list(det.scan("f.py", "code = SECRET-1234"))
    assert len(findings) == 1
    assert findings[0].rule_id == "test-rule"
    assert findings[0].severity == Severity.LOW


def test_load_rules_returns_compiled_patterns():
    rules = load_rules()
    assert len(rules) > 0
    assert all(isinstance(r.pattern, re.Pattern) for r in rules)
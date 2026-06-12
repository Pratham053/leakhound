import io
import json

from leakhound.models import Finding, Severity
from leakhound.reporters.json_reporter import JSONReporter
from leakhound.reporters.sarif import SARIFReporter


def _finding() -> Finding:
    return Finding(
        rule_id="aws-access-key", description="AWS Access Key ID",
        severity=Severity.HIGH, file_path="src/x.py", line_number=7,
        secret="AKIAIOSFODNN7EXAMPLE",
    )


def test_json_reporter_emits_valid_json():
    buf = io.StringIO()
    JSONReporter(stream=buf).report([_finding()])
    data = json.loads(buf.getvalue())
    assert len(data) == 1
    assert data[0]["rule_id"] == "aws-access-key"
    assert data[0]["severity"] == "high"
    assert data[0]["line"] == 7


def test_json_reporter_redacts_secret():
    buf = io.StringIO()
    JSONReporter(stream=buf).report([_finding()])
    data = json.loads(buf.getvalue())
    assert data[0]["secret"] != "AKIAIOSFODNN7EXAMPLE"
    assert "*" in data[0]["secret"]


def test_json_reporter_empty():
    buf = io.StringIO()
    JSONReporter(stream=buf).report([])
    assert json.loads(buf.getvalue()) == []


def test_sarif_reporter_structure():
    buf = io.StringIO()
    SARIFReporter(stream=buf).report([_finding()])
    sarif = json.loads(buf.getvalue())
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "leakhound"
    assert run["results"][0]["ruleId"] == "aws-access-key"
    assert run["results"][0]["level"] == "error"  # HIGH -> error


def test_sarif_uses_forward_slash_uris():
    f = Finding(rule_id="r", description="R", severity=Severity.LOW,
                file_path="a\\b\\c.py", line_number=1, secret="x")
    buf = io.StringIO()
    SARIFReporter(stream=buf).report([f])
    sarif = json.loads(buf.getvalue())
    uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "a/b/c.py"    
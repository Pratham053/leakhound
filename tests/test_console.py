from leakhound.models import Finding, Severity
from leakhound.reporters.console import ConsoleReporter


def test_empty_findings_message(capsys):
    ConsoleReporter(use_color=False).report([])
    assert "No secrets found" in capsys.readouterr().out


def test_reports_finding_details(capsys):
    f = Finding(
        rule_id="aws-access-key", description="AWS Access Key ID",
        severity=Severity.HIGH, file_path="x.py", line_number=3,
        secret="AKIAIOSFODNN7EXAMPLE",
    )
    ConsoleReporter(use_color=False).report([f])
    out = capsys.readouterr().out
    assert "AWS Access Key ID" in out
    assert "x.py:3" in out
    assert "1 finding(s)" in out
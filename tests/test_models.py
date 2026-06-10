from leakhound.models import Finding, Severity


def _finding(secret: str) -> Finding:
    return Finding(
        rule_id="x", description="X", severity=Severity.HIGH,
        file_path="f", line_number=1, secret=secret,
    )


def test_redacted_masks_middle_keeps_ends():
    f = _finding("ABCDEFGHIJKLMNOP")  # 16 chars
    r = f.redacted(visible=4)
    assert r.startswith("ABCD")
    assert r.endswith("MNOP")
    assert "*" in r
    assert len(r) == len("ABCDEFGHIJKLMNOP")


def test_redacted_short_secret_fully_masked():
    f = _finding("abc")  # shorter than visible*2
    assert f.redacted(visible=4) == "***"


def test_severity_str():
    assert str(Severity.CRITICAL) == "critical"
    assert str(Severity.MEDIUM) == "medium"
import re

from leakhound.detectors.regex_detector import RegexDetector, Rule
from leakhound.engine import Scanner
from leakhound.models import Severity


def _scanner() -> Scanner:
    rule = Rule(id="aws-access-key", description="AWS Access Key ID",
                severity=Severity.HIGH, pattern=re.compile(r"AKIA[0-9A-Z]{16}"))
    return Scanner([RegexDetector(rules=[rule])])


def test_scans_single_file(tmp_path):
    f = tmp_path / "secret.txt"
    f.write_text('key = "AKIAIOSFODNN7EXAMPLE"', encoding="utf-8")
    assert len(_scanner().scan_path(str(f))) == 1


def test_scans_directory_recursively(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "a.txt").write_text("AKIAIOSFODNN7EXAMPLE", encoding="utf-8")
    (tmp_path / "b.txt").write_text("nothing here", encoding="utf-8")
    assert len(_scanner().scan_path(str(tmp_path))) == 1


def test_skips_git_directory(tmp_path):
    git = tmp_path / ".git"
    git.mkdir()
    (git / "config").write_text("AKIAIOSFODNN7EXAMPLE", encoding="utf-8")
    assert _scanner().scan_path(str(tmp_path)) == []


def test_skips_binary_file(tmp_path):
    f = tmp_path / "image.bin"
    f.write_bytes(b"\x00\x01\xff\xfe AKIAIOSFODNN7EXAMPLE")
    # Invalid UTF-8 -> file is skipped, not crashed on
    assert _scanner().scan_path(str(tmp_path)) == []
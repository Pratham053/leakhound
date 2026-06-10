from leakhound.detectors.entropy_detector import EntropyDetector, shannon_entropy


def test_entropy_zero_for_uniform_string():
    assert shannon_entropy("aaaaaaaa") == 0.0


def test_entropy_empty_string():
    assert shannon_entropy("") == 0.0


def test_entropy_higher_for_random_than_repetitive():
    assert shannon_entropy("aaaaaaaaaaaaaaaa") < shannon_entropy("aB3xZ9qLmK2wPq7r")


def test_detector_flags_high_entropy_token():
    det = EntropyDetector(threshold=4.0, min_length=16)
    findings = list(det.scan("f.py", 'token = "aB3xZ9qLmK2wPq7rN8vC1tH5"'))
    assert len(findings) >= 1
    assert findings[0].rule_id == "high-entropy-string"
    assert findings[0].entropy is not None


def test_detector_ignores_low_entropy_token():
    det = EntropyDetector(threshold=4.0, min_length=16)
    findings = list(det.scan("f.py", 'word = "aaaaaaaaaaaaaaaaaaaa"'))
    assert findings == []


def test_detector_respects_min_length():
    det = EntropyDetector(threshold=1.0, min_length=50)
    findings = list(det.scan("f.py", 'x = "aB3xZ9qLmK2wPq7r"'))
    assert findings == []
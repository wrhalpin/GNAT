from gnat.agents.secrets.hygiene.duplicate_detector import DuplicateSecretDetector
from gnat.agents.secrets.hygiene.leak_scanner import SecretLeakScanner
from gnat.agents.secrets.hygiene.unsafe_secrets import UnsafeSecretAnalyzer


def test_leak_scanner_finds_hardcoded_secret_assignment():
    scanner = SecretLeakScanner()
    findings = scanner.scan_text('api_key = "abc123456789XYZ"
print("ok")', path="example.py")
    assert len(findings) == 1
    assert findings[0].rule_id == "generic_assignment"


def test_duplicate_detector_groups_identical_values():
    detector = DuplicateSecretDetector()
    findings = detector.find_duplicates(
        [
            ("dev/alienvault/api-key", "same-value"),
            ("dev/misp/api-key", "same-value"),
            ("dev/other/api-key", "different"),
        ]
    )
    assert len(findings) == 1
    assert len(findings[0].locations) == 2


def test_unsafe_secret_analyzer_flags_obvious_default():
    analyzer = UnsafeSecretAnalyzer()
    findings = analyzer.analyze([("prod/alienvault/api-key", "password")])
    assert findings
    assert findings[0].severity == "high"

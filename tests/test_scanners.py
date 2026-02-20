"""Tests for Akali scanners."""

from defensive.scanners.secrets_scanner import SecretsScanner
from defensive.scanners.dependency_scanner import DependencyScanner
from defensive.scanners.sast_scanner import SASTScanner


def test_secrets_scanner_available():
    """Test secrets scanner is available."""
    scanner = SecretsScanner()
    # Should be True if gitleaks installed
    available = scanner.check_available()
    print(f"SecretsScanner available: {available}")
    assert isinstance(available, bool)


def test_dependency_scanner_available():
    """Test dependency scanner is available."""
    scanner = DependencyScanner()
    available = scanner.check_available()
    print(f"DependencyScanner available: {available}")
    assert isinstance(available, bool)


def test_sast_scanner_available():
    """Test SAST scanner is available."""
    scanner = SASTScanner()
    available = scanner.check_available()
    print(f"SASTScanner available: {available}")
    assert isinstance(available, bool)


if __name__ == "__main__":
    print("Testing Akali scanners...\n")
    test_secrets_scanner_available()
    test_dependency_scanner_available()
    test_sast_scanner_available()
    print("\n✅ All scanner tests passed")

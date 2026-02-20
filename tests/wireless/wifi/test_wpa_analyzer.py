"""Tests for WPA analyzer."""

import pytest
from wireless.wifi.wpa_analyzer import WPAAnalyzer


def test_identify_encryption_type():
    """Test WPA encryption type identification"""
    analyzer = WPAAnalyzer()

    # Test various encryption types
    assert analyzer.identify_encryption("WPA2 PSK") == "WPA2-PSK"
    assert analyzer.identify_encryption("WPA3 SAE") == "WPA3-SAE"
    assert analyzer.identify_encryption("WPA PSK") == "WPA-PSK"
    assert analyzer.identify_encryption("WEP") == "WEP"
    assert analyzer.identify_encryption("Open") == "Open"


def test_assess_security_level():
    """Test security level assessment"""
    analyzer = WPAAnalyzer()

    # Strong encryption
    assert analyzer.assess_security("WPA3-SAE") == "strong"

    # Moderate encryption
    assert analyzer.assess_security("WPA2-PSK") == "moderate"

    # Weak encryption
    assert analyzer.assess_security("WPA-PSK") == "weak"
    assert analyzer.assess_security("WEP") == "weak"

    # Insecure
    assert analyzer.assess_security("Open") == "insecure"

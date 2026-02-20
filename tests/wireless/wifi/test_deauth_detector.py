"""Tests for deauth attack detector."""

import pytest
from pathlib import Path
from wireless.wifi.deauth_detector import DeauthDetector


def test_detect_deauth_frames():
    """Test deauth frame detection"""
    detector = DeauthDetector()
    pcap_path = Path("tests/fixtures/deauth_attack.pcap")

    # Test with non-existent file first
    result = detector.detect_deauth_frames(pcap_path)

    assert isinstance(result, dict)
    assert 'deauth_count' in result
    assert 'suspicious' in result
    assert isinstance(result['deauth_count'], int)
    assert isinstance(result['suspicious'], bool)


def test_analyze_deauth_pattern():
    """Test deauth pattern analysis"""
    detector = DeauthDetector()

    # Low count - not suspicious
    result = detector.analyze_pattern(deauth_count=5, timespan=60)
    assert result['suspicious'] is False
    assert result['severity'] == "low"

    # High count - suspicious
    result = detector.analyze_pattern(deauth_count=50, timespan=10)
    assert result['suspicious'] is True
    assert result['severity'] in ["medium", "high"]

    # Very high count - critical
    result = detector.analyze_pattern(deauth_count=200, timespan=10)
    assert result['suspicious'] is True
    assert result['severity'] == "high"

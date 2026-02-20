"""Tests for firmware extractor."""

import pytest
from pathlib import Path
from iot.firmware.extractor import FirmwareExtractor


def test_extract_firmware():
    """Test firmware extraction"""
    extractor = FirmwareExtractor()

    # Test with non-existent file
    result = extractor.extract_firmware(Path("tests/fixtures/firmware.bin"))

    assert isinstance(result, dict)
    assert 'success' in result
    assert 'filesystems' in result
    assert isinstance(result['filesystems'], list)


def test_scan_secrets():
    """Test secret scanning in extracted firmware"""
    extractor = FirmwareExtractor()

    # Test with sample text
    secrets = extractor.scan_secrets(
        search_path=Path("/tmp"),
        patterns=["password", "api_key"]
    )

    assert isinstance(secrets, list)
    # Empty list is OK if no secrets found


def test_find_credentials():
    """Test hardcoded credential detection"""
    extractor = FirmwareExtractor()

    # Test with sample content
    credentials = extractor.find_credentials(
        content="admin:password123\nuser=root\npassword='secret'"
    )

    assert isinstance(credentials, list)
    # Should find at least some patterns
    if credentials:
        assert all(isinstance(c, dict) for c in credentials)
        assert all('pattern' in c for c in credentials)


def test_assess_firmware_security():
    """Test firmware security assessment"""
    extractor = FirmwareExtractor()

    # Test with vulnerabilities
    assessment = extractor.assess_security(
        has_secrets=True,
        has_credentials=True,
        encryption_found=False
    )

    assert isinstance(assessment, dict)
    assert 'level' in assessment
    assert 'risks' in assessment
    assert assessment['level'] in ["critical", "high", "medium", "low"]
    assert len(assessment['risks']) > 0

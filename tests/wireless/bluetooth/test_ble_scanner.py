"""Tests for BLE scanner."""

import pytest
from wireless.bluetooth.ble_scanner import BLEScanner


@pytest.mark.integration  # Requires Bluetooth hardware
def test_scan_devices():
    """Test BLE device scanning"""
    scanner = BLEScanner()

    devices = scanner.scan_devices(timeout=5)

    assert isinstance(devices, list)
    # May be empty if no Bluetooth, that's OK
    if devices:
        assert all(hasattr(d, 'address') for d in devices)
        assert all(hasattr(d, 'name') for d in devices)


def test_analyze_device_security():
    """Test device security analysis"""
    scanner = BLEScanner()

    # Test with mock device data
    security = scanner.analyze_security(
        supports_pairing=True,
        encrypted=True,
        bonded=False
    )

    assert isinstance(security, dict)
    assert 'level' in security
    assert 'risks' in security
    assert isinstance(security['risks'], list)

"""Tests for IoT device scanner."""

import pytest
from iot.device.scanner import IoTScanner


@pytest.mark.integration  # Requires network access
def test_scan_network():
    """Test IoT device network scanning"""
    scanner = IoTScanner()

    # Scan localhost only for testing
    devices = scanner.scan_network("127.0.0.1/32", timeout=2)

    assert isinstance(devices, list)
    # Localhost should have at least one device (itself)
    if devices:
        assert all(hasattr(d, 'ip') for d in devices)
        assert all(hasattr(d, 'hostname') for d in devices)


def test_identify_device_type():
    """Test device type identification from ports"""
    scanner = IoTScanner()

    # Common IoT device ports
    device_type = scanner.identify_device_type(
        open_ports=[80, 443, 1883],  # HTTP + MQTT
        services={"1883": "mqtt"}
    )

    assert isinstance(device_type, str)
    # Should identify as IoT device with MQTT
    assert "mqtt" in device_type.lower() or "iot" in device_type.lower()


def test_check_default_credentials():
    """Test default credential checking"""
    scanner = IoTScanner()

    # Test with mock device info
    has_defaults = scanner.check_default_credentials(
        device_type="camera",
        vendor="generic"
    )

    assert isinstance(has_defaults, dict)
    assert 'vulnerable' in has_defaults
    assert 'credentials' in has_defaults

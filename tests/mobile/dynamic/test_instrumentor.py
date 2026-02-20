import pytest
from mobile.dynamic.instrumentor import MobileInstrumentor

@pytest.mark.integration  # Mark as integration test
def test_frida_device_connection():
    """Test Frida can connect to device"""
    instrumentor = MobileInstrumentor()

    devices = instrumentor.list_devices()

    assert len(devices) >= 1  # At least USB device or emulator
    assert any(d.type in ['usb', 'local'] for d in devices)

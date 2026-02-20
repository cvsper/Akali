import pytest
from pathlib import Path
from mobile.dynamic.instrumentor import MobileInstrumentor

@pytest.mark.integration  # Mark as integration test
def test_frida_device_connection():
    """Test Frida can connect to device"""
    instrumentor = MobileInstrumentor()

    devices = instrumentor.list_devices()

    assert len(devices) >= 1  # At least USB device or emulator
    assert any(d.type in ['usb', 'local'] for d in devices)

def test_load_script():
    """Test Frida script can be loaded"""
    instrumentor = MobileInstrumentor()
    script_path = Path("mobile/dynamic/scripts/ssl_bypass.js")

    script_code = instrumentor.load_script(script_path)

    assert "NSURLSession" in script_code  # iOS code
    assert "OkHttp3" in script_code  # Android code

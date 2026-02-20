"""Tests for WiFi scanner."""

import pytest
from pathlib import Path
from wireless.wifi.wifi_scanner import WiFiScanner


@pytest.mark.integration  # Requires wireless interface
def test_scan_networks():
    """Test WiFi network scanning"""
    scanner = WiFiScanner()

    networks = scanner.scan_networks()

    assert isinstance(networks, list)
    # May be empty if no interface, that's OK
    if networks:
        assert all(hasattr(n, 'ssid') for n in networks)
        assert all(hasattr(n, 'bssid') for n in networks)
        assert all(hasattr(n, 'channel') for n in networks)

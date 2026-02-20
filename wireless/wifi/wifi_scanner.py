"""WiFi security scanner and analyzer."""

import subprocess
import re
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class WiFiNetwork:
    ssid: str
    bssid: str
    channel: int
    signal_strength: int
    encryption: str
    cipher: Optional[str] = None


class WiFiScanner:
    """WiFi network scanner and analyzer"""

    def __init__(self):
        self.interface = self._detect_interface()

    def _detect_interface(self) -> Optional[str]:
        """Detect wireless interface"""
        try:
            # macOS: airport command
            result = subprocess.run(
                ['networksetup', '-listallhardwareports'],
                capture_output=True,
                text=True,
                check=True
            )

            # Extract Wi-Fi interface (usually en0)
            lines = result.stdout.split('\n')
            for i, line in enumerate(lines):
                if 'Wi-Fi' in line:
                    if i + 1 < len(lines):
                        device_line = lines[i + 1]
                        match = re.search(r'Device: (\w+)', device_line)
                        if match:
                            return match.group(1)
        except Exception:
            pass

        return None

    def scan_networks(self) -> List[WiFiNetwork]:
        """Scan for nearby WiFi networks"""
        if not self.interface:
            return []

        try:
            # macOS airport scan
            cmd = [
                '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport',
                '-s'
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)

            networks = []
            lines = result.stdout.strip().split('\n')[1:]  # Skip header

            for line in lines:
                # Parse: SSID BSSID RSSI CHANNEL HT CC SECURITY
                parts = line.split()
                if len(parts) >= 7:
                    networks.append(WiFiNetwork(
                        ssid=parts[0],
                        bssid=parts[1],
                        signal_strength=int(parts[2]),
                        channel=int(parts[3]),
                        encryption=' '.join(parts[6:])
                    ))

            return networks
        except Exception:
            return []

    def detect_wpa_handshake(self, pcap_path) -> bool:
        """Detect WPA handshake in pcap file"""
        try:
            # Use aircrack-ng to detect handshake
            cmd = ['aircrack-ng', str(pcap_path)]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5
            )

            # Check for handshake indicators in output
            output = result.stdout + result.stderr
            has_handshake = (
                'handshake' in output.lower() or
                'WPA (1 handshake)' in output or
                'WPA (2 handshakes)' in output
            )

            return has_handshake
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return False

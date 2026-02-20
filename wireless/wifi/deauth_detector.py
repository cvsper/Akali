"""WiFi deauth attack detector."""

import subprocess
from pathlib import Path
from typing import Dict, Literal


SeverityLevel = Literal["low", "medium", "high"]


class DeauthDetector:
    """Detect deauthentication attack patterns"""

    def detect_deauth_frames(self, pcap_path: Path) -> Dict:
        """Detect deauth frames in pcap file"""
        if not pcap_path.exists():
            return {
                'deauth_count': 0,
                'suspicious': False,
                'severity': 'low'
            }

        try:
            # Use tshark to count deauth frames
            cmd = [
                'tshark',
                '-r', str(pcap_path),
                '-Y', 'wlan.fc.type_subtype == 0x0c',  # Deauth frame filter
                '-T', 'fields',
                '-e', 'frame.time_epoch'
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )

            # Count deauth frames
            frames = result.stdout.strip().split('\n')
            deauth_count = len([f for f in frames if f])

            # Calculate timespan
            if deauth_count > 1:
                timestamps = [float(f) for f in frames if f]
                timespan = max(timestamps) - min(timestamps)
            else:
                timespan = 0

            # Analyze pattern
            analysis = self.analyze_pattern(deauth_count, timespan)

            return {
                'deauth_count': deauth_count,
                'suspicious': analysis['suspicious'],
                'severity': analysis['severity'],
                'timespan': timespan
            }

        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return {
                'deauth_count': 0,
                'suspicious': False,
                'severity': 'low'
            }

    def analyze_pattern(self, deauth_count: int, timespan: float) -> Dict:
        """Analyze deauth pattern for attack indicators"""
        if deauth_count == 0:
            return {
                'suspicious': False,
                'severity': 'low'
            }

        # Calculate rate (deauths per second)
        if timespan > 0:
            rate = deauth_count / timespan
        else:
            rate = deauth_count  # All in same second

        # Thresholds for attack detection
        # Normal: < 1/sec
        # Suspicious: 1-10/sec
        # Critical: > 10/sec

        if rate >= 10 or deauth_count >= 100:
            return {
                'suspicious': True,
                'severity': 'high'
            }
        elif rate >= 1 or deauth_count >= 20:
            return {
                'suspicious': True,
                'severity': 'medium'
            }
        else:
            return {
                'suspicious': False,
                'severity': 'low'
            }

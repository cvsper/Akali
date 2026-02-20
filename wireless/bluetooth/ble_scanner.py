"""Bluetooth Low Energy (BLE) scanner and analyzer."""

import subprocess
from dataclasses import dataclass
from typing import List, Dict, Optional


@dataclass
class BLEDevice:
    address: str
    name: Optional[str]
    rssi: Optional[int] = None
    manufacturer: Optional[str] = None


class BLEScanner:
    """BLE device scanner and security analyzer"""

    def scan_devices(self, timeout: int = 10) -> List[BLEDevice]:
        """Scan for nearby BLE devices"""
        devices = []

        try:
            # Try using system_profiler on macOS
            cmd = ['system_profiler', 'SPBluetoothDataType', '-json']
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=True
            )

            # Parse JSON output
            import json
            data = json.loads(result.stdout)

            # Extract BLE devices (simplified parsing)
            if 'SPBluetoothDataType' in data:
                bt_data = data['SPBluetoothDataType']
                for item in bt_data:
                    if 'device_connected' in item:
                        for dev_name, dev_info in item['device_connected'].items():
                            if isinstance(dev_info, dict):
                                address = dev_info.get('device_address', 'unknown')
                                devices.append(BLEDevice(
                                    address=address,
                                    name=dev_name,
                                    rssi=dev_info.get('device_rssi'),
                                    manufacturer=dev_info.get('device_manufacturer')
                                ))

            return devices

        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError, Exception):
            # Fallback: empty list if Bluetooth not available
            return []

    def analyze_security(
        self,
        supports_pairing: bool,
        encrypted: bool,
        bonded: bool
    ) -> Dict:
        """Analyze BLE device security configuration"""
        risks = []

        # Assess encryption
        if not encrypted:
            risks.append("Unencrypted connection")

        # Assess pairing
        if not supports_pairing:
            risks.append("No pairing support")

        # Assess bonding
        if supports_pairing and not bonded:
            risks.append("Not bonded - temporary pairing only")

        # Determine security level
        if encrypted and bonded:
            level = "high"
        elif encrypted or supports_pairing:
            level = "medium"
        else:
            level = "low"

        return {
            'level': level,
            'risks': risks,
            'encrypted': encrypted,
            'bonded': bonded
        }

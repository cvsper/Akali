"""IoT device network scanner and identifier."""

import subprocess
from dataclasses import dataclass
from typing import List, Dict, Optional


@dataclass
class IoTDevice:
    ip: str
    hostname: Optional[str]
    mac: Optional[str] = None
    vendor: Optional[str] = None
    open_ports: List[int] = None
    device_type: Optional[str] = None

    def __post_init__(self):
        if self.open_ports is None:
            self.open_ports = []


class IoTScanner:
    """IoT device network scanner and analyzer"""

    # Common default credentials database
    DEFAULT_CREDENTIALS = {
        "camera": [
            ("admin", "admin"),
            ("admin", "12345"),
            ("root", "root")
        ],
        "router": [
            ("admin", "admin"),
            ("admin", "password"),
            ("root", "root")
        ],
        "generic": [
            ("admin", "admin"),
            ("root", "root")
        ]
    }

    # IoT device port signatures
    IOT_PORT_SIGNATURES = {
        1883: "mqtt",
        8883: "mqtt-ssl",
        5683: "coap",
        5684: "coap-dtls",
        8080: "http-alt",
        8443: "https-alt",
        502: "modbus",
        47808: "bacnet"
    }

    def scan_network(self, network: str, timeout: int = 30) -> List[IoTDevice]:
        """Scan network for IoT devices using nmap"""
        devices = []

        try:
            # Use nmap for network scanning
            cmd = [
                'nmap',
                '-sn',  # Ping scan (no port scan)
                '--host-timeout', f'{timeout}s',
                network
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 5
            )

            # Parse nmap output
            lines = result.stdout.split('\n')
            current_ip = None
            current_hostname = None

            for line in lines:
                if 'Nmap scan report for' in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        # Extract IP and hostname
                        if '(' in line and ')' in line:
                            # Format: "Nmap scan report for hostname (IP)"
                            current_hostname = parts[4]
                            current_ip = parts[5].strip('()')
                        else:
                            # Format: "Nmap scan report for IP"
                            current_ip = parts[4]
                            current_hostname = None

                        if current_ip:
                            devices.append(IoTDevice(
                                ip=current_ip,
                                hostname=current_hostname
                            ))

            return devices

        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return []

    def identify_device_type(
        self,
        open_ports: List[int],
        services: Dict[str, str]
    ) -> str:
        """Identify device type from open ports and services"""
        device_indicators = []

        # Check for IoT-specific ports
        for port in open_ports:
            if port in self.IOT_PORT_SIGNATURES:
                device_indicators.append(self.IOT_PORT_SIGNATURES[port])

        # Check services
        for port_str, service in services.items():
            service_lower = service.lower()
            if any(iot_svc in service_lower for iot_svc in ['mqtt', 'coap', 'modbus', 'bacnet']):
                device_indicators.append(service_lower)

        # Identify device type
        if 'mqtt' in device_indicators or 'coap' in device_indicators:
            return "iot-sensor"
        elif 'modbus' in device_indicators or 'bacnet' in device_indicators:
            return "iot-industrial"
        elif 8080 in open_ports or 8443 in open_ports:
            return "iot-gateway"
        else:
            return "unknown"

    def check_default_credentials(
        self,
        device_type: str,
        vendor: str = "generic"
    ) -> Dict:
        """Check if device likely uses default credentials"""
        # Get credential list for device type
        creds = self.DEFAULT_CREDENTIALS.get(
            device_type,
            self.DEFAULT_CREDENTIALS["generic"]
        )

        return {
            'vulnerable': len(creds) > 0,
            'credentials': creds,
            'device_type': device_type,
            'vendor': vendor
        }

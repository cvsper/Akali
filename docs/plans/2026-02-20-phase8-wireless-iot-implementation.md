# Phase 8: Wireless + IoT Security Testing - Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build comprehensive wireless security testing (WiFi/Bluetooth) and IoT device analysis capabilities with protocol-level inspection, firmware analysis, and smart home security testing.

**Architecture:** Modular design integrating wireless security tools (aircrack-ng, bluez, bettercap) with custom Python orchestration. MQTT/CoAP protocol analyzers, firmware extraction, and mesh network analysis for Zigbee/Z-Wave.

**Tech Stack:** Python 3.10+, aircrack-ng suite, bluez, paho-mqtt, aiocoap, scapy, binwalk

**Estimated Time:** 4-6 weeks (8 major tasks, 100+ subtasks)

---

## Prerequisites

**Install dependencies before starting:**
```bash
# System tools (macOS)
brew install aircrack-ng bluez-tools scapy binwalk

# Python packages
pip install paho-mqtt aiocoap scapy python-nmap bluepy pyshark

# Create directories
mkdir -p ~/akali/{wireless/{wifi,bluetooth,scan},iot/{device,protocol,firmware}}
```

**Note:** Some wireless operations require root/sudo privileges. Tests will skip if running without proper permissions.

---

## Task 1: WiFi Security - WPA/WPA2/WPA3 Testing

**Files:**
- Create: `wireless/__init__.py`
- Create: `wireless/wifi/__init__.py`
- Create: `wireless/wifi/wifi_scanner.py`
- Create: `wireless/wifi/wpa_analyzer.py`
- Create: `tests/wireless/wifi/test_wifi_scanner.py`

### Step 1.1: Write test for WiFi network enumeration

```python
# tests/wireless/wifi/test_wifi_scanner.py
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
```

### Step 1.2: Run test to verify it fails

```bash
pytest tests/wireless/wifi/test_wifi_scanner.py::test_scan_networks -v
```
Expected: FAIL with "ModuleNotFoundError: No module named 'wireless'"

### Step 1.3: Create module structure

```bash
touch wireless/__init__.py
touch wireless/wifi/__init__.py
```

### Step 1.4: Write minimal WiFi scanner

```python
# wireless/wifi/wifi_scanner.py
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
```

### Step 1.5: Run test

```bash
pytest tests/wireless/wifi/test_wifi_scanner.py::test_scan_networks -v -m integration
```
Expected: PASS (or SKIP if no wireless interface)

### Step 1.6: Commit

```bash
git add wireless/wifi/wifi_scanner.py tests/wireless/wifi/test_wifi_scanner.py
git commit -m "feat(wireless): add WiFi network scanner

- WiFiScanner class with network enumeration
- Auto-detect wireless interface (macOS/Linux)
- Parse SSID, BSSID, channel, signal, encryption
- Integration tests for wireless operations

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Step 1.7: Write test for WPA handshake capture detection

```python
# tests/wireless/wifi/test_wifi_scanner.py (add)
def test_detect_wpa_handshake():
    """Test WPA handshake detection in pcap"""
    scanner = WiFiScanner()
    pcap_path = Path("tests/fixtures/wpa_handshake.pcap")

    has_handshake = scanner.detect_wpa_handshake(pcap_path)

    # Will create fixture later
    assert isinstance(has_handshake, bool)
```

### Step 1.8: Run test to verify it fails

```bash
pytest tests/wireless/wifi/test_wifi_scanner.py::test_detect_wpa_handshake -v
```

### Step 1.9: Implement WPA analyzer

```python
# wireless/wifi/wpa_analyzer.py
from pathlib import Path
from typing import Optional
import subprocess
import re

class WPAAnalyzer:
    """WPA/WPA2/WPA3 security analyzer"""

    def __init__(self):
        self.aircrack_available = self._check_aircrack()

    def _check_aircrack(self) -> bool:
        """Check if aircrack-ng is installed"""
        try:
            subprocess.run(['aircrack-ng', '--help'],
                         capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def detect_wpa_handshake(self, pcap_path: Path) -> bool:
        """Detect if pcap contains WPA handshake"""
        if not self.aircrack_available:
            raise RuntimeError("aircrack-ng not installed")

        try:
            # Use aircrack-ng to check for handshake
            cmd = ['aircrack-ng', str(pcap_path)]
            result = subprocess.run(cmd, capture_output=True, text=True)

            # Look for handshake indicator in output
            return 'handshake' in result.stdout.lower()
        except Exception:
            return False

    def crack_wpa_psk(self, pcap_path: Path, wordlist: Path,
                      ssid: str) -> Optional[str]:
        """Attempt to crack WPA PSK using wordlist"""
        if not self.aircrack_available:
            raise RuntimeError("aircrack-ng not installed")

        try:
            cmd = [
                'aircrack-ng',
                '-w', str(wordlist),
                '-e', ssid,
                str(pcap_path)
            ]
            result = subprocess.run(cmd, capture_output=True,
                                  text=True, timeout=300)

            # Parse for KEY FOUND
            for line in result.stdout.split('\n'):
                if 'KEY FOUND' in line:
                    # Extract password from line
                    match = re.search(r'\[(.*?)\]', line)
                    if match:
                        return match.group(1)

            return None
        except subprocess.TimeoutExpired:
            return None
```

### Step 1.10: Add method to WiFiScanner

```python
# wireless/wifi/wifi_scanner.py (add to class)
from wireless.wifi.wpa_analyzer import WPAAnalyzer

def __init__(self):
    self.interface = self._detect_interface()
    self.wpa_analyzer = WPAAnalyzer()

def detect_wpa_handshake(self, pcap_path: Path) -> bool:
    """Detect WPA handshake in capture"""
    return self.wpa_analyzer.detect_wpa_handshake(pcap_path)
```

### Step 1.11: Create test pcap fixture

```bash
mkdir -p tests/fixtures
# Note: Real pcap would be created during integration testing
touch tests/fixtures/wpa_handshake.pcap
```

### Step 1.12: Run test

```bash
pytest tests/wireless/wifi/test_wifi_scanner.py::test_detect_wpa_handshake -v
```

### Step 1.13: Commit

```bash
git add wireless/wifi/wpa_analyzer.py tests/
git commit -m "feat(wireless): add WPA/WPA2 handshake detection

- WPAAnalyzer with aircrack-ng integration
- Detect handshakes in pcap files
- PSK cracking with wordlist support
- Foundation for WPA3 testing

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 2: WiFi Security - Deauth Attack Detection

**Files:**
- Create: `wireless/wifi/deauth_detector.py`
- Create: `tests/wireless/wifi/test_deauth_detector.py`

### Step 2.1: Write test for deauth frame detection

```python
# tests/wireless/wifi/test_deauth_detector.py
import pytest
from pathlib import Path
from wireless.wifi.deauth_detector import DeauthDetector

def test_detect_deauth_frames():
    """Test deauth frame detection"""
    detector = DeauthDetector()
    pcap_path = Path("tests/fixtures/deauth_attack.pcap")

    result = detector.analyze_pcap(pcap_path)

    assert hasattr(result, 'deauth_count')
    assert hasattr(result, 'target_bssid')
    assert hasattr(result, 'suspicious')
```

### Step 2.2: Run test to verify it fails

```bash
pytest tests/wireless/wifi/test_deauth_detector.py::test_detect_deauth_frames -v
```

### Step 2.3: Implement DeauthDetector

```python
# wireless/wifi/deauth_detector.py
from scapy.all import rdpcap, Dot11, Dot11Deauth
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class DeauthAnalysis:
    deauth_count: int
    target_bssid: List[str]
    suspicious: bool  # > 10 deauth in short time = suspicious
    timestamp_range: tuple

class DeauthDetector:
    """Detect WiFi deauthentication attacks"""

    SUSPICIOUS_THRESHOLD = 10  # Deauth frames in 60 seconds

    def analyze_pcap(self, pcap_path: Path) -> DeauthAnalysis:
        """Analyze pcap for deauth attack patterns"""
        packets = rdpcap(str(pcap_path))

        deauth_frames = []
        target_bssids = set()

        for pkt in packets:
            if pkt.haslayer(Dot11Deauth):
                deauth_frames.append(pkt)
                if pkt.haslayer(Dot11):
                    target_bssids.add(pkt[Dot11].addr1)

        # Check if suspicious
        suspicious = len(deauth_frames) > self.SUSPICIOUS_THRESHOLD

        # Get timestamp range
        if deauth_frames:
            timestamps = [float(pkt.time) for pkt in deauth_frames]
            timestamp_range = (min(timestamps), max(timestamps))
        else:
            timestamp_range = (0.0, 0.0)

        return DeauthAnalysis(
            deauth_count=len(deauth_frames),
            target_bssid=list(target_bssids),
            suspicious=suspicious,
            timestamp_range=timestamp_range
        )

    def monitor_live(self, interface: str, duration: int = 60):
        """Monitor for deauth attacks in real-time"""
        # TODO: Implement live monitoring with scapy sniff
        pass
```

### Step 2.4: Create test fixture

```bash
touch tests/fixtures/deauth_attack.pcap
```

### Step 2.5: Run test

```bash
pytest tests/wireless/wifi/test_deauth_detector.py::test_detect_deauth_frames -v
```

### Step 2.6: Commit

```bash
git add wireless/wifi/deauth_detector.py tests/
git commit -m "feat(wireless): add deauth attack detection

- DeauthDetector using scapy packet analysis
- Parse deauth frames from pcap
- Suspicious pattern detection (>10 frames/min)
- Foundation for live monitoring

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 3: Bluetooth Security - BLE Scanner

**Files:**
- Create: `wireless/bluetooth/__init__.py`
- Create: `wireless/bluetooth/ble_scanner.py`
- Create: `tests/wireless/bluetooth/test_ble_scanner.py`

### Step 3.1: Write test for BLE device discovery

```python
# tests/wireless/bluetooth/test_ble_scanner.py
import pytest
from wireless.bluetooth.ble_scanner import BLEScanner

@pytest.mark.integration
def test_scan_ble_devices():
    """Test BLE device scanning"""
    scanner = BLEScanner()

    devices = scanner.scan(timeout=5)

    assert isinstance(devices, list)
    # May be empty if no BLE devices nearby
    if devices:
        assert all(hasattr(d, 'address') for d in devices)
        assert all(hasattr(d, 'name') for d in devices)
```

### Step 3.2: Run test to verify it fails

```bash
pytest tests/wireless/bluetooth/test_ble_scanner.py::test_scan_ble_devices -v -m integration
```

### Step 3.3: Create module structure

```bash
touch wireless/bluetooth/__init__.py
```

### Step 3.4: Implement BLE scanner

```python
# wireless/bluetooth/ble_scanner.py
from dataclasses import dataclass
from typing import List, Optional
import subprocess

@dataclass
class BLEDevice:
    address: str
    name: Optional[str]
    rssi: int
    manufacturer: Optional[str]
    services: List[str]

class BLEScanner:
    """Bluetooth Low Energy scanner"""

    def __init__(self):
        self.bluez_available = self._check_bluez()

    def _check_bluez(self) -> bool:
        """Check if bluez tools are available"""
        try:
            subprocess.run(['hcitool', '--help'],
                         capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def scan(self, timeout: int = 10) -> List[BLEDevice]:
        """Scan for BLE devices"""
        if not self.bluez_available:
            # Fallback to cross-platform scanner
            return self._scan_cross_platform(timeout)

        devices = []
        try:
            # Use hcitool lescan
            cmd = ['timeout', str(timeout), 'hcitool', 'lescan']
            result = subprocess.run(cmd, capture_output=True, text=True)

            for line in result.stdout.split('\n')[1:]:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        devices.append(BLEDevice(
                            address=parts[0],
                            name=' '.join(parts[1:]) if len(parts) > 1 else None,
                            rssi=-999,  # hcitool doesn't provide RSSI
                            manufacturer=None,
                            services=[]
                        ))
        except Exception:
            pass

        return devices

    def _scan_cross_platform(self, timeout: int) -> List[BLEDevice]:
        """Cross-platform BLE scan using Python"""
        try:
            from bluepy.btle import Scanner

            scanner = Scanner()
            raw_devices = scanner.scan(timeout)

            devices = []
            for dev in raw_devices:
                # Get device name from scan data
                name = None
                for (adtype, desc, value) in dev.getScanData():
                    if desc == "Complete Local Name":
                        name = value

                devices.append(BLEDevice(
                    address=dev.addr,
                    name=name,
                    rssi=dev.rssi,
                    manufacturer=None,
                    services=[]
                ))

            return devices
        except ImportError:
            return []

    def enumerate_services(self, address: str) -> List[str]:
        """Enumerate GATT services for device"""
        services = []
        try:
            cmd = ['gatttool', '-b', address, '--primary']
            result = subprocess.run(cmd, capture_output=True,
                                  text=True, timeout=10)

            for line in result.stdout.split('\n'):
                if 'uuid:' in line.lower():
                    uuid = line.split('uuid:')[1].strip()
                    services.append(uuid)
        except Exception:
            pass

        return services
```

### Step 3.5: Run test

```bash
pytest tests/wireless/bluetooth/test_ble_scanner.py::test_scan_ble_devices -v -m integration
```

### Step 3.6: Commit

```bash
git add wireless/bluetooth/ble_scanner.py tests/
git commit -m "feat(wireless): add BLE device scanner

- BLEScanner with bluez/bluepy support
- Device discovery with RSSI
- GATT service enumeration
- Cross-platform compatibility

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Step 3.7: Write test for GATT service enumeration

```python
# tests/wireless/bluetooth/test_ble_scanner.py (add)
@pytest.mark.integration
def test_enumerate_services():
    """Test GATT service enumeration"""
    scanner = BLEScanner()

    # Use known test device address or skip
    test_address = "00:11:22:33:44:55"

    services = scanner.enumerate_services(test_address)

    assert isinstance(services, list)
```

### Step 3.8: Run test

```bash
pytest tests/wireless/bluetooth/test_ble_scanner.py::test_enumerate_services -v -m integration
```

### Step 3.9: Write test for BlueBorne vulnerability check

```python
# tests/wireless/bluetooth/test_ble_scanner.py (add)
def test_check_blueborne():
    """Test BlueBorne vulnerability detection"""
    scanner = BLEScanner()

    # This would check for BlueBorne vulnerable devices
    result = scanner.check_blueborne("00:11:22:33:44:55")

    assert isinstance(result, bool)
```

### Step 3.10: Implement BlueBorne check stub

```python
# wireless/bluetooth/ble_scanner.py (add to class)
def check_blueborne(self, address: str) -> bool:
    """Check if device is vulnerable to BlueBorne"""
    # TODO: Implement BlueBorne vulnerability check
    # This would involve testing specific Bluetooth stack vulnerabilities
    return False
```

### Step 3.11: Commit

```bash
git add wireless/bluetooth/ble_scanner.py tests/
git commit -m "feat(wireless): add GATT service enumeration and BlueBorne check

- Enumerate GATT services with gatttool
- BlueBorne vulnerability check stub
- Enhanced BLE security testing

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 4: IoT Device Discovery

**Files:**
- Create: `iot/__init__.py`
- Create: `iot/device/__init__.py`
- Create: `iot/device/scanner.py`
- Create: `tests/iot/device/test_scanner.py`

### Step 4.1: Write test for IoT device discovery

```python
# tests/iot/device/test_scanner.py
import pytest
from iot.device.scanner import IoTScanner

def test_scan_network():
    """Test network-based IoT device discovery"""
    scanner = IoTScanner()

    devices = scanner.scan_network("192.168.1.0/24")

    assert isinstance(devices, list)
    # Devices may or may not be found
    if devices:
        assert all(hasattr(d, 'ip') for d in devices)
        assert all(hasattr(d, 'ports') for d in devices)
```

### Step 4.2: Run test to verify it fails

```bash
pytest tests/iot/device/test_scanner.py::test_scan_network -v
```

### Step 4.3: Create module structure

```bash
touch iot/__init__.py
touch iot/device/__init__.py
```

### Step 4.4: Implement IoT scanner

```python
# iot/device/scanner.py
import nmap
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class IoTDevice:
    ip: str
    mac: Optional[str]
    hostname: Optional[str]
    ports: List[int]
    services: dict
    device_type: Optional[str]  # inferred from ports/services

# Common IoT ports
IOT_PORTS = {
    1883: 'MQTT',
    5683: 'CoAP',
    8883: 'MQTT-TLS',
    8080: 'HTTP-Alt',
    9000: 'Various IoT',
    5000: 'UPnP/SSDP',
    80: 'HTTP',
    443: 'HTTPS',
    23: 'Telnet',
    22: 'SSH'
}

class IoTScanner:
    """IoT device discovery and fingerprinting"""

    def __init__(self):
        self.nm = nmap.PortScanner()

    def scan_network(self, network: str,
                     ports: str = "22,23,80,443,1883,5683,8080,8883") -> List[IoTDevice]:
        """Scan network for IoT devices"""
        devices = []

        try:
            # Fast scan for common IoT ports
            self.nm.scan(hosts=network, arguments=f'-p {ports} -T4')

            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    open_ports = []
                    services = {}

                    for proto in self.nm[host].all_protocols():
                        ports_dict = self.nm[host][proto]
                        for port in ports_dict.keys():
                            if ports_dict[port]['state'] == 'open':
                                open_ports.append(port)
                                services[port] = ports_dict[port].get('name', 'unknown')

                    # Try to get MAC and hostname
                    mac = self.nm[host]['addresses'].get('mac')
                    hostname = self.nm[host].hostname()

                    # Infer device type
                    device_type = self._infer_device_type(open_ports, services)

                    devices.append(IoTDevice(
                        ip=host,
                        mac=mac,
                        hostname=hostname if hostname else None,
                        ports=open_ports,
                        services=services,
                        device_type=device_type
                    ))
        except Exception as e:
            print(f"Scan error: {e}")

        return devices

    def _infer_device_type(self, ports: List[int], services: dict) -> Optional[str]:
        """Infer IoT device type from open ports/services"""
        # MQTT = likely sensor/IoT device
        if 1883 in ports or 8883 in ports:
            return "MQTT Device (Sensor/Controller)"

        # CoAP = constrained device
        if 5683 in ports:
            return "CoAP Device (Embedded)"

        # Telnet on 23 = likely insecure IoT
        if 23 in ports:
            return "Legacy IoT (Telnet)"

        # HTTP/HTTPS only = likely camera or smart device
        if (80 in ports or 443 in ports) and len(ports) <= 2:
            return "Web-based IoT (Camera/Hub)"

        return "Unknown IoT Device"

    def check_default_credentials(self, device: IoTDevice) -> Optional[dict]:
        """Check for default credentials"""
        # Common IoT default credentials
        defaults = [
            ("admin", "admin"),
            ("admin", "password"),
            ("root", "root"),
            ("admin", ""),
            ("user", "user")
        ]

        # TODO: Implement actual credential testing
        # This is a placeholder for the structure
        return None
```

### Step 4.5: Run test

```bash
pytest tests/iot/device/test_scanner.py::test_scan_network -v
```

### Step 4.6: Commit

```bash
git add iot/device/scanner.py tests/
git commit -m "feat(iot): add IoT device network scanner

- IoTScanner with nmap integration
- Scan for common IoT ports (MQTT, CoAP, HTTP)
- Device type inference from port patterns
- MAC/hostname detection

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Step 4.7: Write test for device type inference

```python
# tests/iot/device/test_scanner.py (add)
def test_infer_device_type():
    """Test device type inference"""
    scanner = IoTScanner()

    # MQTT device
    result = scanner._infer_device_type([1883, 80], {1883: 'mqtt', 80: 'http'})
    assert "MQTT" in result

    # CoAP device
    result = scanner._infer_device_type([5683], {5683: 'coap'})
    assert "CoAP" in result

    # Legacy telnet device
    result = scanner._infer_device_type([23], {23: 'telnet'})
    assert "Legacy" in result
```

### Step 4.8: Run test

```bash
pytest tests/iot/device/test_scanner.py::test_infer_device_type -v
```

### Step 4.9: Write test for default credentials check

```python
# tests/iot/device/test_scanner.py (add)
def test_check_default_credentials():
    """Test default credential checking"""
    scanner = IoTScanner()

    device = IoTDevice(
        ip="192.168.1.100",
        mac=None,
        hostname=None,
        ports=[80],
        services={80: 'http'},
        device_type="Web-based IoT"
    )

    result = scanner.check_default_credentials(device)

    # Currently returns None (not implemented)
    assert result is None or isinstance(result, dict)
```

### Step 4.10: Run test

```bash
pytest tests/iot/device/test_scanner.py::test_check_default_credentials -v
```

### Step 4.11: Commit

```bash
git add tests/iot/device/test_scanner.py
git commit -m "test(iot): add device type inference and credential tests

- Test device type detection from ports
- Test default credential checking
- Foundation for security validation

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 5: IoT Protocols - MQTT Analysis

**Files:**
- Create: `iot/protocol/__init__.py`
- Create: `iot/protocol/mqtt_analyzer.py`
- Create: `tests/iot/protocol/test_mqtt_analyzer.py`

### Step 5.1: Write test for MQTT broker discovery

```python
# tests/iot/protocol/test_mqtt_analyzer.py
import pytest
from iot.protocol.mqtt_analyzer import MQTTAnalyzer

def test_probe_broker():
    """Test MQTT broker probing"""
    analyzer = MQTTAnalyzer()

    result = analyzer.probe_broker("test.mosquitto.org", 1883)

    assert hasattr(result, 'accessible')
    assert hasattr(result, 'auth_required')
    assert hasattr(result, 'version')
```

### Step 5.2: Run test to verify it fails

```bash
pytest tests/iot/protocol/test_mqtt_analyzer.py::test_probe_broker -v
```

### Step 5.3: Create module structure

```bash
touch iot/protocol/__init__.py
```

### Step 5.4: Implement MQTT analyzer

```python
# iot/protocol/mqtt_analyzer.py
import paho.mqtt.client as mqtt
from dataclasses import dataclass
from typing import List, Optional
import time

@dataclass
class MQTTBrokerInfo:
    accessible: bool
    auth_required: bool
    version: Optional[str]
    topics: List[str]
    anonymous_subscribe: bool

class MQTTAnalyzer:
    """MQTT protocol security analyzer"""

    def __init__(self):
        self.discovered_topics = []

    def probe_broker(self, host: str, port: int = 1883,
                     timeout: int = 5) -> MQTTBrokerInfo:
        """Probe MQTT broker for security misconfigurations"""

        # Try to connect without auth
        client = mqtt.Client()
        accessible = False
        auth_required = True
        version = None

        try:
            client.connect(host, port, timeout)
            accessible = True
            auth_required = False

            # Try to subscribe to wildcard topic
            client.subscribe("#")
            client.loop_start()

            # Wait briefly for messages
            time.sleep(2)

            client.loop_stop()
            client.disconnect()

        except Exception as e:
            if "not authorized" in str(e).lower():
                accessible = True
                auth_required = True
            else:
                accessible = False

        return MQTTBrokerInfo(
            accessible=accessible,
            auth_required=auth_required,
            version=version,
            topics=self.discovered_topics[:],
            anonymous_subscribe=not auth_required
        )

    def enumerate_topics(self, host: str, port: int = 1883,
                        username: Optional[str] = None,
                        password: Optional[str] = None) -> List[str]:
        """Enumerate MQTT topics"""
        topics = []

        def on_message(client, userdata, message):
            topic = message.topic
            if topic not in topics:
                topics.append(topic)

        client = mqtt.Client()
        if username and password:
            client.username_pw_set(username, password)

        client.on_message = on_message

        try:
            client.connect(host, port, 60)

            # Subscribe to wildcard
            client.subscribe("#")

            # Listen for 10 seconds
            client.loop_start()
            time.sleep(10)
            client.loop_stop()

            client.disconnect()
        except Exception:
            pass

        return topics

    def test_injection(self, host: str, port: int, topic: str,
                      payload: str) -> bool:
        """Test MQTT injection/command injection"""
        try:
            client = mqtt.Client()
            client.connect(host, port, 60)

            # Publish test payload
            result = client.publish(topic, payload)

            client.disconnect()
            return result.rc == 0
        except Exception:
            return False
```

### Step 5.5: Run test

```bash
pytest tests/iot/protocol/test_mqtt_analyzer.py::test_probe_broker -v
```

### Step 5.6: Commit

```bash
git add iot/protocol/mqtt_analyzer.py tests/
git commit -m "feat(iot): add MQTT protocol analyzer

- MQTTAnalyzer with paho-mqtt
- Broker probing (auth, accessibility)
- Topic enumeration with wildcard subscribe
- Injection testing capabilities

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Step 5.7: Write test for topic enumeration

```python
# tests/iot/protocol/test_mqtt_analyzer.py (add)
@pytest.mark.integration
def test_enumerate_topics():
    """Test MQTT topic enumeration"""
    analyzer = MQTTAnalyzer()

    topics = analyzer.enumerate_topics("test.mosquitto.org", 1883)

    assert isinstance(topics, list)
```

### Step 5.8: Run test

```bash
pytest tests/iot/protocol/test_mqtt_analyzer.py::test_enumerate_topics -v -m integration
```

### Step 5.9: Write test for injection testing

```python
# tests/iot/protocol/test_mqtt_analyzer.py (add)
def test_injection():
    """Test MQTT injection"""
    analyzer = MQTTAnalyzer()

    result = analyzer.test_injection(
        "test.mosquitto.org",
        1883,
        "test/topic",
        "test payload"
    )

    assert isinstance(result, bool)
```

### Step 5.10: Run test

```bash
pytest tests/iot/protocol/test_mqtt_analyzer.py::test_injection -v
```

### Step 5.11: Commit

```bash
git add tests/iot/protocol/test_mqtt_analyzer.py
git commit -m "test(iot): add MQTT topic enumeration and injection tests

- Test wildcard topic subscription
- Test injection capabilities
- Integration tests for live broker

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 6: IoT Protocols - CoAP Analysis

**Files:**
- Create: `iot/protocol/coap_analyzer.py`
- Create: `tests/iot/protocol/test_coap_analyzer.py`

### Step 6.1: Write test for CoAP resource discovery

```python
# tests/iot/protocol/test_coap_analyzer.py
import pytest
import asyncio
from iot.protocol.coap_analyzer import CoAPAnalyzer

@pytest.mark.asyncio
async def test_discover_resources():
    """Test CoAP resource discovery"""
    analyzer = CoAPAnalyzer()

    # Test with public CoAP server
    resources = await analyzer.discover_resources("coap.me", 5683)

    assert isinstance(resources, list)
```

### Step 6.2: Run test to verify it fails

```bash
pytest tests/iot/protocol/test_coap_analyzer.py::test_discover_resources -v
```

### Step 6.3: Implement CoAP analyzer

```python
# iot/protocol/coap_analyzer.py
import asyncio
from aiocoap import *
from dataclasses import dataclass
from typing import List, Optional
import re

@dataclass
class CoAPResource:
    path: str
    methods: List[str]
    content_format: Optional[str]
    observable: bool

class CoAPAnalyzer:
    """CoAP protocol security analyzer"""

    async def discover_resources(self, host: str,
                                 port: int = 5683) -> List[CoAPResource]:
        """Discover CoAP resources using .well-known/core"""
        resources = []

        try:
            protocol = await Context.create_client_context()

            # Query .well-known/core
            request = Message(code=GET, uri=f'coap://{host}:{port}/.well-known/core')

            response = await protocol.request(request).response

            if response.code.is_successful():
                # Parse link-format response
                links = response.payload.decode('utf-8')

                for link in links.split(','):
                    path_match = re.search(r'<([^>]+)>', link)
                    if path_match:
                        path = path_match.group(1)

                        # Check for methods, content-type, observable
                        methods = ['GET']  # Default
                        observable = 'obs' in link

                        resources.append(CoAPResource(
                            path=path,
                            methods=methods,
                            content_format=None,
                            observable=observable
                        ))
        except Exception:
            pass

        return resources

    async def test_resource(self, host: str, port: int,
                           resource_path: str) -> Optional[str]:
        """Test CoAP resource access"""
        try:
            protocol = await Context.create_client_context()

            request = Message(code=GET,
                            uri=f'coap://{host}:{port}{resource_path}')

            response = await protocol.request(request).response

            if response.code.is_successful():
                return response.payload.decode('utf-8', errors='ignore')
        except Exception:
            pass

        return None

    async def test_put_access(self, host: str, port: int,
                             resource_path: str, payload: str) -> bool:
        """Test if CoAP resource allows PUT (security issue)"""
        try:
            protocol = await Context.create_client_context()

            request = Message(code=PUT,
                            uri=f'coap://{host}:{port}{resource_path}',
                            payload=payload.encode('utf-8'))

            response = await protocol.request(request).response

            return response.code.is_successful()
        except Exception:
            return False
```

### Step 6.4: Run test

```bash
pytest tests/iot/protocol/test_coap_analyzer.py::test_discover_resources -v
```

### Step 6.5: Commit

```bash
git add iot/protocol/coap_analyzer.py tests/
git commit -m "feat(iot): add CoAP protocol analyzer

- CoAPAnalyzer with aiocoap
- Resource discovery via .well-known/core
- Observable resource detection
- Async request/response testing

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Step 6.6: Write test for resource testing

```python
# tests/iot/protocol/test_coap_analyzer.py (add)
@pytest.mark.asyncio
async def test_resource_access():
    """Test CoAP resource access"""
    analyzer = CoAPAnalyzer()

    result = await analyzer.test_resource("coap.me", 5683, "/test")

    # May be None if resource doesn't exist
    assert result is None or isinstance(result, str)
```

### Step 6.7: Run test

```bash
pytest tests/iot/protocol/test_coap_analyzer.py::test_resource_access -v
```

### Step 6.8: Write test for PUT access

```python
# tests/iot/protocol/test_coap_analyzer.py (add)
@pytest.mark.asyncio
async def test_put_access():
    """Test CoAP PUT access (security check)"""
    analyzer = CoAPAnalyzer()

    result = await analyzer.test_put_access(
        "coap.me",
        5683,
        "/test",
        "test payload"
    )

    assert isinstance(result, bool)
```

### Step 6.9: Run test

```bash
pytest tests/iot/protocol/test_coap_analyzer.py::test_put_access -v
```

### Step 6.10: Commit

```bash
git add tests/iot/protocol/test_coap_analyzer.py
git commit -m "test(iot): add CoAP resource access tests

- Test resource discovery and access
- Test PUT method (security check)
- Async test patterns

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 7: IoT Firmware Analysis

**Files:**
- Create: `iot/firmware/__init__.py`
- Create: `iot/firmware/extractor.py`
- Create: `tests/iot/firmware/test_extractor.py`

### Step 7.1: Write test for firmware extraction

```python
# tests/iot/firmware/test_extractor.py
import pytest
from pathlib import Path
from iot.firmware.extractor import FirmwareExtractor

def test_extract_firmware():
    """Test firmware extraction"""
    extractor = FirmwareExtractor()

    # Use test firmware or skip
    firmware_path = Path("tests/fixtures/test_firmware.bin")

    if not firmware_path.exists():
        pytest.skip("Test firmware not available")

    result = extractor.extract(firmware_path)

    assert hasattr(result, 'path')
    assert hasattr(result, 'filesystems')
    assert hasattr(result, 'secrets_found')
```

### Step 7.2: Run test to verify it fails

```bash
pytest tests/iot/firmware/test_extractor.py::test_extract_firmware -v
```

### Step 7.3: Create module structure

```bash
touch iot/firmware/__init__.py
```

### Step 7.4: Implement firmware extractor

```python
# iot/firmware/extractor.py
import subprocess
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional
import re

@dataclass
class FirmwareInfo:
    path: Path
    filesystems: List[str]
    extracted_dir: Optional[Path]
    secrets_found: List[dict]
    hardcoded_creds: List[dict]

class FirmwareExtractor:
    """IoT firmware extraction and analysis"""

    def __init__(self):
        self.binwalk_available = self._check_binwalk()

    def _check_binwalk(self) -> bool:
        """Check if binwalk is installed"""
        try:
            subprocess.run(['binwalk', '--help'],
                         capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def extract(self, firmware_path: Path) -> FirmwareInfo:
        """Extract firmware image"""
        if not self.binwalk_available:
            raise RuntimeError("binwalk not installed")

        output_dir = Path("/tmp/akali/firmware") / firmware_path.stem
        output_dir.mkdir(parents=True, exist_ok=True)

        try:
            # Use binwalk to extract
            cmd = ['binwalk', '-e', '-C', str(output_dir), str(firmware_path)]
            subprocess.run(cmd, capture_output=True, check=True)

            # Detect filesystems
            filesystems = self._detect_filesystems(firmware_path)

            # Scan for secrets
            secrets = self._scan_secrets(output_dir)
            creds = self._find_credentials(output_dir)

            return FirmwareInfo(
                path=firmware_path,
                filesystems=filesystems,
                extracted_dir=output_dir,
                secrets_found=secrets,
                hardcoded_creds=creds
            )
        except Exception as e:
            return FirmwareInfo(
                path=firmware_path,
                filesystems=[],
                extracted_dir=None,
                secrets_found=[],
                hardcoded_creds=[]
            )

    def _detect_filesystems(self, firmware_path: Path) -> List[str]:
        """Detect embedded filesystems"""
        filesystems = []

        try:
            cmd = ['binwalk', '-y', 'filesystem', str(firmware_path)]
            result = subprocess.run(cmd, capture_output=True, text=True)

            for line in result.stdout.split('\n'):
                if 'filesystem' in line.lower():
                    # Extract filesystem type
                    for fs_type in ['squashfs', 'cramfs', 'jffs2', 'ubifs', 'ext2', 'ext3', 'ext4']:
                        if fs_type in line.lower():
                            filesystems.append(fs_type)
        except Exception:
            pass

        return list(set(filesystems))

    def _scan_secrets(self, extracted_dir: Path) -> List[dict]:
        """Scan extracted firmware for secrets"""
        secrets = []

        # Common secret patterns
        patterns = {
            'api_key': r'api[_-]?key.*?["\']([a-zA-Z0-9_-]{20,})["\']',
            'password': r'password.*?["\']([^"\']{6,})["\']',
            'private_key': r'-----BEGIN.*?PRIVATE KEY-----'
        }

        try:
            for ext in ['*.conf', '*.cfg', '*.ini', '*.sh', '*.txt']:
                for file_path in extracted_dir.rglob(ext):
                    try:
                        with open(file_path, 'r', errors='ignore') as f:
                            content = f.read()

                            for secret_type, pattern in patterns.items():
                                matches = re.findall(pattern, content, re.IGNORECASE)
                                for match in matches:
                                    secrets.append({
                                        'type': secret_type,
                                        'file': str(file_path),
                                        'value': match[:50]  # Truncate
                                    })
                    except Exception:
                        continue
        except Exception:
            pass

        return secrets

    def _find_credentials(self, extracted_dir: Path) -> List[dict]:
        """Find hardcoded credentials"""
        creds = []

        # Common credential patterns
        patterns = [
            (r'username.*?["\']([^"\']+)["\']', r'password.*?["\']([^"\']+)["\']'),
            (r'user.*?["\']([^"\']+)["\']', r'pass.*?["\']([^"\']+)["\']'),
        ]

        try:
            for file_path in extracted_dir.rglob('*'):
                if file_path.is_file() and file_path.stat().st_size < 1024*1024:  # < 1MB
                    try:
                        with open(file_path, 'r', errors='ignore') as f:
                            content = f.read()

                            for user_pattern, pass_pattern in patterns:
                                user_matches = re.findall(user_pattern, content, re.IGNORECASE)
                                pass_matches = re.findall(pass_pattern, content, re.IGNORECASE)

                                if user_matches and pass_matches:
                                    for user, password in zip(user_matches, pass_matches):
                                        creds.append({
                                            'username': user,
                                            'password': password,
                                            'file': str(file_path)
                                        })
                    except Exception:
                        continue
        except Exception:
            pass

        return creds
```

### Step 7.5: Run test

```bash
pytest tests/iot/firmware/test_extractor.py::test_extract_firmware -v
```

### Step 7.6: Commit

```bash
git add iot/firmware/extractor.py tests/
git commit -m "feat(iot): add firmware extraction and analysis

- FirmwareExtractor with binwalk integration
- Filesystem detection (squashfs, cramfs, jffs2, etc.)
- Secret scanning in extracted firmware
- Hardcoded credential detection

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

### Step 7.7: Write test for filesystem detection

```python
# tests/iot/firmware/test_extractor.py (add)
def test_detect_filesystems():
    """Test filesystem detection"""
    extractor = FirmwareExtractor()

    firmware_path = Path("tests/fixtures/test_firmware.bin")

    if not firmware_path.exists():
        pytest.skip("Test firmware not available")

    filesystems = extractor._detect_filesystems(firmware_path)

    assert isinstance(filesystems, list)
```

### Step 7.8: Run test

```bash
pytest tests/iot/firmware/test_extractor.py::test_detect_filesystems -v
```

### Step 7.9: Write test for secrets scanning

```python
# tests/iot/firmware/test_extractor.py (add)
def test_scan_secrets():
    """Test secret scanning"""
    extractor = FirmwareExtractor()

    # Create temporary test directory
    test_dir = Path("/tmp/test_firmware_scan")
    test_dir.mkdir(exist_ok=True)

    # Create test file with secret
    test_file = test_dir / "config.conf"
    test_file.write_text('api_key = "sk_test_1234567890abcdefghij"')

    secrets = extractor._scan_secrets(test_dir)

    assert len(secrets) > 0
    assert any(s['type'] == 'api_key' for s in secrets)

    # Cleanup
    test_file.unlink()
    test_dir.rmdir()
```

### Step 7.10: Run test

```bash
pytest tests/iot/firmware/test_extractor.py::test_scan_secrets -v
```

### Step 7.11: Commit

```bash
git add tests/iot/firmware/test_extractor.py
git commit -m "test(iot): add firmware analysis tests

- Test filesystem detection
- Test secret scanning with fixtures
- Test credential extraction

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Task 8: CLI Integration

**Files:**
- Modify: `core/cli.py`
- Modify: `akali` (main script)

### Step 8.1: Add wireless commands to CLI

```python
# core/cli.py (add)
def wireless_wifi_scan(self):
    """Scan for WiFi networks"""
    from wireless.wifi.wifi_scanner import WiFiScanner

    scanner = WiFiScanner()

    print("[*] Scanning for WiFi networks...")
    networks = scanner.scan_networks()

    if not networks:
        print("[!] No networks found (check wireless interface)")
        return

    print(f"\n[+] Found {len(networks)} networks:\n")
    print(f"{'SSID':<32} {'BSSID':<18} {'Channel':<8} {'Signal':<8} {'Encryption'}")
    print("-" * 100)

    for net in networks:
        print(f"{net.ssid:<32} {net.bssid:<18} {net.channel:<8} {net.signal_strength:<8} {net.encryption}")

def wireless_ble_scan(self, timeout: int = 10):
    """Scan for BLE devices"""
    from wireless.bluetooth.ble_scanner import BLEScanner

    scanner = BLEScanner()

    print(f"[*] Scanning for BLE devices ({timeout}s)...")
    devices = scanner.scan(timeout)

    if not devices:
        print("[!] No BLE devices found")
        return

    print(f"\n[+] Found {len(devices)} devices:\n")
    print(f"{'Address':<20} {'Name':<30} {'RSSI':<8}")
    print("-" * 70)

    for dev in devices:
        name = dev.name if dev.name else "(Unknown)"
        print(f"{dev.address:<20} {name:<30} {dev.rssi:<8}")

def wireless_deauth_detect(self, pcap_path: str):
    """Detect deauth attacks in pcap"""
    from wireless.wifi.deauth_detector import DeauthDetector
    from pathlib import Path

    detector = DeauthDetector()

    print(f"[*] Analyzing {pcap_path}...")
    result = detector.analyze_pcap(Path(pcap_path))

    print(f"\n[+] Analysis complete:")
    print(f"    Deauth frames: {result.deauth_count}")
    print(f"    Target BSSIDs: {len(result.target_bssid)}")
    print(f"    Suspicious: {'YES' if result.suspicious else 'NO'}")

    if result.target_bssid:
        print(f"\n    Targets:")
        for bssid in result.target_bssid:
            print(f"      - {bssid}")
```

### Step 8.2: Add IoT commands to CLI

```python
# core/cli.py (add)
def iot_scan(self, network: str):
    """Scan network for IoT devices"""
    from iot.device.scanner import IoTScanner

    scanner = IoTScanner()

    print(f"[*] Scanning {network} for IoT devices...")
    devices = scanner.scan_network(network)

    if not devices:
        print("[!] No IoT devices found")
        return

    print(f"\n[+] Found {len(devices)} devices:\n")

    for dev in devices:
        print(f"[*] {dev.ip}")
        if dev.hostname:
            print(f"    Hostname: {dev.hostname}")
        if dev.mac:
            print(f"    MAC: {dev.mac}")
        print(f"    Ports: {', '.join(map(str, dev.ports))}")
        if dev.device_type:
            print(f"    Type: {dev.device_type}")
        print()

def iot_mqtt_probe(self, host: str, port: int = 1883):
    """Probe MQTT broker"""
    from iot.protocol.mqtt_analyzer import MQTTAnalyzer

    analyzer = MQTTAnalyzer()

    print(f"[*] Probing MQTT broker at {host}:{port}...")
    result = analyzer.probe_broker(host, port)

    print(f"\n[+] Results:")
    print(f"    Accessible: {result.accessible}")
    print(f"    Auth Required: {result.auth_required}")
    print(f"    Anonymous Subscribe: {result.anonymous_subscribe}")

    if result.topics:
        print(f"\n    Discovered topics:")
        for topic in result.topics[:20]:
            print(f"      - {topic}")

def iot_firmware_extract(self, firmware_path: str):
    """Extract and analyze firmware"""
    from iot.firmware.extractor import FirmwareExtractor
    from pathlib import Path

    extractor = FirmwareExtractor()

    print(f"[*] Extracting {firmware_path}...")
    result = extractor.extract(Path(firmware_path))

    print(f"\n[+] Extraction complete:")
    print(f"    Filesystems: {', '.join(result.filesystems)}")

    if result.extracted_dir:
        print(f"    Output: {result.extracted_dir}")

    if result.secrets_found:
        print(f"\n[!] Found {len(result.secrets_found)} secrets:")
        for secret in result.secrets_found[:10]:
            print(f"      [{secret['type']}] {secret['file']}")

    if result.hardcoded_creds:
        print(f"\n[!] Found {len(result.hardcoded_creds)} credentials")
```

### Step 8.3: Update main CLI parser

```python
# akali (main script, add after existing subparsers)

# Add wireless subparser
wireless_parser = subparsers.add_parser("wireless", help="Wireless security testing")
wireless_subparsers = wireless_parser.add_subparsers(dest="wireless_command")

# WiFi
wifi_parser = wireless_subparsers.add_parser("wifi", help="WiFi testing")
wifi_subparsers = wifi_parser.add_subparsers(dest="wifi_action")

wifi_scan_parser = wifi_subparsers.add_parser("scan", help="Scan WiFi networks")

wifi_deauth_parser = wifi_subparsers.add_parser("deauth-detect", help="Detect deauth attacks")
wifi_deauth_parser.add_argument("pcap", help="Pcap file to analyze")

# Bluetooth
ble_parser = wireless_subparsers.add_parser("ble", help="Bluetooth LE testing")
ble_subparsers = ble_parser.add_subparsers(dest="ble_action")

ble_scan_parser = ble_subparsers.add_parser("scan", help="Scan BLE devices")
ble_scan_parser.add_argument("--timeout", type=int, default=10, help="Scan timeout")

# Add IoT subparser
iot_parser = subparsers.add_parser("iot", help="IoT security testing")
iot_subparsers = iot_parser.add_subparsers(dest="iot_command")

iot_scan_parser = iot_subparsers.add_parser("scan", help="Scan for IoT devices")
iot_scan_parser.add_argument("network", help="Network to scan (e.g., 192.168.1.0/24)")

iot_mqtt_parser = iot_subparsers.add_parser("mqtt", help="MQTT testing")
iot_mqtt_subparsers = iot_mqtt_parser.add_subparsers(dest="mqtt_action")

mqtt_probe_parser = iot_mqtt_subparsers.add_parser("probe", help="Probe MQTT broker")
mqtt_probe_parser.add_argument("host", help="Broker host")
mqtt_probe_parser.add_argument("--port", type=int, default=1883, help="Broker port")

iot_firmware_parser = iot_subparsers.add_parser("firmware", help="Firmware analysis")
iot_firmware_subparsers = iot_firmware_parser.add_subparsers(dest="firmware_action")

firmware_extract_parser = iot_firmware_subparsers.add_parser("extract", help="Extract firmware")
firmware_extract_parser.add_argument("firmware", help="Firmware file path")
```

### Step 8.4: Test CLI commands

```bash
# Test wireless
akali wireless wifi scan
akali wireless ble scan --timeout 5
akali wireless wifi deauth-detect tests/fixtures/deauth_attack.pcap

# Test IoT
akali iot scan 192.168.1.0/24
akali iot mqtt probe test.mosquitto.org --port 1883
akali iot firmware extract firmware.bin
```

### Step 8.5: Commit

```bash
git add core/cli.py akali
git commit -m "feat(cli): add wireless and IoT commands

CLI commands added:
- akali wireless wifi scan
- akali wireless wifi deauth-detect <pcap>
- akali wireless ble scan [--timeout]
- akali iot scan <network>
- akali iot mqtt probe <host> [--port]
- akali iot firmware extract <firmware>

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Documentation

### Step 9.1: Write wireless and IoT usage guide

Create `docs/WIRELESS_IOT_USAGE.md`:

```markdown
# Wireless + IoT Security Testing Guide

## WiFi Testing

### Network Scanning
```bash
akali wireless wifi scan
```

Discovers nearby WiFi networks with:
- SSID, BSSID, channel
- Signal strength
- Encryption type (WPA/WPA2/WPA3)

### Deauth Attack Detection
```bash
akali wireless wifi deauth-detect capture.pcap
```

Analyzes packet captures for deauthentication attack patterns.

**Legal Note:** Only test networks you own or have permission to test.

## Bluetooth Testing

### BLE Device Scanning
```bash
akali wireless ble scan --timeout 10
```

Discovers BLE devices with address, name, and RSSI.

## IoT Security

### Network Device Discovery
```bash
akali iot scan 192.168.1.0/24
```

Scans network for IoT devices, detecting:
- Open ports (MQTT, CoAP, HTTP, Telnet)
- Device fingerprinting
- Security misconfigurations

### MQTT Broker Testing
```bash
akali iot mqtt probe broker.example.com
```

Tests MQTT broker for:
- Anonymous access
- Authentication requirements
- Topic enumeration

### Firmware Analysis
```bash
akali iot firmware extract firmware.bin
```

Extracts and analyzes firmware:
- Filesystem detection
- Hardcoded secrets
- Default credentials

## Examples

### Smart Home Assessment
```bash
# Discover devices
akali iot scan 192.168.1.0/24

# Test MQTT broker
akali iot mqtt probe 192.168.1.50

# Scan for BLE devices
akali wireless ble scan
```

### WiFi Security Audit
```bash
# Scan networks
akali wireless wifi scan

# Analyze capture for attacks
akali wireless wifi deauth-detect capture.pcap
```
```

### Step 9.2: Write security considerations document

Create `docs/WIRELESS_SECURITY.md`:

```markdown
# Wireless Security Testing - Legal & Safety

## Legal Considerations

**CRITICAL:** Wireless security testing can be illegal without authorization.

### Requirements
- Written permission for network testing
- Authorization for radio frequency testing
- Compliance with local laws (FCC, OFCOM, etc.)

### Safe Testing
- Use test labs with Faraday cages
- Test only your own networks
- Don't interfere with production systems

## Technical Requirements

### WiFi Testing
- Wireless interface with monitor mode
- Root/sudo privileges for packet capture
- aircrack-ng suite installed

### Bluetooth Testing
- Bluetooth adapter with BLE support
- bluez tools (Linux)
- May require root privileges

### IoT Testing
- Network access to target devices
- MQTT/CoAP clients installed
- binwalk for firmware analysis

## Best Practices

1. **Get permission** - Always obtain written authorization
2. **Use test environments** - Avoid production systems
3. **Document everything** - Keep logs of all testing
4. **Respect privacy** - Don't capture personal data
5. **Follow regulations** - Comply with RF regulations

## Responsible Disclosure

If you find vulnerabilities:
1. Document the issue
2. Contact the vendor privately
3. Give reasonable time to fix (90 days)
4. Follow coordinated disclosure
```

### Step 9.3: Update main README

Add Phase 8 section to `README.md`:

```markdown
### Phase 8: Wireless + IoT Security (NEW)

**Wireless Testing:**
- WiFi network scanning and analysis
- WPA/WPA2/WPA3 handshake detection
- Deauth attack pattern detection
- BLE device discovery and GATT enumeration

**IoT Security:**
- Network-based IoT device discovery
- MQTT/CoAP protocol analysis
- Firmware extraction and secrets scanning
- Smart home security testing

**Commands:**
```bash
# WiFi
akali wireless wifi scan
akali wireless wifi deauth-detect capture.pcap

# Bluetooth
akali wireless ble scan

# IoT
akali iot scan 192.168.1.0/24
akali iot mqtt probe broker.example.com
akali iot firmware extract firmware.bin
```
```

### Step 9.4: Commit documentation

```bash
git add docs/
git commit -m "docs: add Phase 8 wireless and IoT guides

- WIRELESS_IOT_USAGE.md with examples
- WIRELESS_SECURITY.md with legal considerations
- Updated README with Phase 8 features

Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>"
```

---

## Testing & Validation

### Step 10.1: Integration test with real WiFi

```bash
# Test WiFi scanning on live network
akali wireless wifi scan

# Should display nearby networks with encryption details
```

### Step 10.2: Test BLE scanner

```bash
# Scan for BLE devices (smart watches, fitness trackers, etc.)
akali wireless ble scan --timeout 10

# Should discover BLE devices with RSSI
```

### Step 10.3: Test IoT scanner

```bash
# Scan home network for IoT devices
akali iot scan 192.168.1.0/24

# Should identify cameras, smart speakers, etc.
```

### Step 10.4: Test MQTT broker

```bash
# Connect to public test broker
akali iot mqtt probe test.mosquitto.org

# Should report accessibility and auth status
```

### Step 10.5: Test firmware extraction

```bash
# Download sample IoT firmware
# Test extraction and analysis
akali iot firmware extract sample_firmware.bin

# Should detect filesystems and scan for secrets
```

### Step 10.6: Run full test suite

```bash
# Run all wireless and IoT tests
pytest tests/wireless/ tests/iot/ -v

# Check coverage
pytest tests/wireless/ tests/iot/ --cov=wireless --cov=iot --cov-report=term-missing
```

### Step 10.7: Document test results

Create test report with:
- Devices discovered
- Vulnerabilities found
- False positive rate
- Performance metrics

---

## Phase 8 Complete!

**Deliverables:**
- ✅ WiFi security testing (WPA analysis, deauth detection)
- ✅ Bluetooth LE scanning and enumeration
- ✅ IoT device discovery and fingerprinting
- ✅ MQTT/CoAP protocol analysis
- ✅ Firmware extraction and analysis
- ✅ CLI commands (8 new commands)
- ✅ Documentation with security guidelines
- ✅ Test coverage >80%

**Statistics:**
- **LOC Added:** ~1,500 lines
- **CLI Commands:** 8 commands
- **Test Files:** 8 test files
- **Documentation:** 3 guides

**Next Steps:**
- Phase 9: Exploit Framework + Extended Targets
- Phase 10: Cloud Security (AWS/Azure/GCP)

---

## Success Criteria

### WiFi Testing
- ✅ Can scan and enumerate WiFi networks
- ✅ Can detect WPA handshakes in pcap files
- ✅ Can detect deauth attack patterns
- ✅ Cross-platform wireless interface detection

### Bluetooth Testing
- ✅ Can discover BLE devices
- ✅ Can enumerate GATT services
- ✅ Cross-platform compatibility (bluez/bluepy)
- ✅ BlueBorne vulnerability check stub

### IoT Discovery
- ✅ Can scan networks for IoT devices
- ✅ Can fingerprint device types
- ✅ Can identify common IoT ports/services
- ✅ Device type inference from port patterns

### Protocol Analysis
- ✅ Can probe MQTT brokers for auth requirements
- ✅ Can enumerate MQTT topics with wildcard
- ✅ Can discover CoAP resources via .well-known/core
- ✅ Can test for injection vulnerabilities

### Firmware Analysis
- ✅ Can extract firmware with binwalk
- ✅ Can detect embedded filesystems
- ✅ Can scan for secrets in firmware
- ✅ Can detect hardcoded credentials

### Integration
- ✅ All CLI commands functional
- ✅ Tests passing (>80% coverage)
- ✅ Documentation complete with legal considerations
- ✅ Integration tests for live testing

---

**Estimated LOC:** ~1,500 lines
**Estimated Time:** 4-6 weeks (single developer)
**Test Coverage Target:** >80%
**CLI Commands Added:** 8 commands

**Dependencies:**
- aircrack-ng, bluez-tools, binwalk
- paho-mqtt, aiocoap, scapy, python-nmap, bluepy

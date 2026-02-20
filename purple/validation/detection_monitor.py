"""Detection monitoring for purple team validation."""

from datetime import datetime
from typing import Dict, List, Optional, Callable
from pathlib import Path
import re
import json
import threading
import time
import uuid


# Detection source configurations
DETECTION_SOURCES = {
    "logs": {
        "syslog": "/var/log/syslog",
        "auth": "/var/log/auth.log",
        "apache": "/var/log/apache2/access.log",
        "nginx": "/var/log/nginx/access.log"
    },
    "siem": {
        "splunk": "http://localhost:8089",
        "elasticsearch": "http://localhost:9200"
    },
    "edr": {
        "endpoint": "http://localhost:8000/api/alerts"
    }
}


class DetectionMonitor:
    """Monitor detection sources for attack detections."""

    def __init__(self):
        """Initialize detection monitor."""
        self.detection_sources = DETECTION_SOURCES
        self.active_monitors = {}

    def list_detection_sources(self) -> List[Dict]:
        """
        List available detection sources.

        Returns:
            List of detection source dictionaries
        """
        sources = []
        for source_type, configs in self.detection_sources.items():
            for name, path in configs.items():
                sources.append({
                    'type': source_type,
                    'name': name,
                    'path': path
                })
        return sources

    def monitor_log_file(self, log_path: str, attack_type: str, timeout: int = 600) -> List[Dict]:
        """
        Monitor a log file for detections.

        Args:
            log_path: Path to log file
            attack_type: Type of attack to monitor for
            timeout: Timeout in seconds

        Returns:
            List of detection events
        """
        detections = []
        log_file = Path(log_path)

        if not log_file.exists():
            return detections

        # Attack pattern mapping
        patterns = self._get_attack_patterns()

        start_time = time.time()
        last_position = 0

        try:
            while time.time() - start_time < timeout:
                with open(log_path, 'r') as f:
                    f.seek(last_position)
                    lines = f.readlines()
                    last_position = f.tell()

                    for line in lines:
                        if self.match_attack_pattern(line, attack_type, patterns):
                            detection = self.parse_log_line(line, 'syslog')
                            if detection:
                                detection['attack_type'] = attack_type
                                detections.append(detection)

                time.sleep(1)  # Check every second

                if detections:
                    break  # Exit once we have detections

        except Exception as e:
            pass  # Ignore errors, return what we have

        return detections

    def monitor_siem(self, siem_type: str, attack_type: str, timeout: int = 600) -> List[Dict]:
        """
        Monitor SIEM for detections.

        Args:
            siem_type: Type of SIEM (splunk, elasticsearch)
            attack_type: Type of attack to monitor for
            timeout: Timeout in seconds

        Returns:
            List of detection events
        """
        detections = []

        # Mock SIEM monitoring - in real scenario, would query SIEM API
        try:
            if siem_type == 'splunk':
                # Mock Splunk query
                pass
            elif siem_type == 'elasticsearch':
                # Mock Elasticsearch query
                pass
        except Exception:
            pass

        return detections

    def monitor_edr(self, attack_type: str, timeout: int = 600) -> List[Dict]:
        """
        Monitor EDR endpoint for alerts.

        Args:
            attack_type: Type of attack to monitor for
            timeout: Timeout in seconds

        Returns:
            List of detection events
        """
        detections = []

        # Mock EDR monitoring - in real scenario, would query EDR API
        try:
            # Mock implementation
            pass
        except Exception:
            pass

        return detections

    def parse_log_line(self, line: str, format: str) -> Optional[Dict]:
        """
        Parse a log line based on format.

        Args:
            line: Log line to parse
            format: Log format (syslog, json, cef)

        Returns:
            Parsed log dictionary or None
        """
        if format == 'syslog':
            # Parse syslog format: "Feb 20 10:00:05 server process[pid]: message"
            pattern = r'^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(.+)$'
            match = re.match(pattern, line)
            if match:
                return {
                    'timestamp': match.group(1),
                    'hostname': match.group(2),
                    'message': match.group(3)
                }

        elif format == 'json':
            # Parse JSON log
            try:
                return json.loads(line)
            except:
                return None

        elif format == 'cef':
            # Parse CEF (Common Event Format)
            # CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
            pattern = r'^CEF:(\d+)\|([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|(.*)$'
            match = re.match(pattern, line)
            if match:
                return {
                    'version': match.group(1),
                    'vendor': match.group(2),
                    'product': match.group(3),
                    'device_version': match.group(4),
                    'signature_id': match.group(5),
                    'name': match.group(6),
                    'severity': match.group(7),
                    'extension': match.group(8)
                }

        return None

    def match_attack_pattern(self, line: str, attack_type: str, patterns: Dict) -> bool:
        """
        Check if log line matches attack pattern.

        Args:
            line: Log line
            attack_type: Attack type
            patterns: Pattern dictionary

        Returns:
            True if matches, False otherwise
        """
        if attack_type not in patterns:
            return False

        attack_patterns = patterns[attack_type]
        for pattern in attack_patterns:
            if pattern.lower() in line.lower():
                return True

        return False

    def _get_attack_patterns(self) -> Dict:
        """
        Get attack detection patterns.

        Returns:
            Dictionary of attack patterns
        """
        return {
            'sqli': ['SQL injection', 'SQLi', 'union select', 'sql attack'],
            'xss': ['XSS', 'script tag', 'cross-site scripting', 'javascript injection'],
            'port_scan': ['port scan', 'portscan', 'scan detected', 'nmap'],
            'brute_force': ['brute force', 'failed password', 'failed login', 'ban', 'fail2ban'],
            'kerberoast': ['kerberoast', 'TGS request', 'service ticket'],
            'privilege_escalation': ['privilege escalation', 'privesc', 'elevation', 'suid']
        }

    def start_continuous_monitoring(self, config: Dict) -> str:
        """
        Start continuous monitoring in background.

        Args:
            config: Monitoring configuration

        Returns:
            Monitor ID
        """
        monitor_id = str(uuid.uuid4())

        # Create monitoring thread
        monitor_thread = threading.Thread(
            target=self._continuous_monitor_worker,
            args=(monitor_id, config),
            daemon=True
        )

        self.active_monitors[monitor_id] = {
            'thread': monitor_thread,
            'config': config,
            'running': True
        }

        monitor_thread.start()

        return monitor_id

    def stop_continuous_monitoring(self, monitor_id: str) -> bool:
        """
        Stop continuous monitoring.

        Args:
            monitor_id: Monitor ID to stop

        Returns:
            True if stopped successfully
        """
        if monitor_id in self.active_monitors:
            self.active_monitors[monitor_id]['running'] = False
            del self.active_monitors[monitor_id]
            return True
        return False

    def _continuous_monitor_worker(self, monitor_id: str, config: Dict):
        """
        Background worker for continuous monitoring.

        Args:
            monitor_id: Monitor ID
            config: Monitoring configuration
        """
        while self.active_monitors.get(monitor_id, {}).get('running', False):
            try:
                # Monitor and call callback
                detections = self.monitor_log_file(
                    config['source'],
                    config['attack_type'],
                    timeout=5
                )

                for detection in detections:
                    if 'callback' in config:
                        config['callback'](detection)

            except Exception:
                pass

            time.sleep(1)

    def get_detection_statistics(self, detections: List[Dict]) -> Dict:
        """
        Calculate detection statistics.

        Args:
            detections: List of detections

        Returns:
            Statistics dictionary
        """
        stats = {
            'total_detections': len(detections),
            'by_source': {},
            'by_severity': {}
        }

        for detection in detections:
            # Count by source
            source = detection.get('source', 'unknown')
            stats['by_source'][source] = stats['by_source'].get(source, 0) + 1

            # Count by severity
            severity = detection.get('severity', 'unknown')
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1

        return stats

    def correlate_detections(self, detections: List[Dict]) -> Dict:
        """
        Correlate detections by source IP or other attributes.

        Args:
            detections: List of detections

        Returns:
            Correlated detections dictionary
        """
        correlated = {}

        for detection in detections:
            # Group by source IP
            source_ip = detection.get('source_ip', 'unknown')

            if source_ip not in correlated:
                correlated[source_ip] = []

            correlated[source_ip].append(detection)

        return correlated

    def monitor_via_websocket(self, ws_url: str, attack_type: str, timeout: int = 600) -> List[Dict]:
        """
        Monitor via WebSocket for real-time alerts.

        Args:
            ws_url: WebSocket URL
            attack_type: Attack type to monitor for
            timeout: Timeout in seconds

        Returns:
            List of detections
        """
        detections = []

        # Mock WebSocket monitoring - in real scenario, would use websocket library
        try:
            # Mock implementation
            pass
        except Exception:
            pass

        return detections

"""Tests for DetectionMonitor class."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
from pathlib import Path

from purple.validation.detection_monitor import DetectionMonitor


class TestDetectionMonitor:
    """Test DetectionMonitor functionality."""

    @pytest.fixture
    def monitor(self):
        """Create DetectionMonitor instance."""
        return DetectionMonitor()

    def test_initialization(self, monitor):
        """Test DetectionMonitor initializes correctly."""
        assert monitor is not None
        assert hasattr(monitor, 'detection_sources')
        assert hasattr(monitor, 'active_monitors')

    def test_list_detection_sources(self, monitor):
        """Test listing available detection sources."""
        sources = monitor.list_detection_sources()

        assert sources is not None
        assert isinstance(sources, list)
        assert 'logs' in [s['type'] for s in sources]
        assert 'siem' in [s['type'] for s in sources]

    @patch('purple.validation.detection_monitor.Path.exists')
    @patch('purple.validation.detection_monitor.Path.open')
    def test_monitor_syslog(self, mock_open, mock_exists, monitor):
        """Test monitoring syslog for detections."""
        mock_exists.return_value = True
        mock_open.return_value.__enter__.return_value.readlines.return_value = [
            "Feb 20 10:00:05 server sshd[1234]: Failed password for admin\n",
            "Feb 20 10:00:06 server sshd[1234]: Failed password for admin\n",
            "Feb 20 10:00:07 server fail2ban: Ban 10.0.0.5\n"
        ]

        detections = monitor.monitor_log_file('/var/log/syslog', 'brute_force', timeout=10)

        assert detections is not None
        assert isinstance(detections, list)
        assert len(detections) > 0

    @patch('purple.validation.detection_monitor.Path.exists')
    @patch('purple.validation.detection_monitor.Path.open')
    def test_monitor_auth_log(self, mock_open, mock_exists, monitor):
        """Test monitoring auth.log for detections."""
        mock_exists.return_value = True
        mock_open.return_value.__enter__.return_value.readlines.return_value = [
            "Feb 20 10:00:05 server sshd[1234]: Invalid user admin from 10.0.0.5\n"
        ]

        detections = monitor.monitor_log_file('/var/log/auth.log', 'brute_force', timeout=10)

        assert detections is not None
        assert isinstance(detections, list)

    @patch('purple.validation.detection_monitor.requests.get')
    def test_monitor_splunk(self, mock_get, monitor):
        """Test monitoring Splunk SIEM."""
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            'results': [
                {
                    'timestamp': '2026-02-20T10:00:05Z',
                    'event': 'SQL injection detected',
                    'severity': 'high',
                    'source': 'WAF'
                }
            ]
        }

        detections = monitor.monitor_siem('splunk', 'sqli', timeout=10)

        assert detections is not None
        assert isinstance(detections, list)
        assert len(detections) > 0
        assert detections[0]['source'] == 'WAF'

    @patch('purple.validation.detection_monitor.requests.get')
    def test_monitor_elasticsearch(self, mock_get, monitor):
        """Test monitoring Elasticsearch."""
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            'hits': {
                'hits': [
                    {
                        '_source': {
                            '@timestamp': '2026-02-20T10:00:05Z',
                            'message': 'XSS attempt blocked',
                            'severity': 'medium'
                        }
                    }
                ]
            }
        }

        detections = monitor.monitor_siem('elasticsearch', 'xss', timeout=10)

        assert detections is not None
        assert isinstance(detections, list)
        assert len(detections) > 0

    @patch('purple.validation.detection_monitor.requests.get')
    def test_monitor_edr(self, mock_get, monitor):
        """Test monitoring EDR endpoint."""
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            'alerts': [
                {
                    'id': 'alert-001',
                    'timestamp': '2026-02-20T10:00:05Z',
                    'type': 'privilege_escalation',
                    'severity': 'critical'
                }
            ]
        }

        detections = monitor.monitor_edr('privilege_escalation', timeout=10)

        assert detections is not None
        assert isinstance(detections, list)
        assert len(detections) > 0
        assert detections[0]['type'] == 'privilege_escalation'

    def test_monitor_timeout(self, monitor):
        """Test monitoring times out with no detections."""
        detections = monitor.monitor_log_file('/var/log/nonexistent.log', 'sqli', timeout=1)

        assert detections is not None
        assert isinstance(detections, list)
        assert len(detections) == 0

    def test_parse_syslog_line(self, monitor):
        """Test parsing syslog format."""
        line = "Feb 20 10:00:05 server fail2ban[1234]: Ban 10.0.0.5"

        parsed = monitor.parse_log_line(line, 'syslog')

        assert parsed is not None
        assert 'timestamp' in parsed
        assert 'message' in parsed
        assert 'Ban 10.0.0.5' in parsed['message']

    def test_parse_json_log_line(self, monitor):
        """Test parsing JSON log format."""
        line = '{"timestamp": "2026-02-20T10:00:05Z", "level": "ERROR", "message": "SQL injection blocked"}'

        parsed = monitor.parse_log_line(line, 'json')

        assert parsed is not None
        assert parsed['timestamp'] == '2026-02-20T10:00:05Z'
        assert parsed['message'] == 'SQL injection blocked'

    def test_parse_cef_log_line(self, monitor):
        """Test parsing CEF (Common Event Format) log."""
        line = "CEF:0|Security|WAF|1.0|100|SQL Injection|High|src=10.0.0.5 dst=10.0.0.10"

        parsed = monitor.parse_log_line(line, 'cef')

        assert parsed is not None
        assert parsed['severity'] == 'High'
        assert 'SQL Injection' in parsed['name']

    def test_match_attack_pattern(self, monitor):
        """Test matching attack patterns in log lines."""
        patterns = {
            'sqli': ['SQL injection', 'SQLi', 'union select'],
            'xss': ['XSS', 'script tag', 'cross-site scripting']
        }

        # Match SQL injection
        assert monitor.match_attack_pattern('SQL injection detected', 'sqli', patterns) is True
        assert monitor.match_attack_pattern('union select from users', 'sqli', patterns) is True

        # Match XSS
        assert monitor.match_attack_pattern('XSS attempt blocked', 'xss', patterns) is True

        # No match
        assert monitor.match_attack_pattern('User login successful', 'sqli', patterns) is False

    def test_start_continuous_monitoring(self, monitor):
        """Test starting continuous monitoring."""
        config = {
            'source': '/var/log/syslog',
            'attack_type': 'brute_force',
            'callback': lambda detection: print(detection)
        }

        monitor_id = monitor.start_continuous_monitoring(config)

        assert monitor_id is not None
        assert monitor_id in monitor.active_monitors

    def test_stop_continuous_monitoring(self, monitor):
        """Test stopping continuous monitoring."""
        config = {
            'source': '/var/log/syslog',
            'attack_type': 'brute_force',
            'callback': lambda detection: print(detection)
        }

        monitor_id = monitor.start_continuous_monitoring(config)
        result = monitor.stop_continuous_monitoring(monitor_id)

        assert result is True
        assert monitor_id not in monitor.active_monitors

    def test_get_detection_statistics(self, monitor):
        """Test getting detection statistics."""
        detections = [
            {'timestamp': '2026-02-20T10:00:05Z', 'source': 'WAF', 'severity': 'high'},
            {'timestamp': '2026-02-20T10:00:10Z', 'source': 'IDS', 'severity': 'medium'},
            {'timestamp': '2026-02-20T10:00:15Z', 'source': 'WAF', 'severity': 'high'}
        ]

        stats = monitor.get_detection_statistics(detections)

        assert stats is not None
        assert stats['total_detections'] == 3
        assert stats['by_source']['WAF'] == 2
        assert stats['by_source']['IDS'] == 1
        assert stats['by_severity']['high'] == 2

    def test_correlate_detections(self, monitor):
        """Test correlating multiple detections."""
        detections = [
            {'timestamp': '2026-02-20T10:00:05Z', 'attack_type': 'port_scan', 'source_ip': '10.0.0.5'},
            {'timestamp': '2026-02-20T10:00:10Z', 'attack_type': 'sqli', 'source_ip': '10.0.0.5'},
            {'timestamp': '2026-02-20T10:00:15Z', 'attack_type': 'xss', 'source_ip': '10.0.0.6'}
        ]

        correlated = monitor.correlate_detections(detections)

        assert correlated is not None
        assert len(correlated) == 2  # Two different source IPs
        assert '10.0.0.5' in correlated
        assert len(correlated['10.0.0.5']) == 2

    @patch('purple.validation.detection_monitor.websocket.WebSocket')
    def test_monitor_via_websocket(self, mock_ws, monitor):
        """Test monitoring via WebSocket (real-time)."""
        mock_ws.return_value.recv.return_value = '{"type": "alert", "attack": "sqli", "severity": "high"}'

        detections = monitor.monitor_via_websocket('ws://localhost:8080/alerts', 'sqli', timeout=10)

        assert detections is not None
        assert isinstance(detections, list)

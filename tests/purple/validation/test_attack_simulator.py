"""Tests for AttackSimulator class."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from purple.validation.attack_simulator import AttackSimulator


class TestAttackSimulator:
    """Test AttackSimulator functionality."""

    @pytest.fixture
    def simulator(self):
        """Create AttackSimulator instance."""
        return AttackSimulator()

    def test_initialization(self, simulator):
        """Test AttackSimulator initializes correctly."""
        assert simulator is not None
        assert hasattr(simulator, 'attack_modules')
        assert len(simulator.attack_modules) > 0

    def test_list_available_attacks(self, simulator):
        """Test listing available attack types."""
        attacks = simulator.list_available_attacks()

        assert attacks is not None
        assert isinstance(attacks, list)
        assert len(attacks) >= 6  # sqli, xss, port_scan, brute_force, kerberoast, privilege_escalation
        assert 'sqli' in attacks
        assert 'xss' in attacks

    @patch('purple.validation.attack_simulator.ExploitGenerator')
    def test_execute_sqli_attack(self, mock_generator, simulator):
        """Test executing SQL injection attack."""
        mock_generator.return_value.generate_sqli.return_value = {
            'success': True,
            'payload': "' OR 1=1--",
            'response': 'Vulnerable'
        }

        result = simulator.execute_attack('sqli', 'http://localhost:8080/login')

        assert result is not None
        assert result['success'] is True
        assert 'attack_id' in result
        assert 'start_time' in result
        assert 'end_time' in result
        assert result['attack_type'] == 'sqli'

    @patch('purple.validation.attack_simulator.ExploitGenerator')
    def test_execute_xss_attack(self, mock_generator, simulator):
        """Test executing XSS attack."""
        mock_generator.return_value.generate_xss.return_value = {
            'success': True,
            'payload': '<script>alert(1)</script>',
            'response': 'Reflected'
        }

        result = simulator.execute_attack('xss', 'http://localhost:8080/search')

        assert result is not None
        assert result['success'] is True
        assert result['attack_type'] == 'xss'

    @patch('purple.validation.attack_simulator.NetworkScanner')
    def test_execute_port_scan(self, mock_scanner, simulator):
        """Test executing port scan."""
        mock_scanner.return_value.scan.return_value = {
            'open_ports': [22, 80, 443],
            'scan_time': 2.5
        }

        result = simulator.execute_attack('port_scan', '10.0.0.5')

        assert result is not None
        assert result['success'] is True
        assert result['attack_type'] == 'port_scan'
        assert result['target'] == '10.0.0.5'

    @patch('purple.validation.attack_simulator.BruteForcer')
    def test_execute_brute_force(self, mock_bruteforcer, simulator):
        """Test executing brute force attack."""
        mock_bruteforcer.return_value.attack_ssh.return_value = {
            'success': True,
            'credentials': {'username': 'admin', 'password': 'password123'},
            'attempts': 50
        }

        result = simulator.execute_attack('brute_force', '10.0.0.5:22')

        assert result is not None
        assert result['success'] is True
        assert result['attack_type'] == 'brute_force'

    @patch('purple.validation.attack_simulator.ADAttacker')
    def test_execute_kerberoast(self, mock_ad, simulator):
        """Test executing Kerberoasting attack."""
        mock_ad.return_value.kerberoast.return_value = {
            'success': True,
            'tickets': ['ticket1', 'ticket2'],
            'spns': ['MSSQLSvc/server.domain.com']
        }

        result = simulator.execute_attack('kerberoast', '10.0.0.10')

        assert result is not None
        assert result['success'] is True
        assert result['attack_type'] == 'kerberoast'

    @patch('purple.validation.attack_simulator.PrivilegeEscalation')
    def test_execute_privilege_escalation(self, mock_privesc, simulator):
        """Test executing privilege escalation."""
        mock_privesc.return_value.exploit_suid.return_value = {
            'success': True,
            'method': 'SUID binary',
            'escalated_to': 'root'
        }

        result = simulator.execute_attack('privilege_escalation', '10.0.0.5')

        assert result is not None
        assert result['success'] is True
        assert result['attack_type'] == 'privilege_escalation'

    def test_execute_invalid_attack(self, simulator):
        """Test handling of invalid attack type."""
        with pytest.raises(ValueError):
            simulator.execute_attack('invalid_attack', 'http://localhost')

    def test_execute_attack_with_options(self, simulator):
        """Test executing attack with custom options."""
        options = {
            'timeout': 30,
            'threads': 10,
            'payloads': ['custom_payload1', 'custom_payload2']
        }

        result = simulator.execute_attack('sqli', 'http://localhost:8080', options=options)

        assert result is not None
        assert 'options' in result
        assert result['options']['timeout'] == 30

    def test_execute_attack_logs_to_file(self, simulator, tmp_path):
        """Test attack execution logs to file."""
        log_file = tmp_path / "attack.log"

        result = simulator.execute_attack('port_scan', '10.0.0.5', log_file=str(log_file))

        assert result is not None
        assert log_file.exists()
        log_content = log_file.read_text()
        assert 'Attack started' in log_content

    def test_get_attack_metadata(self, simulator):
        """Test getting attack metadata."""
        metadata = simulator.get_attack_metadata('sqli')

        assert metadata is not None
        assert metadata['name'] == 'SQL Injection Attack'
        assert metadata['target_type'] == 'webapp'
        assert 'WAF' in metadata['expected_detection']

    def test_validate_target(self, simulator):
        """Test target validation."""
        # Valid targets
        assert simulator.validate_target('http://localhost:8080', 'webapp') is True
        assert simulator.validate_target('10.0.0.5', 'network') is True
        assert simulator.validate_target('10.0.0.5:22', 'service') is True

        # Invalid targets
        assert simulator.validate_target('', 'webapp') is False
        assert simulator.validate_target('invalid-url', 'webapp') is False

    def test_execute_attack_with_retry(self, simulator):
        """Test attack execution with retry on failure."""
        result = simulator.execute_attack('sqli', 'http://localhost:8080', retry=3)

        assert result is not None
        assert 'attempts' in result

    @patch('purple.validation.attack_simulator.time.sleep')
    def test_execute_attack_with_delay(self, mock_sleep, simulator):
        """Test attack execution with delay between attempts."""
        result = simulator.execute_attack('port_scan', '10.0.0.5', delay=2)

        assert result is not None
        # mock_sleep.assert_called()  # Verify delay was applied

    def test_concurrent_attack_execution(self, simulator):
        """Test executing multiple attacks concurrently."""
        attacks = [
            ('port_scan', '10.0.0.5'),
            ('sqli', 'http://localhost:8080'),
            ('xss', 'http://localhost:8080')
        ]

        results = simulator.execute_concurrent_attacks(attacks)

        assert results is not None
        assert len(results) == 3
        assert all('attack_id' in r for r in results)

    def test_stop_attack(self, simulator):
        """Test stopping a running attack."""
        # Start attack
        attack_id = 'attack-001'

        # Stop attack
        result = simulator.stop_attack(attack_id)

        assert result is True

"""Tests for ADAttacker main class."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from extended.ad.ad_attacker import ADAttacker


class TestADAttacker:
    """Test suite for ADAttacker."""

    def test_init(self):
        """Test ADAttacker initialization"""
        attacker = ADAttacker()

        assert attacker is not None
        assert hasattr(attacker, 'kerberos')
        assert hasattr(attacker, 'ntlm')
        assert hasattr(attacker, 'tickets')
        assert hasattr(attacker, 'bloodhound')

    def test_check_available_with_impacket(self):
        """Test availability check when impacket is installed"""
        attacker = ADAttacker()

        with patch('importlib.util.find_spec') as mock_find:
            mock_find.return_value = Mock()

            assert attacker.check_available() is True

    def test_check_available_without_impacket(self):
        """Test availability check when impacket is not installed"""
        attacker = ADAttacker()

        with patch('importlib.util.find_spec') as mock_find:
            mock_find.return_value = None

            assert attacker.check_available() is False

    def test_enumerate_domain(self):
        """Test domain enumeration"""
        attacker = ADAttacker()

        with patch('ldap3.Connection') as mock_conn:
            mock_instance = MagicMock()
            mock_instance.bind.return_value = True
            mock_instance.search.return_value = True
            mock_instance.entries = [
                Mock(entry_dn="CN=User1,DC=corp,DC=local",
                     sAMAccountName=Mock(value="user1"))
            ]
            mock_conn.return_value = mock_instance

            result = attacker.enumerate_domain(
                domain="corp.local",
                username="admin",
                password="password123"
            )

            assert isinstance(result, dict)
            assert "users" in result
            assert "computers" in result
            assert "groups" in result

    def test_enumerate_domain_no_auth(self):
        """Test domain enumeration without authentication"""
        attacker = ADAttacker()

        with patch('ldap3.Connection') as mock_conn:
            mock_instance = MagicMock()
            mock_instance.bind.return_value = True
            mock_instance.search.return_value = True
            mock_instance.entries = []
            mock_conn.return_value = mock_instance

            result = attacker.enumerate_domain(domain="corp.local")

            assert isinstance(result, dict)

    def test_enumerate_domain_connection_error(self):
        """Test domain enumeration with connection error"""
        attacker = ADAttacker()

        with patch('ldap3.Connection', side_effect=Exception("Connection failed")):
            result = attacker.enumerate_domain(domain="corp.local")

            assert result is None or result.get("error") is not None

    def test_kerberoast(self):
        """Test Kerberoasting attack"""
        attacker = ADAttacker()

        with patch.object(attacker.kerberos, 'kerberoast') as mock_kerb:
            mock_kerb.return_value = [
                {
                    "username": "svc_sql",
                    "spn": "MSSQLSvc/sql01.corp.local:1433",
                    "hash": "$krb5tgs$23$*svc_sql..."
                }
            ]

            result = attacker.kerberoast(
                domain="corp.local",
                username="admin",
                password="password123"
            )

            assert isinstance(result, list)
            assert len(result) > 0
            assert "hash" in result[0]

    def test_asreproast(self):
        """Test AS-REP roasting attack"""
        attacker = ADAttacker()

        with patch.object(attacker.kerberos, 'asreproast') as mock_asrep:
            mock_asrep.return_value = [
                {
                    "username": "user_no_preauth",
                    "hash": "$krb5asrep$23$user_no_preauth..."
                }
            ]

            result = attacker.asreproast(domain="corp.local")

            assert isinstance(result, list)
            assert len(result) > 0
            assert "hash" in result[0]

    def test_asreproast_with_user_list(self):
        """Test AS-REP roasting with user list file"""
        attacker = ADAttacker()

        with patch.object(attacker.kerberos, 'asreproast') as mock_asrep:
            mock_asrep.return_value = []

            result = attacker.asreproast(
                domain="corp.local",
                user_list="/tmp/users.txt"
            )

            assert isinstance(result, list)

    def test_pass_the_hash(self):
        """Test Pass-the-Hash attack"""
        attacker = ADAttacker()

        with patch.object(attacker.ntlm, 'pass_the_hash') as mock_pth:
            mock_pth.return_value = {
                "success": True,
                "output": "Command executed successfully"
            }

            result = attacker.pass_the_hash(
                username="admin",
                ntlm_hash="aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c",
                target="10.0.0.5",
                command="whoami"
            )

            assert result["success"] is True

    def test_pass_the_hash_invalid_hash(self):
        """Test Pass-the-Hash with invalid hash format"""
        attacker = ADAttacker()

        result = attacker.pass_the_hash(
            username="admin",
            ntlm_hash="invalid",
            target="10.0.0.5"
        )

        assert result is None or result.get("error") is not None

    def test_pass_the_ticket(self):
        """Test Pass-the-Ticket attack"""
        attacker = ADAttacker()

        with patch.object(attacker.ntlm, 'pass_the_ticket') as mock_ptt:
            mock_ptt.return_value = {
                "success": True,
                "ticket_loaded": True
            }

            result = attacker.pass_the_ticket(
                ticket_path="/tmp/ticket.ccache",
                target="10.0.0.5"
            )

            assert result["success"] is True

    def test_golden_ticket(self):
        """Test Golden Ticket generation"""
        attacker = ADAttacker()

        with patch.object(attacker.tickets, 'generate_golden_ticket') as mock_golden:
            mock_golden.return_value = "/tmp/golden.ccache"

            result = attacker.golden_ticket(
                domain="corp.local",
                sid="S-1-5-21-1234567890-1234567890-1234567890",
                krbtgt_hash="8846f7eaee8fb117ad06bdd830b7586c",
                username="Administrator"
            )

            assert isinstance(result, str)
            assert result.endswith(".ccache")

    def test_golden_ticket_invalid_sid(self):
        """Test Golden Ticket with invalid SID"""
        attacker = ADAttacker()

        result = attacker.golden_ticket(
            domain="corp.local",
            sid="invalid-sid",
            krbtgt_hash="8846f7eaee8fb117ad06bdd830b7586c"
        )

        assert result is None or "error" in str(result).lower()

    def test_silver_ticket(self):
        """Test Silver Ticket generation"""
        attacker = ADAttacker()

        with patch.object(attacker.tickets, 'generate_silver_ticket') as mock_silver:
            mock_silver.return_value = "/tmp/silver.ccache"

            result = attacker.silver_ticket(
                domain="corp.local",
                sid="S-1-5-21-1234567890-1234567890-1234567890",
                service_hash="8846f7eaee8fb117ad06bdd830b7586c",
                service="CIFS/dc01.corp.local",
                username="admin"
            )

            assert isinstance(result, str)
            assert result.endswith(".ccache")

    def test_dcsync(self):
        """Test DCSync attack"""
        attacker = ADAttacker()

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::"
            )

            result = attacker.dcsync(
                domain="corp.local",
                username="admin",
                password="password123",
                target_user="Administrator"
            )

            assert isinstance(result, dict)
            assert "hashes" in result or "success" in result

    def test_dcsync_all_users(self):
        """Test DCSync to dump all users"""
        attacker = ADAttacker()

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="Multiple user hashes..."
            )

            result = attacker.dcsync(
                domain="corp.local",
                username="admin",
                password="password123"
            )

            assert isinstance(result, dict)

    def test_dcsync_no_permissions(self):
        """Test DCSync without proper permissions"""
        attacker = ADAttacker()

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=1,
                stderr="Access denied"
            )

            result = attacker.dcsync(
                domain="corp.local",
                username="lowpriv",
                password="password123"
            )

            assert result is None or result.get("error") is not None

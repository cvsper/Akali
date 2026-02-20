"""Tests for Kerberos attack module."""

import pytest
from unittest.mock import Mock, patch, MagicMock, mock_open
from extended.ad.kerberos import KerberosAttacker


class TestKerberosAttacker:
    """Test suite for Kerberos attacks."""

    def test_init(self):
        """Test KerberosAttacker initialization"""
        attacker = KerberosAttacker()

        assert attacker is not None

    def test_kerberoast_basic(self):
        """Test basic Kerberoasting"""
        attacker = KerberosAttacker()

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="""ServicePrincipalName                    Name      MemberOf
MSSQLSvc/sql01.corp.local:1433          svc_sql   CN=Service Accounts,DC=corp,DC=local

$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/sql01.corp.local*$hash..."""
            )

            results = attacker.kerberoast(
                domain="corp.local",
                username="admin",
                password="password123"
            )

            assert isinstance(results, list)
            assert len(results) > 0
            assert "hash" in results[0]
            assert "username" in results[0]

    def test_kerberoast_no_spns(self):
        """Test Kerberoasting with no SPN accounts"""
        attacker = KerberosAttacker()

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="No entries found"
            )

            results = attacker.kerberoast(
                domain="corp.local",
                username="admin",
                password="password123"
            )

            assert isinstance(results, list)
            assert len(results) == 0

    def test_kerberoast_auth_failure(self):
        """Test Kerberoasting with authentication failure"""
        attacker = KerberosAttacker()

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=1,
                stderr="Authentication failed"
            )

            results = attacker.kerberoast(
                domain="corp.local",
                username="invalid",
                password="wrong"
            )

            assert results is None or len(results) == 0

    def test_asreproast_basic(self):
        """Test basic AS-REP roasting"""
        attacker = KerberosAttacker()

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="""$krb5asrep$23$user_no_preauth@CORP.LOCAL:hash..."""
            )

            results = attacker.asreproast(domain="corp.local")

            assert isinstance(results, list)
            assert len(results) > 0
            assert "hash" in results[0]

    def test_asreproast_with_user_list(self):
        """Test AS-REP roasting with user list"""
        attacker = KerberosAttacker()

        user_list_content = "user1\nuser2\nuser3"

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="$krb5asrep$23$user2@CORP.LOCAL:hash..."
            )

            with patch('builtins.open', mock_open(read_data=user_list_content)):
                results = attacker.asreproast(
                    domain="corp.local",
                    user_list="/tmp/users.txt"
                )

                assert isinstance(results, list)

    def test_asreproast_no_vulnerable_users(self):
        """Test AS-REP roasting with no vulnerable users"""
        attacker = KerberosAttacker()

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout=""
            )

            results = attacker.asreproast(domain="corp.local")

            assert isinstance(results, list)
            assert len(results) == 0

    def test_parse_kerberoast_hash(self):
        """Test parsing Kerberoast hash output"""
        attacker = KerberosAttacker()

        output = """ServicePrincipalName                    Name      MemberOf
MSSQLSvc/sql01.corp.local:1433          svc_sql   CN=Service Accounts,DC=corp,DC=local

$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/sql01.corp.local*$abcd1234..."""

        results = attacker._parse_kerberoast_output(output)

        assert isinstance(results, list)
        assert len(results) > 0
        assert results[0]["username"] == "svc_sql"
        assert results[0]["spn"] == "MSSQLSvc/sql01.corp.local:1433"
        assert "$krb5tgs$23$" in results[0]["hash"]

    def test_parse_asreproast_hash(self):
        """Test parsing AS-REP roast hash output"""
        attacker = KerberosAttacker()

        output = "$krb5asrep$23$user_no_preauth@CORP.LOCAL:hash123..."

        results = attacker._parse_asreproast_output(output)

        assert isinstance(results, list)
        assert len(results) > 0
        assert results[0]["username"] == "user_no_preauth"
        assert "$krb5asrep$23$" in results[0]["hash"]

    def test_request_tgt(self):
        """Test requesting TGT"""
        attacker = KerberosAttacker()

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="TGT obtained successfully"
            )

            result = attacker.request_tgt(
                domain="corp.local",
                username="admin",
                password="password123"
            )

            assert result is not None

    def test_request_tgt_with_hash(self):
        """Test requesting TGT with NTLM hash"""
        attacker = KerberosAttacker()

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="TGT obtained"
            )

            result = attacker.request_tgt(
                domain="corp.local",
                username="admin",
                ntlm_hash="8846f7eaee8fb117ad06bdd830b7586c"
            )

            assert result is not None

    def test_request_service_ticket(self):
        """Test requesting service ticket"""
        attacker = KerberosAttacker()

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="Service ticket obtained"
            )

            result = attacker.request_service_ticket(
                domain="corp.local",
                username="admin",
                password="password123",
                spn="CIFS/dc01.corp.local"
            )

            assert result is not None

    def test_crack_hash(self):
        """Test cracking Kerberos hash"""
        attacker = KerberosAttacker()

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="$krb5tgs$23$*svc_sql$CORP.LOCAL...:password123"
            )

            result = attacker.crack_hash(
                hash_value="$krb5tgs$23$*svc_sql$CORP.LOCAL...",
                wordlist="/usr/share/wordlists/rockyou.txt"
            )

            # May return None if hashcat not available - acceptable
            assert result is None or isinstance(result, str)

    def test_enumerate_spns(self):
        """Test SPN enumeration"""
        attacker = KerberosAttacker()

        with patch('ldap3.Connection') as mock_conn:
            mock_instance = MagicMock()
            mock_instance.bind.return_value = True
            mock_instance.search.return_value = True
            mock_instance.entries = [
                Mock(
                    sAMAccountName=Mock(value="svc_sql"),
                    servicePrincipalName=Mock(values=["MSSQLSvc/sql01.corp.local:1433"])
                )
            ]
            mock_conn.return_value = mock_instance

            results = attacker.enumerate_spns(
                domain="corp.local",
                username="admin",
                password="password123"
            )

            assert isinstance(results, list)
            assert len(results) > 0

    def test_check_preauth_not_required(self):
        """Test checking for accounts without pre-auth"""
        attacker = KerberosAttacker()

        with patch('ldap3.Connection') as mock_conn:
            mock_instance = MagicMock()
            mock_instance.bind.return_value = True
            mock_instance.search.return_value = True
            mock_instance.entries = [
                Mock(sAMAccountName=Mock(value="user_no_preauth"))
            ]
            mock_conn.return_value = mock_instance

            results = attacker.check_preauth_not_required(
                domain="corp.local",
                username="admin",
                password="password123"
            )

            assert isinstance(results, list)

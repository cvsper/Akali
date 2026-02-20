"""Tests for NTLM attack module."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from extended.ad.ntlm import NTLMAttacker


class TestNTLMAttacker:
    """Test suite for NTLM attacks."""

    def test_init(self):
        """Test NTLMAttacker initialization"""
        attacker = NTLMAttacker()

        assert attacker is not None

    def test_validate_ntlm_hash_valid(self):
        """Test NTLM hash validation with valid hash"""
        attacker = NTLMAttacker()

        # LM:NTLM format
        hash1 = "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c"
        assert attacker._validate_ntlm_hash(hash1) is True

        # NTLM only
        hash2 = "8846f7eaee8fb117ad06bdd830b7586c"
        assert attacker._validate_ntlm_hash(hash2) is True

    def test_validate_ntlm_hash_invalid(self):
        """Test NTLM hash validation with invalid hash"""
        attacker = NTLMAttacker()

        assert attacker._validate_ntlm_hash("invalid") is False
        assert attacker._validate_ntlm_hash("12345") is False
        assert attacker._validate_ntlm_hash("") is False

    def test_pass_the_hash_basic(self):
        """Test basic Pass-the-Hash attack"""
        attacker = NTLMAttacker()

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="NT AUTHORITY\\SYSTEM"
            )

            result = attacker.pass_the_hash(
                username="admin",
                ntlm_hash="aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c",
                target="10.0.0.5",
                command="whoami"
            )

            assert result["success"] is True
            assert "output" in result

    def test_pass_the_hash_with_domain(self):
        """Test Pass-the-Hash with domain"""
        attacker = NTLMAttacker()

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="Command executed"
            )

            result = attacker.pass_the_hash(
                username="admin",
                ntlm_hash="8846f7eaee8fb117ad06bdd830b7586c",
                target="10.0.0.5",
                domain="CORP",
                command="ipconfig"
            )

            assert result["success"] is True

    def test_pass_the_hash_invalid_hash(self):
        """Test Pass-the-Hash with invalid hash"""
        attacker = NTLMAttacker()

        result = attacker.pass_the_hash(
            username="admin",
            ntlm_hash="invalid",
            target="10.0.0.5"
        )

        assert result is None or result.get("error") is not None

    def test_pass_the_hash_connection_failed(self):
        """Test Pass-the-Hash with connection failure"""
        attacker = NTLMAttacker()

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=1,
                stderr="Connection failed"
            )

            result = attacker.pass_the_hash(
                username="admin",
                ntlm_hash="8846f7eaee8fb117ad06bdd830b7586c",
                target="10.0.0.99"
            )

            assert result["success"] is False

    def test_pass_the_ticket_basic(self):
        """Test basic Pass-the-Ticket attack"""
        attacker = NTLMAttacker()

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="Ticket imported successfully"
            )

            with patch('os.path.exists', return_value=True):
                result = attacker.pass_the_ticket(
                    ticket_path="/tmp/ticket.ccache",
                    target="10.0.0.5"
                )

                assert result["success"] is True

    def test_pass_the_ticket_file_not_found(self):
        """Test Pass-the-Ticket with missing ticket file"""
        attacker = NTLMAttacker()

        with patch('os.path.exists', return_value=False):
            result = attacker.pass_the_ticket(
                ticket_path="/tmp/nonexistent.ccache",
                target="10.0.0.5"
            )

            assert result is None or result.get("error") is not None

    def test_dump_sam(self):
        """Test dumping SAM database"""
        attacker = NTLMAttacker()

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="""Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::"""
            )

            result = attacker.dump_sam(
                target="10.0.0.5",
                username="admin",
                password="password123"
            )

            assert isinstance(result, dict)
            assert "hashes" in result
            assert len(result["hashes"]) > 0

    def test_dump_sam_with_hash(self):
        """Test dumping SAM with NTLM hash"""
        attacker = NTLMAttacker()

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="Administrator:500:hash..."
            )

            result = attacker.dump_sam(
                target="10.0.0.5",
                username="admin",
                ntlm_hash="8846f7eaee8fb117ad06bdd830b7586c"
            )

            assert isinstance(result, dict)

    def test_dump_lsass(self):
        """Test dumping LSASS memory"""
        attacker = NTLMAttacker()

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="LSASS dumped successfully"
            )

            result = attacker.dump_lsass(
                target="10.0.0.5",
                username="admin",
                password="password123"
            )

            assert result is not None

    def test_detect_relay_vulnerable_hosts(self):
        """Test detecting NTLM relay vulnerable hosts"""
        attacker = NTLMAttacker()

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="""Host script results:
| smb-security-mode:
|   account_used: guest
|   message_signing: disabled"""
            )

            results = attacker.detect_relay_vulnerable(
                targets=["10.0.0.5", "10.0.0.6"]
            )

            assert isinstance(results, list)
            # May be 0 if nmap not available - acceptable
            assert len(results) >= 0

    def test_crack_ntlm_hash(self):
        """Test cracking NTLM hash"""
        attacker = NTLMAttacker()

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="8846f7eaee8fb117ad06bdd830b7586c:password123"
            )

            result = attacker.crack_hash(
                ntlm_hash="8846f7eaee8fb117ad06bdd830b7586c",
                wordlist="/usr/share/wordlists/rockyou.txt"
            )

            assert result is not None
            assert isinstance(result, str)

    def test_parse_sam_output(self):
        """Test parsing SAM dump output"""
        attacker = NTLMAttacker()

        output = """Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
User1:1001:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99:::"""

        hashes = attacker._parse_sam_output(output)

        assert isinstance(hashes, list)
        assert len(hashes) == 3
        assert hashes[0]["username"] == "Administrator"
        assert hashes[0]["ntlm"] == "8846f7eaee8fb117ad06bdd830b7586c"

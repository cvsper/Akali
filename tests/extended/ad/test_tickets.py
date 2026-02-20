"""Tests for Kerberos ticket generation module."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from extended.ad.tickets import TicketGenerator


class TestTicketGenerator:
    """Test suite for Kerberos ticket generation."""

    def test_init(self):
        """Test TicketGenerator initialization"""
        generator = TicketGenerator()

        assert generator is not None

    def test_validate_sid_valid(self):
        """Test SID validation with valid SIDs"""
        generator = TicketGenerator()

        # Standard domain SID
        sid1 = "S-1-5-21-1234567890-1234567890-1234567890"
        assert generator._validate_sid(sid1) is True

        # With RID
        sid2 = "S-1-5-21-1234567890-1234567890-1234567890-500"
        assert generator._validate_sid(sid2) is True

    def test_validate_sid_invalid(self):
        """Test SID validation with invalid SIDs"""
        generator = TicketGenerator()

        assert generator._validate_sid("invalid") is False
        assert generator._validate_sid("S-1-5") is False
        assert generator._validate_sid("") is False

    def test_generate_golden_ticket_basic(self):
        """Test basic Golden Ticket generation"""
        generator = TicketGenerator()

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="Ticket saved to /tmp/Administrator.ccache"
            )

            with patch('os.path.exists', return_value=True):
                result = generator.generate_golden_ticket(
                    domain="corp.local",
                    sid="S-1-5-21-1234567890-1234567890-1234567890",
                    krbtgt_hash="8846f7eaee8fb117ad06bdd830b7586c",
                    username="Administrator"
                )

                assert result is not None
                assert isinstance(result, str)
                assert ".ccache" in result

    def test_generate_golden_ticket_with_groups(self):
        """Test Golden Ticket with custom group memberships"""
        generator = TicketGenerator()

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="Ticket created"
            )

            with patch('os.path.exists', return_value=True):
                result = generator.generate_golden_ticket(
                    domain="corp.local",
                    sid="S-1-5-21-1234567890-1234567890-1234567890",
                    krbtgt_hash="8846f7eaee8fb117ad06bdd830b7586c",
                    username="FakeAdmin",
                    groups=[512, 513, 518, 519, 520]  # Enterprise Admins, Domain Admins, etc.
                )

                assert result is not None

    def test_generate_golden_ticket_invalid_sid(self):
        """Test Golden Ticket with invalid SID"""
        generator = TicketGenerator()

        result = generator.generate_golden_ticket(
            domain="corp.local",
            sid="invalid-sid",
            krbtgt_hash="8846f7eaee8fb117ad06bdd830b7586c"
        )

        assert result is None or "error" in str(result).lower()

    def test_generate_silver_ticket_basic(self):
        """Test basic Silver Ticket generation"""
        generator = TicketGenerator()

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="Ticket saved"
            )

            with patch('os.path.exists', return_value=True):
                result = generator.generate_silver_ticket(
                    domain="corp.local",
                    sid="S-1-5-21-1234567890-1234567890-1234567890",
                    service_hash="8846f7eaee8fb117ad06bdd830b7586c",
                    service="CIFS/dc01.corp.local",
                    username="admin"
                )

                assert result is not None
                assert isinstance(result, str)
                assert ".ccache" in result

    def test_generate_silver_ticket_mssql(self):
        """Test Silver Ticket for MSSQL service"""
        generator = TicketGenerator()

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="Ticket created"
            )

            with patch('os.path.exists', return_value=True):
                result = generator.generate_silver_ticket(
                    domain="corp.local",
                    sid="S-1-5-21-1234567890-1234567890-1234567890",
                    service_hash="8846f7eaee8fb117ad06bdd830b7586c",
                    service="MSSQLSvc/sql01.corp.local:1433",
                    username="dba_user"
                )

                assert result is not None

    def test_parse_ticket_info(self):
        """Test parsing ticket information"""
        generator = TicketGenerator()

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="""Ticket cache: FILE:/tmp/ticket.ccache
Default principal: admin@CORP.LOCAL

Valid starting     Expires            Service principal
12/01/26 10:00:00  12/01/26 20:00:00  krbtgt/CORP.LOCAL@CORP.LOCAL"""
            )

            info = generator.parse_ticket_info("/tmp/ticket.ccache")

            assert isinstance(info, dict)
            assert "principal" in info or "valid" in info

    def test_validate_ticket_structure(self):
        """Test validating ticket structure"""
        generator = TicketGenerator()

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="Ticket is valid"
            )

            result = generator.validate_ticket("/tmp/ticket.ccache")

            assert result is not None

    def test_export_ticket_to_kirbi(self):
        """Test exporting ticket to .kirbi format"""
        generator = TicketGenerator()

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="Ticket exported"
            )

            with patch('os.path.exists', return_value=True):
                result = generator.export_to_kirbi(
                    ccache_path="/tmp/ticket.ccache",
                    output_path="/tmp/ticket.kirbi"
                )

                assert result is not None

    def test_import_ticket_from_kirbi(self):
        """Test importing ticket from .kirbi format"""
        generator = TicketGenerator()

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="Ticket imported"
            )

            with patch('os.path.exists', return_value=True):
                result = generator.import_from_kirbi(
                    kirbi_path="/tmp/ticket.kirbi",
                    output_path="/tmp/ticket.ccache"
                )

                assert result is not None

    def test_renew_ticket(self):
        """Test renewing a ticket"""
        generator = TicketGenerator()

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="Ticket renewed"
            )

            result = generator.renew_ticket("/tmp/ticket.ccache")

            assert result is not None

    def test_destroy_ticket(self):
        """Test destroying a ticket"""
        generator = TicketGenerator()

        with patch('os.path.exists', return_value=True):
            with patch('os.remove') as mock_remove:
                result = generator.destroy_ticket("/tmp/ticket.ccache")

                assert result is True
                mock_remove.assert_called_once_with("/tmp/ticket.ccache")

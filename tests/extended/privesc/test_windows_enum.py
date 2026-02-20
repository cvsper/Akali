"""Tests for Windows enumeration module."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from extended.privesc.windows_enum import WindowsEnumerator


class TestWindowsEnumerator:
    """Test suite for WindowsEnumerator class."""

    @pytest.fixture
    def enumerator(self):
        """Create WindowsEnumerator instance."""
        return WindowsEnumerator()

    def test_init(self, enumerator):
        """Test initialization."""
        assert enumerator is not None

    @patch('subprocess.run')
    def test_check_unquoted_service_paths(self, mock_run, enumerator):
        """Test unquoted service path detection."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout='ServiceName: VulnerableService\nPathName: C:\\Program Files\\Vulnerable App\\service.exe\n'
        )

        result = enumerator.check_unquoted_service_paths()
        assert isinstance(result, list)
        if result:
            assert 'service_name' in result[0]
            assert 'path' in result[0]
            assert 'severity' in result[0]

    @patch('subprocess.run')
    def test_check_weak_service_permissions(self, mock_run, enumerator):
        """Test weak service permission detection."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout='SERVICE_ALL_ACCESS\nSERVICE_CHANGE_CONFIG\n'
        )

        result = enumerator.check_weak_service_permissions()
        assert isinstance(result, list)

    @patch('subprocess.run')
    def test_check_always_install_elevated(self, mock_run, enumerator):
        """Test AlwaysInstallElevated registry check."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout='AlwaysInstallElevated    REG_DWORD    0x1\n'
        )

        result = enumerator.check_always_install_elevated()
        assert isinstance(result, dict)
        assert 'enabled' in result
        assert 'severity' in result

    @patch('subprocess.run')
    def test_check_dll_hijacking(self, mock_run, enumerator):
        """Test DLL hijacking opportunity detection."""
        result = enumerator.check_dll_hijacking()
        assert isinstance(result, list)

    @patch('subprocess.run')
    def test_check_scheduled_tasks(self, mock_run, enumerator):
        """Test scheduled task enumeration."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout='TaskName: \\VulnerableTask\nRun As User: SYSTEM\n'
        )

        result = enumerator.check_scheduled_tasks()
        assert isinstance(result, list)

    @patch('subprocess.run')
    def test_check_registry_autoruns(self, mock_run, enumerator):
        """Test registry autorun detection."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout='TestApp    REG_SZ    C:\\test.exe\n'
        )

        result = enumerator.check_registry_autoruns()
        assert isinstance(result, list)

    @patch('subprocess.run')
    def test_find_passwords_in_registry(self, mock_run, enumerator):
        """Test password discovery in registry."""
        result = enumerator.find_passwords_in_registry()
        assert isinstance(result, list)

    @patch('subprocess.run')
    def test_find_passwords_in_files(self, mock_run, enumerator):
        """Test password discovery in files."""
        result = enumerator.find_passwords_in_files()
        assert isinstance(result, list)

    def test_check_token_privileges(self, enumerator):
        """Test token privilege enumeration."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout='SeDebugPrivilege\nSeImpersonatePrivilege\n'
            )
            result = enumerator.check_token_privileges()
            assert isinstance(result, list)

    def test_check_uac_bypass_vectors(self, enumerator):
        """Test UAC bypass vector detection."""
        result = enumerator.check_uac_bypass_vectors()
        assert isinstance(result, list)

    @patch('subprocess.run')
    def test_enumerate_installed_software(self, mock_run, enumerator):
        """Test installed software enumeration."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout='DisplayName    REG_SZ    VulnerableApp 1.0\n'
        )

        result = enumerator.enumerate_installed_software()
        assert isinstance(result, list)

    def test_parse_service_output(self, enumerator):
        """Test service output parsing."""
        output = """SERVICE_NAME: VulnerableService
DISPLAY_NAME: Vulnerable Service
BINARY_PATH_NAME: C:\\Program Files\\App\\service.exe
START_TYPE: AUTO_START
"""
        result = enumerator._parse_service_output(output)
        assert isinstance(result, dict)
        assert result.get('SERVICE_NAME') == 'VulnerableService'

    def test_is_writable_path(self, enumerator):
        """Test writable path detection."""
        with patch('os.access', return_value=True):
            assert enumerator._is_writable_path('C:\\test') is True

    def test_severity_for_privilege(self, enumerator):
        """Test severity calculation for privileges."""
        assert enumerator._severity_for_privilege('SeDebugPrivilege') == 'high'
        assert enumerator._severity_for_privilege('SeChangeNotifyPrivilege') == 'medium'

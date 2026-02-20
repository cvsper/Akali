"""Tests for Linux enumeration module."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from extended.privesc.linux_enum import LinuxEnumerator


class TestLinuxEnumerator:
    """Test suite for LinuxEnumerator class."""

    @pytest.fixture
    def enumerator(self):
        """Create LinuxEnumerator instance."""
        return LinuxEnumerator()

    def test_init(self, enumerator):
        """Test initialization."""
        assert enumerator is not None

    @patch('subprocess.run')
    def test_find_suid_binaries(self, mock_run, enumerator):
        """Test SUID binary discovery."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout='/usr/bin/vim\n/usr/bin/find\n/bin/systemctl\n'
        )

        result = enumerator.find_suid_binaries()
        assert isinstance(result, list)
        if result:
            assert 'path' in result[0]
            assert 'severity' in result[0]
            assert 'exploitable' in result[0]

    @patch('subprocess.run')
    def test_find_sgid_binaries(self, mock_run, enumerator):
        """Test SGID binary discovery."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout='/usr/bin/wall\n/usr/bin/write\n'
        )

        result = enumerator.find_sgid_binaries()
        assert isinstance(result, list)

    @patch('subprocess.run')
    def test_check_sudo_config(self, mock_run, enumerator):
        """Test sudo configuration check."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout='(ALL : ALL) NOPASSWD: /usr/bin/vim\n'
        )

        result = enumerator.check_sudo_config()
        assert isinstance(result, list)
        if result:
            assert 'commands' in result[0]
            assert 'severity' in result[0]

    @patch('subprocess.run')
    def test_check_cron_jobs(self, mock_run, enumerator):
        """Test cron job enumeration."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout='* * * * * root /root/backup.sh\n'
        )

        result = enumerator.check_cron_jobs()
        assert isinstance(result, list)

    @patch('os.access')
    def test_check_writable_etc_files(self, mock_access, enumerator):
        """Test writable /etc file detection."""
        mock_access.return_value = True

        result = enumerator.check_writable_etc_files()
        assert isinstance(result, list)

    @patch('subprocess.run')
    def test_check_docker_escape(self, mock_run, enumerator):
        """Test Docker escape vector detection."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout='privileged\n'
        )

        result = enumerator.check_docker_escape()
        assert isinstance(result, list)

    @patch('subprocess.run')
    def test_check_capabilities(self, mock_run, enumerator):
        """Test Linux capabilities check."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout='/usr/bin/python3 = cap_setuid+ep\n'
        )

        result = enumerator.check_capabilities()
        assert isinstance(result, list)
        if result:
            assert 'binary' in result[0]
            assert 'capabilities' in result[0]

    @patch('subprocess.run')
    def test_check_nfs_exports(self, mock_run, enumerator):
        """Test NFS export misconfiguration check."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout='/home *(rw,no_root_squash)\n'
        )

        result = enumerator.check_nfs_exports()
        assert isinstance(result, list)

    def test_find_passwords_in_history(self, enumerator):
        """Test password discovery in shell history."""
        with patch('pathlib.Path.exists', return_value=True):
            with patch('builtins.open', mock_open(read_data='mysql -u root -pPassword123\n')):
                result = enumerator.find_passwords_in_history()
                assert isinstance(result, list)

    def test_find_passwords_in_config(self, enumerator):
        """Test password discovery in config files."""
        result = enumerator.find_passwords_in_config()
        assert isinstance(result, list)

    def test_check_path_writable(self, enumerator):
        """Test PATH writable directory check."""
        with patch('os.getenv', return_value='/usr/local/bin:/tmp:/usr/bin'):
            with patch('os.access', return_value=True):
                result = enumerator.check_path_writable()
                assert isinstance(result, list)

    @patch('subprocess.run')
    def test_get_kernel_version(self, mock_run, enumerator):
        """Test kernel version retrieval."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout='5.4.0-42-generic\n'
        )

        result = enumerator.get_kernel_version()
        assert isinstance(result, str)
        assert len(result) > 0

    @patch('subprocess.run')
    def test_get_os_release(self, mock_run, enumerator):
        """Test OS release retrieval."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout='Ubuntu 20.04.2 LTS\n'
        )

        result = enumerator.get_os_release()
        assert isinstance(result, str)

    def test_is_suid_exploitable(self, enumerator):
        """Test SUID exploitability check."""
        assert enumerator._is_suid_exploitable('vim') is True
        assert enumerator._is_suid_exploitable('find') is True
        assert enumerator._is_suid_exploitable('ping') is False

    def test_parse_sudo_line(self, enumerator):
        """Test sudo line parsing."""
        line = '(ALL : ALL) NOPASSWD: /usr/bin/vim, /usr/bin/nano'
        result = enumerator._parse_sudo_line(line)
        assert isinstance(result, dict)
        assert result['nopasswd'] is True
        assert len(result['commands']) == 2

    def test_is_dangerous_capability(self, enumerator):
        """Test dangerous capability detection."""
        assert enumerator._is_dangerous_capability('cap_setuid') is True
        assert enumerator._is_dangerous_capability('cap_dac_override') is True
        assert enumerator._is_dangerous_capability('cap_chown') is False


def mock_open(read_data):
    """Helper to create mock file open."""
    from unittest.mock import mock_open as original_mock_open
    return original_mock_open(read_data=read_data)

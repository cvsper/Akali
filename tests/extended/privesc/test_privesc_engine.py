"""Tests for PrivilegeEscalation engine."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import platform

# Import will be available after implementation
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from extended.privesc.privesc_engine import PrivilegeEscalation


class TestPrivilegeEscalation:
    """Test suite for PrivilegeEscalation class."""

    @pytest.fixture
    def privesc(self):
        """Create PrivilegeEscalation instance."""
        return PrivilegeEscalation()

    def test_init(self, privesc):
        """Test initialization."""
        assert privesc is not None
        assert hasattr(privesc, 'enumerate_windows')
        assert hasattr(privesc, 'enumerate_linux')
        assert hasattr(privesc, 'check_kernel_exploits')

    @patch('platform.system', return_value='Windows')
    def test_detect_os_windows(self, mock_system, privesc):
        """Test OS detection returns Windows."""
        result = privesc.detect_os()
        assert result == 'windows'

    @patch('platform.system', return_value='Linux')
    def test_detect_os_linux(self, mock_system, privesc):
        """Test OS detection returns Linux."""
        result = privesc.detect_os()
        assert result == 'linux'

    @patch('platform.system', return_value='Darwin')
    def test_detect_os_macos(self, mock_system, privesc):
        """Test OS detection returns linux for macOS (unix-like)."""
        result = privesc.detect_os()
        assert result == 'linux'

    def test_enumerate_windows_structure(self, privesc):
        """Test enumerate_windows returns expected structure."""
        with patch.object(privesc, '_enumerate_windows_local') as mock_enum:
            mock_enum.return_value = {
                'services': [],
                'scheduled_tasks': [],
                'registry': [],
                'dll_hijacking': [],
                'path_hijacking': [],
                'passwords': [],
                'kernel_exploits': [],
                'uac_bypass': []
            }
            result = privesc.enumerate_windows(local=True)

            assert 'services' in result
            assert 'scheduled_tasks' in result
            assert 'registry' in result
            assert 'dll_hijacking' in result

    def test_enumerate_linux_structure(self, privesc):
        """Test enumerate_linux returns expected structure."""
        with patch.object(privesc, '_enumerate_linux_local') as mock_enum:
            mock_enum.return_value = {
                'suid_binaries': [],
                'sudo_config': [],
                'cron_jobs': [],
                'capabilities': [],
                'docker_escape': [],
                'path_hijacking': [],
                'passwords': [],
                'kernel_exploits': []
            }
            result = privesc.enumerate_linux(local=True)

            assert 'suid_binaries' in result
            assert 'sudo_config' in result
            assert 'cron_jobs' in result
            assert 'capabilities' in result

    def test_enumerate_windows_local_default(self, privesc):
        """Test Windows enumeration defaults to local."""
        with patch.object(privesc, '_enumerate_windows_local') as mock_local:
            mock_local.return_value = {'services': []}
            privesc.enumerate_windows()
            mock_local.assert_called_once()

    def test_enumerate_linux_local_default(self, privesc):
        """Test Linux enumeration defaults to local."""
        with patch.object(privesc, '_enumerate_linux_local') as mock_local:
            mock_local.return_value = {'suid_binaries': []}
            privesc.enumerate_linux()
            mock_local.assert_called_once()

    def test_check_kernel_exploits_windows(self, privesc):
        """Test kernel exploit check for Windows."""
        with patch.object(privesc, '_load_kernel_db') as mock_load:
            mock_load.return_value = {
                'windows': [
                    {
                        'cve': 'CVE-2021-1732',
                        'name': 'Win32k Elevation of Privilege',
                        'versions': ['Windows 10 1809-2004'],
                        'severity': 'high'
                    }
                ]
            }
            result = privesc.check_kernel_exploits('windows', 'Windows 10 1909')
            assert isinstance(result, list)
            assert len(result) > 0
            assert result[0]['cve'] == 'CVE-2021-1732'

    def test_check_kernel_exploits_linux(self, privesc):
        """Test kernel exploit check for Linux."""
        with patch.object(privesc, '_load_kernel_db') as mock_load:
            mock_load.return_value = {
                'linux': [
                    {
                        'cve': 'CVE-2021-3493',
                        'name': 'OverlayFS Ubuntu Kernel Exploit',
                        'versions': ['Ubuntu 20.04'],
                        'severity': 'high'
                    }
                ]
            }
            result = privesc.check_kernel_exploits('linux', 'Ubuntu 20.04')
            assert isinstance(result, list)
            assert len(result) > 0
            assert result[0]['cve'] == 'CVE-2021-3493'

    def test_check_kernel_exploits_no_match(self, privesc):
        """Test kernel exploit check with no matches."""
        with patch.object(privesc.kernel_db, '_load_database') as mock_load:
            mock_load.return_value = {'windows': [], 'linux': []}
            result = privesc.check_kernel_exploits('windows', 'Windows 99')
            assert isinstance(result, list)
            assert len(result) == 0

    def test_exploit_service_permissions_windows(self, privesc):
        """Test Windows service permission exploitation."""
        result = privesc.exploit_service_permissions(
            'VulnerableService',
            'C:\\payload.exe'
        )
        assert 'success' in result
        assert 'message' in result
        assert isinstance(result['success'], bool)

    def test_exploit_suid_binary_linux(self, privesc):
        """Test SUID binary exploitation."""
        result = privesc.exploit_suid_binary(
            '/usr/bin/vim',
            '!/bin/bash'
        )
        assert 'success' in result
        assert 'message' in result
        assert isinstance(result['success'], bool)

    def test_check_sudo_misconfig(self, privesc):
        """Test sudo misconfiguration check."""
        with patch.object(privesc.linux_enum, 'check_sudo_config') as mock_sudo:
            mock_sudo.return_value = [
                {
                    'user': 'testuser',
                    'host': 'ALL',
                    'runas': 'ALL',
                    'nopasswd': True,
                    'commands': ['/usr/bin/vim'],
                    'severity': 'high',
                    'description': 'vim can be used to escape to shell'
                }
            ]
            result = privesc.check_sudo_misconfig()
            assert isinstance(result, list)
            assert len(result) > 0
            assert result[0]['severity'] == 'high'

    def test_check_path_hijacking(self, privesc):
        """Test PATH hijacking check."""
        with patch.object(privesc.linux_enum, 'check_path_writable') as mock_paths:
            mock_paths.return_value = [
                {
                    'path': '/tmp',
                    'writable': True,
                    'in_path': True,
                    'priority': 5,
                    'severity': 'medium',
                    'description': 'Writable directory in PATH'
                }
            ]
            result = privesc.check_path_hijacking()
            assert isinstance(result, list)
            assert len(result) > 0
            assert result[0]['writable'] is True

    def test_export_results_json(self, privesc, tmp_path):
        """Test exporting results to JSON."""
        results = {
            'services': [{'name': 'test', 'severity': 'high'}],
            'sudo_config': []
        }
        output_file = tmp_path / "results.json"

        success = privesc.export_results(results, str(output_file), format='json')
        assert success is True
        assert output_file.exists()

    def test_export_results_html(self, privesc, tmp_path):
        """Test exporting results to HTML."""
        results = {
            'services': [{'name': 'test', 'severity': 'high'}],
            'sudo_config': []
        }
        output_file = tmp_path / "results.html"

        success = privesc.export_results(results, str(output_file), format='html')
        assert success is True
        assert output_file.exists()

    def test_categorize_severity(self, privesc):
        """Test severity categorization."""
        assert privesc.categorize_severity('kernel_exploit') == 'critical'
        assert privesc.categorize_severity('suid_root') == 'high'
        assert privesc.categorize_severity('writable_path') == 'medium'
        assert privesc.categorize_severity('password_file') == 'low'

    def test_auto_enumerate(self, privesc):
        """Test auto-enumeration based on detected OS."""
        with patch.object(privesc, 'detect_os', return_value='linux'):
            with patch.object(privesc, 'enumerate_linux') as mock_linux:
                mock_linux.return_value = {'suid_binaries': []}
                result = privesc.auto_enumerate()
                mock_linux.assert_called_once()
                assert 'suid_binaries' in result

"""Windows privilege escalation enumeration."""

import subprocess
import os
import re
from pathlib import Path
from typing import List, Dict, Optional


class WindowsEnumerator:
    """Windows privilege escalation enumeration."""

    def __init__(self):
        """Initialize Windows enumerator."""
        self.dangerous_privileges = [
            'SeDebugPrivilege',
            'SeImpersonatePrivilege',
            'SeAssignPrimaryTokenPrivilege',
            'SeLoadDriverPrivilege',
            'SeRestorePrivilege',
            'SeBackupPrivilege',
            'SeTakeOwnershipPrivilege',
            'SeCreateTokenPrivilege'
        ]

        self.exploitable_suid_binaries = [
            'vim', 'find', 'nano', 'less', 'more', 'cp', 'mv',
            'python', 'perl', 'ruby', 'node', 'php', 'bash', 'sh'
        ]

    def check_unquoted_service_paths(self) -> List[Dict]:
        """Check for unquoted service paths with spaces.

        Returns:
            List of vulnerable services
        """
        vulnerabilities = []

        try:
            # Use wmic to enumerate services
            result = subprocess.run(
                ['wmic', 'service', 'get', 'name,pathname'],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                return vulnerabilities

            for line in result.stdout.split('\n'):
                line = line.strip()
                if not line or 'Name' in line or 'PathName' in line:
                    continue

                # Parse service line
                parts = line.split()
                if len(parts) < 2:
                    continue

                service_name = parts[0]
                path = ' '.join(parts[1:])

                # Check for unquoted path with spaces
                if ' ' in path and not path.startswith('"') and path.endswith('.exe'):
                    # Check if directory is writable
                    dir_path = str(Path(path).parent)

                    vulnerabilities.append({
                        'service_name': service_name,
                        'path': path,
                        'directory': dir_path,
                        'writable': self._is_writable_path(dir_path),
                        'severity': 'high',
                        'description': f'Unquoted service path with spaces'
                    })

        except Exception:
            pass

        return vulnerabilities

    def check_weak_service_permissions(self) -> List[Dict]:
        """Check for services with weak permissions.

        Returns:
            List of services with weak permissions
        """
        vulnerabilities = []

        try:
            # Get list of services
            result = subprocess.run(
                ['sc', 'query', 'state=', 'all'],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                return vulnerabilities

            # Parse service names
            service_names = []
            for line in result.stdout.split('\n'):
                if 'SERVICE_NAME:' in line:
                    service_name = line.split('SERVICE_NAME:')[1].strip()
                    service_names.append(service_name)

            # Check permissions for each service (limit to first 50)
            for service_name in service_names[:50]:
                try:
                    perm_result = subprocess.run(
                        ['sc', 'sdshow', service_name],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )

                    if perm_result.returncode == 0:
                        sddl = perm_result.stdout.strip()

                        # Check for dangerous permissions (Everyone, Authenticated Users)
                        if 'WD' in sddl or 'AU' in sddl:
                            vulnerabilities.append({
                                'service_name': service_name,
                                'permissions': sddl,
                                'severity': 'high',
                                'description': 'Service modifiable by low-privilege users'
                            })

                except Exception:
                    continue

        except Exception:
            pass

        return vulnerabilities

    def check_always_install_elevated(self) -> Dict:
        """Check if AlwaysInstallElevated is enabled.

        Returns:
            Dictionary with status and severity
        """
        result = {
            'enabled': False,
            'hklm': False,
            'hkcu': False,
            'severity': 'none'
        }

        try:
            # Check HKLM
            hklm_result = subprocess.run(
                ['reg', 'query', 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer',
                 '/v', 'AlwaysInstallElevated'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if hklm_result.returncode == 0 and '0x1' in hklm_result.stdout:
                result['hklm'] = True

            # Check HKCU
            hkcu_result = subprocess.run(
                ['reg', 'query', 'HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer',
                 '/v', 'AlwaysInstallElevated'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if hkcu_result.returncode == 0 and '0x1' in hkcu_result.stdout:
                result['hkcu'] = True

            # Both must be enabled
            if result['hklm'] and result['hkcu']:
                result['enabled'] = True
                result['severity'] = 'high'
                result['description'] = 'MSI packages install with SYSTEM privileges'

        except Exception:
            pass

        return result

    def check_dll_hijacking(self) -> List[Dict]:
        """Check for DLL hijacking opportunities.

        Returns:
            List of potential DLL hijacking opportunities
        """
        opportunities = []

        try:
            # Check common application directories
            common_dirs = [
                'C:\\Program Files',
                'C:\\Program Files (x86)'
            ]

            for base_dir in common_dirs:
                if not os.path.exists(base_dir):
                    continue

                # Check writable directories (limit depth)
                try:
                    for root, dirs, files in os.walk(base_dir):
                        # Limit depth
                        depth = root[len(base_dir):].count(os.sep)
                        if depth > 2:
                            continue

                        if self._is_writable_path(root):
                            opportunities.append({
                                'directory': root,
                                'writable': True,
                                'severity': 'medium',
                                'description': f'Writable application directory: {root}'
                            })

                except Exception:
                    continue

        except Exception:
            pass

        return opportunities[:20]  # Limit results

    def check_scheduled_tasks(self) -> List[Dict]:
        """Enumerate scheduled tasks running with high privileges.

        Returns:
            List of high-privilege scheduled tasks
        """
        tasks = []

        try:
            result = subprocess.run(
                ['schtasks', '/query', '/fo', 'LIST', '/v'],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                return tasks

            current_task = {}
            for line in result.stdout.split('\n'):
                line = line.strip()

                if 'TaskName:' in line:
                    if current_task:
                        tasks.append(current_task)
                    current_task = {'task_name': line.split('TaskName:')[1].strip()}

                elif 'Run As User:' in line:
                    run_as = line.split('Run As User:')[1].strip()
                    current_task['run_as'] = run_as

                    # Check for high-privilege accounts
                    if any(x in run_as.upper() for x in ['SYSTEM', 'ADMINISTRATOR']):
                        current_task['severity'] = 'medium'
                        current_task['description'] = f'Task runs as {run_as}'

            if current_task:
                tasks.append(current_task)

        except Exception:
            pass

        return [t for t in tasks if 'severity' in t]

    def check_registry_autoruns(self) -> List[Dict]:
        """Check registry autorun locations.

        Returns:
            List of autorun entries
        """
        autoruns = []

        autorun_keys = [
            'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
            'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
            'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
            'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
        ]

        for key in autorun_keys:
            try:
                result = subprocess.run(
                    ['reg', 'query', key],
                    capture_output=True,
                    text=True,
                    timeout=5
                )

                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        line = line.strip()
                        if 'REG_SZ' in line or 'REG_EXPAND_SZ' in line:
                            parts = line.split()
                            if len(parts) >= 3:
                                name = parts[0]
                                path = ' '.join(parts[2:])

                                # Check if path is writable
                                writable = False
                                try:
                                    file_path = path.split()[0].strip('"')
                                    if os.path.exists(file_path):
                                        writable = os.access(file_path, os.W_OK)
                                except Exception:
                                    pass

                                autoruns.append({
                                    'key': key,
                                    'name': name,
                                    'path': path,
                                    'writable': writable,
                                    'severity': 'medium' if writable else 'low',
                                    'description': f'Autorun entry in {key}'
                                })

            except Exception:
                continue

        return autoruns

    def find_passwords_in_registry(self) -> List[Dict]:
        """Search for passwords in registry.

        Returns:
            List of potential password locations
        """
        passwords = []

        search_keys = [
            'HKCU\\Software\\SimonTatham\\PuTTY\\Sessions',
            'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon'
        ]

        for key in search_keys:
            try:
                result = subprocess.run(
                    ['reg', 'query', key, '/s'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                if result.returncode == 0:
                    # Look for password-related keys
                    for line in result.stdout.split('\n'):
                        if any(word in line.lower() for word in ['password', 'passwd', 'pwd']):
                            passwords.append({
                                'location': key,
                                'content': line.strip(),
                                'severity': 'medium',
                                'description': 'Potential password in registry'
                            })

            except Exception:
                continue

        return passwords

    def find_passwords_in_files(self) -> List[Dict]:
        """Search for passwords in common file locations.

        Returns:
            List of files with potential passwords
        """
        passwords = []

        search_paths = [
            os.path.expanduser('~\\AppData\\Roaming'),
            'C:\\Windows\\Panther',
            'C:\\inetpub\\wwwroot'
        ]

        search_patterns = [
            '*.xml',
            '*.config',
            '*.ini',
            '*.txt',
            'unattend.xml',
            'sysprep.inf'
        ]

        for base_path in search_paths:
            if not os.path.exists(base_path):
                continue

            try:
                for root, dirs, files in os.walk(base_path):
                    # Limit depth
                    depth = root[len(base_path):].count(os.sep)
                    if depth > 3:
                        continue

                    for file in files[:50]:  # Limit files per directory
                        if any(file.endswith(p.replace('*', '')) for p in search_patterns):
                            full_path = os.path.join(root, file)
                            passwords.append({
                                'file': full_path,
                                'severity': 'low',
                                'description': 'File may contain credentials'
                            })

            except Exception:
                continue

        return passwords[:50]  # Limit results

    def check_token_privileges(self) -> List[Dict]:
        """Check current token privileges.

        Returns:
            List of enabled privileges
        """
        privileges = []

        try:
            result = subprocess.run(
                ['whoami', '/priv'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                return privileges

            for line in result.stdout.split('\n'):
                line = line.strip()

                for priv in self.dangerous_privileges:
                    if priv in line and 'Enabled' in line:
                        privileges.append({
                            'privilege': priv,
                            'enabled': True,
                            'severity': self._severity_for_privilege(priv),
                            'description': f'Dangerous privilege {priv} is enabled'
                        })

        except Exception:
            pass

        return privileges

    def check_uac_bypass_vectors(self) -> List[Dict]:
        """Check for UAC bypass vectors.

        Returns:
            List of potential UAC bypass opportunities
        """
        vectors = []

        try:
            # Check UAC level
            result = subprocess.run(
                ['reg', 'query', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',
                 '/v', 'EnableLUA'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                if '0x0' in result.stdout:
                    vectors.append({
                        'type': 'uac_disabled',
                        'severity': 'critical',
                        'description': 'UAC is completely disabled'
                    })
                elif '0x1' in result.stdout:
                    # Check ConsentPromptBehaviorAdmin
                    consent_result = subprocess.run(
                        ['reg', 'query', 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System',
                         '/v', 'ConsentPromptBehaviorAdmin'],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )

                    if consent_result.returncode == 0 and '0x0' in consent_result.stdout:
                        vectors.append({
                            'type': 'uac_no_prompt',
                            'severity': 'high',
                            'description': 'UAC enabled but no admin prompt'
                        })

        except Exception:
            pass

        return vectors

    def enumerate_installed_software(self) -> List[Dict]:
        """Enumerate installed software.

        Returns:
            List of installed software
        """
        software = []

        reg_paths = [
            'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall',
            'HKLM\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall'
        ]

        for reg_path in reg_paths:
            try:
                result = subprocess.run(
                    ['reg', 'query', reg_path, '/s'],
                    capture_output=True,
                    text=True,
                    timeout=15
                )

                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'DisplayName' in line and 'REG_SZ' in line:
                            parts = line.split('REG_SZ')
                            if len(parts) >= 2:
                                name = parts[1].strip()
                                software.append({
                                    'name': name,
                                    'severity': 'info',
                                    'description': 'Installed software'
                                })

            except Exception:
                continue

        return software[:100]  # Limit results

    def _parse_service_output(self, output: str) -> Dict:
        """Parse service query output.

        Args:
            output: Service query output

        Returns:
            Parsed service information
        """
        service_info = {}

        for line in output.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                service_info[key.strip()] = value.strip()

        return service_info

    def _is_writable_path(self, path: str) -> bool:
        """Check if path is writable.

        Args:
            path: Path to check

        Returns:
            True if writable
        """
        try:
            return os.access(path, os.W_OK)
        except Exception:
            return False

    def _severity_for_privilege(self, privilege: str) -> str:
        """Get severity level for privilege.

        Args:
            privilege: Privilege name

        Returns:
            Severity level
        """
        high_severity = [
            'SeDebugPrivilege',
            'SeImpersonatePrivilege',
            'SeAssignPrimaryTokenPrivilege',
            'SeLoadDriverPrivilege'
        ]

        if privilege in high_severity:
            return 'high'
        return 'medium'

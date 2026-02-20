"""Linux privilege escalation enumeration."""

import subprocess
import os
import re
from pathlib import Path
from typing import List, Dict, Optional


class LinuxEnumerator:
    """Linux privilege escalation enumeration."""

    def __init__(self):
        """Initialize Linux enumerator."""
        self.exploitable_suid_binaries = [
            'vim', 'vi', 'find', 'nano', 'less', 'more', 'cp', 'mv', 'cat',
            'python', 'python2', 'python3', 'perl', 'ruby', 'node', 'php',
            'bash', 'sh', 'ash', 'csh', 'ksh', 'zsh', 'awk', 'sed',
            'systemctl', 'journalctl', 'git', 'tar', 'zip', 'unzip',
            'docker', 'kubectl', 'nmap', 'tcpdump', 'wireshark'
        ]

        self.dangerous_capabilities = [
            'cap_setuid', 'cap_setgid', 'cap_dac_override', 'cap_dac_read_search',
            'cap_sys_admin', 'cap_sys_ptrace', 'cap_sys_module', 'cap_net_raw'
        ]

    def find_suid_binaries(self) -> List[Dict]:
        """Find SUID binaries on the system.

        Returns:
            List of SUID binaries with exploitation info
        """
        binaries = []

        try:
            result = subprocess.run(
                ['find', '/', '-perm', '-4000', '-type', 'f', '2>/dev/null'],
                capture_output=True,
                text=True,
                timeout=60,
                shell=True
            )

            if result.returncode != 0:
                return binaries

            for line in result.stdout.split('\n'):
                path = line.strip()
                if not path:
                    continue

                binary_name = os.path.basename(path)
                exploitable = self._is_suid_exploitable(binary_name)

                binaries.append({
                    'path': path,
                    'binary': binary_name,
                    'exploitable': exploitable,
                    'severity': 'high' if exploitable else 'medium',
                    'description': f'SUID binary: {path}' + (' (exploitable)' if exploitable else '')
                })

        except Exception:
            pass

        return binaries

    def find_sgid_binaries(self) -> List[Dict]:
        """Find SGID binaries on the system.

        Returns:
            List of SGID binaries
        """
        binaries = []

        try:
            result = subprocess.run(
                ['find', '/', '-perm', '-2000', '-type', 'f', '2>/dev/null'],
                capture_output=True,
                text=True,
                timeout=60,
                shell=True
            )

            if result.returncode != 0:
                return binaries

            for line in result.stdout.split('\n'):
                path = line.strip()
                if not path:
                    continue

                binaries.append({
                    'path': path,
                    'binary': os.path.basename(path),
                    'severity': 'low',
                    'description': f'SGID binary: {path}'
                })

        except Exception:
            pass

        return binaries

    def check_sudo_config(self) -> List[Dict]:
        """Check sudo configuration for misconfigurations.

        Returns:
            List of sudo misconfigurations
        """
        misconfigs = []

        try:
            result = subprocess.run(
                ['sudo', '-l'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                return misconfigs

            for line in result.stdout.split('\n'):
                line = line.strip()
                if not line or line.startswith('User') or line.startswith('Matching'):
                    continue

                # Parse sudo rules
                if '(' in line and ')' in line:
                    parsed = self._parse_sudo_line(line)
                    if parsed:
                        # Check for dangerous combinations
                        severity = 'low'
                        if parsed.get('nopasswd'):
                            severity = 'medium'

                        # Check for exploitable commands
                        for cmd in parsed.get('commands', []):
                            cmd_base = os.path.basename(cmd.split()[0])
                            if cmd_base in self.exploitable_suid_binaries:
                                severity = 'high'
                                parsed['exploitable_command'] = cmd_base
                                break

                        parsed['severity'] = severity
                        misconfigs.append(parsed)

        except Exception:
            pass

        return misconfigs

    def check_cron_jobs(self) -> List[Dict]:
        """Enumerate cron jobs.

        Returns:
            List of cron jobs
        """
        cron_jobs = []

        cron_locations = [
            '/etc/crontab',
            '/etc/cron.d',
            '/var/spool/cron/crontabs'
        ]

        for location in cron_locations:
            try:
                if os.path.isfile(location):
                    with open(location, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                cron_jobs.append({
                                    'source': location,
                                    'entry': line,
                                    'severity': 'low',
                                    'description': f'Cron job in {location}'
                                })

                elif os.path.isdir(location):
                    for file in os.listdir(location):
                        file_path = os.path.join(location, file)
                        if os.path.isfile(file_path):
                            try:
                                with open(file_path, 'r') as f:
                                    for line in f:
                                        line = line.strip()
                                        if line and not line.startswith('#'):
                                            cron_jobs.append({
                                                'source': file_path,
                                                'entry': line,
                                                'severity': 'low',
                                                'description': f'Cron job in {file_path}'
                                            })
                            except Exception:
                                continue

            except Exception:
                continue

        return cron_jobs

    def check_writable_etc_files(self) -> List[Dict]:
        """Check for writable /etc files.

        Returns:
            List of writable /etc files
        """
        writable_files = []

        important_files = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/sudoers',
            '/etc/hosts',
            '/etc/crontab'
        ]

        for file_path in important_files:
            try:
                if os.path.exists(file_path) and os.access(file_path, os.W_OK):
                    writable_files.append({
                        'file': file_path,
                        'writable': True,
                        'severity': 'critical',
                        'description': f'Critical file {file_path} is writable'
                    })
            except Exception:
                continue

        return writable_files

    def check_docker_escape(self) -> List[Dict]:
        """Check for Docker escape vectors.

        Returns:
            List of Docker escape opportunities
        """
        vectors = []

        try:
            # Check if in Docker container
            if os.path.exists('/.dockerenv') or os.path.exists('/run/.containerenv'):
                vectors.append({
                    'type': 'in_container',
                    'severity': 'info',
                    'description': 'Running inside a container'
                })

                # Check for privileged container
                try:
                    with open('/proc/self/status', 'r') as f:
                        status = f.read()
                        if 'CapEff:	0000003fffffffff' in status or 'CapEff:	0000001fffffffff' in status:
                            vectors.append({
                                'type': 'privileged_container',
                                'severity': 'high',
                                'description': 'Running in privileged container'
                            })
                except Exception:
                    pass

                # Check for Docker socket
                if os.path.exists('/var/run/docker.sock'):
                    vectors.append({
                        'type': 'docker_socket',
                        'path': '/var/run/docker.sock',
                        'severity': 'critical',
                        'description': 'Docker socket accessible from container'
                    })

        except Exception:
            pass

        # Check if user in docker group
        try:
            result = subprocess.run(
                ['groups'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0 and 'docker' in result.stdout:
                vectors.append({
                    'type': 'docker_group',
                    'severity': 'high',
                    'description': 'User is member of docker group'
                })

        except Exception:
            pass

        return vectors

    def check_capabilities(self) -> List[Dict]:
        """Check for Linux capabilities on binaries.

        Returns:
            List of binaries with capabilities
        """
        capabilities = []

        try:
            result = subprocess.run(
                ['getcap', '-r', '/', '2>/dev/null'],
                capture_output=True,
                text=True,
                timeout=60,
                shell=True
            )

            if result.returncode != 0:
                return capabilities

            for line in result.stdout.split('\n'):
                line = line.strip()
                if not line or '=' not in line:
                    continue

                parts = line.split('=')
                if len(parts) >= 2:
                    binary = parts[0].strip()
                    caps = parts[1].strip()

                    # Check for dangerous capabilities
                    dangerous = any(cap in caps for cap in self.dangerous_capabilities)

                    capabilities.append({
                        'binary': binary,
                        'capabilities': caps,
                        'dangerous': dangerous,
                        'severity': 'high' if dangerous else 'low',
                        'description': f'{binary} has capabilities: {caps}'
                    })

        except Exception:
            pass

        return capabilities

    def check_nfs_exports(self) -> List[Dict]:
        """Check NFS exports for misconfigurations.

        Returns:
            List of NFS misconfigurations
        """
        misconfigs = []

        try:
            if not os.path.exists('/etc/exports'):
                return misconfigs

            with open('/etc/exports', 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    # Check for no_root_squash
                    if 'no_root_squash' in line:
                        misconfigs.append({
                            'export': line,
                            'severity': 'high',
                            'description': 'NFS export with no_root_squash'
                        })

        except Exception:
            pass

        return misconfigs

    def find_passwords_in_history(self) -> List[Dict]:
        """Search for passwords in shell history files.

        Returns:
            List of potential password locations
        """
        passwords = []

        history_files = [
            '~/.bash_history',
            '~/.zsh_history',
            '~/.sh_history',
            '~/.mysql_history',
            '~/.psql_history'
        ]

        password_patterns = [
            r'password\s*=\s*[\'"]?(\S+)',
            r'-p\s*[\'"]?(\S+)',
            r'--password[=\s]+[\'"]?(\S+)',
            r'mysql.*-p\s*(\S+)',
            r'psql.*password\s*(\S+)'
        ]

        for history_file in history_files:
            try:
                history_path = os.path.expanduser(history_file)
                if not os.path.exists(history_path):
                    continue

                with open(history_path, 'r', errors='ignore') as f:
                    for i, line in enumerate(f):
                        for pattern in password_patterns:
                            if re.search(pattern, line, re.IGNORECASE):
                                passwords.append({
                                    'file': history_file,
                                    'line': i + 1,
                                    'severity': 'medium',
                                    'description': 'Potential password in history'
                                })
                                break

            except Exception:
                continue

        return passwords

    def find_passwords_in_config(self) -> List[Dict]:
        """Search for passwords in config files.

        Returns:
            List of config files with potential passwords
        """
        passwords = []

        config_locations = [
            '~/.ssh',
            '~/.config',
            '/etc',
            '/var/www'
        ]

        config_patterns = ['*.conf', '*.config', '*.ini', '*.xml', '*.json', '*.yml', '*.yaml']

        for location in config_locations:
            try:
                location = os.path.expanduser(location)
                if not os.path.exists(location):
                    continue

                for root, dirs, files in os.walk(location):
                    # Limit depth
                    depth = root[len(location):].count(os.sep)
                    if depth > 3:
                        continue

                    for file in files[:50]:  # Limit files per directory
                        if any(file.endswith(p.replace('*', '')) for p in config_patterns):
                            full_path = os.path.join(root, file)
                            passwords.append({
                                'file': full_path,
                                'severity': 'low',
                                'description': 'Config file may contain credentials'
                            })

            except Exception:
                continue

        return passwords[:50]  # Limit results

    def check_path_writable(self) -> List[Dict]:
        """Check for writable directories in PATH.

        Returns:
            List of writable PATH directories
        """
        writable_paths = []

        try:
            path_env = os.getenv('PATH', '')
            paths = path_env.split(':')

            for i, path in enumerate(paths):
                if not path:
                    continue

                try:
                    if os.path.exists(path) and os.access(path, os.W_OK):
                        writable_paths.append({
                            'path': path,
                            'writable': True,
                            'priority': i,
                            'severity': 'high' if i < 5 else 'medium',
                            'description': f'Writable directory in PATH: {path}'
                        })
                except Exception:
                    continue

        except Exception:
            pass

        return writable_paths

    def get_kernel_version(self) -> str:
        """Get kernel version.

        Returns:
            Kernel version string
        """
        try:
            result = subprocess.run(
                ['uname', '-r'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                return result.stdout.strip()

        except Exception:
            pass

        return ''

    def get_os_release(self) -> str:
        """Get OS release information.

        Returns:
            OS release string
        """
        try:
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release', 'r') as f:
                    for line in f:
                        if line.startswith('PRETTY_NAME='):
                            return line.split('=')[1].strip().strip('"')

            result = subprocess.run(
                ['lsb_release', '-d'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                return result.stdout.split(':')[1].strip()

        except Exception:
            pass

        return ''

    def _is_suid_exploitable(self, binary_name: str) -> bool:
        """Check if SUID binary is exploitable.

        Args:
            binary_name: Binary name

        Returns:
            True if exploitable
        """
        return binary_name in self.exploitable_suid_binaries

    def _parse_sudo_line(self, line: str) -> Optional[Dict]:
        """Parse sudo configuration line.

        Args:
            line: Sudo line to parse

        Returns:
            Parsed sudo rule or None
        """
        try:
            # Example: (ALL : ALL) NOPASSWD: /usr/bin/vim, /usr/bin/nano
            result = {
                'raw': line,
                'nopasswd': 'NOPASSWD:' in line,
                'commands': []
            }

            # Extract commands after NOPASSWD: or last )
            if 'NOPASSWD:' in line:
                commands_part = line.split('NOPASSWD:')[1]
            elif ')' in line:
                commands_part = line.split(')')[-1]
            else:
                return None

            # Parse commands
            commands = [cmd.strip() for cmd in commands_part.split(',')]
            result['commands'] = commands

            # Extract runas info
            if '(' in line and ')' in line:
                runas = line[line.find('(')+1:line.find(')')]
                result['runas'] = runas

            return result

        except Exception:
            return None

    def _is_dangerous_capability(self, capability: str) -> bool:
        """Check if capability is dangerous.

        Args:
            capability: Capability name

        Returns:
            True if dangerous
        """
        return any(cap in capability.lower() for cap in self.dangerous_capabilities)

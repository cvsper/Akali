"""IoT firmware extractor and analyzer."""

import subprocess
import re
from pathlib import Path
from typing import List, Dict, Literal


SecurityLevel = Literal["low", "medium", "high", "critical"]


class FirmwareExtractor:
    """Firmware extraction and security analysis"""

    # Common secret patterns
    SECRET_PATTERNS = [
        (r'password\s*[=:]\s*["\']?([^"\'\s]+)', 'password'),
        (r'api[_-]?key\s*[=:]\s*["\']?([^"\'\s]+)', 'api_key'),
        (r'secret\s*[=:]\s*["\']?([^"\'\s]+)', 'secret'),
        (r'token\s*[=:]\s*["\']?([^"\'\s]+)', 'token'),
        (r'private[_-]?key\s*[=:]\s*["\']?([^"\'\s]+)', 'private_key'),
    ]

    # Credential patterns
    CREDENTIAL_PATTERNS = [
        (r'(\w+):(\w+)@', 'user:pass@host'),
        (r'username\s*[=:]\s*["\']?(\w+)', 'username'),
        (r'passwd\s*[=:]\s*["\']?([^"\'\s]+)', 'password'),
        (r'user\s*[=:]\s*["\']?(\w+)', 'user'),
    ]

    def extract_firmware(self, firmware_path: Path) -> Dict:
        """Extract firmware using binwalk"""
        if not firmware_path.exists():
            return {
                'success': False,
                'filesystems': [],
                'output_dir': None,
                'error': 'File not found'
            }

        try:
            # Use binwalk for extraction
            output_dir = Path("/tmp/akali/firmware") / firmware_path.stem
            output_dir.mkdir(parents=True, exist_ok=True)

            cmd = [
                'binwalk',
                '-e',  # Extract
                '-C', str(output_dir),  # Output directory
                str(firmware_path)
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            # Parse binwalk output for filesystem types
            filesystems = []
            for line in result.stdout.split('\n'):
                if any(fs in line.lower() for fs in ['squashfs', 'cramfs', 'jffs2', 'ext2', 'ext3', 'ext4']):
                    filesystems.append(line.strip())

            return {
                'success': result.returncode == 0,
                'filesystems': filesystems,
                'output_dir': output_dir if output_dir.exists() else None,
                'stdout': result.stdout
            }

        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            return {
                'success': False,
                'filesystems': [],
                'output_dir': None,
                'error': str(e)
            }

    def scan_secrets(
        self,
        search_path: Path,
        patterns: List[str] = None
    ) -> List[Dict]:
        """Scan for secrets in extracted firmware"""
        if not search_path.exists():
            return []

        secrets = []
        patterns_to_use = patterns or [p[1] for p in self.SECRET_PATTERNS]

        try:
            # Use grep to search for patterns
            for pattern_regex, pattern_name in self.SECRET_PATTERNS:
                if pattern_name not in patterns_to_use:
                    continue

                cmd = [
                    'grep',
                    '-r',  # Recursive
                    '-i',  # Case insensitive
                    '-E',  # Extended regex
                    pattern_regex,
                    str(search_path)
                ]

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if result.returncode == 0 and result.stdout:
                    for line in result.stdout.split('\n')[:10]:  # Limit results
                        if line:
                            secrets.append({
                                'type': pattern_name,
                                'match': line.split(':', 2)[-1].strip()[:100]  # Limit length
                            })

            return secrets

        except (subprocess.TimeoutExpired, Exception):
            return []

    def find_credentials(self, content: str) -> List[Dict]:
        """Find hardcoded credentials in content"""
        credentials = []

        for pattern_regex, pattern_type in self.CREDENTIAL_PATTERNS:
            matches = re.finditer(pattern_regex, content, re.IGNORECASE)
            for match in matches:
                credentials.append({
                    'pattern': pattern_type,
                    'match': match.group(0),
                    'value': match.group(1) if match.groups() else match.group(0)
                })

        return credentials

    def assess_security(
        self,
        has_secrets: bool,
        has_credentials: bool,
        encryption_found: bool
    ) -> Dict:
        """Assess firmware security"""
        risks = []

        if has_secrets:
            risks.append("Hardcoded secrets found")

        if has_credentials:
            risks.append("Hardcoded credentials found")

        if not encryption_found:
            risks.append("No encryption detected")

        # Determine security level
        if has_secrets and has_credentials and not encryption_found:
            level: SecurityLevel = "critical"
        elif has_secrets or has_credentials:
            level = "high"
        elif not encryption_found:
            level = "medium"
        else:
            level = "low"

        return {
            'level': level,
            'risks': risks,
            'has_secrets': has_secrets,
            'has_credentials': has_credentials,
            'encryption_found': encryption_found
        }

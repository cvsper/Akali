"""CoAP protocol analyzer and security tester."""

import socket
from typing import List, Dict, Literal


SecurityLevel = Literal["good", "moderate", "weak", "critical"]


class CoAPAnalyzer:
    """CoAP server analyzer and security tester"""

    # Well-known CoAP resource discovery endpoint
    WELL_KNOWN_CORE = "/.well-known/core"

    # Common CoAP resources to probe
    COMMON_RESOURCES = [
        "/",
        "/.well-known/core",
        "/sensors",
        "/actuators",
        "/light",
        "/temp",
        "/humidity"
    ]

    def probe_server(
        self,
        server: str,
        port: int = 5683,
        timeout: int = 5
    ) -> Dict:
        """Probe CoAP server for accessibility"""
        try:
            # Try to connect to CoAP port (UDP)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)

            # Send CoAP GET request to /.well-known/core
            # CoAP header: Version=1, Type=CON(0), Token Length=0, Code=GET(1)
            coap_get = bytes([0x40, 0x01, 0x00, 0x00])  # Minimal CoAP GET

            sock.sendto(coap_get, (server, port))

            # Try to receive response
            try:
                data, addr = sock.recvfrom(1024)
                accessible = len(data) > 0
                protocol = "coap"
            except socket.timeout:
                accessible = False
                protocol = "unknown"

            sock.close()

            # Test anonymous access if accessible
            anonymous_allowed = False
            if accessible:
                anonymous_allowed = self.test_anonymous_access(server, port, timeout)

            return {
                'accessible': accessible,
                'protocol': protocol,
                'anonymous_allowed': anonymous_allowed,
                'port': port,
                'server': server
            }

        except (socket.timeout, socket.error, Exception):
            return {
                'accessible': False,
                'protocol': 'unknown',
                'anonymous_allowed': False,
                'port': port,
                'server': server
            }

    def test_anonymous_access(
        self,
        server: str,
        port: int = 5683,
        timeout: int = 5
    ) -> bool:
        """Test if server allows anonymous CoAP requests"""
        try:
            # Try importing aiocoap
            import asyncio

            async def check_access():
                try:
                    from aiocoap import Context, Message, GET

                    context = await Context.create_client_context()

                    # Try GET request to well-known core
                    request = Message(code=GET, uri=f'coap://{server}:{port}/.well-known/core')

                    response = await asyncio.wait_for(
                        context.request(request).response,
                        timeout=timeout
                    )

                    # If we got a response, anonymous access is allowed
                    return response.code.is_successful()

                except:
                    return False

            # Run async check
            return asyncio.run(check_access())

        except ImportError:
            # aiocoap not installed, can't test
            return False
        except Exception:
            # Connection failed
            return False

    def discover_resources(
        self,
        server: str,
        port: int = 5683,
        timeout: int = 5
    ) -> List[str]:
        """Discover CoAP resources using .well-known/core"""
        discovered = []

        try:
            import asyncio

            async def discover():
                try:
                    from aiocoap import Context, Message, GET

                    context = await Context.create_client_context()

                    # Query well-known core
                    request = Message(code=GET, uri=f'coap://{server}:{port}/.well-known/core')

                    response = await asyncio.wait_for(
                        context.request(request).response,
                        timeout=timeout
                    )

                    if response.code.is_successful():
                        # Parse link-format response
                        payload = response.payload.decode('utf-8')
                        # Simple parsing: extract </resource> patterns
                        import re
                        resources = re.findall(r'<([^>]+)>', payload)
                        return resources

                    return []

                except:
                    return []

            discovered = asyncio.run(discover())

        except ImportError:
            # aiocoap not installed
            pass
        except Exception:
            pass

        return discovered

    def assess_security(
        self,
        anonymous_allowed: bool,
        encryption: bool,
        dtls_enabled: bool
    ) -> Dict:
        """Assess CoAP server security configuration"""
        risks = []

        # Check anonymous access
        if anonymous_allowed:
            risks.append("Anonymous access allowed")

        # Check DTLS encryption
        if not dtls_enabled:
            risks.append("DTLS not enabled")

        # Check general encryption
        if not encryption:
            risks.append("No encryption configured")

        # Determine security level
        if anonymous_allowed and not dtls_enabled and not encryption:
            level: SecurityLevel = "critical"
        elif anonymous_allowed or not dtls_enabled:
            level = "weak"
        elif not encryption:
            level = "moderate"
        else:
            level = "good"

        return {
            'level': level,
            'risks': risks,
            'anonymous_allowed': anonymous_allowed,
            'encryption': encryption,
            'dtls_enabled': dtls_enabled
        }

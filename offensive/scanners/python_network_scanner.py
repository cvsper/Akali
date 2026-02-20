"""Pure Python network scanner - no nmap required."""

import socket
import ssl
import struct
import threading
from typing import List, Dict, Any, Optional, Set
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

import sys
sys.path.append(str(Path(__file__).parent.parent.parent))
from defensive.scanners.scanner_base import Scanner, Finding, Severity


class PythonNetworkScanner(Scanner):
    """Pure Python network scanner with no external dependencies."""

    def __init__(self):
        super().__init__("python-network-scanner")
        self.timeout = 2
        self.max_threads = 100

        # Common port list
        self.common_ports = {
            20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
            25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
            143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
            8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt', 9200: 'Elasticsearch',
            27017: 'MongoDB'
        }

    def check_available(self) -> bool:
        """Pure Python scanner - always available."""
        return True

    def scan(self, target: str, quick: bool = False, ports: str = None) -> List[Finding]:
        """Run network scan.

        Args:
            target: Target hostname or IP
            quick: If True, scan top 20 ports only
            ports: Port spec (e.g., "80,443" or "1-1000")

        Returns:
            List of findings
        """
        self.findings = []
        print(f"🐍 Starting Python-based network scan on {target}")

        # Validate target
        try:
            ip = socket.gethostbyname(target)
            print(f"  📡 Resolved {target} to {ip}")
        except socket.gaierror:
            print(f"❌ Could not resolve {target}")
            return self.findings

        # Determine ports to scan
        if ports:
            port_list = self._parse_port_spec(ports)
        elif quick:
            port_list = sorted(self.common_ports.keys())[:20]
        else:
            port_list = sorted(self.common_ports.keys())

        print(f"  🔍 Scanning {len(port_list)} ports...")

        # Scan ports
        open_ports = self._scan_ports_parallel(ip, port_list)

        if open_ports:
            print(f"  ✅ Found {len(open_ports)} open ports")

            # Banner grab
            print("  🔍 Grabbing banners...")
            self._grab_banners(ip, open_ports)

            # SSL/TLS check
            https_ports = [p for p in open_ports if p in [443, 8443, 9443]]
            if https_ports:
                print("  🔍 Testing SSL/TLS...")
                for port in https_ports:
                    self._check_ssl(target, port)
        else:
            print("  ℹ️  No open ports found")

        print(f"✅ Scan complete. Found {len(self.findings)} issues.")
        return self.findings

    def _parse_port_spec(self, ports: str) -> List[int]:
        """Parse port specification string."""
        port_list = []

        for part in ports.split(','):
            if '-' in part:
                start, end = part.split('-')
                port_list.extend(range(int(start), int(end) + 1))
            else:
                port_list.append(int(part))

        return port_list

    def _scan_ports_parallel(self, ip: str, ports: List[int]) -> List[int]:
        """Scan ports in parallel."""
        open_ports = []
        lock = threading.Lock()

        def scan_port(port: int) -> Optional[int]:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            try:
                result = sock.connect_ex((ip, port))
                if result == 0:
                    return port
            except:
                pass
            finally:
                sock.close()
            return None

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(scan_port, port): port for port in ports}

            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    with lock:
                        open_ports.append(result)
                        service = self.common_ports.get(result, 'Unknown')
                        print(f"    ✅ Port {result}/tcp ({service})")

        return sorted(open_ports)

    def _grab_banners(self, ip: str, ports: List[int]) -> None:
        """Grab service banners from open ports."""
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((ip, port))

                # Try to get banner
                banner = None

                # Send HTTP request for HTTP ports
                if port in [80, 8080, 8000, 8888]:
                    sock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                else:
                    # Try to receive banner directly
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')

                sock.close()

                if banner:
                    # Check for version disclosure
                    if self._has_version_disclosure(banner):
                        service = self.common_ports.get(port, 'Unknown')
                        self._add_finding(
                            severity=Severity.LOW,
                            title=f"Version information disclosed on port {port}",
                            description=f"Service banner reveals version: {banner[:100]}",
                            location=f"{ip}:{port} ({service})",
                            recommendation="Configure service to hide version information"
                        )

                    # Check for insecure services
                    self._check_insecure_service(ip, port, banner)

            except:
                pass

    def _has_version_disclosure(self, banner: str) -> bool:
        """Check if banner contains version information."""
        # Look for version patterns
        version_patterns = [
            r'\d+\.\d+\.\d+',  # Semantic versioning
            r'[vV]ersion\s+\d+',
            r'[vV]\d+\.\d+',
        ]

        import re
        for pattern in version_patterns:
            if re.search(pattern, banner):
                return True
        return False

    def _check_insecure_service(self, ip: str, port: int, banner: str) -> None:
        """Check for known insecure services."""
        insecure_services = {
            21: ('FTP', 'Use SFTP or FTPS instead'),
            23: ('Telnet', 'Use SSH instead'),
            80: ('HTTP', 'Use HTTPS instead'),
            445: ('SMB', 'Restrict access and use SMB signing'),
            3389: ('RDP', 'Use VPN and strong authentication'),
            5900: ('VNC', 'Use SSH tunnel or strong authentication'),
        }

        if port in insecure_services:
            service, recommendation = insecure_services[port]
            self._add_finding(
                severity=Severity.MEDIUM,
                title=f"Potentially insecure service: {service}",
                description=f"Port {port} running {service} which may transmit data in cleartext",
                location=f"{ip}:{port}",
                recommendation=recommendation
            )

    def _check_ssl(self, hostname: str, port: int) -> None:
        """Check SSL/TLS configuration."""
        try:
            # Test default SSL connection
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    version = ssock.version()
                    cipher = ssock.cipher()
                    cert = ssock.getpeercert()

                    # Check protocol version
                    if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        self._add_finding(
                            severity=Severity.HIGH,
                            title=f"Weak SSL/TLS protocol on port {port}",
                            description=f"Server supports {version}",
                            location=f"{hostname}:{port}",
                            recommendation="Disable SSLv2, SSLv3, TLSv1.0, and TLSv1.1"
                        )

                    # Check cipher strength
                    if cipher:
                        cipher_name, version, bits = cipher
                        weak_ciphers = ['DES', 'RC4', 'MD5', 'NULL', 'EXPORT', 'anon']

                        if any(weak in cipher_name.upper() for weak in weak_ciphers):
                            self._add_finding(
                                severity=Severity.MEDIUM,
                                title=f"Weak cipher on port {port}",
                                description=f"Server uses weak cipher: {cipher_name}",
                                location=f"{hostname}:{port}",
                                recommendation="Configure strong cipher suites only"
                            )

                        if bits and bits < 128:
                            self._add_finding(
                                severity=Severity.HIGH,
                                title=f"Weak encryption on port {port}",
                                description=f"Cipher strength: {bits} bits (minimum 128 required)",
                                location=f"{hostname}:{port}",
                                recommendation="Use ciphers with at least 128-bit encryption"
                            )

                    # Check certificate
                    if cert:
                        # Check if cert is expired
                        not_after = cert.get('notAfter')
                        if not_after:
                            from datetime import datetime
                            try:
                                expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                                if expiry < datetime.now():
                                    self._add_finding(
                                        severity=Severity.CRITICAL,
                                        title=f"Expired SSL certificate on port {port}",
                                        description=f"Certificate expired on {not_after}",
                                        location=f"{hostname}:{port}",
                                        recommendation="Renew SSL certificate immediately"
                                    )
                            except:
                                pass

            # Test for SSLv3 support (POODLE vulnerability)
            try:
                context_ssl3 = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                context_ssl3.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
                context_ssl3.check_hostname = False
                context_ssl3.verify_mode = ssl.CERT_NONE

                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context_ssl3.wrap_socket(sock) as ssock:
                        # If we get here, SSLv3 is supported
                        self._add_finding(
                            severity=Severity.HIGH,
                            title=f"SSLv3 enabled on port {port} (POODLE)",
                            description="Server supports SSLv3, vulnerable to POODLE attack",
                            location=f"{hostname}:{port}",
                            recommendation="Disable SSLv3 support"
                        )
            except:
                pass  # SSLv3 not supported (good)

        except ssl.SSLError as e:
            # Check if it's due to certificate verification
            if 'certificate verify failed' in str(e).lower():
                self._add_finding(
                    severity=Severity.MEDIUM,
                    title=f"SSL certificate verification failed on port {port}",
                    description=f"Certificate error: {str(e)[:100]}",
                    location=f"{hostname}:{port}",
                    recommendation="Use a valid certificate from trusted CA"
                )
        except Exception as e:
            pass

    def _add_finding(self, severity: Severity, title: str, description: str,
                    location: str, recommendation: str) -> None:
        """Add a finding."""
        finding = Finding(
            scanner_id=self.name,
            severity=severity,
            title=title,
            description=description,
            location=location,
            recommendation=recommendation,
            timestamp=datetime.now()
        )
        self.findings.append(finding)


if __name__ == "__main__":
    scanner = PythonNetworkScanner()
    findings = scanner.scan("www.ssemble.com", quick=False)
    for finding in findings:
        print(f"\n{finding.severity.name}: {finding.title}")
        print(f"  {finding.description}")

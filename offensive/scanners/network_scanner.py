"""Network scanner for offensive security testing."""

import re
import json
import socket
import subprocess
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path
import xml.etree.ElementTree as ET

import sys
sys.path.append(str(Path(__file__).parent.parent.parent))
from defensive.scanners.scanner_base import Scanner, Finding, Severity


class NetworkScanner(Scanner):
    """Scanner for network vulnerabilities and reconnaissance."""

    def __init__(self):
        super().__init__("network-scanner")
        self.timeout = 900  # 15 minutes for network scans

    def check_available(self) -> bool:
        """Check if required tools are available."""
        try:
            # Check for nmap
            nmap_result = subprocess.run(
                ["nmap", "--version"],
                capture_output=True,
                text=True,
                check=False
            )
            if nmap_result.returncode != 0:
                return False

            # Check for testssl.sh
            testssl_result = subprocess.run(
                ["testssl.sh", "--version"],
                capture_output=True,
                text=True,
                check=False
            )
            # testssl.sh might not support --version, just check if it exists

            return True
        except FileNotFoundError:
            return False

    def scan(self, target: str, quick: bool = False, ports: str = None) -> List[Finding]:
        """Run comprehensive network scan.

        Args:
            target: Target host/IP (e.g., example.com or 192.168.1.1)
            quick: If True, run quick scans only (top 100 ports)
            ports: Port specification (e.g., "80,443" or "1-1000")

        Returns:
            List of security findings
        """
        self.findings = []
        print(f"🥷 Starting network scan on {target}")

        # Validate target
        if not self._validate_target(target):
            print("❌ Invalid target. Must be a hostname or IP address.")
            return self.findings

        # Run port scanning
        print("  🔍 Scanning ports...")
        open_ports = self._scan_ports(target, quick, ports)

        # Run service enumeration
        if open_ports:
            print("  🔍 Enumerating services...")
            self._enumerate_services(target, open_ports)

        # Run SSL/TLS testing on HTTPS ports
        https_ports = [p for p in open_ports if p in [443, 8443, 9443]]
        if https_ports:
            print("  🔍 Testing SSL/TLS...")
            for port in https_ports:
                self._test_ssl_tls(target, port)

        # Banner grabbing
        print("  🔍 Grabbing banners...")
        self._grab_banners(target, open_ports)

        print(f"✅ Network scan complete. Found {len(self.findings)} issues.")
        return self.findings

    def _validate_target(self, target: str) -> bool:
        """Validate target is a valid hostname or IP."""
        try:
            socket.gethostbyname(target)
            return True
        except socket.gaierror:
            return False

    def _scan_ports(self, target: str, quick: bool = False, ports: str = None) -> List[int]:
        """Scan ports using nmap."""
        open_ports = []

        try:
            # Build nmap command
            cmd = ["nmap"]

            if quick:
                cmd.extend(["-F"])  # Fast scan (top 100 ports)
            elif ports:
                cmd.extend(["-p", ports])
            else:
                cmd.extend(["-p-"])  # Scan all ports (slow)

            cmd.extend([
                "-sV",  # Version detection
                "-O",   # OS detection (requires sudo, may fail)
                "--open",  # Only show open ports
                "-oX", "/tmp/akali-nmap.xml",  # XML output
                target
            ])

            result = self.run_command(cmd, timeout=self.timeout)

            # Parse nmap XML output
            try:
                tree = ET.parse("/tmp/akali-nmap.xml")
                root = tree.getroot()

                for host in root.findall(".//host"):
                    for port in host.findall(".//port"):
                        state = port.find("state")
                        if state is not None and state.get("state") == "open":
                            port_id = int(port.get("portid"))
                            open_ports.append(port_id)

                            # Create finding for open port
                            service = port.find("service")
                            service_name = service.get("name", "unknown") if service is not None else "unknown"
                            service_version = service.get("version", "") if service is not None else ""

                            # Determine severity based on port
                            severity = self._port_severity(port_id, service_name)

                            finding = Finding(
                                id=self.generate_finding_id(),
                                timestamp=datetime.now().isoformat(),
                                severity=severity.value,
                                type="open-port",
                                title=f"Open Port {port_id}/{service_name}",
                                description=f"Port {port_id} is open running {service_name} {service_version}".strip(),
                                file=f"{target}:{port_id}",
                                fix=self._port_recommendation(port_id, service_name),
                                scanner=self.name
                            )
                            self.findings.append(finding)

            except (ET.ParseError, FileNotFoundError) as e:
                print(f"  ⚠️  Failed to parse nmap output: {e}")

        except Exception as e:
            print(f"  ⚠️  Port scan failed: {e}")

        return open_ports

    def _port_severity(self, port: int, service: str) -> Severity:
        """Determine severity based on port and service."""
        # High-risk ports
        if port in [21, 23, 25, 110, 143, 3389, 5900]:  # FTP, Telnet, SMTP, POP3, IMAP, RDP, VNC
            return Severity.HIGH

        # Database ports (should not be exposed)
        if port in [3306, 5432, 27017, 6379, 1433]:  # MySQL, PostgreSQL, MongoDB, Redis, MSSQL
            return Severity.CRITICAL

        # Administrative/management ports
        if port in [22, 3306, 5432, 8080, 8443, 9090]:
            return Severity.MEDIUM

        # Standard web ports
        if port in [80, 443]:
            return Severity.INFO

        return Severity.LOW

    def _port_recommendation(self, port: int, service: str) -> str:
        """Get recommendation for open port."""
        recommendations = {
            21: "FTP transmits credentials in plaintext. Use SFTP or FTPS instead. Restrict access or disable if not needed.",
            22: "Ensure SSH uses key-based authentication. Disable password authentication. Use fail2ban to prevent brute force.",
            23: "Telnet is insecure (no encryption). Replace with SSH immediately.",
            25: "SMTP should require authentication. Implement SPF/DKIM/DMARC. Restrict relay access.",
            80: "HTTP traffic is unencrypted. Redirect to HTTPS. Consider disabling HTTP entirely.",
            110: "POP3 transmits credentials in plaintext. Use POP3S (port 995) or IMAP over TLS.",
            143: "IMAP transmits credentials in plaintext. Use IMAPS (port 993) instead.",
            443: "Ensure TLS 1.2+ is used. Disable weak ciphers. Keep certificates up to date.",
            3306: "MySQL should not be exposed to the internet. Use firewall rules to restrict access.",
            3389: "RDP is frequently targeted. Use VPN, change default port, enable NLA, use strong passwords.",
            5432: "PostgreSQL should not be exposed. Restrict to localhost or trusted networks only.",
            5900: "VNC has weak encryption by default. Use SSH tunnel or VPN for remote access.",
            6379: "Redis should not be exposed. Requires authentication and bound to localhost only.",
            27017: "MongoDB should not be exposed. Enable authentication and bind to localhost."
        }
        return recommendations.get(port, f"Review if port {port} needs to be publicly accessible. Apply principle of least privilege.")

    def _enumerate_services(self, target: str, ports: List[int]) -> None:
        """Enumerate services running on open ports."""
        try:
            port_list = ",".join(map(str, ports[:20]))  # Limit to first 20 ports

            cmd = [
                "nmap",
                "-p", port_list,
                "-sV",  # Version detection
                "--script=banner,http-title,ssl-cert",
                "-oX", "/tmp/akali-nmap-services.xml",
                target
            ]

            result = self.run_command(cmd, timeout=300)

            # Parse service information
            try:
                tree = ET.parse("/tmp/akali-nmap-services.xml")
                root = tree.getroot()

                for port in root.findall(".//port"):
                    service = port.find("service")
                    if service is not None:
                        # Check for outdated/vulnerable services
                        product = service.get("product", "")
                        version = service.get("version", "")

                        if product and version:
                            # Flag old versions (simple heuristic)
                            if self._is_outdated_service(product, version):
                                finding = Finding(
                                    id=self.generate_finding_id(),
                                    timestamp=datetime.now().isoformat(),
                                    severity=Severity.HIGH.value,
                                    type="outdated-service",
                                    title=f"Potentially Outdated Service: {product} {version}",
                                    description=f"Service {product} version {version} may be outdated and contain known vulnerabilities.",
                                    file=f"{target}:{port.get('portid')}",
                                    fix=f"Update {product} to the latest version. Check CVE databases for known vulnerabilities.",
                                    scanner=self.name
                                )
                                self.findings.append(finding)

            except (ET.ParseError, FileNotFoundError):
                pass

        except Exception as e:
            print(f"  ⚠️  Service enumeration failed: {e}")

    def _is_outdated_service(self, product: str, version: str) -> bool:
        """Simple heuristic to detect potentially outdated services."""
        # Extract major version
        version_match = re.match(r'(\d+)\.', version)
        if not version_match:
            return False

        major_version = int(version_match.group(1))

        # Known old versions (heuristic)
        outdated_checks = {
            "Apache httpd": 2,  # Apache < 2.4 is old
            "nginx": 1,  # nginx < 1.20 is old
            "OpenSSH": 7,  # OpenSSH < 8.0 is old
            "MySQL": 5,  # MySQL < 8.0 is old
            "PostgreSQL": 10,  # PostgreSQL < 12 is old
        }

        for prod, min_version in outdated_checks.items():
            if prod.lower() in product.lower() and major_version < min_version:
                return True

        return False

    def _test_ssl_tls(self, target: str, port: int) -> None:
        """Test SSL/TLS configuration using testssl.sh."""
        try:
            cmd = [
                "testssl.sh",
                "--jsonfile", f"/tmp/akali-testssl-{port}.json",
                "--quiet",
                "--fast",  # Fast scan mode
                f"{target}:{port}"
            ]

            result = self.run_command(cmd, timeout=300)

            # Parse testssl.sh JSON output
            try:
                with open(f"/tmp/akali-testssl-{port}.json", "r") as f:
                    # testssl.sh outputs JSONL (one JSON per line)
                    for line in f:
                        try:
                            data = json.loads(line.strip())

                            # Check for vulnerabilities
                            if data.get("severity") in ["CRITICAL", "HIGH"]:
                                finding = Finding(
                                    id=self.generate_finding_id(),
                                    timestamp=datetime.now().isoformat(),
                                    severity=Severity.HIGH.value if data.get("severity") == "HIGH" else Severity.CRITICAL.value,
                                    type="ssl-tls-vulnerability",
                                    title=data.get("id", "SSL/TLS Issue"),
                                    description=data.get("finding", "SSL/TLS configuration issue detected."),
                                    file=f"{target}:{port}",
                                    fix="Update TLS configuration. Disable weak protocols (SSLv3, TLS 1.0, TLS 1.1). Use strong ciphers only.",
                                    scanner=self.name
                                )
                                self.findings.append(finding)
                        except json.JSONDecodeError:
                            continue

            except FileNotFoundError:
                pass

        except Exception as e:
            print(f"  ⚠️  SSL/TLS test failed: {e}")

    def _grab_banners(self, target: str, ports: List[int]) -> None:
        """Grab service banners for information disclosure."""
        for port in ports[:10]:  # Limit to first 10 ports
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((target, port))

                # Send generic request for banner
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()

                # Check for information disclosure in banner
                if any(keyword in banner.lower() for keyword in ['server:', 'apache', 'nginx', 'microsoft', 'version']):
                    finding = Finding(
                        id=self.generate_finding_id(),
                        timestamp=datetime.now().isoformat(),
                        severity=Severity.LOW.value,
                        type="information-disclosure",
                        title=f"Service Banner Disclosure on Port {port}",
                        description=f"Service banner reveals version information: {banner[:200]}",
                        file=f"{target}:{port}",
                        fix="Configure server to hide version information in banners. Update server configuration to minimize information disclosure.",
                        scanner=self.name
                    )
                    self.findings.append(finding)

            except (socket.timeout, socket.error, ConnectionRefusedError):
                pass  # Port not accessible or no banner


def main():
    """CLI for network scanner."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python network_scanner.py <target> [--quick] [--ports=80,443]")
        print("Example: python network_scanner.py example.com")
        print("Example: python network_scanner.py 192.168.1.1 --quick")
        sys.exit(1)

    target = sys.argv[1]
    quick = "--quick" in sys.argv

    ports = None
    for arg in sys.argv:
        if arg.startswith("--ports="):
            ports = arg.split("=")[1]

    scanner = NetworkScanner()

    if not scanner.check_available():
        print("❌ Required tools not available. Run: scripts/install_offensive_tools.sh")
        sys.exit(1)

    findings = scanner.scan(target, quick=quick, ports=ports)

    # Print results
    print(f"\n📊 Scan Results:")
    print(f"  Total findings: {len(findings)}")

    by_severity = {}
    for finding in findings:
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

    for severity in ["critical", "high", "medium", "low", "info"]:
        count = by_severity.get(severity, 0)
        if count > 0:
            print(f"  {severity.upper()}: {count}")

    # Print findings
    if findings:
        print("\n📋 Findings:")
        for finding in findings:
            print(f"\n  [{finding.severity.upper()}] {finding.title}")
            print(f"    Type: {finding.type}")
            print(f"    Description: {finding.description}")
            if finding.fix:
                print(f"    Fix: {finding.fix}")


if __name__ == "__main__":
    main()

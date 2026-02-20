"""Pure Python web vulnerability scanner - no external dependencies."""

import re
import json
import requests
import socket
import ssl
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, urljoin, parse_qs, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import time

import sys
sys.path.append(str(Path(__file__).parent.parent.parent))
from defensive.scanners.scanner_base import Scanner, Finding, Severity


class PythonWebScanner(Scanner):
    """Pure Python web vulnerability scanner with no external tool dependencies."""

    def __init__(self):
        super().__init__("python-web-scanner")
        self.timeout = 10
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
        })

        # XSS payloads
        self.xss_payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '"><script>alert(1)</script>',
            '<svg/onload=alert(1)>',
            'javascript:alert(1)',
            '<iframe src="javascript:alert(1)">',
        ]

        # SQL injection payloads
        self.sqli_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "\" OR \"1\"=\"1",
            "' OR 'a'='a",
            "admin'--",
            "' UNION SELECT NULL--",
            "1' AND '1'='1",
        ]

        # Command injection payloads
        self.cmd_payloads = [
            "; ls",
            "| whoami",
            "& dir",
            "`id`",
            "$(whoami)",
            "; cat /etc/passwd",
        ]

        # Path traversal payloads
        self.path_traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ]

    def check_available(self) -> bool:
        """Pure Python scanner - always available."""
        return True

    def scan(self, target: str, quick: bool = False) -> List[Finding]:
        """Run comprehensive web vulnerability scan.

        Args:
            target: Target URL
            quick: If True, run only basic checks

        Returns:
            List of findings
        """
        self.findings = []
        print(f"🐍 Starting Python-based web scan on {target}")

        if not target.startswith(("http://", "https://")):
            print("❌ Target must be a valid URL")
            return self.findings

        # Run checks
        print("  🔍 Testing for XSS...")
        self._check_xss(target)

        print("  🔍 Testing for SQL injection...")
        self._check_sqli(target)

        print("  🔍 Testing for command injection...")
        self._check_command_injection(target)

        print("  🔍 Testing for path traversal...")
        self._check_path_traversal(target)

        print("  🔍 Checking security headers...")
        self._check_security_headers(target)

        if not quick:
            print("  🔍 Testing CORS configuration...")
            self._check_cors(target)

            print("  🔍 Checking for sensitive files...")
            self._check_sensitive_files(target)

            print("  🔍 Testing SSL/TLS...")
            self._check_ssl_tls(target)

        print(f"✅ Scan complete. Found {len(self.findings)} issues.")
        return self.findings

    def _check_xss(self, target: str) -> None:
        """Check for XSS vulnerabilities."""
        try:
            # Get page and find forms/parameters
            response = self.session.get(target, timeout=self.timeout)

            # Test reflected XSS
            parsed = urlparse(target)
            query_params = parse_qs(parsed.query)

            for param in query_params.keys():
                for payload in self.xss_payloads[:3]:  # Test first 3 payloads
                    test_params = query_params.copy()
                    test_params[param] = [payload]

                    # Rebuild URL
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, '&'.join([f"{k}={v[0]}" for k, v in test_params.items()]),
                        parsed.fragment
                    ))

                    try:
                        test_response = self.session.get(test_url, timeout=self.timeout)
                        if payload in test_response.text:
                            self._add_finding(
                                severity=Severity.HIGH,
                                title=f"Potential XSS vulnerability in parameter '{param}'",
                                description=f"Payload '{payload}' was reflected in response",
                                location=f"{target} (parameter: {param})",
                                recommendation="Implement proper input validation and output encoding"
                            )
                            break
                    except:
                        pass

        except Exception as e:
            pass

    def _check_sqli(self, target: str) -> None:
        """Check for SQL injection vulnerabilities."""
        try:
            parsed = urlparse(target)
            query_params = parse_qs(parsed.query)

            if not query_params:
                return

            for param in query_params.keys():
                # Get baseline response
                try:
                    baseline = self.session.get(target, timeout=self.timeout)
                    baseline_time = baseline.elapsed.total_seconds()
                    baseline_len = len(baseline.text)
                except:
                    continue

                for payload in self.sqli_payloads[:4]:
                    test_params = query_params.copy()
                    test_params[param] = [payload]

                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, '&'.join([f"{k}={v[0]}" for k, v in test_params.items()]),
                        parsed.fragment
                    ))

                    try:
                        test_response = self.session.get(test_url, timeout=self.timeout)
                        test_len = len(test_response.text)

                        # Check for SQL errors
                        sql_errors = [
                            'sql syntax', 'mysql', 'postgresql', 'sqlite',
                            'ora-', 'microsoft sql', 'odbc', 'jdbc',
                            'syntax error', 'unterminated string'
                        ]

                        response_lower = test_response.text.lower()
                        if any(error in response_lower for error in sql_errors):
                            self._add_finding(
                                severity=Severity.CRITICAL,
                                title=f"Potential SQL injection in parameter '{param}'",
                                description=f"SQL error detected with payload: {payload}",
                                location=f"{target} (parameter: {param})",
                                recommendation="Use parameterized queries and input validation"
                            )
                            break

                        # Check for significant response changes
                        if abs(test_len - baseline_len) > baseline_len * 0.3:
                            self._add_finding(
                                severity=Severity.HIGH,
                                title=f"Possible SQL injection in parameter '{param}'",
                                description=f"Response changed significantly with payload: {payload}",
                                location=f"{target} (parameter: {param})",
                                recommendation="Investigate manually and use parameterized queries"
                            )
                            break

                    except:
                        pass

        except Exception as e:
            pass

    def _check_command_injection(self, target: str) -> None:
        """Check for command injection vulnerabilities."""
        try:
            parsed = urlparse(target)
            query_params = parse_qs(parsed.query)

            for param in query_params.keys():
                baseline = self.session.get(target, timeout=self.timeout)
                baseline_time = baseline.elapsed.total_seconds()

                # Test time-based injection
                sleep_payload = query_params.copy()
                sleep_payload[param] = ["; sleep 5"]

                sleep_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, '&'.join([f"{k}={v[0]}" for k, v in sleep_payload.items()]),
                    parsed.fragment
                ))

                try:
                    start = time.time()
                    self.session.get(sleep_url, timeout=15)
                    elapsed = time.time() - start

                    if elapsed > 4.5:  # Sleep worked
                        self._add_finding(
                            severity=Severity.CRITICAL,
                            title=f"Command injection detected in parameter '{param}'",
                            description=f"Time-based detection: sleep command executed",
                            location=f"{target} (parameter: {param})",
                            recommendation="Never pass user input to system commands"
                        )
                except:
                    pass

        except Exception as e:
            pass

    def _check_path_traversal(self, target: str) -> None:
        """Check for path traversal vulnerabilities."""
        try:
            parsed = urlparse(target)
            query_params = parse_qs(parsed.query)

            for param in query_params.keys():
                for payload in self.path_traversal_payloads[:3]:
                    test_params = query_params.copy()
                    test_params[param] = [payload]

                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, '&'.join([f"{k}={v[0]}" for k, v in test_params.items()]),
                        parsed.fragment
                    ))

                    try:
                        response = self.session.get(test_url, timeout=self.timeout)

                        # Check for common file signatures
                        if ('root:' in response.text and '/bin/' in response.text) or \
                           ('[drivers]' in response.text.lower() and '[fonts]' in response.text.lower()):
                            self._add_finding(
                                severity=Severity.HIGH,
                                title=f"Path traversal detected in parameter '{param}'",
                                description=f"System file accessed with payload: {payload}",
                                location=f"{target} (parameter: {param})",
                                recommendation="Validate and sanitize file paths, use whitelisting"
                            )
                            break
                    except:
                        pass

        except Exception as e:
            pass

    def _check_security_headers(self, target: str) -> None:
        """Check for missing security headers."""
        try:
            response = self.session.get(target, timeout=self.timeout)

            security_headers = {
                'Content-Security-Policy': 'CSP',
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME-sniffing protection',
                'Strict-Transport-Security': 'HSTS',
                'X-XSS-Protection': 'XSS filter',
                'Referrer-Policy': 'Referrer control',
                'Permissions-Policy': 'Feature policy'
            }

            missing = []
            for header, description in security_headers.items():
                if header not in response.headers:
                    missing.append(f"{header} ({description})")

            if len(missing) >= 4:  # Report if 4+ headers missing
                self._add_finding(
                    severity=Severity.MEDIUM,
                    title="Multiple security headers missing",
                    description=f"Missing headers: {', '.join(missing)}",
                    location=target,
                    recommendation="Implement security headers for defense in depth"
                )

        except Exception as e:
            pass

    def _check_cors(self, target: str) -> None:
        """Check CORS configuration."""
        try:
            headers = {
                'Origin': 'https://evil.com',
                'Access-Control-Request-Method': 'POST'
            }
            response = self.session.options(target, headers=headers, timeout=self.timeout)

            acao = response.headers.get('Access-Control-Allow-Origin')
            acac = response.headers.get('Access-Control-Allow-Credentials')

            if acao == '*':
                severity = Severity.CRITICAL if acac == 'true' else Severity.HIGH
                self._add_finding(
                    severity=severity,
                    title="Wildcard CORS policy detected",
                    description=f"Access-Control-Allow-Origin: * {'with credentials' if acac == 'true' else ''}",
                    location=target,
                    recommendation="Use origin whitelist instead of wildcard"
                )
            elif acao == 'https://evil.com':
                self._add_finding(
                    severity=Severity.HIGH,
                    title="Permissive CORS policy",
                    description="CORS reflects arbitrary origins",
                    location=target,
                    recommendation="Validate allowed origins against whitelist"
                )

        except Exception as e:
            pass

    def _check_sensitive_files(self, target: str) -> None:
        """Check for exposed sensitive files."""
        sensitive_files = [
            '.env', '.env.local', '.env.production',
            '.git/config', '.git/HEAD',
            'backup.zip', 'backup.sql', 'database.sql',
            '.DS_Store', 'web.config', '.htaccess',
            'composer.json', 'package.json',
            'phpinfo.php', 'info.php',
            'admin', 'administrator', 'phpmyadmin'
        ]

        base_url = urlparse(target)._replace(path='', params='', query='', fragment='').geturl()

        for file in sensitive_files:
            url = urljoin(base_url, file)
            try:
                response = self.session.head(url, timeout=5, allow_redirects=False)
                if response.status_code == 200:
                    self._add_finding(
                        severity=Severity.HIGH,
                        title=f"Sensitive file exposed: {file}",
                        description=f"File accessible at {url}",
                        location=url,
                        recommendation="Restrict access to sensitive files"
                    )
            except:
                pass

    def _check_ssl_tls(self, target: str) -> None:
        """Check SSL/TLS configuration."""
        try:
            parsed = urlparse(target)
            if parsed.scheme != 'https':
                return

            hostname = parsed.netloc.split(':')[0]
            port = int(parsed.netloc.split(':')[1]) if ':' in parsed.netloc else 443

            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    version = ssock.version()
                    cipher = ssock.cipher()

                    # Check for weak protocols
                    if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        self._add_finding(
                            severity=Severity.HIGH,
                            title=f"Weak SSL/TLS protocol: {version}",
                            description=f"Server supports outdated protocol {version}",
                            location=target,
                            recommendation="Disable SSLv2, SSLv3, TLSv1.0, and TLSv1.1"
                        )

                    # Check for weak ciphers
                    weak_ciphers = ['DES', 'RC4', 'MD5', 'NULL', 'EXPORT', 'anon']
                    cipher_name = cipher[0] if cipher else ''
                    if any(weak in cipher_name.upper() for weak in weak_ciphers):
                        self._add_finding(
                            severity=Severity.MEDIUM,
                            title=f"Weak cipher in use: {cipher_name}",
                            description=f"Server supports weak cipher {cipher_name}",
                            location=target,
                            recommendation="Use strong cipher suites only"
                        )

        except Exception as e:
            pass

    def _add_finding(self, severity: Severity, title: str, description: str,
                    location: str, recommendation: str) -> None:
        """Add a finding to the results."""
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
    scanner = PythonWebScanner()
    findings = scanner.scan("https://www.ssemble.com", quick=False)
    for finding in findings:
        print(f"\n{finding.severity.name}: {finding.title}")
        print(f"  {finding.description}")

"""API scanner for offensive security testing."""

import re
import json
import requests
import subprocess
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, urljoin

import sys
sys.path.append(str(Path(__file__).parent.parent.parent))
from defensive.scanners.scanner_base import Scanner, Finding, Severity


class APIScanner(Scanner):
    """Scanner for API vulnerabilities and security testing."""

    def __init__(self):
        super().__init__("api-scanner")
        self.timeout = 600  # 10 minutes for API scans
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Akali-Security-Scanner/2.0'
        })

    def check_available(self) -> bool:
        """Check if required tools are available."""
        try:
            # Check for ffuf (fuzzing tool)
            ffuf_result = subprocess.run(
                ["ffuf", "-V"],
                capture_output=True,
                text=True,
                check=False
            )
            return ffuf_result.returncode == 0
        except FileNotFoundError:
            return False

    def scan(self, target: str, wordlist: str = None) -> List[Finding]:
        """Run comprehensive API security scan.

        Args:
            target: Target API base URL (e.g., https://api.example.com)
            wordlist: Path to wordlist for endpoint discovery

        Returns:
            List of security findings
        """
        self.findings = []
        print(f"🥷 Starting API security scan on {target}")

        # Validate target is a URL
        if not target.startswith(("http://", "https://")):
            print("❌ Target must be a valid URL (http:// or https://)")
            return self.findings

        # Run endpoint discovery
        print("  🔍 Discovering API endpoints...")
        endpoints = self._discover_endpoints(target, wordlist)

        # Test authentication bypass
        print("  🔍 Testing authentication bypass...")
        self._test_auth_bypass(target, endpoints)

        # Check rate limiting
        print("  🔍 Checking rate limiting...")
        self._check_rate_limiting(target)

        # Test for common API vulnerabilities
        print("  🔍 Testing API vulnerabilities...")
        self._test_api_vulns(target, endpoints)

        # Parameter fuzzing
        if endpoints:
            print("  🔍 Fuzzing parameters...")
            self._fuzz_parameters(target, endpoints[:5])  # Limit to first 5 endpoints

        print(f"✅ API scan complete. Found {len(self.findings)} issues.")
        return self.findings

    def _discover_endpoints(self, target: str, wordlist: str = None) -> List[str]:
        """Discover API endpoints using fuzzing."""
        endpoints = []

        # Common API endpoints to check
        common_endpoints = [
            "/api/v1/users",
            "/api/v1/auth",
            "/api/v1/login",
            "/api/v1/admin",
            "/api/users",
            "/api/auth",
            "/api/config",
            "/api/status",
            "/api/health",
            "/api/docs",
            "/api/swagger",
            "/api/graphql",
            "/v1/users",
            "/v1/auth",
            "/v2/users",
            "/v2/auth"
        ]

        # Test common endpoints
        for endpoint in common_endpoints:
            url = urljoin(target, endpoint)
            try:
                response = self.session.get(url, timeout=10, verify=False, allow_redirects=False)

                # Consider 200, 401, 403 as existing endpoints
                if response.status_code in [200, 401, 403, 301, 302]:
                    endpoints.append(endpoint)

                    # Create finding for discovered endpoint
                    if response.status_code == 200:
                        finding = Finding(
                            id=self.generate_finding_id(),
                            timestamp=datetime.now().isoformat(),
                            severity=Severity.INFO.value,
                            type="endpoint-discovered",
                            title=f"API Endpoint Discovered: {endpoint}",
                            description=f"Endpoint {endpoint} is accessible and returned status {response.status_code}",
                            file=url,
                            scanner=self.name
                        )
                        self.findings.append(finding)

            except requests.RequestException:
                pass

        # Use ffuf for deeper discovery if wordlist provided
        if wordlist and Path(wordlist).exists():
            try:
                cmd = [
                    "ffuf",
                    "-u", f"{target}/FUZZ",
                    "-w", wordlist,
                    "-mc", "200,201,204,301,302,307,401,403",
                    "-o", "/tmp/akali-ffuf.json",
                    "-of", "json",
                    "-t", "10",  # 10 threads
                    "-timeout", "10"
                ]

                result = self.run_command(cmd, timeout=300)

                # Parse ffuf output
                try:
                    with open("/tmp/akali-ffuf.json", "r") as f:
                        ffuf_data = json.load(f)

                    for result_item in ffuf_data.get("results", []):
                        endpoint = result_item.get("input", {}).get("FUZZ", "")
                        if endpoint and endpoint not in endpoints:
                            endpoints.append(f"/{endpoint}")

                except (FileNotFoundError, json.JSONDecodeError):
                    pass

            except Exception as e:
                print(f"  ⚠️  Endpoint discovery with ffuf failed: {e}")

        return endpoints

    def _test_auth_bypass(self, target: str, endpoints: List[str]) -> None:
        """Test for authentication bypass vulnerabilities."""
        # Common auth bypass techniques
        bypass_headers = [
            {"X-Original-URL": "/admin"},
            {"X-Rewrite-URL": "/admin"},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"Authorization": "Bearer null"},
            {"Authorization": "Bearer undefined"},
        ]

        # Test on admin/auth endpoints
        auth_endpoints = [ep for ep in endpoints if any(x in ep for x in ['admin', 'auth', 'login'])]

        for endpoint in auth_endpoints[:3]:  # Limit to first 3
            url = urljoin(target, endpoint)

            # Baseline request
            try:
                baseline = self.session.get(url, timeout=10, verify=False)

                # If endpoint requires auth (401/403), test bypass
                if baseline.status_code in [401, 403]:
                    for headers in bypass_headers:
                        try:
                            response = self.session.get(url, headers=headers, timeout=10, verify=False)

                            # If we get 200 with bypass headers, it's a vulnerability
                            if response.status_code == 200:
                                finding = Finding(
                                    id=self.generate_finding_id(),
                                    timestamp=datetime.now().isoformat(),
                                    severity=Severity.CRITICAL.value,
                                    type="auth-bypass",
                                    title=f"Authentication Bypass: {endpoint}",
                                    description=f"Authentication bypass detected using headers: {headers}. Endpoint returned 200 instead of 401/403.",
                                    file=url,
                                    cvss=9.1,
                                    cwe="CWE-287",
                                    owasp="A01:2021 - Broken Access Control",
                                    fix="Validate authentication properly. Do not trust client-provided headers for authorization decisions.",
                                    scanner=self.name
                                )
                                self.findings.append(finding)
                                break

                        except requests.RequestException:
                            pass

            except requests.RequestException:
                pass

    def _check_rate_limiting(self, target: str) -> None:
        """Check for missing rate limiting."""
        test_endpoint = urljoin(target, "/api/v1/users")

        try:
            # Make 50 rapid requests
            responses = []
            for i in range(50):
                try:
                    response = self.session.get(test_endpoint, timeout=5, verify=False)
                    responses.append(response.status_code)
                except requests.RequestException:
                    break

            # If all requests succeeded, rate limiting might be missing
            if len(responses) == 50 and all(s in [200, 404] for s in responses):
                finding = Finding(
                    id=self.generate_finding_id(),
                    timestamp=datetime.now().isoformat(),
                    severity=Severity.MEDIUM.value,
                    type="missing-rate-limiting",
                    title="Missing Rate Limiting",
                    description=f"API endpoint {test_endpoint} does not appear to implement rate limiting. 50 rapid requests were all successful.",
                    file=test_endpoint,
                    cvss=5.3,
                    cwe="CWE-770",
                    owasp="A04:2021 - Insecure Design",
                    fix="Implement rate limiting using token bucket or sliding window algorithms. Return 429 status code when limit exceeded.",
                    scanner=self.name
                )
                self.findings.append(finding)

        except Exception as e:
            print(f"  ⚠️  Rate limiting check failed: {e}")

    def _test_api_vulns(self, target: str, endpoints: List[str]) -> None:
        """Test for common API vulnerabilities."""
        # Test for excessive data exposure
        for endpoint in endpoints[:5]:
            url = urljoin(target, endpoint)

            try:
                response = self.session.get(url, timeout=10, verify=False)

                if response.status_code == 200:
                    try:
                        data = response.json()

                        # Check for sensitive fields in response
                        sensitive_fields = ['password', 'secret', 'token', 'api_key', 'private_key', 'ssn', 'credit_card']
                        found_sensitive = []

                        def check_dict(d, path=""):
                            if isinstance(d, dict):
                                for key, value in d.items():
                                    current_path = f"{path}.{key}" if path else key
                                    if any(sf in key.lower() for sf in sensitive_fields):
                                        found_sensitive.append(current_path)
                                    check_dict(value, current_path)
                            elif isinstance(d, list):
                                for i, item in enumerate(d):
                                    check_dict(item, f"{path}[{i}]")

                        check_dict(data)

                        if found_sensitive:
                            finding = Finding(
                                id=self.generate_finding_id(),
                                timestamp=datetime.now().isoformat(),
                                severity=Severity.HIGH.value,
                                type="excessive-data-exposure",
                                title=f"Excessive Data Exposure: {endpoint}",
                                description=f"API response contains sensitive fields: {', '.join(found_sensitive)}",
                                file=url,
                                cvss=7.5,
                                cwe="CWE-200",
                                owasp="A01:2021 - Broken Access Control",
                                fix="Remove sensitive fields from API responses. Implement field-level access control.",
                                scanner=self.name
                            )
                            self.findings.append(finding)

                    except (json.JSONDecodeError, ValueError):
                        pass

                # Test for CORS misconfig
                cors_headers = response.headers.get("Access-Control-Allow-Origin")
                if cors_headers == "*":
                    finding = Finding(
                        id=self.generate_finding_id(),
                        timestamp=datetime.now().isoformat(),
                        severity=Severity.MEDIUM.value,
                        type="cors-misconfiguration",
                        title=f"Overly Permissive CORS: {endpoint}",
                        description="API allows requests from any origin (Access-Control-Allow-Origin: *)",
                        file=url,
                        cvss=5.3,
                        cwe="CWE-942",
                        owasp="A05:2021 - Security Misconfiguration",
                        fix="Restrict CORS to trusted origins only. Avoid using wildcard (*) in production.",
                        scanner=self.name
                    )
                    self.findings.append(finding)

            except requests.RequestException:
                pass

    def _fuzz_parameters(self, target: str, endpoints: List[str]) -> None:
        """Fuzz API parameters for vulnerabilities."""
        # Test parameter pollution
        test_params = [
            {"id": "1"},
            {"id": "1&id=2"},  # Parameter pollution
            {"id": "-1"},  # Negative ID
            {"id": "999999999"},  # Large number
            {"id": "'; DROP TABLE users--"},  # SQL injection
            {"id": "../../../etc/passwd"},  # Path traversal
        ]

        for endpoint in endpoints:
            url = urljoin(target, endpoint)

            for params in test_params:
                try:
                    response = self.session.get(url, params=params, timeout=10, verify=False)

                    # Check for error messages that leak information
                    if response.status_code == 500:
                        error_patterns = [
                            r'SQLException',
                            r'mysql_fetch',
                            r'ORA-\d+',
                            r'PostgreSQL.*ERROR',
                            r'Warning:.*mysql',
                            r'Traceback',
                            r'stack trace'
                        ]

                        for pattern in error_patterns:
                            if re.search(pattern, response.text, re.IGNORECASE):
                                finding = Finding(
                                    id=self.generate_finding_id(),
                                    timestamp=datetime.now().isoformat(),
                                    severity=Severity.MEDIUM.value,
                                    type="error-information-disclosure",
                                    title=f"Error Information Disclosure: {endpoint}",
                                    description=f"API exposes internal error details in response. Pattern matched: {pattern}",
                                    file=url,
                                    cvss=5.3,
                                    cwe="CWE-209",
                                    owasp="A05:2021 - Security Misconfiguration",
                                    fix="Implement generic error messages. Log detailed errors server-side only.",
                                    scanner=self.name
                                )
                                self.findings.append(finding)
                                break

                except requests.RequestException:
                    pass


def main():
    """CLI for API scanner."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python api_scanner.py <target_api_url> [--wordlist=/path/to/wordlist.txt]")
        print("Example: python api_scanner.py https://api.example.com")
        sys.exit(1)

    target = sys.argv[1]

    wordlist = None
    for arg in sys.argv:
        if arg.startswith("--wordlist="):
            wordlist = arg.split("=")[1]

    scanner = APIScanner()

    if not scanner.check_available():
        print("❌ Required tools not available. Run: scripts/install_offensive_tools.sh")
        sys.exit(1)

    findings = scanner.scan(target, wordlist=wordlist)

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

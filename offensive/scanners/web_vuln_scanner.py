"""Web vulnerability scanner for offensive security testing."""

import re
import json
import requests
import subprocess
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path

import sys
sys.path.append(str(Path(__file__).parent.parent.parent))
from defensive.scanners.scanner_base import Scanner, Finding, Severity


class WebVulnScanner(Scanner):
    """Scanner for web application vulnerabilities."""

    def __init__(self):
        super().__init__("web-vuln-scanner")
        self.payloads_dir = Path(__file__).parent.parent / "payloads"
        self.timeout = 600  # 10 minutes for deep scans

    def check_available(self) -> bool:
        """Check if required tools are available."""
        try:
            # Check for sqlmap
            sqlmap_result = subprocess.run(
                ["sqlmap", "--version"],
                capture_output=True,
                text=True,
                check=False
            )
            if sqlmap_result.returncode != 0:
                return False

            # Check for nikto
            nikto_result = subprocess.run(
                ["nikto", "-Version"],
                capture_output=True,
                text=True,
                check=False
            )
            if nikto_result.returncode != 0:
                return False

            return True
        except FileNotFoundError:
            return False

    def scan(self, target: str, quick: bool = False) -> List[Finding]:
        """Run comprehensive web vulnerability scan.

        Args:
            target: Target URL (e.g., https://example.com)
            quick: If True, run quick scans only (skip deep tests)

        Returns:
            List of security findings
        """
        self.findings = []
        print(f"🥷 Starting web vulnerability scan on {target}")

        # Validate target is a URL
        if not target.startswith(("http://", "https://")):
            print("❌ Target must be a valid URL (http:// or https://)")
            return self.findings

        # Run all vulnerability checks
        print("  🔍 Checking for SQL injection...")
        self._check_sql_injection(target, quick)

        print("  🔍 Checking for XSS vulnerabilities...")
        self._check_xss(target)

        print("  🔍 Checking for CSRF vulnerabilities...")
        self._check_csrf(target)

        print("  🔍 Checking for path traversal...")
        self._check_path_traversal(target)

        print("  🔍 Checking for command injection...")
        self._check_command_injection(target)

        if not quick:
            print("  🔍 Running Nikto scan...")
            self._run_nikto(target)

        print(f"✅ Web vulnerability scan complete. Found {len(self.findings)} issues.")
        return self.findings

    def _check_sql_injection(self, target: str, quick: bool = False) -> None:
        """Check for SQL injection vulnerabilities using sqlmap."""
        try:
            # Build sqlmap command
            cmd = [
                "sqlmap",
                "-u", target,
                "--batch",  # Never ask for user input
                "--random-agent",  # Randomize user agent
                "--level=1" if quick else "--level=3",
                "--risk=1" if quick else "--risk=2",
                "--threads=5",
                "--timeout=30",
                "--retries=1",
                "--technique=BEUSTQ",  # All techniques
                "--output-dir=/tmp/akali-sqlmap"
            ]

            result = self.run_command(cmd, timeout=self.timeout)

            # Parse sqlmap output for vulnerabilities
            if "sqlmap identified the following injection point" in result.stdout:
                finding = Finding(
                    id=self.generate_finding_id(),
                    timestamp=datetime.now().isoformat(),
                    severity=Severity.CRITICAL.value,
                    type="sql-injection",
                    title="SQL Injection Vulnerability Detected",
                    description=f"sqlmap detected SQL injection vulnerability at {target}",
                    file=target,
                    cvss=9.8,
                    cwe="CWE-89",
                    owasp="A03:2021 - Injection",
                    fix="Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.",
                    scanner=self.name
                )
                self.findings.append(finding)

            # Check for vulnerable parameters
            if "Parameter:" in result.stdout and "is vulnerable" in result.stdout:
                # Extract vulnerable parameter
                param_match = re.search(r"Parameter: (\w+)", result.stdout)
                param_name = param_match.group(1) if param_match else "unknown"

                finding = Finding(
                    id=self.generate_finding_id(),
                    timestamp=datetime.now().isoformat(),
                    severity=Severity.CRITICAL.value,
                    type="sql-injection",
                    title=f"SQL Injection in Parameter '{param_name}'",
                    description=f"The parameter '{param_name}' is vulnerable to SQL injection attacks.",
                    file=target,
                    cvss=9.8,
                    cwe="CWE-89",
                    owasp="A03:2021 - Injection",
                    fix=f"Sanitize and validate the '{param_name}' parameter. Use prepared statements.",
                    scanner=self.name
                )
                self.findings.append(finding)

        except Exception as e:
            print(f"  ⚠️  SQL injection scan failed: {e}")

    def _check_xss(self, target: str) -> None:
        """Check for Cross-Site Scripting (XSS) vulnerabilities."""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src='javascript:alert(\"XSS\")'>"
        ]

        try:
            # Test for reflected XSS
            for payload in xss_payloads:
                test_url = f"{target}?q={payload}"
                try:
                    response = requests.get(test_url, timeout=10, verify=False)

                    # Check if payload is reflected in response
                    if payload in response.text:
                        finding = Finding(
                            id=self.generate_finding_id(),
                            timestamp=datetime.now().isoformat(),
                            severity=Severity.HIGH.value,
                            type="xss-reflected",
                            title="Reflected Cross-Site Scripting (XSS)",
                            description=f"Reflected XSS detected. Payload '{payload}' was reflected in the response without sanitization.",
                            file=target,
                            cvss=7.1,
                            cwe="CWE-79",
                            owasp="A03:2021 - Injection",
                            fix="Encode all user input before displaying. Use Content-Security-Policy headers. Implement input validation.",
                            scanner=self.name
                        )
                        self.findings.append(finding)
                        break  # Found XSS, no need to test more payloads

                except requests.RequestException:
                    pass  # Skip this payload

        except Exception as e:
            print(f"  ⚠️  XSS scan failed: {e}")

    def _check_csrf(self, target: str) -> None:
        """Check for CSRF vulnerabilities."""
        try:
            response = requests.get(target, timeout=10, verify=False)

            # Check for forms without CSRF tokens
            forms = re.findall(r'<form[^>]*>(.*?)</form>', response.text, re.DOTALL | re.IGNORECASE)

            for form in forms:
                # Check if form has POST method
                if 'method' in form.lower() and 'post' in form.lower():
                    # Look for CSRF token patterns
                    csrf_patterns = [
                        r'csrf',
                        r'_token',
                        r'authenticity_token',
                        r'csrfmiddlewaretoken'
                    ]

                    has_csrf_token = any(re.search(pattern, form, re.IGNORECASE) for pattern in csrf_patterns)

                    if not has_csrf_token:
                        finding = Finding(
                            id=self.generate_finding_id(),
                            timestamp=datetime.now().isoformat(),
                            severity=Severity.MEDIUM.value,
                            type="csrf",
                            title="Missing CSRF Protection",
                            description="Form found without CSRF token. Application may be vulnerable to Cross-Site Request Forgery attacks.",
                            file=target,
                            cvss=5.4,
                            cwe="CWE-352",
                            owasp="A01:2021 - Broken Access Control",
                            fix="Implement CSRF tokens for all state-changing requests. Use SameSite cookie attribute.",
                            scanner=self.name
                        )
                        self.findings.append(finding)
                        break  # Report once per page

        except Exception as e:
            print(f"  ⚠️  CSRF scan failed: {e}")

    def _check_path_traversal(self, target: str) -> None:
        """Check for path traversal vulnerabilities."""
        path_traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]

        try:
            for payload in path_traversal_payloads:
                test_url = f"{target}?file={payload}"
                try:
                    response = requests.get(test_url, timeout=10, verify=False)

                    # Check for signs of successful path traversal
                    if "root:" in response.text or "[extensions]" in response.text or "# localhost" in response.text:
                        finding = Finding(
                            id=self.generate_finding_id(),
                            timestamp=datetime.now().isoformat(),
                            severity=Severity.HIGH.value,
                            type="path-traversal",
                            title="Path Traversal Vulnerability",
                            description=f"Path traversal detected. Server returned sensitive file content for payload '{payload}'.",
                            file=target,
                            cvss=7.5,
                            cwe="CWE-22",
                            owasp="A01:2021 - Broken Access Control",
                            fix="Validate and sanitize file path inputs. Use allowlists for permitted files. Avoid direct file path manipulation.",
                            scanner=self.name
                        )
                        self.findings.append(finding)
                        break

                except requests.RequestException:
                    pass

        except Exception as e:
            print(f"  ⚠️  Path traversal scan failed: {e}")

    def _check_command_injection(self, target: str) -> None:
        """Check for command injection vulnerabilities."""
        cmd_injection_payloads = [
            "; sleep 5",
            "| sleep 5",
            "`sleep 5`",
            "$(sleep 5)"
        ]

        try:
            for payload in cmd_injection_payloads:
                test_url = f"{target}?cmd={payload}"
                try:
                    start_time = datetime.now()
                    response = requests.get(test_url, timeout=10, verify=False)
                    elapsed = (datetime.now() - start_time).total_seconds()

                    # If response took ~5 seconds, likely command injection
                    if elapsed >= 4.5 and elapsed <= 6:
                        finding = Finding(
                            id=self.generate_finding_id(),
                            timestamp=datetime.now().isoformat(),
                            severity=Severity.CRITICAL.value,
                            type="command-injection",
                            title="Command Injection Vulnerability",
                            description=f"Command injection detected. Payload '{payload}' caused a time delay, indicating command execution.",
                            file=target,
                            cvss=9.8,
                            cwe="CWE-78",
                            owasp="A03:2021 - Injection",
                            fix="Never pass user input directly to system commands. Use safe APIs. Implement strict input validation.",
                            scanner=self.name
                        )
                        self.findings.append(finding)
                        break

                except requests.RequestException:
                    pass

        except Exception as e:
            print(f"  ⚠️  Command injection scan failed: {e}")

    def _run_nikto(self, target: str) -> None:
        """Run Nikto web server scanner."""
        try:
            cmd = [
                "nikto",
                "-h", target,
                "-Format", "json",
                "-output", "/tmp/akali-nikto.json",
                "-Tuning", "x",  # All tests
                "-timeout", "10"
            ]

            result = self.run_command(cmd, timeout=self.timeout)

            # Parse Nikto JSON output
            try:
                with open("/tmp/akali-nikto.json", "r") as f:
                    nikto_data = json.load(f)

                if "vulnerabilities" in nikto_data:
                    for vuln in nikto_data.get("vulnerabilities", []):
                        # Map Nikto severity to our severity levels
                        severity = Severity.MEDIUM.value
                        if "critical" in vuln.get("msg", "").lower():
                            severity = Severity.CRITICAL.value
                        elif "high" in vuln.get("msg", "").lower():
                            severity = Severity.HIGH.value

                        finding = Finding(
                            id=self.generate_finding_id(),
                            timestamp=datetime.now().isoformat(),
                            severity=severity,
                            type="nikto-finding",
                            title=vuln.get("msg", "Nikto Finding"),
                            description=f"Nikto identified: {vuln.get('msg', 'Unknown vulnerability')}",
                            file=target,
                            fix="Review Nikto output and apply recommended fixes.",
                            scanner=self.name
                        )
                        self.findings.append(finding)
            except (FileNotFoundError, json.JSONDecodeError):
                # Nikto output parsing failed, continue
                pass

        except Exception as e:
            print(f"  ⚠️  Nikto scan failed: {e}")


def main():
    """CLI for web vulnerability scanner."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python web_vuln_scanner.py <target_url> [--quick]")
        print("Example: python web_vuln_scanner.py https://example.com")
        sys.exit(1)

    target = sys.argv[1]
    quick = "--quick" in sys.argv

    scanner = WebVulnScanner()

    if not scanner.check_available():
        print("❌ Required tools not available. Run: scripts/install_offensive_tools.sh")
        sys.exit(1)

    findings = scanner.scan(target, quick=quick)

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

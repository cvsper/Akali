"""Akali CLI interface logic."""

import sys
from pathlib import Path
from typing import List, Optional

# Add project root and scanners to path
sys.path.insert(0, str(Path.home() / "akali"))
sys.path.append(str(Path.home() / "akali" / "offensive" / "scanners"))

# Import defensive scanners as package (preserves relative imports)
from defensive.scanners.secrets_scanner import SecretsScanner
from defensive.scanners.dependency_scanner import DependencyScanner
from defensive.scanners.sast_scanner import SASTScanner
from defensive.scanners.scanner_base import Finding
from data.findings_db import FindingsDB

# Offensive scanners (standalone imports work due to absolute import strategy)
from web_vuln_scanner import WebVulnScanner
from network_scanner import NetworkScanner
from api_scanner import APIScanner
from exploit_scanner import ExploitScanner


class AkaliCLI:
    """Akali command-line interface."""

    def __init__(self):
        self.db = FindingsDB()
        self.scanners = {
            "secrets": SecretsScanner(),
            "dependencies": DependencyScanner(),
            "sast": SASTScanner()
        }
        self.offensive_scanners = {
            "web": WebVulnScanner(),
            "network": NetworkScanner(),
            "api": APIScanner(),
            "exploit": ExploitScanner()
        }

    def scan(self, target: str, scanner_types: Optional[List[str]] = None) -> List[Finding]:
        """Run security scan on target."""
        if not scanner_types:
            scanner_types = list(self.scanners.keys())

        all_findings = []

        for scanner_type in scanner_types:
            if scanner_type not in self.scanners:
                print(f"⚠️  Unknown scanner: {scanner_type}")
                continue

            scanner = self.scanners[scanner_type]

            if not scanner.check_available():
                print(f"⚠️  Scanner '{scanner_type}' not available (tool not installed)")
                continue

            print(f"🔍 Running {scanner_type} scanner...")
            try:
                findings = scanner.scan(target)
                all_findings.extend(findings)

                if findings:
                    print(f"   Found {len(findings)} issues")
                    # Store in database
                    self.db.add_findings([f.to_dict() for f in findings])
                else:
                    print(f"   ✅ No issues found")

            except Exception as e:
                print(f"   ❌ Error: {e}")

        return all_findings

    def list_findings(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        scanner: Optional[str] = None
    ):
        """List findings with optional filters."""
        findings = self.db.list_findings(status=status, severity=severity, scanner=scanner)

        if not findings:
            print("No findings match the filters.")
            return

        print(f"\n📋 Found {len(findings)} findings:\n")

        for finding in findings:
            severity_emoji = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🔵",
                "info": "⚪"
            }.get(finding.get("severity", "info"), "⚪")

            print(f"{severity_emoji} {finding['id']} - {finding['title']}")
            print(f"   Severity: {finding['severity'].upper()}")
            if finding.get("file"):
                location = f"{finding['file']}"
                if finding.get("line"):
                    location += f":{finding['line']}"
                print(f"   Location: {location}")
            print(f"   Status: {finding['status']}")
            print()

    def show_finding(self, finding_id: str):
        """Show detailed information about a finding."""
        finding = self.db.get_finding(finding_id)

        if not finding:
            print(f"❌ Finding not found: {finding_id}")
            return

        print(f"\n🔍 Finding: {finding['id']}\n")
        print(f"Title: {finding['title']}")
        print(f"Severity: {finding['severity'].upper()}")
        print(f"Type: {finding['type']}")
        print(f"Status: {finding['status']}")
        print(f"Timestamp: {finding['timestamp']}")

        if finding.get("file"):
            location = f"{finding['file']}"
            if finding.get("line"):
                location += f":{finding['line']}"
            print(f"Location: {location}")

        print(f"\nDescription:")
        print(f"  {finding['description']}")

        if finding.get("cvss"):
            print(f"\nCVSS: {finding['cvss']}")
        if finding.get("cwe"):
            print(f"CWE: {finding['cwe']}")
        if finding.get("owasp"):
            print(f"OWASP: {finding['owasp']}")

        if finding.get("fix"):
            print(f"\nRecommended Fix:")
            print(f"  {finding['fix']}")

        print()

    def show_stats(self):
        """Show database statistics."""
        stats = self.db.get_stats()

        print("\n📊 Akali Statistics\n")
        print(f"Total Findings: {stats['total']}")

        if stats['by_severity']:
            print("\nBy Severity:")
            for severity, count in sorted(stats['by_severity'].items()):
                print(f"  {severity}: {count}")

        if stats['by_status']:
            print("\nBy Status:")
            for status, count in sorted(stats['by_status'].items()):
                print(f"  {status}: {count}")

        if stats['by_scanner']:
            print("\nBy Scanner:")
            for scanner, count in sorted(stats['by_scanner'].items()):
                print(f"  {scanner}: {count}")

        print()

    def attack(self, target: str, attack_type: str = "full", quick: bool = False, **kwargs) -> List[Finding]:
        """Run offensive security scan on target.

        ⚠️  WARNING: Only use on systems you own or have explicit permission to test.

        Args:
            target: Target URL/hostname/IP
            attack_type: Type of attack scan (web, network, api, full)
            quick: Run quick scans only
            **kwargs: Additional scanner-specific arguments

        Returns:
            List of findings
        """
        print("\n⚠️  AUTHORIZATION CHECK")
        print("Offensive scanning requires explicit permission.")
        print("Only scan systems you own or have written authorization to test.")

        consent = input("\nDo you have authorization to scan this target? (yes/no): ")
        if consent.lower() != "yes":
            print("❌ Scan cancelled. Authorization required.")
            return []

        all_findings = []

        if attack_type in ["web", "full"]:
            print("\n🕷️  Running web vulnerability scan...")
            scanner = self.offensive_scanners["web"]
            if scanner.check_available():
                try:
                    findings = scanner.scan(target, quick=quick)
                    all_findings.extend(findings)
                    if findings:
                        self.db.add_findings([f.to_dict() for f in findings])
                except Exception as e:
                    print(f"   ❌ Web scan error: {e}")
            else:
                print("   ⚠️  Web scanner not available (tools not installed)")

        if attack_type in ["network", "full"]:
            print("\n🌐 Running network scan...")
            scanner = self.offensive_scanners["network"]
            if scanner.check_available():
                try:
                    findings = scanner.scan(target, quick=quick, ports=kwargs.get("ports"))
                    all_findings.extend(findings)
                    if findings:
                        self.db.add_findings([f.to_dict() for f in findings])
                except Exception as e:
                    print(f"   ❌ Network scan error: {e}")
            else:
                print("   ⚠️  Network scanner not available (tools not installed)")

        if attack_type in ["api", "full"]:
            print("\n🔌 Running API scan...")
            scanner = self.offensive_scanners["api"]
            if scanner.check_available():
                try:
                    findings = scanner.scan(target, wordlist=kwargs.get("wordlist"))
                    all_findings.extend(findings)
                    if findings:
                        self.db.add_findings([f.to_dict() for f in findings])
                except Exception as e:
                    print(f"   ❌ API scan error: {e}")
            else:
                print("   ⚠️  API scanner not available (tools not installed)")

        print(f"\n✅ Attack scan complete. Found {len(all_findings)} total findings.")

        # Print summary
        by_severity = {}
        for finding in all_findings:
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1

        if by_severity:
            print("\nFindings by severity:")
            for severity in ["critical", "high", "medium", "low", "info"]:
                count = by_severity.get(severity, 0)
                if count > 0:
                    print(f"  {severity.upper()}: {count}")

        return all_findings

    def exploit(self, cve_id: str):
        """Look up CVE and exploit information.

        Args:
            cve_id: CVE identifier (e.g., CVE-2021-44228)
        """
        scanner = self.offensive_scanners["exploit"]

        if not scanner.check_available():
            print("⚠️  Warning: NVD API not accessible. Results may be limited.")

        cve_info = scanner.lookup_cve(cve_id)

        if cve_info:
            scanner.print_cve_report(cve_info)
        else:
            print(f"❌ Failed to retrieve information for {cve_id}")

    def status(self):
        """Show Akali status and tool availability."""
        print("\n🥷 Akali Status\n")

        print("Defensive Scanners:")
        for name, scanner in self.scanners.items():
            available = "✅" if scanner.check_available() else "❌"
            print(f"  {available} {name}")

        print("\nOffensive Scanners:")
        for name, scanner in self.offensive_scanners.items():
            if name == "exploit":
                # Exploit scanner is API-based, always "available"
                print(f"  ✅ {name} (CVE lookup)")
            else:
                available = "✅" if scanner.check_available() else "❌"
                print(f"  {available} {name}")

        print()
        self.show_stats()

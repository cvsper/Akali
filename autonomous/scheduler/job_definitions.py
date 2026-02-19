"""Job definitions for Akali autonomous scheduler."""

import subprocess
from pathlib import Path
from datetime import datetime
import sys
import json

sys.path.insert(0, str(Path.home() / "akali"))
from core.cli import AkaliCLI


# Family projects to scan
FAMILY_PROJECTS = [
    {"name": "umuve-platform", "path": str(Path.home() / "goumuve" / "umuve" / "platform")},
    {"name": "umuve-backend", "path": str(Path.home() / "goumuve" / "umuve" / "backend")},
    {"name": "zim-memory", "path": str(Path.home() / "zim-memory")},
    {"name": "hub", "path": str(Path.home() / "services" / "hub")},
]

# Authorized targets for offensive scans (must be in auth whitelist)
AUTHORIZED_TARGETS = [
    {"name": "localhost-test", "target": "http://localhost:3000", "type": "web"},
    {"name": "local-api", "target": "http://localhost:5000", "type": "api"},
]


def daily_defensive_scan():
    """Run defensive security scan on all family projects."""
    print("🥷 Starting daily defensive scan")

    cli = AkaliCLI()
    total_findings = 0

    for project in FAMILY_PROJECTS:
        project_path = Path(project["path"])

        if not project_path.exists():
            print(f"  ⚠️  Project not found: {project['name']} ({project['path']})")
            continue

        print(f"\n  📁 Scanning {project['name']}...")

        try:
            findings = cli.scan(str(project_path))
            total_findings += len(findings)

            # Alert on critical findings
            critical_findings = [f for f in findings if f.severity == "critical"]
            if critical_findings:
                print(f"    🚨 {len(critical_findings)} CRITICAL findings!")
                # TODO: Send to ZimMemory

        except Exception as e:
            print(f"    ❌ Error scanning {project['name']}: {e}")

    print(f"\n✅ Daily defensive scan complete. Total findings: {total_findings}")
    return total_findings


def weekly_offensive_scan():
    """Run offensive security scan on authorized targets."""
    print("🥷 Starting weekly offensive scan")

    cli = AkaliCLI()
    total_findings = 0

    for target in AUTHORIZED_TARGETS:
        print(f"\n  🎯 Scanning {target['name']} ({target['target']})...")

        try:
            # Run appropriate scan type
            findings = []

            if target['type'] == 'web':
                # Note: This will still prompt for authorization in real run
                # In production, would use a headless mode or pre-authorized flag
                print(f"    ⚠️  Requires manual authorization for: {target['target']}")
            elif target['type'] == 'api':
                print(f"    ⚠️  Requires manual authorization for: {target['target']}")

            total_findings += len(findings)

        except Exception as e:
            print(f"    ❌ Error scanning {target['name']}: {e}")

    print(f"\n✅ Weekly offensive scan complete. Total findings: {total_findings}")
    return total_findings


def daily_cve_check():
    """Check for new CVEs affecting our stack."""
    print("🥷 Starting daily CVE check")

    # Collect all dependencies from family projects
    dependencies = {
        "python": set(),
        "npm": set()
    }

    for project in FAMILY_PROJECTS:
        project_path = Path(project["path"])

        if not project_path.exists():
            continue

        # Check for requirements.txt (Python)
        requirements_file = project_path / "requirements.txt"
        if requirements_file.exists():
            try:
                with open(requirements_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # Extract package name (before ==, >=, etc.)
                            pkg = line.split('==')[0].split('>=')[0].split('<=')[0].strip()
                            dependencies["python"].add(pkg)
            except Exception as e:
                print(f"  ⚠️  Error reading requirements.txt: {e}")

        # Check for package.json (npm)
        package_json = project_path / "package.json"
        if package_json.exists():
            try:
                with open(package_json, 'r') as f:
                    data = json.load(f)
                    for pkg in data.get("dependencies", {}).keys():
                        dependencies["npm"].add(pkg)
                    for pkg in data.get("devDependencies", {}).keys():
                        dependencies["npm"].add(pkg)
            except Exception as e:
                print(f"  ⚠️  Error reading package.json: {e}")

    print(f"\n  📦 Tracking {len(dependencies['python'])} Python packages")
    print(f"  📦 Tracking {len(dependencies['npm'])} npm packages")

    # TODO: Query CVE database for these packages
    # For now, just log the check
    print("\n✅ Daily CVE check complete")

    return 0


def daily_report_generation():
    """Generate and distribute daily security report."""
    print("🥷 Generating daily security report")

    from data.findings_db import FindingsDB
    from offensive.reports.report_generator import ReportGenerator

    db = FindingsDB()
    report_gen = ReportGenerator()

    # Get findings from last 24 hours
    all_findings = db.list_findings()
    recent_findings = []

    now = datetime.now()
    for finding in all_findings:
        try:
            timestamp = datetime.fromisoformat(finding['timestamp'])
            hours_ago = (now - timestamp).total_seconds() / 3600
            if hours_ago <= 24:
                recent_findings.append(finding)
        except:
            pass

    print(f"  📊 {len(recent_findings)} findings in last 24 hours")

    if recent_findings:
        # Generate reports
        from defensive.scanners.scanner_base import Finding

        finding_objects = []
        for f in recent_findings:
            try:
                finding_objects.append(Finding(**f))
            except:
                pass

        if finding_objects:
            # Generate HTML report
            html_path = report_gen.generate_html(
                finding_objects,
                target="Daily Scan",
                scan_type="Automated Daily Scan"
            )
            print(f"  📄 HTML report: {html_path}")

            # Generate Markdown report
            md_path = report_gen.generate_markdown(
                finding_objects,
                target="Daily Scan",
                scan_type="Automated Daily Scan"
            )
            print(f"  📄 Markdown report: {md_path}")

    print("\n✅ Daily report generation complete")
    return len(recent_findings)


def weekly_summary_report():
    """Generate and distribute weekly summary report."""
    print("🥷 Generating weekly summary report")

    from data.findings_db import FindingsDB

    db = FindingsDB()
    stats = db.get_stats()

    print(f"\n  📊 Weekly Security Summary:")
    print(f"     Total findings: {stats['total']}")

    if stats['by_severity']:
        print(f"     By severity:")
        for severity, count in sorted(stats['by_severity'].items()):
            print(f"       {severity}: {count}")

    print("\n✅ Weekly summary report complete")
    return stats['total']


# Phase 4: Intelligence & Metrics Jobs

def hourly_cve_check():
    """Check for new CVEs every hour (Phase 4)."""
    print("🥷 Running hourly CVE check")

    script = Path.home() / "akali" / "intelligence" / "cve_monitor" / "cve_tracker.py"
    result = subprocess.run(
        ["python3", str(script), "critical"],
        capture_output=True,
        text=True
    )

    print(result.stdout)

    # Check for critical alerts
    if "CRITICAL" in result.stdout or "HIGH" in result.stdout:
        print("  🚨 Critical CVEs detected!")
        # TODO: Send immediate alert to ZimMemory

    print("\n✅ Hourly CVE check complete")
    return 0


def daily_scorecard_update():
    """Calculate and update security scorecard (Phase 4)."""
    print("🥷 Calculating security scorecard")

    script = Path.home() / "akali" / "metrics" / "scorecard" / "score_calculator.py"
    result = subprocess.run(
        ["python3", str(script)],
        capture_output=True,
        text=True
    )

    print(result.stdout)

    # Extract score from output
    for line in result.stdout.split('\n'):
        if "Overall Score:" in line:
            print(f"  📊 {line.strip()}")

    print("\n✅ Scorecard update complete")
    return 0


def daily_intel_update():
    """Update threat intelligence feeds (Phase 4)."""
    print("🥷 Updating threat intelligence")

    # Fetch security feeds
    feed_script = Path.home() / "akali" / "intelligence" / "threat_hub" / "feed_aggregator.py"
    feed_result = subprocess.run(
        ["python3", str(feed_script), "fetch", "24"],
        capture_output=True,
        text=True
    )

    print(feed_result.stdout)

    print("\n✅ Intel update complete")
    return 0


def weekly_supply_chain_audit():
    """Audit supply chain dependencies (Phase 4)."""
    print("🥷 Running weekly supply chain audit")

    # Scan dependencies
    dep_script = Path.home() / "akali" / "intelligence" / "cve_monitor" / "dependency_mapper.py"
    result = subprocess.run(
        ["python3", str(dep_script), "scan"],
        capture_output=True,
        text=True
    )

    print(result.stdout)

    # Build supply chain inventory
    inv_script = Path.home() / "akali" / "intelligence" / "supply_chain" / "inventory_builder.py"
    inv_result = subprocess.run(
        ["python3", str(inv_script)],
        capture_output=True,
        text=True
    )

    print(inv_result.stdout)

    print("\n✅ Supply chain audit complete")
    return 0


def register_all_jobs(cron_manager):
    """Register all job definitions with the cron manager.

    Args:
        cron_manager: CronManager instance
    """
    # Daily defensive scan at 2 AM
    cron_manager.register_job(
        job_id="daily_defensive_scan",
        name="Daily Defensive Scan",
        schedule="daily",
        command=daily_defensive_scan,
        description="Scan all family projects for secrets, dependencies, and SAST issues"
    )

    # Weekly offensive scan on Sunday at 1 AM
    cron_manager.register_job(
        job_id="weekly_offensive_scan",
        name="Weekly Offensive Scan",
        schedule="weekly",
        command=weekly_offensive_scan,
        description="Run offensive security scans on authorized targets"
    )

    # Daily CVE check at 9 AM
    cron_manager.register_job(
        job_id="daily_cve_check",
        name="Daily CVE Check",
        schedule="@every 1d",
        command=daily_cve_check,
        description="Check for new CVEs affecting our dependency stack"
    )

    # Daily report generation at 8 AM
    cron_manager.register_job(
        job_id="daily_report_generation",
        name="Daily Report Generation",
        schedule="@every 1d",
        command=daily_report_generation,
        description="Generate daily security report from last 24 hours"
    )

    # Weekly summary report on Monday at 9 AM
    cron_manager.register_job(
        job_id="weekly_summary_report",
        name="Weekly Summary Report",
        schedule="weekly",
        command=weekly_summary_report,
        description="Generate weekly security summary with trends"
    )

    # Phase 4: Intelligence & Metrics Jobs

    # Hourly CVE check
    cron_manager.register_job(
        job_id="hourly_cve_check",
        name="Hourly CVE Check",
        schedule="@every 1h",
        command=hourly_cve_check,
        description="Check for new Critical/High CVEs every hour"
    )

    # Daily scorecard calculation at 8:30 AM
    cron_manager.register_job(
        job_id="daily_scorecard_update",
        name="Daily Scorecard Update",
        schedule="@every 1d",
        command=daily_scorecard_update,
        description="Calculate and update family security scorecard"
    )

    # Daily intel update at 7 AM
    cron_manager.register_job(
        job_id="daily_intel_update",
        name="Daily Intelligence Update",
        schedule="@every 1d",
        command=daily_intel_update,
        description="Fetch and aggregate security threat intelligence"
    )

    # Weekly supply chain audit on Sunday at 2 AM
    cron_manager.register_job(
        job_id="weekly_supply_chain_audit",
        name="Weekly Supply Chain Audit",
        schedule="weekly",
        command=weekly_supply_chain_audit,
        description="Audit all project dependencies and supply chain"
    )

    print(f"✅ Registered {len(cron_manager.jobs)} jobs")


if __name__ == "__main__":
    # Test job registration
    from cron_manager import CronManager

    manager = CronManager()
    register_all_jobs(manager)

    print("\n📋 Registered Jobs:\n")
    for job in manager.list_jobs():
        print(f"  • {job['job_id']}: {job['name']}")
        print(f"    Schedule: {job['schedule']}")
        print(f"    Description: {job['description']}")
        print()

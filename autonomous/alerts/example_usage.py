#!/usr/bin/env python3
"""
Example usage of Akali Alert Manager and ZimMemory integration.

This script demonstrates the complete alert workflow:
1. Create a security finding
2. Create an alert for the finding
3. Send the alert to ZimMemory
4. Handle acknowledgments and escalations
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from data.findings_db import FindingsDB
from autonomous.alerts.alert_manager import AlertManager
from autonomous.alerts.zim_alerter import ZimAlerter


def example_basic_alert():
    """Example 1: Create and send a basic alert."""
    print("\n=== Example 1: Basic Alert ===\n")

    # Initialize components
    db = FindingsDB()
    manager = AlertManager(findings_db=db)
    alerter = ZimAlerter()

    # Create a security finding
    finding = {
        "id": "vul-2026-001",
        "title": "Cross-Site Scripting (XSS) Vulnerability",
        "description": "Reflected XSS in search parameter. User input is not properly sanitized.",
        "severity": "high",
        "scanner": "zap",
        "target": "app.goumuve.com",
        "file_path": "/app/search/page.tsx",
        "line_number": 142,
        "status": "open",
        "remediation": "Use proper HTML encoding/escaping for user input. Consider Content Security Policy.",
        "created_at": "2026-02-19T12:00:00"
    }

    # Add to database
    db.add_finding(finding)
    print(f"✓ Finding created: {finding['id']}")

    # Create alert (auto-routes to appropriate agent)
    alert_result = manager.send_alert(finding["id"])
    print(f"✓ Alert created: {alert_result['alert_id']}")
    print(f"  - Routed to: {alert_result['agent_id']}")
    print(f"  - Severity: {alert_result['severity']}")

    # Get full alert details
    alert = manager.get_alert(alert_result["alert_id"])

    # Send to ZimMemory
    zim_result = alerter.send_to_zim(finding, alert)

    if zim_result["success"]:
        print(f"✓ Sent to ZimMemory")
        print(f"  - Message ID: {zim_result['message_id']}")

        # Mark as sent
        manager.mark_sent(alert_result["alert_id"], success=True)
        print(f"✓ Alert marked as sent")
    else:
        print(f"✗ Failed to send to ZimMemory: {zim_result.get('error')}")


def example_critical_alert_with_escalation():
    """Example 2: Critical alert with escalation workflow."""
    print("\n=== Example 2: Critical Alert with Escalation ===\n")

    db = FindingsDB()
    manager = AlertManager(findings_db=db)
    alerter = ZimAlerter()

    # Critical finding
    finding = {
        "id": "vul-2026-002",
        "title": "SQL Injection in Authentication",
        "description": "Critical SQL injection vulnerability in login endpoint allows authentication bypass.",
        "severity": "critical",
        "scanner": "nuclei",
        "target": "api.goumuve.com",
        "file_path": "/api/auth/login.py",
        "line_number": 78,
        "status": "open",
        "remediation": "Use parameterized queries. Never concatenate user input into SQL strings.",
        "created_at": "2026-02-19T13:00:00"
    }

    db.add_finding(finding)
    print(f"✓ Critical finding: {finding['id']}")

    # Create alert
    alert_result = manager.send_alert(finding["id"])
    alert = manager.get_alert(alert_result["alert_id"])
    print(f"✓ Alert created for {alert['agent_id']}")

    # Send to ZimMemory
    zim_result = alerter.send_to_zim(finding, alert)

    if zim_result["success"]:
        manager.mark_sent(alert_result["alert_id"], success=True)
        print(f"✓ Alert sent successfully")
    else:
        print(f"⚠️  Send failed, will retry later")

    # Simulate escalation (if unacknowledged for 24h)
    print("\n  Simulating escalation scenario...")
    escalation_result = alerter.send_escalation(
        alert=alert,
        finding=finding,
        reason="Critical vulnerability unacknowledged for 24 hours"
    )

    if escalation_result["success"]:
        print(f"✓ Escalation sent to sevs")
    else:
        print(f"✗ Escalation failed: {escalation_result.get('error')}")


def example_daily_digest():
    """Example 3: Send daily digest of low/medium findings."""
    print("\n=== Example 3: Daily Digest ===\n")

    db = FindingsDB()
    manager = AlertManager(findings_db=db)
    alerter = ZimAlerter()

    # Create multiple low/medium findings
    findings = [
        {
            "id": "vul-2026-003",
            "title": "Missing Security Headers",
            "description": "X-Frame-Options and CSP headers not set",
            "severity": "low",
            "scanner": "nikto",
            "target": "app.goumuve.com",
            "status": "open",
            "created_at": "2026-02-19T08:00:00"
        },
        {
            "id": "vul-2026-004",
            "title": "Outdated JavaScript Library",
            "description": "jQuery 3.5.0 has known vulnerabilities",
            "severity": "medium",
            "scanner": "dependency_check",
            "target": "platform",
            "status": "open",
            "created_at": "2026-02-19T09:00:00"
        },
        {
            "id": "vul-2026-005",
            "title": "Information Disclosure",
            "description": "Server version exposed in HTTP headers",
            "severity": "low",
            "scanner": "nikto",
            "target": "api.goumuve.com",
            "status": "open",
            "created_at": "2026-02-19T10:00:00"
        }
    ]

    # Add findings and create alerts
    alerts_list = []
    findings_list = []

    for finding in findings:
        db.add_finding(finding)
        alert_result = manager.send_alert(finding["id"])
        alert = manager.get_alert(alert_result["alert_id"])

        alerts_list.append(alert)
        findings_list.append(finding)

    print(f"✓ Created {len(findings)} findings with alerts")

    # Send as digest instead of individual alerts
    digest_result = alerter.send_digest(
        alerts=alerts_list,
        findings=findings_list,
        digest_type="daily"
    )

    print(f"✓ Digest sent to {digest_result['total_agents']} agents")
    print(f"  - Total alerts: {digest_result['total_alerts']}")

    for result in digest_result["results"]:
        if result["success"]:
            print(f"  ✓ {result['agent_id']}: {result['alert_count']} alerts")
        else:
            print(f"  ✗ {result['agent_id']}: {result.get('error')}")


def example_manual_routing():
    """Example 4: Manually route alert to specific agent."""
    print("\n=== Example 4: Manual Routing ===\n")

    db = FindingsDB()
    manager = AlertManager(findings_db=db)
    alerter = ZimAlerter()

    # Finding that needs specific agent attention
    finding = {
        "id": "vul-2026-006",
        "title": "Test Coverage Below Threshold",
        "description": "Authentication module test coverage is only 45%, below the 80% requirement",
        "severity": "medium",
        "scanner": "pytest",
        "target": "backend",
        "status": "open",
        "created_at": "2026-02-19T14:00:00"
    }

    db.add_finding(finding)
    print(f"✓ Finding created: {finding['id']}")

    # Manually route to banksy (QA lead)
    alert_result = manager.send_alert(finding["id"], agent_id="banksy")
    alert = manager.get_alert(alert_result["alert_id"])

    print(f"✓ Alert manually routed to: {alert['agent_id']}")

    # Send with override
    zim_result = alerter.send_to_zim(finding, alert, recipient_id="banksy")

    if zim_result["success"]:
        manager.mark_sent(alert_result["alert_id"], success=True)
        print(f"✓ Alert delivered to banksy")
    else:
        print(f"⚠️  Delivery failed: {zim_result.get('error')}")


def example_alert_stats():
    """Example 5: View alert statistics."""
    print("\n=== Example 5: Alert Statistics ===\n")

    manager = AlertManager()

    # Get overall stats
    stats = manager.get_stats()

    print("Alert Statistics:")
    print(f"  Pending: {stats['pending_alerts']}")
    print(f"  Sent: {stats['sent_alerts']}")
    print(f"  Acknowledged: {stats['acknowledged_alerts']}")
    print(f"  Escalated: {stats['escalated_alerts']}")
    print(f"  History: {stats['history_count']}")
    print()
    print("Totals:")
    print(f"  Total Sent: {stats['total_sent']}")
    print(f"  Total Acknowledged: {stats['total_acknowledged']}")
    print(f"  Total Escalated: {stats['total_escalated']}")

    # List pending alerts
    pending = manager.list_alerts(status="pending")
    if pending:
        print(f"\nPending Alerts ({len(pending)}):")
        for alert in pending:
            print(f"  - {alert['id']}: {alert['title']} ({alert['severity']})")


def main():
    """Run all examples."""
    print("=" * 70)
    print("Akali Alert System - Usage Examples")
    print("=" * 70)

    try:
        # Run examples
        example_basic_alert()
        example_critical_alert_with_escalation()
        example_daily_digest()
        example_manual_routing()
        example_alert_stats()

        print("\n" + "=" * 70)
        print("✅ All examples completed!")
        print("=" * 70)

        print("\nNote: ZimMemory connection may fail if service is not running.")
        print("This is expected in local testing. Alerts will still be queued.")

    except Exception as e:
        print(f"\n❌ Example failed: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

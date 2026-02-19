#!/usr/bin/env python3
"""
Complete alert workflow demonstration.

This script shows the end-to-end flow:
Finding → Alert → ZimMemory → Agent Notification
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from data.findings_db import FindingsDB
from autonomous.alerts import AlertManager, ZimAlerter


def print_section(title):
    """Print section header."""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70 + "\n")


def demo_workflow():
    """Run complete alert workflow demonstration."""
    print_section("Akali Alert System - Complete Workflow Demo")

    # Initialize components
    print("Initializing components...")
    db = FindingsDB()
    manager = AlertManager(findings_db=db)
    alerter = ZimAlerter()
    print("✓ Components initialized\n")

    # Step 1: Create a critical security finding
    print_section("Step 1: Create Security Finding")

    finding = {
        "id": "demo-vul-001",
        "title": "Authentication Bypass Vulnerability",
        "description": "Critical authentication bypass found in OAuth callback handler. "
                      "Improper validation of state parameter allows session fixation attacks.",
        "severity": "critical",
        "scanner": "manual",
        "target": "api.goumuve.com",
        "file_path": "/api/oauth/callback.py",
        "line_number": 156,
        "status": "open",
        "remediation": "1. Validate state parameter against server-side session\n"
                      "2. Implement CSRF token validation\n"
                      "3. Add rate limiting to OAuth endpoints\n"
                      "4. Log all authentication attempts",
        "cvss_score": 9.1,
        "cwe_id": "CWE-287",
        "created_at": "2026-02-19T15:00:00"
    }

    db.add_finding(finding)
    print(f"Finding ID: {finding['id']}")
    print(f"Title: {finding['title']}")
    print(f"Severity: {finding['severity'].upper()}")
    print(f"Target: {finding['target']}")
    print(f"Scanner: {finding['scanner']}")
    print("✓ Finding stored in database")

    # Step 2: Create alert with routing
    print_section("Step 2: Create Alert")

    alert_result = manager.send_alert(finding["id"])

    print(f"Alert ID: {alert_result['alert_id']}")
    print(f"Finding ID: {alert_result['finding_id']}")
    print(f"Routed to: {alert_result['agent_id']}")
    print(f"Severity: {alert_result['severity']}")
    print(f"Status: {alert_result['status']}")
    print("✓ Alert created and queued")

    # Show routing logic
    print("\nRouting Logic:")
    print("  - Scanner: manual (not auto-detected)")
    print("  - Target: api.goumuve.com (backend)")
    print("  - Severity: critical (high priority)")
    print(f"  → Routed to: {alert_result['agent_id']} (backend specialist)")

    # Step 3: Get alert details
    print_section("Step 3: Retrieve Alert Details")

    alert = manager.get_alert(alert_result["alert_id"])

    print("Alert Details:")
    print(f"  ID: {alert['id']}")
    print(f"  Title: {alert['title']}")
    print(f"  Target: {alert['target']}")
    print(f"  Created: {alert['created_at']}")
    print(f"  Status: {alert['status']}")
    print(f"  Agent: {alert['agent_id']}")
    print("✓ Alert retrieved from queue")

    # Step 4: Format message for ZimMemory
    print_section("Step 4: Format ZimMemory Message")

    message = alerter._format_message(finding, alert)
    print("Message Preview:")
    print("-" * 70)
    print(message)
    print("-" * 70)
    print(f"✓ Message formatted ({len(message)} characters)")

    # Step 5: Send to ZimMemory (with retry logic)
    print_section("Step 5: Send to ZimMemory")

    print(f"Target: {alerter.zim_url}/messages/send")
    print(f"Recipient: {alert['agent_id']}")
    print(f"Priority: {alerter._map_priority(finding['severity'])}")
    print(f"Sender: {alerter.sender_id}")
    print()

    print("Attempting to send (with 3 retries)...")
    zim_result = alerter.send_to_zim(finding, alert)

    if zim_result["success"]:
        print("✓ Alert sent successfully!")
        print(f"  - Message ID: {zim_result['message_id']}")
        print(f"  - Recipient: {zim_result['recipient_id']}")
        print(f"  - Attempts: {zim_result['attempt']}")

        # Mark as sent in alert manager
        manager.mark_sent(alert_result["alert_id"], success=True)
        print("✓ Alert marked as sent in queue")

    else:
        print("⚠️  Alert send failed (this is expected if ZimMemory is offline)")
        print(f"  - Error: {zim_result['error']}")
        print(f"  - Attempts: {zim_result['attempts']}")
        print("  - Alert remains in queue for retry")

    # Step 6: Check alert status
    print_section("Step 6: Alert Status and Statistics")

    # Get updated alert
    updated_alert = manager.get_alert(alert_result["alert_id"])

    if updated_alert:
        print("Updated Alert Status:")
        print(f"  Status: {updated_alert['status']}")
        print(f"  Sent at: {updated_alert.get('sent_at', 'Not sent')}")
        print(f"  Retry count: {updated_alert['retry_count']}")
    else:
        print("Alert moved to history")

    # Get statistics
    stats = manager.get_stats()
    print("\nAlert System Statistics:")
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

    # Step 7: Demonstrate escalation (simulation)
    print_section("Step 7: Escalation Workflow (Simulated)")

    print("Escalation Scenario:")
    print("  - Alert sent to agent")
    print("  - 24 hours pass without acknowledgment")
    print("  - System checks for stale alerts")
    print("  - Alert escalated to sevs")
    print()

    # Check for escalations (won't find any in real-time, but shows the API)
    escalations = manager.check_escalations()
    print(f"Current escalations: {len(escalations)}")

    if not escalations:
        print("\n(Simulating escalation for demonstration)")
        escalation_result = alerter.send_escalation(
            alert=alert,
            finding=finding,
            reason="DEMO: Alert unacknowledged for 24+ hours"
        )

        if escalation_result["success"]:
            print("✓ Escalation sent to sevs")
        else:
            print(f"⚠️  Escalation failed: {escalation_result.get('error')}")

    # Step 8: Summary
    print_section("Workflow Summary")

    print("Complete alert workflow demonstrated:")
    print()
    print("1. ✓ Security finding created in database")
    print("2. ✓ Alert created with intelligent routing")
    print("3. ✓ Alert details retrieved from queue")
    print("4. ✓ Rich message formatted for ZimMemory")
    print("5. ✓ Alert sent with retry logic")
    print("6. ✓ Alert status tracked and statistics updated")
    print("7. ✓ Escalation workflow demonstrated")
    print()
    print("Alert System Features:")
    print("  - Deduplication (24h window)")
    print("  - Rate limiting (10/hour)")
    print("  - Intelligent routing (by scanner/target/severity)")
    print("  - Retry logic (3 attempts, exponential backoff)")
    print("  - Escalation (24h unacknowledged)")
    print("  - Full audit trail")
    print()
    print("Integration Points:")
    print("  - Findings Database (storage)")
    print("  - ZimMemory API (agent messaging)")
    print("  - Alert Queue (persistence)")
    print()

    # Cleanup option
    print_section("Cleanup")
    print("Demo finding and alerts remain in the system.")
    print("To remove demo data:")
    print(f"  - Finding: `akali findings delete {finding['id']}`")
    print(f"  - Alerts: Check queue at ~/akali/autonomous/alerts/alert_queue.json")
    print()
    print("To clean old history:")
    print("  manager.cleanup_old_history(days=30)")

    print("\n" + "=" * 70)
    print("  Demo Complete!")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    try:
        demo_workflow()
    except Exception as e:
        print(f"\n❌ Demo failed: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

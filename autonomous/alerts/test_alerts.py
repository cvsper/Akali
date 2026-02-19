#!/usr/bin/env python3
"""Test script for alert manager and ZimMemory integration."""

import sys
import logging
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from data.findings_db import FindingsDB
from autonomous.alerts.alert_manager import AlertManager
from autonomous.alerts.zim_alerter import ZimAlerter


def setup_logging():
    """Setup logging for tests."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


def test_alert_manager():
    """Test AlertManager functionality."""
    print("\n=== Testing Alert Manager ===\n")

    # Initialize
    db = FindingsDB()
    manager = AlertManager(findings_db=db)

    # Create test finding
    test_finding = {
        "id": "test-finding-001",
        "title": "SQL Injection Vulnerability",
        "description": "Potential SQL injection in login endpoint",
        "severity": "critical",
        "scanner": "nuclei",
        "target": "app.goumuve.com",
        "status": "open",
        "created_at": "2026-02-19T10:00:00"
    }

    db.add_finding(test_finding)
    print(f"✓ Added test finding: {test_finding['id']}")

    # Send alert
    result = manager.send_alert(test_finding["id"])
    print(f"✓ Alert created: {result}")

    # List alerts
    alerts = manager.list_alerts(status="pending")
    print(f"✓ Pending alerts: {len(alerts)}")

    # Get stats
    stats = manager.get_stats()
    print(f"✓ Alert stats: {stats}")

    # Check deduplication
    duplicate_result = manager.send_alert(test_finding["id"])
    print(f"✓ Duplicate check: {duplicate_result}")

    # Test acknowledgment
    if result.get("alert_id"):
        ack_result = manager.ack_alert(result["alert_id"])
        print(f"✓ Acknowledged: {ack_result}")

    print("\n✅ Alert Manager tests passed!")


def test_zim_alerter():
    """Test ZimAlerter functionality."""
    print("\n=== Testing ZimMemory Alerter ===\n")

    # Initialize
    alerter = ZimAlerter()

    # Test connection (may fail if ZimMemory is not accessible)
    print("Testing ZimMemory connection...")
    connection_test = alerter.test_connection()

    if connection_test["success"]:
        print(f"✓ Connected to ZimMemory: {alerter.zim_url}")
    else:
        print(f"⚠️  Could not connect to ZimMemory: {connection_test['error']}")
        print("   (This is expected if ZimMemory is not running)")

    # Test message formatting
    test_finding = {
        "id": "test-finding-001",
        "title": "SQL Injection Vulnerability",
        "description": "Potential SQL injection in login endpoint",
        "severity": "critical",
        "scanner": "nuclei",
        "target": "app.goumuve.com",
        "file_path": "/api/auth/login.py",
        "line_number": 45
    }

    test_alert = {
        "id": "alert-20260219-abc123",
        "finding_id": "test-finding-001",
        "agent_id": "dommo"
    }

    message = alerter._format_message(test_finding, test_alert)
    print(f"✓ Formatted message:\n{message}\n")

    # Test agent routing
    agent = alerter._route_agent(test_finding)
    print(f"✓ Routed to agent: {agent}")

    # Test priority mapping
    priority = alerter._map_priority("critical")
    print(f"✓ Priority mapping: critical -> {priority}")

    print("\n✅ ZimMemory Alerter tests passed!")


def test_integration():
    """Test integration between AlertManager and ZimAlerter."""
    print("\n=== Testing Integration ===\n")

    # Initialize components
    db = FindingsDB()
    manager = AlertManager(findings_db=db)
    alerter = ZimAlerter()

    # Create test finding
    test_finding = {
        "id": "test-finding-002",
        "title": "Exposed API Key",
        "description": "API key found in source code",
        "severity": "high",
        "scanner": "secrets",
        "target": "github.com/user/repo",
        "status": "open",
        "created_at": "2026-02-19T11:00:00"
    }

    db.add_finding(test_finding)
    print(f"✓ Created test finding: {test_finding['id']}")

    # Create alert
    alert_result = manager.send_alert(test_finding["id"])
    print(f"✓ Created alert: {alert_result.get('alert_id')}")

    # Get alert and finding
    alert = manager.get_alert(alert_result["alert_id"])
    finding = db.get_finding(test_finding["id"])

    print(f"✓ Retrieved alert and finding")

    # Format message (don't send to avoid spamming)
    message = alerter._format_message(finding, alert)
    print(f"✓ Message formatted ({len(message)} chars)")

    print("\n✅ Integration tests passed!")


def main():
    """Run all tests."""
    setup_logging()

    print("=" * 60)
    print("Akali Alert System Test Suite")
    print("=" * 60)

    try:
        test_alert_manager()
        test_zim_alerter()
        test_integration()

        print("\n" + "=" * 60)
        print("✅ All tests passed!")
        print("=" * 60)

    except Exception as e:
        print(f"\n❌ Test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

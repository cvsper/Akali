#!/usr/bin/env python3
"""Example usage of the triage engine with findings database."""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from autonomous.triage.triage_engine import TriageEngine
from data.findings_db import FindingsDB
from datetime import datetime


def main():
    """Demonstrate triage engine integration."""

    print("=" * 70)
    print("Akali Triage Engine - Integration Example")
    print("=" * 70)

    # Initialize
    engine = TriageEngine()
    db = FindingsDB()

    # Create sample findings
    sample_findings = [
        {
            "id": f"DEMO-{datetime.now().strftime('%Y%m%d%H%M%S')}-001",
            "timestamp": datetime.now().isoformat(),
            "severity": "high",
            "type": "sql_injection",
            "title": "SQL Injection in User Search",
            "description": "Unsanitized user input in search query",
            "file": "src/api/routes/users.py",
            "line": 45,
            "cvss": 8.5,
            "cwe": "CWE-89",
            "owasp": "A03:2021",
            "status": "open",
            "scanner": "bandit"
        },
        {
            "id": f"DEMO-{datetime.now().strftime('%Y%m%d%H%M%S')}-002",
            "timestamp": datetime.now().isoformat(),
            "severity": "medium",
            "type": "secrets",
            "title": "API Key in Test File",
            "description": "Hardcoded API key found",
            "file": "tests/fixtures/test_api_keys.py",
            "line": 12,
            "status": "open",
            "scanner": "gitleaks"
        },
        {
            "id": f"DEMO-{datetime.now().strftime('%Y%m%d%H%M%S')}-003",
            "timestamp": datetime.now().isoformat(),
            "severity": "critical",
            "type": "auth_bypass",
            "title": "Authentication Bypass",
            "description": "Missing authorization check in payment endpoint",
            "file": "src/api/payment/checkout.py",
            "line": 89,
            "cvss": 9.8,
            "cwe": "CWE-306",
            "owasp": "A07:2021",
            "status": "open",
            "scanner": "semgrep"
        }
    ]

    # Add findings to database
    print("\n1. Adding sample findings to database...")
    for finding in sample_findings:
        db.add_finding(finding)
        print(f"   Added: {finding['id']} - {finding['title']}")

    # Perform triage on each finding
    print("\n2. Performing automated triage...")
    print("-" * 70)

    for finding in sample_findings:
        decision = engine.triage(finding)

        print(f"\n   Finding: {finding['id']}")
        print(f"   Title: {finding['title']}")
        print(f"   Original Severity: {finding['severity']}")
        print(f"   Triaged Risk Score: {decision.risk_score}/10")
        print(f"   Triaged Severity: {decision.severity.upper()}")
        print(f"   False Positive: {decision.is_false_positive}")

        if decision.false_positive_reason:
            print(f"   FP Reason: {decision.false_positive_reason}")

        print(f"   Can Auto-Remediate: {decision.can_auto_remediate}")

        if decision.remediation_action:
            print(f"   Remediation: {decision.remediation_action}")

        print(f"   Confidence: {decision.confidence:.0%}")

        # Update finding in database with triage results
        db.update_finding(finding['id'], {
            "risk_score": decision.risk_score,
            "triaged_severity": decision.severity,
            "is_false_positive": decision.is_false_positive,
            "triage_timestamp": decision.timestamp,
            "triage_confidence": decision.confidence
        })

    # Show statistics
    print("\n3. Triage Statistics")
    print("-" * 70)

    stats = engine.get_triage_stats()
    print(f"   False Positive Patterns: {stats['false_positives']['pattern_count']}")
    print(f"   User Marked FPs: {stats['false_positives']['user_marked_count']}")
    print(f"   Total Feedback: {stats['feedback']['total_feedback']}")

    # Show findings by triaged severity
    print("\n4. Findings by Triaged Severity")
    print("-" * 70)

    all_findings = db.list_findings()
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for f in all_findings:
        sev = f.get("triaged_severity", f.get("severity", "unknown"))
        if sev in severity_counts:
            severity_counts[sev] += 1

    for severity, count in severity_counts.items():
        if count > 0:
            print(f"   {severity.upper()}: {count}")

    # Demonstrate feedback recording
    print("\n5. Recording User Feedback")
    print("-" * 70)

    # Acknowledge the critical auth bypass
    critical_finding = sample_findings[2]
    engine.record_feedback(critical_finding['id'], "ack", "Will fix immediately")
    print(f"   ✓ Acknowledged: {critical_finding['id']}")

    # Mark test file secret as false positive
    test_finding = sample_findings[1]
    engine.record_feedback(test_finding['id'], "false_positive", "Test fixture only")
    print(f"   ✓ Marked FP: {test_finding['id']}")

    # Clean up demo findings
    print("\n6. Cleanup (removing demo findings)")
    print("-" * 70)
    for finding in sample_findings:
        db.delete_finding(finding['id'])
        print(f"   Removed: {finding['id']}")

    print("\n" + "=" * 70)
    print("✓ Integration example completed successfully!")
    print("=" * 70)


if __name__ == "__main__":
    main()

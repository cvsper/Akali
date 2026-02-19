"""Test script for triage engine functionality."""

import json
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from autonomous.triage.triage_engine import TriageEngine


def test_risk_scoring():
    """Test risk scoring algorithm."""
    print("\n=== Testing Risk Scoring ===")

    engine = TriageEngine()

    # Test case 1: Production API endpoint with auth
    finding1 = {
        "id": "TEST-001",
        "cvss": 7.5,
        "file": "src/api/routes/auth.py",
        "type": "sql_injection",
        "description": "SQL injection in authentication endpoint",
        "title": "SQL Injection Vulnerability"
    }
    score, severity = engine.score_finding(finding1)
    print(f"Production API auth endpoint: {score}/10 ({severity})")
    assert score >= 9, "Should be critical (production + public + auth)"

    # Test case 2: Test file
    finding2 = {
        "id": "TEST-002",
        "cvss": 8.0,
        "file": "tests/test_api.py",
        "type": "hardcoded_password",
        "description": "Hardcoded password in test file",
        "title": "Hardcoded Password"
    }
    score, severity = engine.score_finding(finding2)
    print(f"Test file secret: {score}/10 ({severity})")
    # Test files get -1, but high CVSS (8.0) keeps it elevated
    assert score <= 8, "Should be reduced or equal due to test file"

    # Test case 3: Production payment logic
    finding3 = {
        "id": "TEST-003",
        "cvss": 6.0,
        "file": "src/services/payment_processor.py",
        "type": "weak_crypto",
        "description": "Weak cryptographic algorithm in payment processing",
        "title": "Weak Cryptography"
    }
    score, severity = engine.score_finding(finding3)
    print(f"Production payment logic: {score}/10 ({severity})")
    assert score >= 7, "Should be elevated (production + sensitive)"

    print("✓ Risk scoring tests passed")


def test_false_positive_detection():
    """Test false positive detection."""
    print("\n=== Testing False Positive Detection ===")

    engine = TriageEngine()

    # Test case 1: .env.example file
    finding1 = {
        "id": "TEST-004",
        "file": ".env.example",
        "type": "secrets",
        "description": "API key found in .env.example"
    }
    is_fp, reason, confidence = engine.is_false_positive(finding1)
    print(f".env.example: FP={is_fp}, Reason={reason}, Confidence={confidence}")
    assert is_fp, "Should detect .env.example as false positive"

    # Test case 2: Test fixture
    finding2 = {
        "id": "TEST-005",
        "file": "tests/fixtures/test_data.py",
        "type": "secrets",
        "description": "Secret key in test fixture"
    }
    is_fp, reason, confidence = engine.is_false_positive(finding2)
    print(f"Test fixture: FP={is_fp}, Reason={reason}, Confidence={confidence}")
    assert is_fp, "Should detect test file as false positive"

    # Test case 3: Real secret in production
    finding3 = {
        "id": "TEST-006",
        "file": "src/config/production.py",
        "type": "secrets",
        "description": "AWS secret key in production config"
    }
    is_fp, reason, confidence = engine.is_false_positive(finding3)
    print(f"Production secret: FP={is_fp}")
    assert not is_fp, "Should NOT detect production secret as false positive"

    print("✓ False positive detection tests passed")


def test_auto_remediation():
    """Test auto-remediation logic."""
    print("\n=== Testing Auto-Remediation ===")

    engine = TriageEngine()

    # Test case 1: Committed .env file
    finding1 = {
        "id": "TEST-007",
        "file": ".env",
        "type": "secrets",
        "description": "Secret keys in .env file"
    }
    can_fix, action, cmd = engine.auto_remediate(finding1)
    print(f"Committed .env: can_fix={can_fix}")
    if can_fix:
        print(f"  Action: {action}")
        print(f"  Command: {cmd}")
    assert can_fix, "Should be able to auto-remediate .env file"

    # Test case 2: Vulnerable dependency
    finding2 = {
        "id": "TEST-008",
        "file": "requirements.txt",
        "type": "dependency",
        "description": "Vulnerable package: requests version 2.0.0"
    }
    can_fix, action, cmd = engine.auto_remediate(finding2)
    print(f"Vulnerable dependency: can_fix={can_fix}")
    if can_fix:
        print(f"  Action: {action}")
        print(f"  Command: {cmd}")
    assert can_fix, "Should be able to auto-remediate vulnerable dependency"

    # Test case 3: Complex vulnerability (no auto-fix)
    finding3 = {
        "id": "TEST-009",
        "file": "src/api/auth.py",
        "type": "auth_bypass",
        "description": "Authentication bypass vulnerability"
    }
    can_fix, action, cmd = engine.auto_remediate(finding3)
    print(f"Auth bypass: can_fix={can_fix}")
    assert not can_fix, "Should NOT auto-remediate complex vulnerabilities"

    print("✓ Auto-remediation tests passed")


def test_learning_feedback():
    """Test learning from user feedback."""
    print("\n=== Testing Learning from Feedback ===")

    engine = TriageEngine()

    # Record several dismissals of a finding type
    for i in range(5):
        engine.record_feedback(f"SAST-{i}", "dismiss", "Not relevant")

    # Record several fixes of another finding type
    for i in range(6):
        engine.record_feedback(f"SECRET-{i}", "fix", "Fixed vulnerability")

    # Check learned adjustments
    sast_adjustment = engine.feedback_db.get_score_adjustment("SAST")
    secret_adjustment = engine.feedback_db.get_score_adjustment("SECRET")

    print(f"SAST type score adjustment: {sast_adjustment}")
    print(f"SECRET type score adjustment: {secret_adjustment}")

    assert sast_adjustment <= 0, "Frequently dismissed type should have negative adjustment"
    assert secret_adjustment >= 0, "Frequently fixed type should have positive adjustment"

    # Get stats
    stats = engine.feedback_db.get_stats()
    print(f"Total feedback recorded: {stats['total_feedback']}")
    print(f"By action: {stats['by_action']}")

    print("✓ Learning feedback tests passed")


def test_full_triage_workflow():
    """Test complete triage workflow."""
    print("\n=== Testing Full Triage Workflow ===")

    engine = TriageEngine()

    # Create a test finding
    finding = {
        "id": "TEST-FULL-001",
        "cvss": 7.5,
        "file": "src/api/payment.py",
        "type": "sql_injection",
        "title": "SQL Injection in Payment API",
        "description": "SQL injection vulnerability in payment processing endpoint",
        "scanner": "bandit",
        "status": "open"
    }

    # Perform full triage
    decision = engine.triage(finding)

    print(f"Finding: {decision.finding_id}")
    print(f"Risk Score: {decision.risk_score}/10")
    print(f"Severity: {decision.severity}")
    print(f"False Positive: {decision.is_false_positive}")
    print(f"Can Auto-Remediate: {decision.can_auto_remediate}")
    print(f"Confidence: {decision.confidence:.2%}")

    assert decision.risk_score > 0, "Should have calculated risk score"
    assert decision.severity in ["critical", "high", "medium", "low", "info"]
    assert 0 <= decision.confidence <= 1.0

    # Record feedback
    engine.record_feedback(decision.finding_id, "ack", "Valid finding, will fix")

    print("✓ Full triage workflow test passed")


def test_false_positive_marking():
    """Test manual false positive marking."""
    print("\n=== Testing False Positive Marking ===")

    engine = TriageEngine()

    finding_id = "TEST-FP-001"

    # Initially should not be marked
    assert not engine.fp_db.is_marked(finding_id)

    # Record as false positive
    engine.record_feedback(finding_id, "false_positive", "Test data only")

    # Should now be marked
    assert engine.fp_db.is_marked(finding_id)
    print(f"✓ {finding_id} correctly marked as false positive")

    # Check it in triage
    finding = {
        "id": finding_id,
        "cvss": 5.0,
        "file": "test.py",
        "type": "test",
        "description": "Test"
    }

    is_fp, reason, confidence = engine.is_false_positive(finding)
    print(f"FP check: {is_fp}, Reason: {reason}")
    assert is_fp, "Should detect manually marked false positive"
    assert confidence == 1.0, "Manual marking should have 100% confidence"

    print("✓ False positive marking test passed")


if __name__ == "__main__":
    print("=" * 60)
    print("Akali Triage Engine Test Suite")
    print("=" * 60)

    try:
        test_risk_scoring()
        test_false_positive_detection()
        test_auto_remediation()
        test_learning_feedback()
        test_full_triage_workflow()
        test_false_positive_marking()

        print("\n" + "=" * 60)
        print("✓ All tests passed!")
        print("=" * 60)

    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        exit(1)
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        exit(1)

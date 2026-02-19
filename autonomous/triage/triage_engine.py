"""Automated triage engine for security findings.

Provides risk scoring, false positive detection, auto-remediation,
and learning from user feedback.
"""

import json
import logging
import re
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class TriageDecision:
    """Represents a triage decision."""
    finding_id: str
    risk_score: int
    severity: str
    is_false_positive: bool
    false_positive_reason: Optional[str]
    can_auto_remediate: bool
    remediation_action: Optional[str]
    timestamp: str
    confidence: float


@dataclass
class UserFeedback:
    """Represents user feedback on a finding."""
    finding_id: str
    action: str  # ack, dismiss, fix, false_positive
    timestamp: str
    notes: Optional[str] = None


class FalsePositiveDB:
    """Database for false positive patterns."""

    def __init__(self, db_path: str = "~/.akali/data/false_positives.json"):
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_db_exists()

    def _ensure_db_exists(self):
        """Create empty database if it doesn't exist."""
        if not self.db_path.exists():
            default_patterns = {
                "patterns": [
                    {
                        "id": "fp_001",
                        "name": "test_file_secrets",
                        "description": "Secrets in test files are usually test fixtures",
                        "pattern": r"(test_|_test\.py|tests/|spec/|__tests__/)",
                        "field": "file",
                        "confidence": 0.8
                    },
                    {
                        "id": "fp_002",
                        "name": "example_env",
                        "description": "Example .env files are documentation",
                        "pattern": r"\.env\.(example|sample|template)",
                        "field": "file",
                        "confidence": 0.9
                    },
                    {
                        "id": "fp_003",
                        "name": "commented_code",
                        "description": "Commented out code is not active",
                        "pattern": r"^\s*(#|//|/\*)",
                        "field": "description",
                        "confidence": 0.7
                    },
                    {
                        "id": "fp_004",
                        "name": "vendor_dependencies",
                        "description": "Vendor/node_modules issues are upstream",
                        "pattern": r"(node_modules|vendor/|\.pyenv/|venv/|\.venv/)",
                        "field": "file",
                        "confidence": 0.6
                    }
                ],
                "user_marked": []
            }
            self.db_path.write_text(json.dumps(default_patterns, indent=2))

    def load(self) -> Dict[str, Any]:
        """Load false positive database."""
        return json.loads(self.db_path.read_text())

    def save(self, data: Dict[str, Any]):
        """Save false positive database."""
        self.db_path.write_text(json.dumps(data, indent=2))

    def add_pattern(self, name: str, description: str, pattern: str, field: str, confidence: float):
        """Add a new false positive pattern."""
        data = self.load()
        pattern_id = f"fp_{len(data['patterns']) + 1:03d}"
        data["patterns"].append({
            "id": pattern_id,
            "name": name,
            "description": description,
            "pattern": pattern,
            "field": field,
            "confidence": confidence,
            "created": datetime.now().isoformat()
        })
        self.save(data)
        return pattern_id

    def mark_false_positive(self, finding_id: str, reason: str):
        """Mark a specific finding as false positive."""
        data = self.load()
        data["user_marked"].append({
            "finding_id": finding_id,
            "reason": reason,
            "timestamp": datetime.now().isoformat()
        })
        self.save(data)

    def is_marked(self, finding_id: str) -> bool:
        """Check if finding is marked as false positive."""
        data = self.load()
        return any(fp["finding_id"] == finding_id for fp in data["user_marked"])


class FeedbackDB:
    """Database for user feedback and learning."""

    def __init__(self, db_path: str = "~/.akali/data/feedback.json"):
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_db_exists()

    def _ensure_db_exists(self):
        """Create empty database if it doesn't exist."""
        if not self.db_path.exists():
            self.db_path.write_text(json.dumps({
                "feedback": [],
                "patterns": {}
            }, indent=2))

    def load(self) -> Dict[str, Any]:
        """Load feedback database."""
        return json.loads(self.db_path.read_text())

    def save(self, data: Dict[str, Any]):
        """Save feedback database."""
        self.db_path.write_text(json.dumps(data, indent=2))

    def add_feedback(self, feedback: UserFeedback):
        """Add user feedback."""
        data = self.load()
        data["feedback"].append(asdict(feedback))
        self._update_patterns(data, feedback)
        self.save(data)

    def _update_patterns(self, data: Dict[str, Any], feedback: UserFeedback):
        """Update learned patterns based on feedback."""
        # Track dismissal patterns
        if feedback.action == "dismiss":
            finding_type = feedback.finding_id.split("-")[0]
            if finding_type not in data["patterns"]:
                data["patterns"][finding_type] = {
                    "dismiss_count": 0,
                    "ack_count": 0,
                    "fix_count": 0,
                    "score_adjustment": 0.0
                }
            data["patterns"][finding_type]["dismiss_count"] += 1
            # Adjust score downward if frequently dismissed
            if data["patterns"][finding_type]["dismiss_count"] > 3:
                data["patterns"][finding_type]["score_adjustment"] = -1.0

        elif feedback.action in ["ack", "fix"]:
            finding_type = feedback.finding_id.split("-")[0]
            if finding_type not in data["patterns"]:
                data["patterns"][finding_type] = {
                    "dismiss_count": 0,
                    "ack_count": 0,
                    "fix_count": 0,
                    "score_adjustment": 0.0
                }
            data["patterns"][finding_type][f"{feedback.action}_count"] += 1
            # Adjust score upward if frequently acted upon
            if data["patterns"][finding_type]["ack_count"] + data["patterns"][finding_type]["fix_count"] > 5:
                data["patterns"][finding_type]["score_adjustment"] = 1.0

    def get_score_adjustment(self, finding_type: str) -> float:
        """Get learned score adjustment for finding type."""
        data = self.load()
        return data["patterns"].get(finding_type, {}).get("score_adjustment", 0.0)

    def get_stats(self) -> Dict[str, Any]:
        """Get feedback statistics."""
        data = self.load()
        stats = {
            "total_feedback": len(data["feedback"]),
            "by_action": {},
            "patterns": data["patterns"]
        }
        for fb in data["feedback"]:
            action = fb["action"]
            stats["by_action"][action] = stats["by_action"].get(action, 0) + 1
        return stats


class TriageEngine:
    """Main triage engine for automated security finding analysis."""

    def __init__(self):
        self.fp_db = FalsePositiveDB()
        self.feedback_db = FeedbackDB()
        self.log_path = Path("~/.akali/logs/triage.log").expanduser()
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def score_finding(self, finding: Dict[str, Any]) -> Tuple[int, str]:
        """
        Calculate risk score for a finding.

        Returns: (risk_score, severity_label)

        Scale: 0-10
        - Critical: 9-10
        - High: 7-8
        - Medium: 4-6
        - Low: 1-3
        - Info: 0
        """
        # Start with base score from CVSS if available
        base_score = finding.get("cvss", 5.0)

        # Convert CVSS (0-10) to initial score
        score = base_score

        file_path = finding.get("file", "").lower()
        description = finding.get("description", "").lower()
        title = finding.get("title", "").lower()
        finding_type = finding.get("type", "")

        # Production code path detection
        production_indicators = [
            "src/", "lib/", "app/", "api/", "routes/",
            "controllers/", "models/", "views/", "services/"
        ]
        if any(indicator in file_path for indicator in production_indicators):
            if "test" not in file_path and "spec" not in file_path:
                score += 2
                logger.info(f"[{finding['id']}] +2 production code path")

        # Publicly accessible code
        public_indicators = [
            "api/", "routes/", "endpoints/", "controllers/",
            "public/", "static/", "web/"
        ]
        if any(indicator in file_path for indicator in public_indicators):
            score += 1
            logger.info(f"[{finding['id']}] +1 publicly accessible")

        # Sensitive logic
        sensitive_keywords = [
            "auth", "login", "password", "token", "jwt",
            "payment", "billing", "credit", "card",
            "admin", "privilege", "permission", "role",
            "secret", "key", "credential"
        ]
        if any(keyword in file_path or keyword in description or keyword in title
               for keyword in sensitive_keywords):
            score += 1
            logger.info(f"[{finding['id']}] +1 sensitive logic")

        # Test/dev code reduction
        test_indicators = [
            "test", "spec", "mock", "fixture", "example",
            "__tests__", ".test.", ".spec.", "_test.py"
        ]
        if any(indicator in file_path for indicator in test_indicators):
            score -= 1
            logger.info(f"[{finding['id']}] -1 test/dev code")

        # Apply learned adjustments from user feedback
        adjustment = self.feedback_db.get_score_adjustment(finding_type)
        if adjustment != 0:
            score += adjustment
            logger.info(f"[{finding['id']}] {adjustment:+.1f} learned adjustment")

        # Clamp to 0-10 range
        score = max(0, min(10, score))

        # Determine severity label
        if score >= 9:
            severity = "critical"
        elif score >= 7:
            severity = "high"
        elif score >= 4:
            severity = "medium"
        elif score >= 1:
            severity = "low"
        else:
            severity = "info"

        return int(round(score)), severity

    def is_false_positive(self, finding: Dict[str, Any]) -> Tuple[bool, Optional[str], float]:
        """
        Check if finding matches false positive patterns.

        Returns: (is_fp, reason, confidence)
        """
        finding_id = finding.get("id")

        # Check if manually marked
        if self.fp_db.is_marked(finding_id):
            return True, "Manually marked as false positive", 1.0

        # Check against patterns
        data = self.fp_db.load()
        for pattern in data["patterns"]:
            field_value = finding.get(pattern["field"], "")
            if not field_value:
                continue

            if re.search(pattern["pattern"], str(field_value), re.IGNORECASE):
                logger.info(
                    f"[{finding_id}] Matched FP pattern: {pattern['name']} "
                    f"(confidence: {pattern['confidence']})"
                )
                return True, pattern["description"], pattern["confidence"]

        return False, None, 0.0

    def auto_remediate(self, finding: Dict[str, Any]) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Determine if finding can be auto-remediated and suggest action.

        Returns: (can_remediate, action_description, command)

        SAFE remediations only:
        - Remove accidentally committed .env files
        - Update vulnerable dependencies (with confirmation)
        - Add missing security headers
        """
        finding_type = finding.get("type", "")
        file_path = finding.get("file", "")
        description = finding.get("description", "").lower()

        # Remove accidentally committed secrets files
        if finding_type == "secrets" and file_path:
            if ".env" in file_path and ".example" not in file_path:
                return (
                    True,
                    f"Remove {file_path} from git and add to .gitignore",
                    f"git rm --cached {file_path} && echo '{Path(file_path).name}' >> .gitignore"
                )

        # Update vulnerable dependencies
        if finding_type == "dependency" and "vulnerable" in description:
            if "requirements.txt" in file_path or "package.json" in file_path:
                # Extract package name from finding
                package_match = re.search(r"package[:\s]+([a-zA-Z0-9_-]+)", description)
                if package_match:
                    package = package_match.group(1)
                    if "requirements.txt" in file_path:
                        return (
                            True,
                            f"Update vulnerable package: {package}",
                            f"pip install --upgrade {package} && pip freeze | grep {package}"
                        )
                    elif "package.json" in file_path:
                        return (
                            True,
                            f"Update vulnerable package: {package}",
                            f"npm update {package}"
                        )

        # Add missing security headers (web server configs)
        if "security header" in description or "missing header" in description:
            if "nginx" in file_path or "apache" in file_path:
                return (
                    True,
                    "Add security headers to web server configuration",
                    "# Manual: Add headers like X-Frame-Options, X-Content-Type-Options, etc."
                )

        # No safe auto-remediation available
        return False, None, None

    def triage(self, finding: Dict[str, Any]) -> TriageDecision:
        """
        Perform complete triage on a finding.

        Returns: TriageDecision with all analysis results
        """
        finding_id = finding.get("id", "unknown")

        # Risk scoring
        risk_score, severity = self.score_finding(finding)

        # False positive detection
        is_fp, fp_reason, fp_confidence = self.is_false_positive(finding)

        # Auto-remediation check
        can_remediate, remediation_action, _ = self.auto_remediate(finding)

        # Calculate overall confidence
        confidence = 1.0 - (fp_confidence if is_fp else 0.0)

        decision = TriageDecision(
            finding_id=finding_id,
            risk_score=risk_score,
            severity=severity,
            is_false_positive=is_fp,
            false_positive_reason=fp_reason,
            can_auto_remediate=can_remediate,
            remediation_action=remediation_action,
            timestamp=datetime.now().isoformat(),
            confidence=confidence
        )

        # Log decision
        self._log_decision(finding, decision)

        return decision

    def record_feedback(self, finding_id: str, action: str, notes: Optional[str] = None):
        """Record user feedback on a finding."""
        feedback = UserFeedback(
            finding_id=finding_id,
            action=action,
            timestamp=datetime.now().isoformat(),
            notes=notes
        )
        self.feedback_db.add_feedback(feedback)
        logger.info(f"Recorded feedback for {finding_id}: {action}")

        # If marked as false positive, add to FP database
        if action == "false_positive":
            self.fp_db.mark_false_positive(finding_id, notes or "User marked")

    def _log_decision(self, finding: Dict[str, Any], decision: TriageDecision):
        """Log triage decision to file."""
        with open(self.log_path, "a") as f:
            log_entry = {
                "timestamp": decision.timestamp,
                "finding_id": finding.get("id"),
                "finding_type": finding.get("type"),
                "file": finding.get("file"),
                "risk_score": decision.risk_score,
                "severity": decision.severity,
                "is_false_positive": decision.is_false_positive,
                "can_auto_remediate": decision.can_auto_remediate
            }
            f.write(json.dumps(log_entry) + "\n")

    def get_triage_stats(self) -> Dict[str, Any]:
        """Get triage statistics."""
        feedback_stats = self.feedback_db.get_stats()

        # Count false positive patterns
        fp_data = self.fp_db.load()
        fp_stats = {
            "pattern_count": len(fp_data["patterns"]),
            "user_marked_count": len(fp_data["user_marked"])
        }

        return {
            "feedback": feedback_stats,
            "false_positives": fp_stats
        }


def main():
    """CLI interface for manual triage operations."""
    import argparse
    import sys
    from data.findings_db import FindingsDB

    parser = argparse.ArgumentParser(description="Akali Triage Engine")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Triage command
    triage_parser = subparsers.add_parser("triage", help="Triage a finding")
    triage_parser.add_argument("finding_id", help="Finding ID to triage")

    # Feedback command
    feedback_parser = subparsers.add_parser("feedback", help="Record user feedback")
    feedback_parser.add_argument("finding_id", help="Finding ID")
    feedback_parser.add_argument("action", choices=["ack", "dismiss", "fix", "false_positive"])
    feedback_parser.add_argument("--notes", help="Optional notes")

    # Add FP pattern command
    fp_parser = subparsers.add_parser("add-fp-pattern", help="Add false positive pattern")
    fp_parser.add_argument("name", help="Pattern name")
    fp_parser.add_argument("pattern", help="Regex pattern")
    fp_parser.add_argument("--field", default="file", help="Field to match against")
    fp_parser.add_argument("--confidence", type=float, default=0.8, help="Confidence level")
    fp_parser.add_argument("--description", help="Pattern description")

    # Stats command
    subparsers.add_parser("stats", help="Show triage statistics")

    # Batch triage command
    batch_parser = subparsers.add_parser("batch", help="Triage all findings")
    batch_parser.add_argument("--status", default="open", help="Filter by status")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    engine = TriageEngine()
    findings_db = FindingsDB()

    if args.command == "triage":
        finding = findings_db.get_finding(args.finding_id)
        if not finding:
            print(f"Finding {args.finding_id} not found")
            sys.exit(1)

        decision = engine.triage(finding)

        print(f"\n=== Triage Decision for {args.finding_id} ===")
        print(f"Risk Score: {decision.risk_score}/10")
        print(f"Severity: {decision.severity.upper()}")
        print(f"False Positive: {decision.is_false_positive}")
        if decision.false_positive_reason:
            print(f"  Reason: {decision.false_positive_reason}")
        print(f"Can Auto-Remediate: {decision.can_auto_remediate}")
        if decision.remediation_action:
            print(f"  Action: {decision.remediation_action}")
        print(f"Confidence: {decision.confidence:.2%}")

        # Update finding in database
        findings_db.update_finding(args.finding_id, {
            "risk_score": decision.risk_score,
            "severity": decision.severity,
            "triage_timestamp": decision.timestamp
        })
        print(f"\nUpdated finding in database")

    elif args.command == "feedback":
        engine.record_feedback(args.finding_id, args.action, args.notes)
        print(f"Recorded {args.action} for {args.finding_id}")

    elif args.command == "add-fp-pattern":
        pattern_id = engine.fp_db.add_pattern(
            name=args.name,
            description=args.description or f"Pattern: {args.name}",
            pattern=args.pattern,
            field=args.field,
            confidence=args.confidence
        )
        print(f"Added false positive pattern: {pattern_id}")

    elif args.command == "stats":
        stats = engine.get_triage_stats()
        print("\n=== Triage Statistics ===")
        print(f"\nFeedback: {stats['feedback']['total_feedback']} total")
        if stats['feedback']['by_action']:
            print("By action:")
            for action, count in stats['feedback']['by_action'].items():
                print(f"  {action}: {count}")

        print(f"\nFalse Positives:")
        print(f"  Patterns: {stats['false_positives']['pattern_count']}")
        print(f"  User marked: {stats['false_positives']['user_marked_count']}")

        if stats['feedback']['patterns']:
            print("\nLearned patterns:")
            for finding_type, pattern in stats['feedback']['patterns'].items():
                adj = pattern['score_adjustment']
                if adj != 0:
                    print(f"  {finding_type}: {adj:+.1f} score adjustment")

    elif args.command == "batch":
        findings = findings_db.list_findings(status=args.status)
        print(f"\nTriaging {len(findings)} findings...")

        results = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": [],
            "false_positive": []
        }

        for finding in findings:
            decision = engine.triage(finding)

            # Update finding
            findings_db.update_finding(finding["id"], {
                "risk_score": decision.risk_score,
                "severity": decision.severity,
                "triage_timestamp": decision.timestamp
            })

            if decision.is_false_positive:
                results["false_positive"].append(finding["id"])
            else:
                results[decision.severity].append(finding["id"])

        print("\n=== Batch Triage Results ===")
        for severity in ["critical", "high", "medium", "low", "info", "false_positive"]:
            count = len(results[severity])
            if count > 0:
                print(f"{severity.upper()}: {count}")
                if count <= 5:
                    for fid in results[severity]:
                        print(f"  - {fid}")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )
    main()

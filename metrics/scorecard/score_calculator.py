#!/usr/bin/env python3
"""
Security Scorecard - Calculate family security score (0-100)
"""

import json
import os
from datetime import datetime
from typing import Dict, List


class ScoreCalculator:
    """Calculate security scorecard"""

    def __init__(self):
        """Initialize score calculator"""
        self.findings_file = os.path.expanduser("~/akali/data/findings.json")
        self.history_file = os.path.expanduser("~/akali/metrics/scorecard/score_history.json")
        self.inventory_file = os.path.expanduser("~/akali/intelligence/cve_monitor/dependency_inventory.json")

    def calculate_score(self) -> Dict:
        """
        Calculate overall family security score

        Returns:
            Score dictionary with breakdown
        """
        print("Calculating security score...")

        # Load data
        findings = self._load_findings()
        inventory = self._load_inventory()

        # Calculate component scores
        component_scores = {
            "dependencies": self._score_dependencies(findings, inventory),
            "secrets": self._score_secrets(findings),
            "auth": self._score_auth(findings),
            "https": self._score_https(findings),
            "rate_limiting": self._score_rate_limiting(findings),
            "input_validation": self._score_input_validation(findings),
            "security_headers": self._score_headers(findings),
            "backups": self._score_backups(findings),
        }

        # Weights for each component
        weights = {
            "dependencies": 0.20,
            "secrets": 0.15,
            "auth": 0.15,
            "https": 0.10,
            "rate_limiting": 0.10,
            "input_validation": 0.10,
            "security_headers": 0.10,
            "backups": 0.10,
        }

        # Calculate weighted average
        overall = sum(score * weights[category]
                      for category, score in component_scores.items())

        # Penalty for critical/high open findings
        critical_high = [
            f for f in findings
            if f.get("status") != "closed" and f.get("severity") in ["critical", "high"]
        ]
        penalty = min(20, len(critical_high) * 2)

        final_score = max(0, overall - penalty)

        # Build result
        result = {
            "score": round(final_score, 1),
            "component_scores": component_scores,
            "open_findings": {
                "critical": len([f for f in findings if f.get("severity") == "critical" and f.get("status") != "closed"]),
                "high": len([f for f in findings if f.get("severity") == "high" and f.get("status") != "closed"]),
                "medium": len([f for f in findings if f.get("severity") == "medium" and f.get("status") != "closed"]),
                "low": len([f for f in findings if f.get("severity") == "low" and f.get("status") != "closed"]),
            },
            "penalty": penalty,
            "timestamp": datetime.now().isoformat(),
        }

        # Save to history
        self._save_to_history(result)

        return result

    def _load_findings(self) -> List[Dict]:
        """Load findings from database"""
        if os.path.exists(self.findings_file):
            try:
                with open(self.findings_file, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        return []

    def _load_inventory(self) -> Dict:
        """Load dependency inventory"""
        if os.path.exists(self.inventory_file):
            try:
                with open(self.inventory_file, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        return {"packages": {}}

    def _score_dependencies(self, findings: List[Dict], inventory: Dict) -> int:
        """Score dependency health (0-100)"""
        # Count vulnerable dependencies
        dep_findings = [f for f in findings if f.get("type") == "dependency" and f.get("status") != "closed"]

        if not dep_findings:
            return 100  # Perfect score

        # Start at 100, deduct points
        score = 100
        score -= min(50, len(dep_findings) * 10)  # -10 per vuln dependency, max -50

        return max(0, score)

    def _score_secrets(self, findings: List[Dict]) -> int:
        """Score secrets management (0-100)"""
        secret_findings = [f for f in findings if f.get("type") == "secret" and f.get("status") != "closed"]

        if not secret_findings:
            return 100
        elif len(secret_findings) == 1:
            return 75
        elif len(secret_findings) <= 3:
            return 50
        else:
            return 0

    def _score_auth(self, findings: List[Dict]) -> int:
        """Score authentication implementation (0-100)"""
        auth_findings = [f for f in findings if "auth" in f.get("type", "").lower() and f.get("status") != "closed"]

        if not auth_findings:
            return 100
        else:
            return max(0, 100 - len(auth_findings) * 15)

    def _score_https(self, findings: List[Dict]) -> int:
        """Score HTTPS enforcement (0-100)"""
        https_findings = [f for f in findings if "https" in f.get("description", "").lower() and f.get("status") != "closed"]

        return 100 if not https_findings else 50

    def _score_rate_limiting(self, findings: List[Dict]) -> int:
        """Score rate limiting implementation (0-100)"""
        rl_findings = [f for f in findings if "rate limit" in f.get("description", "").lower() and f.get("status") != "closed"]

        return 100 if not rl_findings else 60

    def _score_input_validation(self, findings: List[Dict]) -> int:
        """Score input validation (0-100)"""
        injection_findings = [
            f for f in findings
            if any(keyword in f.get("description", "").lower() for keyword in ["injection", "xss", "sqli"])
            and f.get("status") != "closed"
        ]

        if not injection_findings:
            return 100
        else:
            return max(0, 100 - len(injection_findings) * 20)

    def _score_headers(self, findings: List[Dict]) -> int:
        """Score security headers (0-100)"""
        header_findings = [f for f in findings if "header" in f.get("description", "").lower() and f.get("status") != "closed"]

        return 100 if not header_findings else 70

    def _score_backups(self, findings: List[Dict]) -> int:
        """Score backup security (0-100)"""
        # Assume backups are good unless findings say otherwise
        backup_findings = [f for f in findings if "backup" in f.get("description", "").lower() and f.get("status") != "closed"]

        return 100 if not backup_findings else 75

    def _save_to_history(self, result: Dict):
        """Save score to history"""
        history = []

        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, 'r') as f:
                    history = json.load(f)
            except Exception:
                pass

        history.append(result)

        # Keep last 90 days
        history = history[-90:]

        os.makedirs(os.path.dirname(self.history_file), exist_ok=True)
        with open(self.history_file, 'w') as f:
            json.dump(history, f, indent=2)

    def get_score_trend(self, days: int = 30) -> List[Dict]:
        """
        Get score trend over time

        Args:
            days: Number of days to retrieve

        Returns:
            List of score entries
        """
        if not os.path.exists(self.history_file):
            return []

        try:
            with open(self.history_file, 'r') as f:
                history = json.load(f)

            # Return last N entries
            return history[-days:]
        except Exception:
            return []


def main():
    """CLI for scorecard"""
    import sys

    calculator = ScoreCalculator()

    if len(sys.argv) > 1 and sys.argv[1] == "history":
        days = int(sys.argv[2]) if len(sys.argv) > 2 else 30
        trend = calculator.get_score_trend(days)

        print(f"\n{'='*80}")
        print(f"Security Score History (last {days} days)")
        print(f"{'='*80}\n")

        for entry in trend:
            timestamp = entry["timestamp"][:10]  # Date only
            score = entry["score"]
            print(f"{timestamp}: {score:.1f}/100")

    else:
        result = calculator.calculate_score()

        print(f"\n{'='*80}")
        print("FAMILY SECURITY SCORECARD")
        print(f"{'='*80}\n")

        # Display overall score with color
        score = result["score"]
        if score >= 90:
            color = "\033[92m"  # Green
            grade = "A"
        elif score >= 80:
            color = "\033[94m"  # Blue
            grade = "B"
        elif score >= 70:
            color = "\033[93m"  # Yellow
            grade = "C"
        else:
            color = "\033[91m"  # Red
            grade = "D"
        reset = "\033[0m"

        print(f"Overall Score: {color}{score:.1f}/100 ({grade}){reset}")
        print()

        print("Component Scores:")
        for component, score_val in result["component_scores"].items():
            bar = "█" * int(score_val / 5) + "░" * (20 - int(score_val / 5))
            print(f"  {component.replace('_', ' ').title():20s} {bar} {score_val}/100")

        print()
        print("Open Findings:")
        findings = result["open_findings"]
        total = sum(findings.values())
        print(f"  Critical: {findings['critical']}")
        print(f"  High: {findings['high']}")
        print(f"  Medium: {findings['medium']}")
        print(f"  Low: {findings['low']}")
        print(f"  Total: {total}")

        if result["penalty"] > 0:
            print(f"\nScore Penalty: -{result['penalty']} points for {findings['critical'] + findings['high']} Critical/High findings")


if __name__ == "__main__":
    main()

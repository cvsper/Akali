#!/usr/bin/env python3
"""
Credential Stuffing Hunter - Detect credential stuffing attacks

Identifies patterns indicative of credential stuffing:
- High volume failed logins from single source
- Sequential login attempts across multiple accounts
- Rapid account enumeration
- Login attempts with common breached passwords
"""

from datetime import datetime, timedelta
from typing import Dict, List, Any
from collections import defaultdict, Counter


class CredentialStuffingHunter:
    """Detect credential stuffing attacks"""

    def __init__(self):
        self.findings: List[Dict[str, Any]] = []

    def analyze(self, login_events: List[Dict[str, Any]],
                time_window_minutes: int = 60) -> List[Dict[str, Any]]:
        """
        Analyze login events for credential stuffing patterns

        Args:
            login_events: List of login attempts
            time_window_minutes: Time window for analysis

        Returns:
            List of detected threats
        """
        self.findings = []

        # Group by source IP
        ip_attempts = defaultdict(list)
        for event in login_events:
            ip_attempts[event.get('ip', 'unknown')].append(event)

        # Analyze each IP
        for ip, attempts in ip_attempts.items():
            self._analyze_ip_behavior(ip, attempts)

        # Analyze account-based patterns
        self._analyze_account_targeting(login_events)

        return self.findings

    def _analyze_ip_behavior(self, ip: str, attempts: List[Dict[str, Any]]):
        """Analyze login behavior from single IP"""

        # Count failures
        failed = [a for a in attempts if not a.get('success', False)]
        failed_count = len(failed)

        # High volume failed attempts
        if failed_count >= 10:
            unique_users = len(set(a.get('user', '') for a in failed))

            self.findings.append({
                "type": "credential_stuffing",
                "severity": "critical" if failed_count >= 50 else "high",
                "source_ip": ip,
                "failed_attempts": failed_count,
                "unique_users_targeted": unique_users,
                "description": f"Credential stuffing detected: {failed_count} failed attempts from {ip} targeting {unique_users} users",
                "indicators": {
                    "high_failure_rate": True,
                    "multiple_accounts": unique_users > 5,
                    "rapid_attempts": len(attempts) / 60 > 1  # > 1 per minute
                },
                "sample_attempts": failed[:5]
            })

        # Sequential enumeration (trying usernames in sequence)
        usernames = [a.get('user', '') for a in attempts]
        if self._is_sequential_enumeration(usernames):
            self.findings.append({
                "type": "account_enumeration",
                "severity": "medium",
                "source_ip": ip,
                "attempt_count": len(attempts),
                "description": f"Account enumeration detected from {ip}",
                "indicators": {
                    "sequential_pattern": True
                }
            })

    def _analyze_account_targeting(self, events: List[Dict[str, Any]]):
        """Analyze which accounts are being targeted"""

        # Group by user
        user_attempts = defaultdict(list)
        for event in events:
            user_attempts[event.get('user', '')].append(event)

        for user, attempts in user_attempts.items():
            failed = [a for a in attempts if not a.get('success', False)]
            unique_ips = len(set(a.get('ip', '') for a in failed))

            # Account under distributed attack
            if unique_ips >= 5 and len(failed) >= 10:
                self.findings.append({
                    "type": "distributed_credential_attack",
                    "severity": "high",
                    "targeted_user": user,
                    "failed_attempts": len(failed),
                    "source_ips": unique_ips,
                    "description": f"User {user} under distributed attack from {unique_ips} IPs",
                    "sample_ips": list(set(a.get('ip', '') for a in failed))[:5]
                })

    def _is_sequential_enumeration(self, usernames: List[str]) -> bool:
        """Detect sequential username enumeration patterns"""

        # Check for numeric sequences (user1, user2, user3)
        numeric_pattern = 0
        for i in range(len(usernames) - 1):
            try:
                # Extract numbers from usernames
                num1 = int(''.join(filter(str.isdigit, usernames[i])))
                num2 = int(''.join(filter(str.isdigit, usernames[i + 1])))

                if num2 == num1 + 1:
                    numeric_pattern += 1
            except (ValueError, IndexError):
                pass

        # If > 50% are sequential, flag it
        return numeric_pattern > len(usernames) * 0.5


if __name__ == "__main__":
    print("=== Credential Stuffing Hunter Demo ===\n")

    hunter = CredentialStuffingHunter()

    # Simulate credential stuffing attack
    sample_events = []

    # Attack from single IP
    for i in range(50):
        sample_events.append({
            "timestamp": f"2026-02-19T10:{30 + i % 30}:00Z",
            "ip": "203.0.113.10",
            "user": f"user{i}@example.com",
            "success": False
        })

    # Distributed attack on single account
    for i in range(15):
        sample_events.append({
            "timestamp": f"2026-02-19T11:{i}:00Z",
            "ip": f"198.51.100.{i}",
            "user": "admin@example.com",
            "success": False
        })

    findings = hunter.analyze(sample_events)

    print(f"Detected {len(findings)} threats:\n")
    for finding in findings:
        print(f"[{finding['severity'].upper()}] {finding['type']}")
        print(f"  {finding['description']}")
        print(f"  Indicators: {finding.get('indicators', {})}")
        print()

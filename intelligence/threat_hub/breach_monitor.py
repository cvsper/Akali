#!/usr/bin/env python3
"""
Breach Monitor - Monitor for compromised credentials using HaveIBeenPwned
"""

import hashlib
import json
import os
import requests
from datetime import datetime
from typing import Dict, List, Optional


class BreachMonitor:
    """Monitor for data breaches affecting family emails"""

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize breach monitor

        Args:
            api_key: HaveIBeenPwned API key (required for breach lookups)
        """
        self.api_key = api_key
        self.base_url = "https://haveibeenpwned.com/api/v3"
        self.cache_file = os.path.expanduser("~/akali/intelligence/threat_hub/breach_cache.json")
        self.cache = self._load_cache()

    def _load_cache(self) -> Dict:
        """Load breach cache from disk"""
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Warning: Failed to load cache: {e}")
        return {"breaches": {}, "last_check": {}}

    def _save_cache(self):
        """Save breach cache to disk"""
        os.makedirs(os.path.dirname(self.cache_file), exist_ok=True)
        with open(self.cache_file, 'w') as f:
            json.dump(self.cache, f, indent=2)

    def check_email(self, email: str) -> List[Dict]:
        """
        Check if email appears in any breaches

        Args:
            email: Email address to check

        Returns:
            List of breach dictionaries
        """
        if not self.api_key:
            print("Error: HaveIBeenPwned API key required")
            print("Get free key at: https://haveibeenpwned.com/API/Key")
            return []

        print(f"Checking breaches for: {email}")

        # Check cache first (avoid rate limits)
        if email in self.cache.get("last_check", {}):
            last_check = datetime.fromisoformat(self.cache["last_check"][email])
            age = datetime.now() - last_check

            # Cache valid for 24 hours
            if age.total_seconds() < 86400:
                print("  Using cached data")
                return self.cache["breaches"].get(email, [])

        # Fetch from API
        url = f"{self.base_url}/breachedaccount/{email}"
        headers = {
            "hibp-api-key": self.api_key,
            "user-agent": "Akali Security Scanner",
        }

        try:
            response = requests.get(url, headers=headers, timeout=30)

            if response.status_code == 200:
                breaches = response.json()

                # Update cache
                self.cache["breaches"][email] = breaches
                self.cache["last_check"][email] = datetime.now().isoformat()
                self._save_cache()

                print(f"  Found {len(breaches)} breach(es)")
                return breaches

            elif response.status_code == 404:
                # No breaches found (good!)
                print("  No breaches found ✅")
                self.cache["breaches"][email] = []
                self.cache["last_check"][email] = datetime.now().isoformat()
                self._save_cache()
                return []

            else:
                print(f"  API error: {response.status_code}")
                return []

        except requests.exceptions.RequestException as e:
            print(f"  Error checking email: {e}")
            return []

    def check_multiple_emails(self, emails: List[str]) -> Dict[str, List[Dict]]:
        """
        Check multiple emails for breaches

        Args:
            emails: List of email addresses

        Returns:
            Dictionary mapping email -> breaches
        """
        results = {}

        for email in emails:
            breaches = self.check_email(email)
            if breaches:
                results[email] = breaches

        return results

    def check_password(self, password: str) -> Dict:
        """
        Check if password appears in breaches (using k-anonymity)

        This uses the Pwned Passwords API which never sends the full
        password. It uses k-anonymity to protect privacy.

        Args:
            password: Password to check

        Returns:
            Result dictionary with count
        """
        # Hash password with SHA-1
        sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()

        # Get first 5 characters (prefix)
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        # Query API with prefix only (k-anonymity)
        url = f"https://api.pwnedpasswords.com/range/{prefix}"

        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()

            # Parse response
            # Format: SUFFIX:COUNT\r\n
            for line in response.text.split('\r\n'):
                if ':' in line:
                    hash_suffix, count = line.split(':')
                    if hash_suffix == suffix:
                        return {
                            "pwned": True,
                            "count": int(count),
                            "message": f"⚠️  Password appears in {count} breaches!",
                        }

            return {
                "pwned": False,
                "count": 0,
                "message": "✅ Password not found in breaches",
            }

        except requests.exceptions.RequestException as e:
            return {
                "error": True,
                "message": f"Error checking password: {e}",
            }

    def get_breach_summary(self, email: str) -> Dict:
        """
        Get summary of breaches for email

        Args:
            email: Email address

        Returns:
            Summary dictionary
        """
        breaches = self.check_email(email)

        if not breaches:
            return {
                "email": email,
                "breach_count": 0,
                "breached": False,
                "breaches": [],
            }

        # Extract key info from each breach
        breach_summaries = []
        for breach in breaches:
            breach_summaries.append({
                "name": breach.get("Name", "Unknown"),
                "title": breach.get("Title", "Unknown"),
                "domain": breach.get("Domain", ""),
                "breach_date": breach.get("BreachDate", "Unknown"),
                "added_date": breach.get("AddedDate", "Unknown"),
                "pwn_count": breach.get("PwnCount", 0),
                "data_classes": breach.get("DataClasses", []),
                "is_verified": breach.get("IsVerified", False),
                "is_sensitive": breach.get("IsSensitive", False),
            })

        # Find most recent breach
        most_recent = max(breaches, key=lambda b: b.get("BreachDate", ""))

        return {
            "email": email,
            "breach_count": len(breaches),
            "breached": True,
            "breaches": breach_summaries,
            "most_recent": most_recent.get("Name", "Unknown"),
            "most_recent_date": most_recent.get("BreachDate", "Unknown"),
        }


def main():
    """CLI for breach monitoring"""
    import sys

    # Try to load API key from environment
    api_key = os.environ.get("HIBP_API_KEY")

    monitor = BreachMonitor(api_key=api_key)

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python breach_monitor.py email <email>         # Check email")
        print("  python breach_monitor.py password <password>   # Check password")
        print("\nNote: Set HIBP_API_KEY environment variable or get key at:")
        print("https://haveibeenpwned.com/API/Key")
        sys.exit(1)

    command = sys.argv[1]

    if command == "email":
        if len(sys.argv) < 3:
            print("Error: Email required")
            sys.exit(1)

        email = sys.argv[2]
        summary = monitor.get_breach_summary(email)

        print(f"\n{'='*80}")
        print(f"Breach Check: {email}")
        print(f"{'='*80}\n")

        if not summary["breached"]:
            print("✅ Good news! This email was not found in any breaches.")
        else:
            print(f"⚠️  Found in {summary['breach_count']} breach(es):")
            print(f"Most recent: {summary['most_recent']} ({summary['most_recent_date']})\n")

            for breach in summary["breaches"]:
                print(f"• {breach['title']}")
                print(f"  Domain: {breach['domain']}")
                print(f"  Breach Date: {breach['breach_date']}")
                print(f"  Accounts Affected: {breach['pwn_count']:,}")
                print(f"  Data Exposed: {', '.join(breach['data_classes'])}")
                print(f"  Verified: {'Yes' if breach['is_verified'] else 'No'}")
                print()

            print("⚠️  Recommendation: Change password on affected sites")
            print("    and enable two-factor authentication (2FA)")

    elif command == "password":
        if len(sys.argv) < 3:
            print("Error: Password required")
            sys.exit(1)

        password = sys.argv[2]
        result = monitor.check_password(password)

        print(f"\n{'='*80}")
        print("Password Breach Check")
        print(f"{'='*80}\n")

        if "error" in result:
            print(f"Error: {result['message']}")
        else:
            print(result["message"])

            if result["pwned"]:
                print(f"\n⚠️  This password has been seen {result['count']:,} times in data breaches!")
                print("    DO NOT use this password. Choose a unique, strong password.")

    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()

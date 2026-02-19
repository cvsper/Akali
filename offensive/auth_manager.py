"""Authorization manager for offensive security operations."""

import json
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse


class AuthorizationManager:
    """Manage authorization for offensive security scans."""

    def __init__(self, config_path: str = None):
        if config_path:
            self.config_path = Path(config_path)
        else:
            self.config_path = Path.home() / "akali" / "offensive" / "auth_config.json"

        self.audit_log_path = Path.home() / "akali" / "offensive" / "audit.log"

        # Ensure files exist
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self._load_config()

    def _load_config(self):
        """Load authorization configuration."""
        if self.config_path.exists():
            with open(self.config_path, 'r') as f:
                self.config = json.load(f)
        else:
            # Initialize default config
            self.config = {
                "authorized_targets": [],
                "require_explicit_consent": True,
                "audit_enabled": True,
                "max_scan_duration_hours": 24
            }
            self._save_config()

    def _save_config(self):
        """Save authorization configuration."""
        with open(self.config_path, 'w') as f:
            json.dump(self.config, f, indent=2)

    def add_authorized_target(
        self,
        target: str,
        description: str,
        authorized_by: str,
        expires_at: Optional[str] = None
    ) -> bool:
        """Add a target to the authorized whitelist.

        Args:
            target: Target URL/hostname/IP
            description: Description of authorization
            authorized_by: Person who granted authorization
            expires_at: Optional expiration date (ISO format)

        Returns:
            True if added successfully
        """
        # Normalize target
        normalized_target = self._normalize_target(target)

        # Check if already authorized
        for auth in self.config["authorized_targets"]:
            if auth["target"] == normalized_target:
                print(f"⚠️  Target already authorized: {normalized_target}")
                return False

        # Add to whitelist
        authorization = {
            "target": normalized_target,
            "description": description,
            "authorized_by": authorized_by,
            "added_at": datetime.now().isoformat(),
            "expires_at": expires_at,
            "scan_count": 0,
            "last_scanned": None
        }

        self.config["authorized_targets"].append(authorization)
        self._save_config()

        # Audit log
        self._audit_log("TARGET_AUTHORIZED", {
            "target": normalized_target,
            "authorized_by": authorized_by,
            "expires_at": expires_at
        })

        print(f"✅ Target authorized: {normalized_target}")
        return True

    def remove_authorized_target(self, target: str) -> bool:
        """Remove a target from the authorized whitelist.

        Args:
            target: Target to remove

        Returns:
            True if removed successfully
        """
        normalized_target = self._normalize_target(target)

        # Find and remove
        original_length = len(self.config["authorized_targets"])
        self.config["authorized_targets"] = [
            auth for auth in self.config["authorized_targets"]
            if auth["target"] != normalized_target
        ]

        if len(self.config["authorized_targets"]) == original_length:
            print(f"❌ Target not found: {normalized_target}")
            return False

        self._save_config()

        # Audit log
        self._audit_log("TARGET_DEAUTHORIZED", {"target": normalized_target})

        print(f"✅ Target deauthorized: {normalized_target}")
        return True

    def is_authorized(self, target: str) -> bool:
        """Check if a target is authorized for scanning.

        Args:
            target: Target to check

        Returns:
            True if authorized
        """
        normalized_target = self._normalize_target(target)

        # Check whitelist
        for auth in self.config["authorized_targets"]:
            if auth["target"] == normalized_target:
                # Check expiration
                if auth.get("expires_at"):
                    expires = datetime.fromisoformat(auth["expires_at"])
                    if datetime.now() > expires:
                        print(f"❌ Authorization expired for {normalized_target}")
                        return False

                return True

        return False

    def request_authorization(self, target: str, scan_type: str) -> bool:
        """Request explicit authorization for a scan.

        Args:
            target: Target to scan
            scan_type: Type of scan (web, network, api, etc.)

        Returns:
            True if authorized
        """
        normalized_target = self._normalize_target(target)

        print("\n" + "=" * 80)
        print("⚠️  OFFENSIVE SECURITY SCAN - AUTHORIZATION REQUIRED")
        print("=" * 80)
        print(f"\nTarget: {normalized_target}")
        print(f"Scan Type: {scan_type}")
        print("\nWARNING:")
        print("  • Only scan systems you own or have written permission to test")
        print("  • Unauthorized scanning is ILLEGAL and may result in prosecution")
        print("  • All scan activity is logged and auditable")
        print("\n" + "=" * 80)

        # Check if target is whitelisted
        if self.is_authorized(normalized_target):
            print(f"✅ Target is in authorized whitelist")

            if self.config.get("require_explicit_consent"):
                consent = input("\nProceed with scan? (yes/no): ")
                if consent.lower() != "yes":
                    print("❌ Scan cancelled")
                    self._audit_log("SCAN_DENIED", {
                        "target": normalized_target,
                        "scan_type": scan_type,
                        "reason": "User declined"
                    })
                    return False

            # Update scan stats
            self._update_scan_stats(normalized_target)

            # Audit log
            self._audit_log("SCAN_AUTHORIZED", {
                "target": normalized_target,
                "scan_type": scan_type
            })

            return True

        else:
            print(f"❌ Target NOT in authorized whitelist")
            print(f"\nTo authorize this target, run:")
            print(f"  akali authorize add {normalized_target} --description \"Your description\" --authorized-by \"Your name\"")

            self._audit_log("SCAN_DENIED", {
                "target": normalized_target,
                "scan_type": scan_type,
                "reason": "Not in whitelist"
            })

            return False

    def list_authorized_targets(self):
        """List all authorized targets."""
        if not self.config["authorized_targets"]:
            print("No authorized targets.")
            return

        print("\n📋 Authorized Targets:\n")

        for i, auth in enumerate(self.config["authorized_targets"], 1):
            print(f"{i}. {auth['target']}")
            print(f"   Description: {auth['description']}")
            print(f"   Authorized by: {auth['authorized_by']}")
            print(f"   Added: {auth['added_at']}")

            if auth.get("expires_at"):
                expires = datetime.fromisoformat(auth["expires_at"])
                if datetime.now() > expires:
                    print(f"   Status: ❌ EXPIRED ({auth['expires_at']})")
                else:
                    print(f"   Expires: {auth['expires_at']}")
            else:
                print(f"   Expires: Never")

            print(f"   Scan count: {auth['scan_count']}")

            if auth.get("last_scanned"):
                print(f"   Last scanned: {auth['last_scanned']}")

            print()

    def _normalize_target(self, target: str) -> str:
        """Normalize target for consistent comparison.

        Args:
            target: Raw target string

        Returns:
            Normalized target
        """
        # Try to parse as URL
        if target.startswith(("http://", "https://")):
            parsed = urlparse(target)
            return parsed.netloc or parsed.path
        else:
            # Assume hostname or IP
            return target.lower()

    def _update_scan_stats(self, target: str):
        """Update scan statistics for a target."""
        for auth in self.config["authorized_targets"]:
            if auth["target"] == target:
                auth["scan_count"] = auth.get("scan_count", 0) + 1
                auth["last_scanned"] = datetime.now().isoformat()
                break

        self._save_config()

    def _audit_log(self, event: str, data: Dict[str, Any]):
        """Write to audit log.

        Args:
            event: Event type
            data: Event data
        """
        if not self.config.get("audit_enabled"):
            return

        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "event": event,
            "data": data
        }

        # Append to audit log
        with open(self.audit_log_path, 'a') as f:
            f.write(json.dumps(log_entry) + "\n")

    def view_audit_log(self, limit: int = 50):
        """View recent audit log entries.

        Args:
            limit: Maximum number of entries to show
        """
        if not self.audit_log_path.exists():
            print("No audit log found.")
            return

        with open(self.audit_log_path, 'r') as f:
            lines = f.readlines()

        # Get last N lines
        recent_lines = lines[-limit:]

        print(f"\n📋 Audit Log (last {len(recent_lines)} entries):\n")

        for line in recent_lines:
            try:
                entry = json.loads(line)
                timestamp = entry["timestamp"]
                event = entry["event"]
                data = entry["data"]

                print(f"[{timestamp}] {event}")
                for key, value in data.items():
                    print(f"  {key}: {value}")
                print()

            except json.JSONDecodeError:
                continue


def main():
    """CLI for authorization manager."""
    import sys
    import argparse

    parser = argparse.ArgumentParser(description="Akali Authorization Manager")
    subparsers = parser.add_subparsers(dest="command")

    # Add target
    add_parser = subparsers.add_parser("add", help="Add authorized target")
    add_parser.add_argument("target", help="Target URL/hostname/IP")
    add_parser.add_argument("--description", required=True, help="Authorization description")
    add_parser.add_argument("--authorized-by", required=True, help="Person granting authorization")
    add_parser.add_argument("--expires", help="Expiration date (YYYY-MM-DD)")

    # Remove target
    remove_parser = subparsers.add_parser("remove", help="Remove authorized target")
    remove_parser.add_argument("target", help="Target to remove")

    # List targets
    subparsers.add_parser("list", help="List authorized targets")

    # View audit log
    audit_parser = subparsers.add_parser("audit", help="View audit log")
    audit_parser.add_argument("--limit", type=int, default=50, help="Number of entries to show")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    manager = AuthorizationManager()

    if args.command == "add":
        expires = None
        if args.expires:
            try:
                expires = datetime.strptime(args.expires, "%Y-%m-%d").isoformat()
            except ValueError:
                print("❌ Invalid date format. Use YYYY-MM-DD")
                sys.exit(1)

        manager.add_authorized_target(
            target=args.target,
            description=args.description,
            authorized_by=args.authorized_by,
            expires_at=expires
        )

    elif args.command == "remove":
        manager.remove_authorized_target(args.target)

    elif args.command == "list":
        manager.list_authorized_targets()

    elif args.command == "audit":
        manager.view_audit_log(limit=args.limit)


if __name__ == "__main__":
    main()

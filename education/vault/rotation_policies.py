#!/usr/bin/env python3
"""
Akali Secret Rotation Policies - Automated secret rotation

Supports:
- Time-based rotation (every N days)
- Event-based rotation (on specific triggers)
- Custom rotation handlers
- Rotation tracking and audit logs
"""

import os
import sys
import json
from typing import Dict, List, Optional, Callable, Any
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, asdict
from enum import Enum


class RotationType(Enum):
    """Types of rotation policies."""
    TIME_BASED = "time_based"
    EVENT_BASED = "event_based"
    MANUAL = "manual"


class RotationStatus(Enum):
    """Rotation execution status."""
    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class RotationPolicy:
    """Rotation policy definition."""
    policy_id: str
    secret_path: str
    rotation_type: str
    rotation_interval_days: Optional[int] = None
    rotation_handler: Optional[str] = None
    enabled: bool = True
    last_rotated: Optional[str] = None
    next_rotation: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RotationPolicy":
        """Create from dictionary."""
        return cls(**data)


@dataclass
class RotationLog:
    """Rotation execution log entry."""
    log_id: str
    policy_id: str
    secret_path: str
    timestamp: str
    status: str
    error_message: Optional[str] = None
    old_version: Optional[int] = None
    new_version: Optional[int] = None
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


class RotationManager:
    """Manages secret rotation policies and execution."""

    def __init__(self, vault_client, policies_file: Optional[str] = None, logs_file: Optional[str] = None):
        """Initialize rotation manager.

        Args:
            vault_client: VaultClient instance
            policies_file: Path to policies JSON file
            logs_file: Path to rotation logs JSON file
        """
        self.vault = vault_client

        # Default file paths
        akali_data = Path.home() / "akali" / "data"
        akali_data.mkdir(parents=True, exist_ok=True)

        self.policies_file = Path(policies_file or akali_data / "rotation_policies.json")
        self.logs_file = Path(logs_file or akali_data / "rotation_logs.json")

        # Load existing policies and logs
        self.policies = self._load_policies()
        self.logs = self._load_logs()

        # Rotation handlers registry
        self.handlers: Dict[str, Callable] = {}

    def _load_policies(self) -> Dict[str, RotationPolicy]:
        """Load policies from file."""
        if not self.policies_file.exists():
            return {}

        try:
            with open(self.policies_file, 'r') as f:
                data = json.load(f)
                return {
                    p_id: RotationPolicy.from_dict(p_data)
                    for p_id, p_data in data.items()
                }
        except Exception as e:
            print(f"⚠️  Failed to load policies: {e}", file=sys.stderr)
            return {}

    def _save_policies(self):
        """Save policies to file."""
        try:
            with open(self.policies_file, 'w') as f:
                data = {
                    p_id: policy.to_dict()
                    for p_id, policy in self.policies.items()
                }
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"❌ Failed to save policies: {e}", file=sys.stderr)

    def _load_logs(self) -> List[RotationLog]:
        """Load rotation logs from file."""
        if not self.logs_file.exists():
            return []

        try:
            with open(self.logs_file, 'r') as f:
                data = json.load(f)
                return [RotationLog(**log) for log in data]
        except Exception as e:
            print(f"⚠️  Failed to load logs: {e}", file=sys.stderr)
            return []

    def _save_logs(self):
        """Save rotation logs to file."""
        try:
            with open(self.logs_file, 'w') as f:
                data = [log.to_dict() for log in self.logs]
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"❌ Failed to save logs: {e}", file=sys.stderr)

    def register_handler(self, name: str, handler: Callable[[str, Dict], Dict[str, Any]]):
        """Register a custom rotation handler.

        Args:
            name: Handler name
            handler: Function that takes (secret_path, old_secret) and returns new_secret
        """
        self.handlers[name] = handler

    def create_policy(
        self,
        policy_id: str,
        secret_path: str,
        rotation_type: RotationType,
        rotation_interval_days: Optional[int] = None,
        rotation_handler: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> RotationPolicy:
        """Create a new rotation policy.

        Args:
            policy_id: Unique policy identifier
            secret_path: Vault secret path
            rotation_type: Type of rotation (time_based, event_based, manual)
            rotation_interval_days: Days between rotations (for time_based)
            rotation_handler: Custom handler name (optional)
            metadata: Additional metadata

        Returns:
            Created RotationPolicy
        """
        if policy_id in self.policies:
            raise ValueError(f"Policy already exists: {policy_id}")

        # Calculate next rotation for time-based policies
        next_rotation = None
        if rotation_type == RotationType.TIME_BASED and rotation_interval_days:
            next_rotation = (datetime.utcnow() + timedelta(days=rotation_interval_days)).isoformat()

        policy = RotationPolicy(
            policy_id=policy_id,
            secret_path=secret_path,
            rotation_type=rotation_type.value,
            rotation_interval_days=rotation_interval_days,
            rotation_handler=rotation_handler,
            next_rotation=next_rotation,
            metadata=metadata or {}
        )

        self.policies[policy_id] = policy
        self._save_policies()
        return policy

    def delete_policy(self, policy_id: str) -> bool:
        """Delete a rotation policy.

        Args:
            policy_id: Policy to delete

        Returns:
            True if deleted, False if not found
        """
        if policy_id in self.policies:
            del self.policies[policy_id]
            self._save_policies()
            return True
        return False

    def enable_policy(self, policy_id: str) -> bool:
        """Enable a rotation policy."""
        if policy_id in self.policies:
            self.policies[policy_id].enabled = True
            self._save_policies()
            return True
        return False

    def disable_policy(self, policy_id: str) -> bool:
        """Disable a rotation policy."""
        if policy_id in self.policies:
            self.policies[policy_id].enabled = False
            self._save_policies()
            return True
        return False

    def list_policies(self, enabled_only: bool = False) -> List[RotationPolicy]:
        """List all policies.

        Args:
            enabled_only: Only return enabled policies

        Returns:
            List of RotationPolicy objects
        """
        policies = list(self.policies.values())
        if enabled_only:
            policies = [p for p in policies if p.enabled]
        return policies

    def check_due_rotations(self) -> List[RotationPolicy]:
        """Check for policies that need rotation.

        Returns:
            List of policies that are due for rotation
        """
        due_policies = []
        now = datetime.utcnow()

        for policy in self.policies.values():
            if not policy.enabled:
                continue

            if policy.rotation_type == RotationType.TIME_BASED.value:
                if policy.next_rotation:
                    next_rotation_dt = datetime.fromisoformat(policy.next_rotation)
                    if now >= next_rotation_dt:
                        due_policies.append(policy)

        return due_policies

    def rotate_secret(
        self,
        policy_id: str,
        new_secret: Optional[Dict[str, Any]] = None,
        force: bool = False
    ) -> RotationLog:
        """Rotate a secret according to its policy.

        Args:
            policy_id: Policy to execute
            new_secret: New secret data (if None, uses handler or prompts)
            force: Force rotation even if not due

        Returns:
            RotationLog entry
        """
        policy = self.policies.get(policy_id)
        if not policy:
            raise ValueError(f"Policy not found: {policy_id}")

        if not policy.enabled and not force:
            log = RotationLog(
                log_id=f"ROT-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                policy_id=policy_id,
                secret_path=policy.secret_path,
                timestamp=datetime.utcnow().isoformat(),
                status=RotationStatus.SKIPPED.value,
                error_message="Policy disabled"
            )
            self.logs.append(log)
            self._save_logs()
            return log

        # Get current secret
        current_secret = self.vault.get_secret(policy.secret_path)
        if not current_secret:
            log = RotationLog(
                log_id=f"ROT-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                policy_id=policy_id,
                secret_path=policy.secret_path,
                timestamp=datetime.utcnow().isoformat(),
                status=RotationStatus.FAILED.value,
                error_message="Secret not found in Vault"
            )
            self.logs.append(log)
            self._save_logs()
            return log

        # Generate new secret
        if new_secret is None:
            if policy.rotation_handler and policy.rotation_handler in self.handlers:
                # Use custom handler
                handler = self.handlers[policy.rotation_handler]
                try:
                    new_secret = handler(policy.secret_path, current_secret)
                except Exception as e:
                    log = RotationLog(
                        log_id=f"ROT-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                        policy_id=policy_id,
                        secret_path=policy.secret_path,
                        timestamp=datetime.utcnow().isoformat(),
                        status=RotationStatus.FAILED.value,
                        error_message=f"Handler failed: {e}"
                    )
                    self.logs.append(log)
                    self._save_logs()
                    return log
            else:
                # Default handler: keep same structure but mark as rotated
                new_secret = current_secret.copy()
                new_secret["rotated_at"] = datetime.utcnow().isoformat()

        # Get metadata before rotation
        old_metadata = self.vault.get_secret_metadata(policy.secret_path)
        old_version = old_metadata.get("current_version") if old_metadata else None

        # Rotate secret in Vault
        success = self.vault.rotate_secret(policy.secret_path, new_secret)

        if success:
            # Get new metadata
            new_metadata = self.vault.get_secret_metadata(policy.secret_path)
            new_version = new_metadata.get("current_version") if new_metadata else None

            # Update policy
            policy.last_rotated = datetime.utcnow().isoformat()
            if policy.rotation_type == RotationType.TIME_BASED.value and policy.rotation_interval_days:
                policy.next_rotation = (
                    datetime.utcnow() + timedelta(days=policy.rotation_interval_days)
                ).isoformat()
            self._save_policies()

            # Create success log
            log = RotationLog(
                log_id=f"ROT-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                policy_id=policy_id,
                secret_path=policy.secret_path,
                timestamp=datetime.utcnow().isoformat(),
                status=RotationStatus.SUCCESS.value,
                old_version=old_version,
                new_version=new_version
            )
        else:
            # Create failure log
            log = RotationLog(
                log_id=f"ROT-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                policy_id=policy_id,
                secret_path=policy.secret_path,
                timestamp=datetime.utcnow().isoformat(),
                status=RotationStatus.FAILED.value,
                error_message="Vault write failed"
            )

        self.logs.append(log)
        self._save_logs()
        return log

    def get_rotation_history(self, policy_id: Optional[str] = None, limit: int = 50) -> List[RotationLog]:
        """Get rotation history.

        Args:
            policy_id: Filter by policy (optional)
            limit: Maximum number of logs to return

        Returns:
            List of RotationLog entries
        """
        logs = self.logs
        if policy_id:
            logs = [log for log in logs if log.policy_id == policy_id]

        # Return most recent first
        return sorted(logs, key=lambda x: x.timestamp, reverse=True)[:limit]


# Built-in rotation handlers

def random_string_handler(secret_path: str, old_secret: Dict[str, Any]) -> Dict[str, Any]:
    """Generate random string for password fields."""
    import secrets
    import string

    new_secret = old_secret.copy()

    # Look for password/token fields and rotate them
    for key in new_secret:
        if any(keyword in key.lower() for keyword in ["password", "token", "secret", "key"]):
            if isinstance(new_secret[key], str):
                # Generate new random string (same length or 32 chars)
                length = max(32, len(new_secret[key]))
                alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
                new_secret[key] = ''.join(secrets.choice(alphabet) for _ in range(length))

    new_secret["rotated_at"] = datetime.utcnow().isoformat()
    return new_secret


def database_password_handler(secret_path: str, old_secret: Dict[str, Any]) -> Dict[str, Any]:
    """Rotate database password (requires database connection)."""
    # This is a template - real implementation would:
    # 1. Generate new password
    # 2. Connect to database
    # 3. Update user password
    # 4. Test new connection
    # 5. Return new secret

    import secrets
    import string

    new_secret = old_secret.copy()

    # Generate strong password
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    new_password = ''.join(secrets.choice(alphabet) for _ in range(32))

    new_secret["password"] = new_password
    new_secret["rotated_at"] = datetime.utcnow().isoformat()

    # NOTE: In production, you would actually update the database user here
    # Example: execute ALTER USER statement, test connection, etc.

    return new_secret


def api_key_handler(secret_path: str, old_secret: Dict[str, Any]) -> Dict[str, Any]:
    """Rotate API key (requires API call)."""
    # This is a template - real implementation would:
    # 1. Call API to generate new key
    # 2. Revoke old key
    # 3. Return new secret

    new_secret = old_secret.copy()

    # Placeholder - would call actual API
    new_secret["api_key"] = f"rotated_{datetime.utcnow().timestamp()}"
    new_secret["rotated_at"] = datetime.utcnow().isoformat()

    return new_secret


def main():
    """CLI test interface."""
    from vault_client import get_vault_client

    import argparse

    parser = argparse.ArgumentParser(description="Akali Rotation Manager")
    parser.add_argument("--mock", action="store_true", help="Use mock Vault client")

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Create policy
    create_parser = subparsers.add_parser("create", help="Create rotation policy")
    create_parser.add_argument("policy_id", help="Policy ID")
    create_parser.add_argument("secret_path", help="Secret path in Vault")
    create_parser.add_argument("--interval", type=int, default=30, help="Rotation interval (days)")
    create_parser.add_argument("--handler", help="Rotation handler name")

    # List policies
    subparsers.add_parser("list", help="List rotation policies")

    # Check due
    subparsers.add_parser("check", help="Check for due rotations")

    # Rotate
    rotate_parser = subparsers.add_parser("rotate", help="Rotate a secret")
    rotate_parser.add_argument("policy_id", help="Policy ID")
    rotate_parser.add_argument("--force", action="store_true", help="Force rotation")

    # History
    history_parser = subparsers.add_parser("history", help="Show rotation history")
    history_parser.add_argument("--policy", help="Filter by policy ID")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    # Initialize
    vault = get_vault_client(mock=args.mock)
    manager = RotationManager(vault)

    # Register built-in handlers
    manager.register_handler("random_string", random_string_handler)
    manager.register_handler("database_password", database_password_handler)
    manager.register_handler("api_key", api_key_handler)

    # Execute command
    if args.command == "create":
        policy = manager.create_policy(
            policy_id=args.policy_id,
            secret_path=args.secret_path,
            rotation_type=RotationType.TIME_BASED,
            rotation_interval_days=args.interval,
            rotation_handler=args.handler
        )
        print(f"✅ Policy created: {policy.policy_id}")
        print(f"   Secret: {policy.secret_path}")
        print(f"   Interval: {policy.rotation_interval_days} days")
        if policy.next_rotation:
            print(f"   Next rotation: {policy.next_rotation}")

    elif args.command == "list":
        policies = manager.list_policies()
        if not policies:
            print("No rotation policies configured")
            return

        print(f"\n🔐 Rotation Policies ({len(policies)}):\n")
        for policy in policies:
            status = "✅" if policy.enabled else "❌"
            print(f"{status} {policy.policy_id}")
            print(f"   Secret: {policy.secret_path}")
            print(f"   Type: {policy.rotation_type}")
            if policy.rotation_interval_days:
                print(f"   Interval: {policy.rotation_interval_days} days")
            if policy.last_rotated:
                print(f"   Last rotated: {policy.last_rotated}")
            if policy.next_rotation:
                print(f"   Next rotation: {policy.next_rotation}")
            print()

    elif args.command == "check":
        due = manager.check_due_rotations()
        if not due:
            print("✅ No rotations due")
            return

        print(f"\n⚠️  {len(due)} rotation(s) due:\n")
        for policy in due:
            print(f"• {policy.policy_id}")
            print(f"  Secret: {policy.secret_path}")
            print(f"  Next rotation: {policy.next_rotation}")
            print()

    elif args.command == "rotate":
        log = manager.rotate_secret(args.policy_id, force=args.force)
        if log.status == RotationStatus.SUCCESS.value:
            print(f"✅ Secret rotated: {log.secret_path}")
            print(f"   Old version: {log.old_version}")
            print(f"   New version: {log.new_version}")
        else:
            print(f"❌ Rotation failed: {log.error_message}")

    elif args.command == "history":
        logs = manager.get_rotation_history(policy_id=args.policy)
        if not logs:
            print("No rotation history")
            return

        print(f"\n📊 Rotation History ({len(logs)}):\n")
        for log in logs:
            status_emoji = {
                "success": "✅",
                "failed": "❌",
                "skipped": "⏭️"
            }.get(log.status, "❓")

            print(f"{status_emoji} {log.log_id}")
            print(f"   Policy: {log.policy_id}")
            print(f"   Secret: {log.secret_path}")
            print(f"   Timestamp: {log.timestamp}")
            print(f"   Status: {log.status}")
            if log.error_message:
                print(f"   Error: {log.error_message}")
            if log.old_version and log.new_version:
                print(f"   Version: {log.old_version} → {log.new_version}")
            print()


if __name__ == "__main__":
    main()

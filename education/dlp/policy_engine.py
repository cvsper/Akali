"""Policy Enforcement Engine for Akali DLP System.

Enforces DLP policies based on configurable rules. Supports actions:
warn, block, redact, encrypt. Policies defined in YAML configuration.
"""

import sys
import yaml
from typing import Dict, Any, Optional, List
from pathlib import Path
from enum import Enum
from dataclasses import dataclass

# Add project root to path
sys.path.insert(0, str(Path.home() / "akali"))

from education.dlp.pii_detector import PIIType


class PolicyAction(Enum):
    """DLP policy actions."""
    WARN = "warn"
    BLOCK = "block"
    REDACT = "redact"
    ENCRYPT = "encrypt"


@dataclass
class PolicyRule:
    """A DLP policy rule."""
    name: str
    description: str
    pii_types: List[str]  # PII types to match
    severity_threshold: str  # Minimum severity to trigger
    action: PolicyAction
    source_filters: Optional[List[str]] = None  # Filter by source type
    confidence_threshold: float = 0.6  # Minimum confidence
    enabled: bool = True


class PolicyEngine:
    """Enforces DLP policies based on rules."""

    DEFAULT_POLICIES = {
        'critical_pii_block': {
            'name': 'Block Critical PII',
            'description': 'Block commits/requests with SSN, credit cards, or passports',
            'pii_types': ['ssn', 'credit_card', 'passport', 'medical_id'],
            'severity_threshold': 'critical',
            'action': 'block',
            'source_filters': ['git', 'api'],
            'confidence_threshold': 0.7,
            'enabled': True
        },
        'high_pii_warn': {
            'name': 'Warn on High-Risk PII',
            'description': 'Warn when API keys, bank accounts detected',
            'pii_types': ['api_key', 'bank_account'],
            'severity_threshold': 'high',
            'action': 'warn',
            'confidence_threshold': 0.6,
            'enabled': True
        },
        'email_phone_redact': {
            'name': 'Redact Email/Phone in API Responses',
            'description': 'Automatically redact emails and phones in API responses',
            'pii_types': ['email', 'phone'],
            'severity_threshold': 'medium',
            'action': 'redact',
            'source_filters': ['api'],
            'confidence_threshold': 0.6,
            'enabled': False  # Disabled by default (opt-in)
        },
        'sensitive_file_encrypt': {
            'name': 'Encrypt Sensitive Files',
            'description': 'Auto-encrypt files with multiple PII types',
            'pii_types': ['ssn', 'credit_card', 'passport', 'medical_id', 'bank_account'],
            'severity_threshold': 'high',
            'action': 'encrypt',
            'source_filters': ['file'],
            'confidence_threshold': 0.8,
            'enabled': False  # Disabled by default (requires setup)
        }
    }

    def __init__(self, config_path: Optional[str] = None):
        """Initialize policy engine.

        Args:
            config_path: Path to policy configuration file (YAML)
        """
        self.config_path = config_path or str(Path.home() / '.akali' / 'dlp_policies.yaml')
        self.policies: Dict[str, PolicyRule] = {}
        self.load_policies()

    def load_policies(self):
        """Load policies from configuration file."""
        config_file = Path(self.config_path)

        # Create default config if doesn't exist
        if not config_file.exists():
            self._create_default_config()

        # Load policies
        try:
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f) or {}

            policies_data = config.get('policies', self.DEFAULT_POLICIES)

            for policy_id, policy_data in policies_data.items():
                self.policies[policy_id] = PolicyRule(
                    name=policy_data['name'],
                    description=policy_data['description'],
                    pii_types=policy_data['pii_types'],
                    severity_threshold=policy_data['severity_threshold'],
                    action=PolicyAction(policy_data['action']),
                    source_filters=policy_data.get('source_filters'),
                    confidence_threshold=policy_data.get('confidence_threshold', 0.6),
                    enabled=policy_data.get('enabled', True)
                )

            print(f"✅ Loaded {len(self.policies)} DLP policies")

        except Exception as e:
            print(f"⚠️  Failed to load policies: {e}")
            print("Using default policies")
            self._load_default_policies()

    def _create_default_config(self):
        """Create default policy configuration file."""
        config_dir = Path(self.config_path).parent
        config_dir.mkdir(parents=True, exist_ok=True)

        config = {
            'version': '1.0',
            'policies': self.DEFAULT_POLICIES,
            'settings': {
                'send_alerts': True,
                'alert_recipient': 'dommo',
                'log_violations': True,
                'default_action': 'warn'
            }
        }

        with open(self.config_path, 'w') as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False)

        print(f"✅ Created default DLP policy config: {self.config_path}")

    def _load_default_policies(self):
        """Load default policies."""
        for policy_id, policy_data in self.DEFAULT_POLICIES.items():
            self.policies[policy_id] = PolicyRule(
                name=policy_data['name'],
                description=policy_data['description'],
                pii_types=policy_data['pii_types'],
                severity_threshold=policy_data['severity_threshold'],
                action=PolicyAction(policy_data['action']),
                source_filters=policy_data.get('source_filters'),
                confidence_threshold=policy_data.get('confidence_threshold', 0.6),
                enabled=policy_data.get('enabled', True)
            )

    def enforce(self, violation) -> PolicyAction:
        """Enforce policies on a violation.

        Args:
            violation: Violation object from content inspector

        Returns:
            PolicyAction to take
        """
        # Find matching policies
        matching_policies = self._find_matching_policies(violation)

        if not matching_policies:
            return PolicyAction.WARN  # Default action

        # Get most restrictive action
        action = self._get_most_restrictive_action(matching_policies)

        return action

    def _find_matching_policies(self, violation) -> List[PolicyRule]:
        """Find policies that match a violation."""
        matching = []

        for policy in self.policies.values():
            if not policy.enabled:
                continue

            # Check source filter
            if policy.source_filters and violation.source not in policy.source_filters:
                continue

            # Check severity threshold
            if not self._meets_severity_threshold(violation.severity, policy.severity_threshold):
                continue

            # Check PII types
            violation_pii_types = {match['pii_type'] for match in violation.pii_matches}
            policy_pii_types = set(policy.pii_types)

            if violation_pii_types.intersection(policy_pii_types):
                # Check confidence threshold
                high_confidence_matches = [
                    m for m in violation.pii_matches
                    if m['confidence'] >= policy.confidence_threshold
                ]

                if high_confidence_matches:
                    matching.append(policy)

        return matching

    def _meets_severity_threshold(self, severity: str, threshold: str) -> bool:
        """Check if severity meets threshold."""
        severity_levels = {
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4
        }

        return severity_levels.get(severity, 0) >= severity_levels.get(threshold, 0)

    def _get_most_restrictive_action(self, policies: List[PolicyRule]) -> PolicyAction:
        """Get most restrictive action from matching policies.

        Priority: block > encrypt > redact > warn
        """
        action_priority = {
            PolicyAction.BLOCK: 4,
            PolicyAction.ENCRYPT: 3,
            PolicyAction.REDACT: 2,
            PolicyAction.WARN: 1
        }

        most_restrictive = PolicyAction.WARN
        highest_priority = 0

        for policy in policies:
            priority = action_priority.get(policy.action, 0)
            if priority > highest_priority:
                highest_priority = priority
                most_restrictive = policy.action

        return most_restrictive

    def list_policies(self) -> List[Dict[str, Any]]:
        """List all policies.

        Returns:
            List of policy dictionaries
        """
        policies = []

        for policy_id, policy in self.policies.items():
            policies.append({
                'id': policy_id,
                'name': policy.name,
                'description': policy.description,
                'action': policy.action.value,
                'pii_types': policy.pii_types,
                'severity_threshold': policy.severity_threshold,
                'enabled': policy.enabled
            })

        return policies

    def enable_policy(self, policy_id: str) -> bool:
        """Enable a policy."""
        if policy_id in self.policies:
            self.policies[policy_id].enabled = True
            self._save_policies()
            return True
        return False

    def disable_policy(self, policy_id: str) -> bool:
        """Disable a policy."""
        if policy_id in self.policies:
            self.policies[policy_id].enabled = False
            self._save_policies()
            return True
        return False

    def _save_policies(self):
        """Save policies to configuration file."""
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f) or {}

            # Update enabled status
            for policy_id, policy in self.policies.items():
                if policy_id in config.get('policies', {}):
                    config['policies'][policy_id]['enabled'] = policy.enabled

            with open(self.config_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, sort_keys=False)

        except Exception as e:
            print(f"⚠️  Failed to save policies: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Get policy engine statistics."""
        return {
            'total_policies': len(self.policies),
            'enabled_policies': sum(1 for p in self.policies.values() if p.enabled),
            'disabled_policies': sum(1 for p in self.policies.values() if not p.enabled),
            'policies_by_action': self._count_by_action()
        }

    def _count_by_action(self) -> Dict[str, int]:
        """Count policies by action type."""
        counts = {
            'warn': 0,
            'block': 0,
            'redact': 0,
            'encrypt': 0
        }

        for policy in self.policies.values():
            if policy.enabled:
                counts[policy.action.value] += 1

        return counts


def main():
    """Test policy engine."""
    from education.dlp.content_inspector import Violation

    engine = PolicyEngine()

    print("🔍 Testing DLP Policy Engine\n")
    print("=" * 70)

    # List policies
    print("\n📋 Configured Policies:")
    for policy in engine.list_policies():
        status = "✅" if policy['enabled'] else "❌"
        print(f"\n{status} {policy['name']}")
        print(f"   ID: {policy['id']}")
        print(f"   Action: {policy['action'].upper()}")
        print(f"   PII Types: {', '.join(policy['pii_types'])}")
        print(f"   Threshold: {policy['severity_threshold']}")

    # Test violation enforcement
    print("\n\n🧪 Testing Policy Enforcement:")

    # Test 1: Critical PII (should block)
    print("\nTest 1: Git commit with SSN")
    test_violation = Violation(
        violation_id='TEST-001',
        timestamp='2026-02-19T10:00:00Z',
        source='git',
        source_path='HEAD',
        pii_matches=[
            {'pii_type': 'ssn', 'value': '123-45-6789', 'confidence': 0.9}
        ],
        severity='critical'
    )

    action = engine.enforce(test_violation)
    print(f"   Action: {action.value.upper()}")
    print(f"   Expected: BLOCK")

    # Test 2: Email in API response (should redact if enabled)
    print("\nTest 2: API response with email")
    test_violation = Violation(
        violation_id='TEST-002',
        timestamp='2026-02-19T10:00:00Z',
        source='api',
        source_path='/api/users/123',
        pii_matches=[
            {'pii_type': 'email', 'value': 'john@example.com', 'confidence': 0.8}
        ],
        severity='medium'
    )

    action = engine.enforce(test_violation)
    print(f"   Action: {action.value.upper()}")
    print(f"   Expected: WARN (redact policy disabled by default)")

    # Stats
    print("\n\n📊 Policy Engine Stats:")
    stats = engine.get_stats()
    print(f"   Total Policies: {stats['total_policies']}")
    print(f"   Enabled: {stats['enabled_policies']}")
    print(f"   Disabled: {stats['disabled_policies']}")
    print("\n   By Action:")
    for action, count in stats['policies_by_action'].items():
        if count > 0:
            print(f"      {action}: {count}")

    print("\n" + "=" * 70)


if __name__ == '__main__':
    main()

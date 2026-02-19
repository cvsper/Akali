"""Git Monitor for Akali DLP System.

Monitors git commits and staged changes for PII violations.
Can be used as pre-commit hook or standalone monitor.
"""

import subprocess
import sys
from typing import Optional, Dict, Any
from pathlib import Path

sys.path.insert(0, str(Path.home() / "akali"))

from education.dlp.content_inspector import ContentInspector, Violation
from education.dlp.policy_engine import PolicyEngine, PolicyAction


class GitMonitor:
    """Monitor git operations for DLP violations."""

    def __init__(
        self,
        repo_path: str = '.',
        inspector: Optional[ContentInspector] = None,
        policy_engine: Optional[PolicyEngine] = None
    ):
        """Initialize git monitor.

        Args:
            repo_path: Path to git repository
            inspector: Content inspector instance
            policy_engine: Policy engine instance
        """
        self.repo_path = repo_path
        self.inspector = inspector or ContentInspector()
        self.policy_engine = policy_engine or PolicyEngine()

    def check_staged_changes(self) -> Optional[Violation]:
        """Check staged changes for PII (pre-commit).

        Returns:
            Violation object if PII found, None otherwise
        """
        print("🔍 Scanning staged changes for sensitive data...")

        violation = self.inspector.inspect_git_staged(self.repo_path)

        if violation:
            print(f"\n⚠️  DLP VIOLATION DETECTED!")
            print(f"Violation ID: {violation.violation_id}")
            print(f"Severity: {violation.severity.upper()}")
            print(f"\nPII found in staged changes:")

            for match in violation.pii_matches:
                print(f"   - {match['pii_type']}: {match['value']}")
                if match.get('line_number'):
                    print(f"     Line: {match['line_number']}")

            # Apply policy
            action = self.policy_engine.enforce(violation)
            violation.action_taken = action.value

            print(f"\nPolicy Action: {action.value.upper()}")

            if action == PolicyAction.BLOCK:
                print("\n🚫 COMMIT BLOCKED - Remove sensitive data before committing")
                print("\nTo fix:")
                print("1. Remove or redact the PII from your changes")
                print("2. Run 'git add' again")
                print("3. Try committing again")
                return violation

            elif action == PolicyAction.WARN:
                print("\n⚠️  WARNING - Sensitive data detected but commit allowed")
                print("Consider removing PII before committing")

            # Send alert
            self._send_alert(violation)

        else:
            print("✅ No sensitive data detected in staged changes")

        return violation

    def check_commit(self, commit_hash: str = 'HEAD') -> Optional[Violation]:
        """Check a specific commit for PII.

        Args:
            commit_hash: Git commit hash

        Returns:
            Violation object if PII found, None otherwise
        """
        print(f"🔍 Scanning commit {commit_hash} for sensitive data...")

        violation = self.inspector.inspect_git_commit(commit_hash, self.repo_path)

        if violation:
            print(f"\n⚠️  DLP VIOLATION in commit {commit_hash}")
            print(f"Severity: {violation.severity.upper()}")
            print(f"\nPII found:")

            for match in violation.pii_matches:
                print(f"   - {match['pii_type']}: {match['value']}")

            # Send alert
            self._send_alert(violation)

        else:
            print(f"✅ No sensitive data in commit {commit_hash}")

        return violation

    def scan_commit_range(self, start: str, end: str = 'HEAD') -> list:
        """Scan a range of commits for PII.

        Args:
            start: Starting commit hash
            end: Ending commit hash (default: HEAD)

        Returns:
            List of violations
        """
        print(f"🔍 Scanning commits {start}..{end} for sensitive data...")

        # Get list of commits
        try:
            result = subprocess.run(
                ['git', 'rev-list', f'{start}..{end}'],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                print(f"❌ Failed to get commit list: {result.stderr}")
                return []

            commits = result.stdout.strip().split('\n')

        except Exception as e:
            print(f"❌ Error getting commits: {e}")
            return []

        # Scan each commit
        violations = []
        for i, commit in enumerate(commits, 1):
            print(f"\nScanning commit {i}/{len(commits)}: {commit[:8]}...")
            violation = self.check_commit(commit)
            if violation:
                violations.append(violation)

        print(f"\n📊 Scan complete: {len(violations)} violations found")
        return violations

    def install_pre_commit_hook(self) -> bool:
        """Install DLP pre-commit hook in repository.

        Returns:
            True if successful, False otherwise
        """
        hooks_dir = Path(self.repo_path) / '.git' / 'hooks'

        if not hooks_dir.exists():
            print("❌ Not a git repository")
            return False

        hook_path = hooks_dir / 'pre-commit'

        # Hook script
        hook_script = f"""#!/usr/bin/env python3
\"\"\"Akali DLP pre-commit hook.\"\"\"

import sys
from pathlib import Path

# Add akali to path
sys.path.insert(0, str(Path.home() / "akali"))

from education.dlp.monitors.git_monitor import GitMonitor

def main():
    monitor = GitMonitor(repo_path='.')
    violation = monitor.check_staged_changes()

    # Block commit if policy says so
    if violation and violation.action_taken == 'block':
        sys.exit(1)  # Non-zero exit blocks commit

    sys.exit(0)  # Allow commit

if __name__ == '__main__':
    main()
"""

        # Write hook
        try:
            hook_path.write_text(hook_script)
            hook_path.chmod(0o755)  # Make executable
            print(f"✅ DLP pre-commit hook installed: {hook_path}")
            return True
        except Exception as e:
            print(f"❌ Failed to install hook: {e}")
            return False

    def _send_alert(self, violation: Violation):
        """Send alert to ZimMemory."""
        try:
            import requests

            # Determine recipient based on severity
            recipient = 'dommo' if violation.severity in ['critical', 'high'] else 'zim'

            message = f"""🚨 Git DLP Violation Detected

Source: {violation.source_path}
Severity: {violation.severity.upper()}
PII Types: {', '.join([m['pii_type'] for m in violation.pii_matches])}
Total Matches: {len(violation.pii_matches)}

Action: {violation.action_taken or 'WARN'}

Review violation: {violation.violation_id}
"""

            requests.post(
                'http://10.0.0.209:5001/messages/send',
                json={
                    'from_agent': 'akali',
                    'to_agent': recipient,
                    'subject': f'🚨 Git DLP: {violation.severity.upper()}',
                    'body': message,
                    'priority': violation.severity,
                    'metadata': {
                        'violation_id': violation.violation_id,
                        'source': 'git'
                    }
                },
                timeout=5
            )

        except Exception as e:
            print(f"⚠️  Failed to send alert: {e}")


def main():
    """Run git monitor in standalone mode."""
    import argparse

    parser = argparse.ArgumentParser(description='Akali DLP Git Monitor')
    parser.add_argument(
        '--repo',
        default='.',
        help='Path to git repository'
    )
    parser.add_argument(
        '--commit',
        help='Check specific commit'
    )
    parser.add_argument(
        '--range',
        nargs=2,
        metavar=('START', 'END'),
        help='Check range of commits'
    )
    parser.add_argument(
        '--staged',
        action='store_true',
        help='Check staged changes (pre-commit)'
    )
    parser.add_argument(
        '--install-hook',
        action='store_true',
        help='Install pre-commit hook'
    )

    args = parser.parse_args()

    monitor = GitMonitor(repo_path=args.repo)

    if args.install_hook:
        monitor.install_pre_commit_hook()
    elif args.staged:
        violation = monitor.check_staged_changes()
        if violation and violation.action_taken == 'block':
            sys.exit(1)
    elif args.commit:
        monitor.check_commit(args.commit)
    elif args.range:
        monitor.scan_commit_range(args.range[0], args.range[1])
    else:
        # Default: check staged changes
        violation = monitor.check_staged_changes()
        if violation and violation.action_taken == 'block':
            sys.exit(1)


if __name__ == '__main__':
    main()

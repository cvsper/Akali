"""File System Monitor for Akali DLP System.

Monitors file system for new/modified files and scans for PII violations.
Integrates with content inspector and policy engine.
"""

import time
import os
from typing import Dict, Set, Optional, Callable
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

import sys
sys.path.insert(0, str(Path.home() / "akali"))

from education.dlp.content_inspector import ContentInspector, Violation
from education.dlp.policy_engine import PolicyEngine, PolicyAction


class DLPFileHandler(FileSystemEventHandler):
    """Handler for file system events."""

    def __init__(
        self,
        inspector: ContentInspector,
        policy_engine: PolicyEngine,
        on_violation: Optional[Callable[[Violation], None]] = None
    ):
        """Initialize file handler.

        Args:
            inspector: Content inspector instance
            policy_engine: Policy engine instance
            on_violation: Callback for violations (optional)
        """
        self.inspector = inspector
        self.policy_engine = policy_engine
        self.on_violation = on_violation
        self.processed_files: Set[str] = set()

    def on_modified(self, event: FileSystemEvent):
        """Handle file modification."""
        if event.is_directory:
            return

        self._process_file(event.src_path, 'modified')

    def on_created(self, event: FileSystemEvent):
        """Handle file creation."""
        if event.is_directory:
            return

        self._process_file(event.src_path, 'created')

    def _process_file(self, file_path: str, event_type: str):
        """Process file for DLP violations."""
        # Avoid processing same file multiple times
        file_key = f"{file_path}:{os.path.getmtime(file_path)}"
        if file_key in self.processed_files:
            return

        self.processed_files.add(file_key)

        # Keep only recent entries (last 1000)
        if len(self.processed_files) > 1000:
            self.processed_files = set(list(self.processed_files)[-1000:])

        print(f"🔍 Scanning {event_type} file: {file_path}")

        # Inspect file
        violation = self.inspector.inspect_file(file_path)

        if violation:
            print(f"⚠️  DLP violation detected in {file_path}")

            # Apply policy
            action = self.policy_engine.enforce(violation)
            violation.action_taken = action.value

            # Call violation callback
            if self.on_violation:
                self.on_violation(violation)

            # Take action based on policy
            if action == PolicyAction.BLOCK:
                print(f"🚫 BLOCKED: File contains sensitive PII")
                # In production, could quarantine or delete file
            elif action == PolicyAction.REDACT:
                print(f"🔒 REDACTED: Sensitive data will be redacted")
                # In production, redact PII from file
            elif action == PolicyAction.ENCRYPT:
                print(f"🔐 ENCRYPTED: File will be encrypted")
                # In production, encrypt file


class FileMonitor:
    """Real-time file system monitor for DLP."""

    def __init__(
        self,
        watch_paths: Optional[list] = None,
        inspector: Optional[ContentInspector] = None,
        policy_engine: Optional[PolicyEngine] = None
    ):
        """Initialize file monitor.

        Args:
            watch_paths: List of paths to monitor (default: ~/Documents, ~/Desktop)
            inspector: Content inspector instance
            policy_engine: Policy engine instance
        """
        self.watch_paths = watch_paths or [
            str(Path.home() / "Documents"),
            str(Path.home() / "Desktop"),
        ]

        self.inspector = inspector or ContentInspector()
        self.policy_engine = policy_engine or PolicyEngine()
        self.observers: Dict[str, Observer] = {}
        self.violations: list = []

    def start(self):
        """Start monitoring file systems."""
        print("🔍 Starting DLP File Monitor")
        print("=" * 70)

        for watch_path in self.watch_paths:
            if not os.path.exists(watch_path):
                print(f"⚠️  Path does not exist: {watch_path}")
                continue

            print(f"👁️  Monitoring: {watch_path}")

            # Create event handler
            handler = DLPFileHandler(
                self.inspector,
                self.policy_engine,
                on_violation=self._handle_violation
            )

            # Create observer
            observer = Observer()
            observer.schedule(handler, watch_path, recursive=True)
            observer.start()

            self.observers[watch_path] = observer

        print("\n✅ File monitor started. Press Ctrl+C to stop.\n")

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        """Stop monitoring."""
        print("\n🛑 Stopping file monitor...")

        for path, observer in self.observers.items():
            observer.stop()
            observer.join()
            print(f"   Stopped monitoring: {path}")

        print("✅ File monitor stopped")

    def _handle_violation(self, violation: Violation):
        """Handle detected violation."""
        self.violations.append(violation)

        # Send alert to ZimMemory (if configured)
        self._send_alert(violation)

    def _send_alert(self, violation: Violation):
        """Send alert to ZimMemory."""
        try:
            import requests

            # Determine recipient based on severity
            recipient = 'dommo' if violation.severity in ['critical', 'high'] else 'zim'

            message = f"""🚨 DLP Violation Detected

File: {violation.source_path}
Severity: {violation.severity.upper()}
PII Types: {', '.join([m['pii_type'] for m in violation.pii_matches])}
Total Matches: {len(violation.pii_matches)}

Action Taken: {violation.action_taken or 'WARN'}

Review violation: {violation.violation_id}
"""

            requests.post(
                'http://10.0.0.209:5001/messages/send',
                json={
                    'from_agent': 'akali',
                    'to_agent': recipient,
                    'subject': f'🚨 DLP Violation: {violation.severity.upper()}',
                    'body': message,
                    'priority': violation.severity,
                    'metadata': {
                        'violation_id': violation.violation_id,
                        'source': violation.source
                    }
                },
                timeout=5
            )

        except Exception as e:
            print(f"⚠️  Failed to send alert to ZimMemory: {e}")

    def get_stats(self) -> Dict[str, any]:
        """Get monitoring statistics."""
        return {
            'watch_paths': self.watch_paths,
            'active_monitors': len(self.observers),
            'total_violations': len(self.violations),
            'violations_by_severity': self._count_by_severity()
        }

    def _count_by_severity(self) -> Dict[str, int]:
        """Count violations by severity."""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for violation in self.violations:
            counts[violation.severity] = counts.get(violation.severity, 0) + 1
        return counts


def main():
    """Run file monitor in standalone mode."""
    import argparse

    parser = argparse.ArgumentParser(description='Akali DLP File Monitor')
    parser.add_argument(
        '--paths',
        nargs='+',
        help='Paths to monitor (default: ~/Documents ~/Desktop)'
    )
    parser.add_argument(
        '--sensitivity',
        choices=['low', 'medium', 'high'],
        default='medium',
        help='PII detection sensitivity'
    )

    args = parser.parse_args()

    # Create monitor
    inspector = ContentInspector()
    inspector.pii_detector.sensitivity = args.sensitivity

    monitor = FileMonitor(
        watch_paths=args.paths,
        inspector=inspector
    )

    # Start monitoring
    monitor.start()


if __name__ == '__main__':
    main()

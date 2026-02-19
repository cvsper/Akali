#!/usr/bin/env python3
"""Watch daemon - real-time git commit monitoring with secret detection."""

import os
import sys
import json
import subprocess
import time
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any

# Add parent directories to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from autonomous.daemons.daemon_base import DaemonBase
from data.findings_db import FindingsDB
from core.zim_integration import ZimMemory


class WatchDaemon(DaemonBase):
    """
    Git commit monitoring daemon.

    Features:
    - Monitors git repositories for new commits
    - Runs secret detection on each commit
    - Alerts on critical findings
    - Tracks scan history
    """

    def __init__(
        self,
        watch_dirs: List[str] = None,
        check_interval: int = 30,
        pid_dir: str = "~/akali/autonomous/daemons"
    ):
        super().__init__("watch_daemon", pid_dir)

        # Default watch directories
        self.watch_dirs = watch_dirs or [
            "~/umuve-platform",
            "~/junkos-backend",
            "~/sandhill-portal",
            "~/career-focus",
            "~/akali"
        ]

        # Expand paths
        self.watch_dirs = [Path(d).expanduser() for d in self.watch_dirs]

        self.check_interval = check_interval  # seconds
        self.findings_db = FindingsDB()
        self.zim = ZimMemory()

        # State tracking
        self.state_file = self.pid_dir / "watch_state.json"
        self.last_commits = self._load_state()

    def _load_state(self) -> Dict[str, str]:
        """Load last known commit for each repo."""
        if not self.state_file.exists():
            return {}

        try:
            return json.loads(self.state_file.read_text())
        except Exception as e:
            self.logger.error(f"Error loading state: {e}")
            return {}

    def _save_state(self):
        """Save last known commit for each repo."""
        try:
            self.state_file.write_text(json.dumps(self.last_commits, indent=2))
        except Exception as e:
            self.logger.error(f"Error saving state: {e}")

    def _get_latest_commit(self, repo_path: Path) -> str:
        """Get the latest commit hash from a repository."""
        try:
            result = subprocess.run(
                ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception as e:
            self.logger.error(f"Error getting commit from {repo_path}: {e}")

        return ""

    def _get_commit_info(self, repo_path: Path, commit_hash: str) -> Dict[str, Any]:
        """Get commit metadata."""
        try:
            result = subprocess.run(
                ["git", "-C", str(repo_path), "show", "--no-patch",
                 "--format=%an%n%ae%n%at%n%s", commit_hash],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                if len(lines) >= 4:
                    return {
                        "author": lines[0],
                        "email": lines[1],
                        "timestamp": int(lines[2]),
                        "message": lines[3]
                    }
        except Exception as e:
            self.logger.error(f"Error getting commit info: {e}")

        return {}

    def _scan_commit_for_secrets(self, repo_path: Path, commit_hash: str) -> List[Dict[str, Any]]:
        """Scan a specific commit for secrets using gitleaks."""
        findings = []

        try:
            # Check if gitleaks is available
            if not self._check_tool("gitleaks"):
                self.logger.warning("gitleaks not available, skipping secret scan")
                return findings

            # Run gitleaks on specific commit
            result = subprocess.run(
                ["gitleaks", "detect", "--no-git",
                 "--commit", commit_hash,
                 "-v",
                 "--report-format", "json",
                 "--report-path", "/tmp/gitleaks-commit.json"],
                cwd=str(repo_path),
                capture_output=True,
                text=True,
                timeout=30
            )

            # Read results
            report_file = Path("/tmp/gitleaks-commit.json")
            if report_file.exists():
                try:
                    report_data = json.loads(report_file.read_text())

                    for leak in report_data:
                        finding = {
                            "id": f"AKALI-WATCH-{int(time.time())}-{len(findings)}",
                            "timestamp": datetime.now().isoformat(),
                            "severity": "critical",
                            "type": "secret_exposed",
                            "scanner": "watch_daemon/gitleaks",
                            "title": f"Secret detected in commit: {leak.get('RuleID', 'unknown')}",
                            "description": f"Found {leak.get('Description', 'secret')} in {leak.get('File', 'unknown')}",
                            "file": leak.get("File", "unknown"),
                            "line": leak.get("StartLine", 0),
                            "commit": commit_hash,
                            "repository": str(repo_path),
                            "status": "open",
                            "metadata": {
                                "rule_id": leak.get("RuleID"),
                                "secret_type": leak.get("Description"),
                                "match": leak.get("Match", "")[:100]  # Truncate for safety
                            }
                        }
                        findings.append(finding)

                    # Clean up report
                    report_file.unlink()

                except Exception as e:
                    self.logger.error(f"Error parsing gitleaks report: {e}")

        except subprocess.TimeoutExpired:
            self.logger.error(f"Gitleaks scan timed out for commit {commit_hash}")
        except Exception as e:
            self.logger.error(f"Error scanning commit: {e}")

        return findings

    def _check_tool(self, tool_name: str) -> bool:
        """Check if a security tool is available."""
        try:
            result = subprocess.run(
                ["which", tool_name],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False

    def _alert_critical_findings(self, findings: List[Dict[str, Any]], repo_path: Path):
        """Send alerts for critical findings."""
        for finding in findings:
            if finding.get("severity") == "critical":
                # Save to database
                self.findings_db.add_finding(finding)

                # Send alert to ZimMemory
                try:
                    self.zim.alert_finding(finding, target_agent="dommo")
                    self.logger.info(f"Alert sent for finding {finding['id']}")
                except Exception as e:
                    self.logger.error(f"Failed to send alert: {e}")

    def _check_repository(self, repo_path: Path):
        """Check a repository for new commits."""
        if not repo_path.exists():
            self.logger.warning(f"Repository {repo_path} does not exist")
            return

        if not (repo_path / ".git").exists():
            self.logger.warning(f"{repo_path} is not a git repository")
            return

        repo_key = str(repo_path)
        current_commit = self._get_latest_commit(repo_path)

        if not current_commit:
            return

        # Check if this is a new commit
        last_commit = self.last_commits.get(repo_key)

        if last_commit and last_commit != current_commit:
            self.logger.info(f"New commit detected in {repo_path.name}: {current_commit[:8]}")

            # Get commit info
            commit_info = self._get_commit_info(repo_path, current_commit)

            if commit_info:
                self.logger.info(
                    f"  Author: {commit_info.get('author')}, "
                    f"Message: {commit_info.get('message')}"
                )

            # Scan for secrets
            findings = self._scan_commit_for_secrets(repo_path, current_commit)

            if findings:
                self.logger.warning(f"Found {len(findings)} security issue(s) in commit")
                self._alert_critical_findings(findings, repo_path)
            else:
                self.logger.info("No security issues found")

        # Update state
        self.last_commits[repo_key] = current_commit
        self._save_state()

    def run_daemon(self):
        """Main daemon loop."""
        self.logger.info(f"Watch daemon started, monitoring {len(self.watch_dirs)} repositories")
        self.logger.info(f"Check interval: {self.check_interval} seconds")

        # Log watched directories
        for repo_path in self.watch_dirs:
            if repo_path.exists():
                self.logger.info(f"  Watching: {repo_path}")
            else:
                self.logger.warning(f"  Not found: {repo_path}")

        while self.running:
            try:
                # Check each repository
                for repo_path in self.watch_dirs:
                    if not self.running:
                        break

                    self._check_repository(repo_path)

                # Sleep until next check
                if self.running:
                    time.sleep(self.check_interval)

            except Exception as e:
                self.logger.error(f"Error in main loop: {e}", exc_info=True)
                time.sleep(5)  # Brief pause before retrying


def main():
    """CLI entry point."""
    if len(sys.argv) < 2:
        print("Usage: watch_daemon.py {start|stop|status}")
        sys.exit(1)

    command = sys.argv[1]
    daemon = WatchDaemon()

    if command == "start":
        daemon.start()
    elif command == "stop":
        daemon.stop()
    elif command == "status":
        status = daemon.status()
        print(f"Watch Daemon Status:")
        print(f"  Running: {status['running']}")
        if status['pid']:
            print(f"  PID: {status['pid']}")
        print(f"  PID file: {status['pid_file']}")
        print(f"  Log file: {status['log_file']}")
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()

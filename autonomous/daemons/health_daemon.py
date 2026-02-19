#!/usr/bin/env python3
"""Health daemon - system health monitoring and self-healing."""

import os
import sys
import json
import subprocess
import time
import shutil
import requests
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional

# Add parent directories to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from autonomous.daemons.daemon_base import DaemonBase
from data.findings_db import FindingsDB


class HealthDaemon(DaemonBase):
    """
    System health monitoring daemon.

    Features:
    - Tool availability checks (Phase 1 & 2 tools)
    - Database integrity checks
    - Disk space monitoring
    - ZimMemory heartbeat
    - Self-healing capabilities
    - Status reporting
    """

    def __init__(
        self,
        check_interval: int = 300,  # 5 minutes
        pid_dir: str = "~/akali/autonomous/daemons"
    ):
        super().__init__("health_daemon", pid_dir)

        self.check_interval = check_interval
        self.findings_db = FindingsDB()

        # Health status
        self.health_file = self.pid_dir / "health_status.json"
        self.last_health = self._load_health_status()

        # ZimMemory config
        self.zim_url = "http://10.0.0.209:5001"
        self.zim_check_interval = 300  # 5 minutes
        self.last_zim_check = 0

        # Phase 1 defensive tools
        self.defensive_tools = [
            "gitleaks",
            "trufflehog",
            "npm",
            "safety",
            "bandit",
            "semgrep"
        ]

        # Phase 2 offensive tools (optional)
        self.offensive_tools = [
            "nmap",
            "nikto",
            "sqlmap",
            "gobuster",
            "testssl.sh",
            "ffuf"
        ]

        # Critical thresholds
        self.disk_warn_threshold = 10  # Warn if < 10% free
        self.disk_critical_threshold = 5  # Critical if < 5% free

    def _load_health_status(self) -> Dict[str, Any]:
        """Load last health status."""
        if not self.health_file.exists():
            return {}

        try:
            return json.loads(self.health_file.read_text())
        except Exception as e:
            self.logger.error(f"Error loading health status: {e}")
            return {}

    def _save_health_status(self, status: Dict[str, Any]):
        """Save health status to disk."""
        try:
            status["last_updated"] = datetime.now().isoformat()
            self.health_file.write_text(json.dumps(status, indent=2))
            self.last_health = status
        except Exception as e:
            self.logger.error(f"Error saving health status: {e}")

    def _check_tool_availability(self, tool_name: str) -> Dict[str, Any]:
        """Check if a tool is available and get version."""
        result = {
            "name": tool_name,
            "available": False,
            "version": None,
            "path": None
        }

        try:
            # Check if tool exists
            which_result = subprocess.run(
                ["which", tool_name],
                capture_output=True,
                text=True,
                timeout=5
            )

            if which_result.returncode == 0:
                result["available"] = True
                result["path"] = which_result.stdout.strip()

                # Try to get version (common patterns)
                for flag in ["--version", "-v", "version"]:
                    try:
                        version_result = subprocess.run(
                            [tool_name, flag],
                            capture_output=True,
                            text=True,
                            timeout=5
                        )
                        if version_result.returncode == 0:
                            # Get first line of version output
                            version_line = version_result.stdout.strip().split('\n')[0]
                            result["version"] = version_line[:100]  # Truncate
                            break
                    except Exception:
                        continue

        except Exception as e:
            self.logger.error(f"Error checking tool {tool_name}: {e}")

        return result

    def check_tool_availability(self) -> Dict[str, Any]:
        """Check availability of all security tools."""
        self.logger.info("Checking tool availability...")

        tools_status = {
            "defensive": [],
            "offensive": [],
            "summary": {
                "defensive_available": 0,
                "defensive_total": len(self.defensive_tools),
                "offensive_available": 0,
                "offensive_total": len(self.offensive_tools)
            }
        }

        # Check defensive tools
        for tool in self.defensive_tools:
            status = self._check_tool_availability(tool)
            tools_status["defensive"].append(status)
            if status["available"]:
                tools_status["summary"]["defensive_available"] += 1

        # Check offensive tools
        for tool in self.offensive_tools:
            status = self._check_tool_availability(tool)
            tools_status["offensive"].append(status)
            if status["available"]:
                tools_status["summary"]["offensive_available"] += 1

        # Log summary
        def_summary = tools_status["summary"]
        self.logger.info(
            f"Defensive tools: {def_summary['defensive_available']}/{def_summary['defensive_total']} available"
        )
        self.logger.info(
            f"Offensive tools: {def_summary['offensive_available']}/{def_summary['offensive_total']} available"
        )

        return tools_status

    def check_database_integrity(self) -> Dict[str, Any]:
        """Check findings database integrity."""
        self.logger.info("Checking database integrity...")

        status = {
            "healthy": True,
            "issues": [],
            "stats": {}
        }

        try:
            # Check if database exists
            db_path = Path("~/akali/data/findings.json").expanduser()
            if not db_path.exists():
                status["healthy"] = False
                status["issues"].append("Database file does not exist")
                return status

            # Check if database is readable
            try:
                db_data = json.loads(db_path.read_text())
            except json.JSONDecodeError:
                status["healthy"] = False
                status["issues"].append("Database file is corrupted (invalid JSON)")
                return status

            # Check structure
            if "findings" not in db_data:
                status["healthy"] = False
                status["issues"].append("Database missing 'findings' key")
                return status

            if not isinstance(db_data["findings"], list):
                status["healthy"] = False
                status["issues"].append("'findings' is not a list")
                return status

            # Get stats
            stats = self.findings_db.get_stats()
            status["stats"] = stats

            self.logger.info(f"Database healthy: {stats['total']} findings")

        except Exception as e:
            status["healthy"] = False
            status["issues"].append(f"Error checking database: {str(e)}")
            self.logger.error(f"Database check failed: {e}")

        return status

    def check_disk_space(self) -> Dict[str, Any]:
        """Monitor disk space on Akali data directory."""
        self.logger.info("Checking disk space...")

        status = {
            "healthy": True,
            "level": "ok",
            "issues": [],
            "usage": {}
        }

        try:
            # Get disk usage for home directory
            home = Path.home()
            stat = shutil.disk_usage(home)

            total_gb = stat.total / (1024**3)
            used_gb = stat.used / (1024**3)
            free_gb = stat.free / (1024**3)
            percent_free = (stat.free / stat.total) * 100

            status["usage"] = {
                "total_gb": round(total_gb, 2),
                "used_gb": round(used_gb, 2),
                "free_gb": round(free_gb, 2),
                "percent_free": round(percent_free, 2)
            }

            # Check thresholds
            if percent_free < self.disk_critical_threshold:
                status["healthy"] = False
                status["level"] = "critical"
                status["issues"].append(
                    f"Critical: Only {percent_free:.1f}% disk space free (< {self.disk_critical_threshold}%)"
                )
                self.logger.error(status["issues"][-1])

            elif percent_free < self.disk_warn_threshold:
                status["level"] = "warning"
                status["issues"].append(
                    f"Warning: Only {percent_free:.1f}% disk space free (< {self.disk_warn_threshold}%)"
                )
                self.logger.warning(status["issues"][-1])

            else:
                self.logger.info(f"Disk space OK: {percent_free:.1f}% free ({free_gb:.1f} GB)")

        except Exception as e:
            status["healthy"] = False
            status["issues"].append(f"Error checking disk space: {str(e)}")
            self.logger.error(f"Disk check failed: {e}")

        return status

    def check_zim_memory_heartbeat(self) -> Dict[str, Any]:
        """Check ZimMemory API connectivity."""
        current_time = time.time()

        # Only check every N seconds
        if current_time - self.last_zim_check < self.zim_check_interval:
            return self.last_health.get("zim_memory", {"skipped": True})

        self.logger.info("Checking ZimMemory heartbeat...")
        self.last_zim_check = current_time

        status = {
            "healthy": False,
            "reachable": False,
            "response_time_ms": None,
            "issues": []
        }

        try:
            start_time = time.time()
            response = requests.get(
                f"{self.zim_url}/health",
                timeout=5
            )
            response_time = (time.time() - start_time) * 1000

            status["response_time_ms"] = round(response_time, 2)
            status["reachable"] = True

            if response.status_code == 200:
                status["healthy"] = True
                self.logger.info(f"ZimMemory healthy (response time: {response_time:.0f}ms)")
            else:
                status["issues"].append(f"ZimMemory returned status {response.status_code}")
                self.logger.warning(status["issues"][-1])

        except requests.Timeout:
            status["issues"].append("ZimMemory request timed out")
            self.logger.error(status["issues"][-1])

        except requests.ConnectionError:
            status["issues"].append("Cannot connect to ZimMemory (10.0.0.209:5001)")
            self.logger.error(status["issues"][-1])

        except Exception as e:
            status["issues"].append(f"Error checking ZimMemory: {str(e)}")
            self.logger.error(status["issues"][-1])

        return status

    def attempt_self_healing(self, health_status: Dict[str, Any]):
        """Attempt to fix issues automatically."""
        self.logger.info("Checking for self-healing opportunities...")

        healed = []

        # Fix database issues
        db_status = health_status.get("database", {})
        if not db_status.get("healthy"):
            for issue in db_status.get("issues", []):
                if "does not exist" in issue:
                    # Recreate database
                    try:
                        db_path = Path("~/akali/data/findings.json").expanduser()
                        db_path.parent.mkdir(parents=True, exist_ok=True)
                        db_path.write_text(json.dumps({"findings": []}, indent=2))
                        self.logger.info("Self-healed: Created missing database file")
                        healed.append("database_recreated")
                    except Exception as e:
                        self.logger.error(f"Failed to recreate database: {e}")

        # More self-healing logic can be added here
        # Examples:
        # - Restart failed services
        # - Clean up temp files
        # - Repair file permissions

        if healed:
            self.logger.info(f"Self-healing completed: {', '.join(healed)}")
        else:
            self.logger.info("No self-healing actions needed")

        return healed

    def generate_status_report(self, health_status: Dict[str, Any]) -> str:
        """Generate human-readable status report."""
        lines = [
            "\n=== Akali Health Report ===",
            f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            ""
        ]

        # Overall status
        overall_healthy = all([
            health_status.get("tools", {}).get("summary", {}).get("defensive_available", 0) >= 4,
            health_status.get("database", {}).get("healthy", False),
            health_status.get("disk", {}).get("healthy", True)
        ])

        status_emoji = "✅" if overall_healthy else "⚠️"
        lines.append(f"{status_emoji} Overall Status: {'HEALTHY' if overall_healthy else 'ISSUES DETECTED'}")
        lines.append("")

        # Tools
        tools = health_status.get("tools", {})
        if tools:
            summary = tools.get("summary", {})
            lines.append(f"🔧 Tools:")
            lines.append(f"  Defensive: {summary.get('defensive_available', 0)}/{summary.get('defensive_total', 0)}")
            lines.append(f"  Offensive: {summary.get('offensive_available', 0)}/{summary.get('offensive_total', 0)}")
            lines.append("")

        # Database
        db = health_status.get("database", {})
        if db:
            db_emoji = "✅" if db.get("healthy") else "❌"
            lines.append(f"{db_emoji} Database:")
            if db.get("healthy"):
                stats = db.get("stats", {})
                lines.append(f"  Total findings: {stats.get('total', 0)}")
            else:
                for issue in db.get("issues", []):
                    lines.append(f"  ⚠️  {issue}")
            lines.append("")

        # Disk
        disk = health_status.get("disk", {})
        if disk:
            disk_emoji = "✅" if disk.get("healthy") else "⚠️"
            lines.append(f"{disk_emoji} Disk Space:")
            usage = disk.get("usage", {})
            lines.append(f"  Free: {usage.get('free_gb', 0):.1f} GB ({usage.get('percent_free', 0):.1f}%)")
            for issue in disk.get("issues", []):
                lines.append(f"  ⚠️  {issue}")
            lines.append("")

        # ZimMemory
        zim = health_status.get("zim_memory", {})
        if zim and not zim.get("skipped"):
            zim_emoji = "✅" if zim.get("healthy") else "❌"
            lines.append(f"{zim_emoji} ZimMemory:")
            if zim.get("healthy"):
                lines.append(f"  Response time: {zim.get('response_time_ms', 0):.0f}ms")
            else:
                for issue in zim.get("issues", []):
                    lines.append(f"  ⚠️  {issue}")
            lines.append("")

        lines.append("=" * 30)

        return "\n".join(lines)

    def run_daemon(self):
        """Main daemon loop."""
        self.logger.info(f"Health daemon started")
        self.logger.info(f"Check interval: {self.check_interval} seconds")

        while self.running:
            try:
                self.logger.info("Running health checks...")

                health_status = {
                    "timestamp": datetime.now().isoformat(),
                    "tools": self.check_tool_availability(),
                    "database": self.check_database_integrity(),
                    "disk": self.check_disk_space(),
                    "zim_memory": self.check_zim_memory_heartbeat()
                }

                # Attempt self-healing
                healed = self.attempt_self_healing(health_status)
                if healed:
                    health_status["self_healed"] = healed

                # Save status
                self._save_health_status(health_status)

                # Generate report
                report = self.generate_status_report(health_status)
                self.logger.info(report)

                # Sleep until next check
                if self.running:
                    time.sleep(self.check_interval)

            except Exception as e:
                self.logger.error(f"Error in main loop: {e}", exc_info=True)
                time.sleep(30)  # Brief pause before retrying


def main():
    """CLI entry point."""
    if len(sys.argv) < 2:
        print("Usage: health_daemon.py {start|stop|status|report}")
        sys.exit(1)

    command = sys.argv[1]
    daemon = HealthDaemon()

    if command == "start":
        daemon.start()

    elif command == "stop":
        daemon.stop()

    elif command == "status":
        status = daemon.status()
        print(f"Health Daemon Status:")
        print(f"  Running: {status['running']}")
        if status['pid']:
            print(f"  PID: {status['pid']}")
        print(f"  PID file: {status['pid_file']}")
        print(f"  Log file: {status['log_file']}")

    elif command == "report":
        # Show latest health report
        health_file = Path("~/akali/autonomous/daemons/health_status.json").expanduser()
        if health_file.exists():
            try:
                health_status = json.loads(health_file.read_text())
                report = daemon.generate_status_report(health_status)
                print(report)
            except Exception as e:
                print(f"Error reading health report: {e}")
        else:
            print("No health report available yet")

    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()

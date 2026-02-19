"""Cron job scheduler for Akali autonomous operations."""

import json
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable
import sys
import time

sys.path.insert(0, str(Path.home() / "akali"))
from data.findings_db import FindingsDB


class Job:
    """Represents a scheduled job."""

    def __init__(
        self,
        job_id: str,
        name: str,
        schedule: str,
        command: Callable,
        args: List[Any] = None,
        kwargs: Dict[str, Any] = None,
        enabled: bool = True,
        description: str = ""
    ):
        self.job_id = job_id
        self.name = name
        self.schedule = schedule  # cron format or special keywords
        self.command = command
        self.args = args or []
        self.kwargs = kwargs or {}
        self.enabled = enabled
        self.description = description
        self.last_run = None
        self.next_run = None
        self.run_count = 0
        self.last_status = None
        self.last_error = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert job to dictionary for serialization."""
        return {
            "job_id": self.job_id,
            "name": self.name,
            "schedule": self.schedule,
            "enabled": self.enabled,
            "description": self.description,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "next_run": self.next_run.isoformat() if self.next_run else None,
            "run_count": self.run_count,
            "last_status": self.last_status,
            "last_error": self.last_error
        }


class CronManager:
    """Manage scheduled jobs for Akali."""

    def __init__(self, config_path: str = None):
        if config_path:
            self.config_path = Path(config_path)
        else:
            self.config_path = Path.home() / "akali" / "autonomous" / "scheduler" / "schedule_config.json"

        self.log_path = Path.home() / "akali" / "autonomous" / "scheduler" / "scheduler.log"
        self.config_path.parent.mkdir(parents=True, exist_ok=True)

        self.jobs: Dict[str, Job] = {}
        self.db = FindingsDB()
        self._load_config()

    def _load_config(self):
        """Load scheduler configuration."""
        if self.config_path.exists():
            with open(self.config_path, 'r') as f:
                config = json.load(f)
                # Jobs are registered programmatically, just load metadata
                self.config = config
        else:
            self.config = {
                "enabled": True,
                "max_concurrent_jobs": 3,
                "job_timeout_minutes": 120,
                "retry_failed_jobs": True,
                "max_retries": 3
            }
            self._save_config()

    def _save_config(self):
        """Save scheduler configuration."""
        with open(self.config_path, 'w') as f:
            json.dump(self.config, f, indent=2)

    def register_job(
        self,
        job_id: str,
        name: str,
        schedule: str,
        command: Callable,
        args: List[Any] = None,
        kwargs: Dict[str, Any] = None,
        description: str = "",
        enabled: bool = True
    ) -> Job:
        """Register a new scheduled job.

        Args:
            job_id: Unique job identifier
            name: Human-readable job name
            schedule: Schedule in cron format or keywords (daily, weekly, hourly)
            command: Function to execute
            args: Positional arguments for command
            kwargs: Keyword arguments for command
            description: Job description
            enabled: Whether job is enabled

        Returns:
            Job object
        """
        job = Job(
            job_id=job_id,
            name=name,
            schedule=schedule,
            command=command,
            args=args,
            kwargs=kwargs,
            enabled=enabled,
            description=description
        )

        # Calculate next run time
        job.next_run = self._calculate_next_run(schedule)

        self.jobs[job_id] = job
        self._log(f"Registered job: {job_id} ({name}) - Schedule: {schedule}")

        return job

    def unregister_job(self, job_id: str) -> bool:
        """Unregister a job.

        Args:
            job_id: Job identifier

        Returns:
            True if unregistered successfully
        """
        if job_id in self.jobs:
            del self.jobs[job_id]
            self._log(f"Unregistered job: {job_id}")
            return True
        return False

    def enable_job(self, job_id: str) -> bool:
        """Enable a job."""
        if job_id in self.jobs:
            self.jobs[job_id].enabled = True
            self._log(f"Enabled job: {job_id}")
            return True
        return False

    def disable_job(self, job_id: str) -> bool:
        """Disable a job."""
        if job_id in self.jobs:
            self.jobs[job_id].enabled = False
            self._log(f"Disabled job: {job_id}")
            return True
        return False

    def run_job(self, job_id: str, force: bool = False) -> bool:
        """Run a job immediately.

        Args:
            job_id: Job identifier
            force: Run even if disabled

        Returns:
            True if job ran successfully
        """
        if job_id not in self.jobs:
            self._log(f"Job not found: {job_id}", level="ERROR")
            return False

        job = self.jobs[job_id]

        if not job.enabled and not force:
            self._log(f"Job is disabled: {job_id}", level="WARNING")
            return False

        self._log(f"Running job: {job_id} ({job.name})")

        try:
            # Execute job command
            start_time = datetime.now()
            result = job.command(*job.args, **job.kwargs)

            # Update job metadata
            job.last_run = start_time
            job.run_count += 1
            job.last_status = "success"
            job.last_error = None
            job.next_run = self._calculate_next_run(job.schedule)

            duration = (datetime.now() - start_time).total_seconds()
            self._log(f"Job completed: {job_id} - Duration: {duration:.2f}s")

            return True

        except Exception as e:
            job.last_run = datetime.now()
            job.last_status = "failed"
            job.last_error = str(e)
            job.next_run = self._calculate_next_run(job.schedule)

            self._log(f"Job failed: {job_id} - Error: {e}", level="ERROR")

            # Retry logic
            if self.config.get("retry_failed_jobs"):
                self._log(f"Will retry job: {job_id}")

            return False

    def run_due_jobs(self):
        """Run all jobs that are due."""
        now = datetime.now()
        due_jobs = []

        for job_id, job in self.jobs.items():
            if not job.enabled:
                continue

            if job.next_run and now >= job.next_run:
                due_jobs.append(job_id)

        if due_jobs:
            self._log(f"Running {len(due_jobs)} due jobs: {', '.join(due_jobs)}")

        for job_id in due_jobs:
            self.run_job(job_id)

    def list_jobs(self) -> List[Dict[str, Any]]:
        """List all registered jobs.

        Returns:
            List of job dictionaries
        """
        return [job.to_dict() for job in self.jobs.values()]

    def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get job status.

        Args:
            job_id: Job identifier

        Returns:
            Job status dictionary or None
        """
        if job_id in self.jobs:
            return self.jobs[job_id].to_dict()
        return None

    def _calculate_next_run(self, schedule: str) -> datetime:
        """Calculate next run time based on schedule.

        Args:
            schedule: Schedule string (cron format or keyword)

        Returns:
            Next run datetime
        """
        now = datetime.now()

        # Handle special keywords
        if schedule == "hourly":
            return now + timedelta(hours=1)
        elif schedule == "daily":
            # Run at 2 AM next day
            next_run = now.replace(hour=2, minute=0, second=0, microsecond=0)
            if next_run <= now:
                next_run += timedelta(days=1)
            return next_run
        elif schedule == "weekly":
            # Run on Sunday at 1 AM
            days_until_sunday = (6 - now.weekday()) % 7
            if days_until_sunday == 0 and now.hour >= 1:
                days_until_sunday = 7
            next_run = now + timedelta(days=days_until_sunday)
            next_run = next_run.replace(hour=1, minute=0, second=0, microsecond=0)
            return next_run
        elif schedule.startswith("@every"):
            # Parse @every syntax: @every 30m, @every 1h, @every 1d
            parts = schedule.split()
            if len(parts) == 2:
                duration_str = parts[1]
                if duration_str.endswith('m'):
                    minutes = int(duration_str[:-1])
                    return now + timedelta(minutes=minutes)
                elif duration_str.endswith('h'):
                    hours = int(duration_str[:-1])
                    return now + timedelta(hours=hours)
                elif duration_str.endswith('d'):
                    days = int(duration_str[:-1])
                    return now + timedelta(days=days)

        # Default: run in 1 hour
        return now + timedelta(hours=1)

    def _log(self, message: str, level: str = "INFO"):
        """Log a message.

        Args:
            message: Log message
            level: Log level (INFO, WARNING, ERROR)
        """
        timestamp = datetime.now().isoformat()
        log_entry = f"[{timestamp}] [{level}] {message}\n"

        # Append to log file
        with open(self.log_path, 'a') as f:
            f.write(log_entry)

        # Also print to console
        print(f"[CronManager] {log_entry.strip()}")

    def start_scheduler(self, interval_seconds: int = 60):
        """Start the scheduler daemon.

        Args:
            interval_seconds: Check interval in seconds
        """
        self._log("Starting scheduler daemon")

        try:
            while True:
                self.run_due_jobs()
                time.sleep(interval_seconds)

        except KeyboardInterrupt:
            self._log("Scheduler stopped by user")
        except Exception as e:
            self._log(f"Scheduler error: {e}", level="ERROR")


def main():
    """CLI for cron manager."""
    import sys
    import argparse

    parser = argparse.ArgumentParser(description="Akali Cron Manager")
    subparsers = parser.add_subparsers(dest="command")

    # List jobs
    subparsers.add_parser("list", help="List all scheduled jobs")

    # Run job
    run_parser = subparsers.add_parser("run", help="Run a job immediately")
    run_parser.add_argument("job_id", help="Job ID to run")
    run_parser.add_argument("--force", action="store_true", help="Force run even if disabled")

    # Enable/disable job
    enable_parser = subparsers.add_parser("enable", help="Enable a job")
    enable_parser.add_argument("job_id", help="Job ID to enable")

    disable_parser = subparsers.add_parser("disable", help="Disable a job")
    disable_parser.add_argument("job_id", help="Job ID to disable")

    # Start scheduler daemon
    start_parser = subparsers.add_parser("start", help="Start scheduler daemon")
    start_parser.add_argument("--interval", type=int, default=60, help="Check interval in seconds")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    manager = CronManager()

    # Load job definitions (would be from job_definitions.py in production)
    from job_definitions import register_all_jobs
    register_all_jobs(manager)

    if args.command == "list":
        jobs = manager.list_jobs()
        if not jobs:
            print("No scheduled jobs.")
        else:
            print(f"\n📋 Scheduled Jobs ({len(jobs)}):\n")
            for job in jobs:
                status_emoji = "✅" if job["enabled"] else "❌"
                print(f"{status_emoji} {job['job_id']} - {job['name']}")
                print(f"   Schedule: {job['schedule']}")
                print(f"   Description: {job['description']}")
                if job['last_run']:
                    print(f"   Last run: {job['last_run']} ({job['last_status']})")
                if job['next_run']:
                    print(f"   Next run: {job['next_run']}")
                print(f"   Run count: {job['run_count']}")
                print()

    elif args.command == "run":
        success = manager.run_job(args.job_id, force=args.force)
        if success:
            print(f"✅ Job {args.job_id} completed successfully")
        else:
            print(f"❌ Job {args.job_id} failed")
            sys.exit(1)

    elif args.command == "enable":
        if manager.enable_job(args.job_id):
            print(f"✅ Enabled job: {args.job_id}")
        else:
            print(f"❌ Job not found: {args.job_id}")
            sys.exit(1)

    elif args.command == "disable":
        if manager.disable_job(args.job_id):
            print(f"✅ Disabled job: {args.job_id}")
        else:
            print(f"❌ Job not found: {args.job_id}")
            sys.exit(1)

    elif args.command == "start":
        print(f"🥷 Starting Akali scheduler daemon (check interval: {args.interval}s)")
        print("Press Ctrl+C to stop")
        manager.start_scheduler(interval_seconds=args.interval)


if __name__ == "__main__":
    main()

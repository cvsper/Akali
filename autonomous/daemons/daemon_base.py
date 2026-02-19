"""Base daemon class for Akali daemons."""

import os
import sys
import signal
import logging
import time
from pathlib import Path
from typing import Optional
from abc import ABC, abstractmethod


class DaemonBase(ABC):
    """Base class for all Akali daemons."""

    def __init__(self, name: str, pid_dir: str = "~/akali/autonomous/daemons"):
        self.name = name
        self.pid_dir = Path(pid_dir).expanduser()
        self.pid_file = self.pid_dir / f"{name}.pid"
        self.log_file = self.pid_dir / "daemon.log"
        self.running = False

        # Ensure directories exist
        self.pid_dir.mkdir(parents=True, exist_ok=True)

        # Setup logging
        self._setup_logging()

        # Setup signal handlers
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

    def _setup_logging(self):
        """Setup logging to file and console."""
        self.logger = logging.getLogger(self.name)
        self.logger.setLevel(logging.INFO)

        # File handler
        file_handler = logging.FileHandler(self.log_file)
        file_handler.setLevel(logging.INFO)

        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)

        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

    def _handle_signal(self, signum, frame):
        """Handle termination signals gracefully."""
        signal_name = signal.Signals(signum).name
        self.logger.info(f"Received signal {signal_name}, shutting down gracefully...")
        self.running = False

    def _write_pid(self):
        """Write PID to file."""
        pid = os.getpid()
        self.pid_file.write_text(str(pid))
        self.logger.info(f"PID {pid} written to {self.pid_file}")

    def _remove_pid(self):
        """Remove PID file."""
        if self.pid_file.exists():
            self.pid_file.unlink()
            self.logger.info(f"Removed PID file {self.pid_file}")

    def _read_pid(self) -> Optional[int]:
        """Read PID from file."""
        if not self.pid_file.exists():
            return None

        try:
            pid_str = self.pid_file.read_text().strip()
            return int(pid_str)
        except (ValueError, IOError) as e:
            self.logger.error(f"Error reading PID file: {e}")
            return None

    def _is_running(self) -> bool:
        """Check if daemon is running."""
        pid = self._read_pid()
        if pid is None:
            return False

        # Check if process exists
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            # Process doesn't exist
            self._remove_pid()
            return False

    @abstractmethod
    def run_daemon(self):
        """Main daemon loop - must be implemented by subclasses."""
        pass

    def start(self):
        """Start the daemon."""
        if self._is_running():
            pid = self._read_pid()
            self.logger.error(f"Daemon already running with PID {pid}")
            return False

        self.logger.info(f"Starting {self.name} daemon...")
        self._write_pid()
        self.running = True

        try:
            self.run_daemon()
        except Exception as e:
            self.logger.error(f"Daemon crashed: {e}", exc_info=True)
            raise
        finally:
            self._remove_pid()
            self.logger.info(f"{self.name} daemon stopped")

        return True

    def stop(self):
        """Stop the daemon."""
        if not self._is_running():
            self.logger.error("Daemon is not running")
            return False

        pid = self._read_pid()
        if pid is None:
            self.logger.error("Could not read PID file")
            return False

        self.logger.info(f"Stopping daemon with PID {pid}...")

        try:
            os.kill(pid, signal.SIGTERM)

            # Wait for process to terminate
            for _ in range(10):
                time.sleep(0.5)
                try:
                    os.kill(pid, 0)
                except OSError:
                    self.logger.info("Daemon stopped successfully")
                    self._remove_pid()
                    return True

            # Force kill if still running
            self.logger.warning("Daemon did not stop gracefully, force killing...")
            os.kill(pid, signal.SIGKILL)
            self._remove_pid()
            return True

        except OSError as e:
            self.logger.error(f"Error stopping daemon: {e}")
            return False

    def status(self) -> dict:
        """Get daemon status."""
        is_running = self._is_running()
        pid = self._read_pid() if is_running else None

        return {
            "name": self.name,
            "running": is_running,
            "pid": pid,
            "pid_file": str(self.pid_file),
            "log_file": str(self.log_file)
        }

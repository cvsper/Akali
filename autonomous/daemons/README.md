# Akali Daemons

Autonomous background processes for continuous security monitoring.

## Available Daemons

### 1. Watch Daemon (`watch_daemon.py`)

Real-time git commit monitoring with automatic secret detection.

**Features:**
- Monitors configured git repositories for new commits
- Runs gitleaks secret detection on each commit
- Alerts on critical findings via ZimMemory
- Tracks scan history (stores last commit per repo)
- Graceful shutdown handling

**Default Monitored Repositories:**
- ~/umuve-platform
- ~/junkos-backend
- ~/sandhill-portal
- ~/career-focus
- ~/akali

**Configuration:**
- Check interval: 30 seconds (configurable)
- State file: `~/akali/autonomous/daemons/watch_state.json`
- PID file: `~/akali/autonomous/daemons/watch_daemon.pid`

**Usage:**
```bash
# Start daemon
python3 autonomous/daemons/watch_daemon.py start

# Stop daemon
python3 autonomous/daemons/watch_daemon.py stop

# Check status
python3 autonomous/daemons/watch_daemon.py status
```

### 2. Health Daemon (`health_daemon.py`)

System health monitoring with self-healing capabilities.

**Features:**
- **Tool availability checks** - Verifies all Phase 1 & 2 security tools are installed
- **Database integrity checks** - Validates findings database structure
- **Disk space monitoring** - Warns if < 10% free, critical if < 5% free
- **ZimMemory heartbeat** - Pings Mac Mini every 5 minutes
- **Self-healing** - Auto-repairs common issues (e.g., recreates missing DB)
- **Status reporting** - Generates human-readable health reports

**Monitored Tools:**

*Defensive (Phase 1):*
- gitleaks, trufflehog, npm, safety, bandit, semgrep

*Offensive (Phase 2):*
- nmap, nikto, sqlmap, gobuster, testssl.sh, ffuf

**Configuration:**
- Check interval: 300 seconds (5 minutes)
- ZimMemory URL: http://10.0.0.209:5001
- Health status file: `~/akali/autonomous/daemons/health_status.json`
- PID file: `~/akali/autonomous/daemons/health_daemon.pid`

**Usage:**
```bash
# Start daemon
python3 autonomous/daemons/health_daemon.py start

# Stop daemon
python3 autonomous/daemons/health_daemon.py stop

# Check status
python3 autonomous/daemons/health_daemon.py status

# View health report
python3 autonomous/daemons/health_daemon.py report
```

## Base Daemon Class

Both daemons inherit from `DaemonBase` which provides:

- **PID file management** - Prevents duplicate processes
- **Signal handling** - Graceful shutdown on SIGTERM/SIGINT
- **Logging** - Unified logging to `daemon.log` and console
- **Status reporting** - Standard status interface

## File Locations

```
~/akali/autonomous/daemons/
├── daemon_base.py           # Base daemon class
├── watch_daemon.py          # Git commit monitoring
├── health_daemon.py         # System health checks
├── daemon.log               # Unified daemon logs
├── watch_daemon.pid         # Watch daemon PID
├── health_daemon.pid        # Health daemon PID
├── watch_state.json         # Watch daemon state
└── health_status.json       # Latest health report
```

## Integration

Both daemons integrate with:

- **FindingsDB** - Store security findings
- **ZimMemory** - Alert other agents about issues
- **Phase 1 & 2 Tools** - Use installed security tools

## Logging

All daemon activity is logged to `~/akali/autonomous/daemons/daemon.log` with timestamps and log levels.

**Log format:**
```
2026-02-19 15:40:00 - watch_daemon - INFO - New commit detected in umuve-platform: abc1234
```

## Self-Healing

The health daemon can automatically fix common issues:

- **Missing database** - Creates `findings.json` if missing
- **Corrupted database** - Recreates with valid structure
- More healing capabilities can be added in the future

## Future Enhancements

- [ ] launchd/systemd integration for auto-start on boot
- [ ] Email/Slack notifications for critical issues
- [ ] Web dashboard for daemon status
- [ ] More self-healing capabilities
- [ ] Performance metrics collection
- [ ] Integration with Phase 4 intelligence feeds

## Architecture

```
┌─────────────────┐
│  Watch Daemon   │──> Git Commits ──> Gitleaks ──> Findings DB ──> ZimMemory
└─────────────────┘

┌─────────────────┐
│  Health Daemon  │──> Tool Checks
└─────────────────┘   ├─> DB Integrity
                      ├─> Disk Space
                      ├─> ZimMemory Ping
                      └─> Self-Healing
```

## Development

To create a new daemon:

1. Inherit from `DaemonBase`
2. Implement `run_daemon()` method
3. Add signal handling via `self.running` flag
4. Use `self.logger` for logging
5. Add CLI entry point with start/stop/status

**Example:**
```python
from daemon_base import DaemonBase

class MyDaemon(DaemonBase):
    def __init__(self):
        super().__init__("my_daemon")

    def run_daemon(self):
        while self.running:
            # Do work
            time.sleep(60)
```

---

**Status:** Phase 3 Complete ✅
**Next:** Phase 4 (Intelligence & Metrics)

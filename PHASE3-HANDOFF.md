# Akali Phase 3: Autonomous Operations - Handoff

**Date:** 2026-02-19
**Status:** Ready to start
**Context:** Phase 1 & 2 complete, Phase 3 planning ready

---

## Phase 2 Summary ✅

**Completed:** All 10 tasks (100%)
- Offensive security tools installed
- Web/network/API vulnerability scanners
- CVE/exploit lookup
- Authorization system with whitelisting
- Report generation (HTML/Markdown/JSON)
- Payload library
- CLI integration (`attack`, `exploit` commands)
- Comprehensive documentation

**Git:** Tagged as `v2.0-phase2`

---

## Phase 3: Autonomous Operations - Scope

### Goal
Build autonomous capabilities for continuous security monitoring, scheduled scans, and automated alerting without human intervention.

### Philosophy
- **Always-on security** - Continuous monitoring, not just on-demand
- **Smart automation** - Prioritize high-value scans, avoid alert fatigue
- **Resilient** - Auto-restart on failure, graceful degradation
- **Observable** - Logs, metrics, health checks

### Phase 3 Features

#### 1. Cron Job Scheduler
- **Daily defensive scans** - Secrets, dependencies, SAST on all family projects
- **Weekly offensive scans** - Authorized targets only
- **Daily CVE checks** - Monitor for new vulnerabilities affecting our stack
- **Report automation** - Generate and distribute reports

#### 2. Daemon Processes
- **Continuous secret monitoring** - Watch for new commits with secrets
- **Dependency watcher** - Alert on new vulnerable package versions
- **Health monitor** - Self-check Akali status and tool availability

#### 3. Alert System
- **ZimMemory integration** - Send alerts to relevant agents
- **Severity-based routing** - Critical → immediate alert, Low → daily digest
- **Deduplication** - Don't re-alert on same finding
- **Alert escalation** - If unaddressed, escalate to sevs

#### 4. Automated Triage
- **False positive detection** - Learn from user feedback
- **Auto-remediation** - Fix simple issues automatically (with approval)
- **Risk scoring** - Prioritize findings by exploitability + impact

---

## Architecture Plan

### New Directory Structure
```
~/akali/autonomous/
├── scheduler/
│   ├── cron_manager.py        # Cron job management
│   ├── job_definitions.py     # Scan job definitions
│   └── schedule_config.json   # Cron schedule config
├── daemons/
│   ├── watch_daemon.py        # Continuous monitoring
│   ├── health_daemon.py       # Self-health checks
│   └── alert_daemon.py        # Alert processing
├── alerts/
│   ├── alert_manager.py       # Alert routing and deduplication
│   ├── zim_alerter.py         # ZimMemory integration
│   └── alert_queue.json       # Pending alerts
└── triage/
    ├── triage_engine.py       # Automated triage
    ├── false_positive_db.json # Known false positives
    └── auto_fix.py            # Auto-remediation
```

### New CLI Commands
```bash
akali schedule list                    # List scheduled jobs
akali schedule add <job_type>          # Add scheduled job
akali schedule remove <job_id>         # Remove scheduled job
akali schedule run <job_id>            # Run job immediately

akali daemon start [--type=watch|health|alert]  # Start daemon
akali daemon stop <daemon_id>                   # Stop daemon
akali daemon status                             # Show daemon status

akali alert send <finding_id> <agent_id>        # Send alert
akali alert list [--pending]                    # List alerts
akali alert ack <alert_id>                      # Acknowledge alert

akali triage auto <finding_id>                  # Auto-triage finding
akali triage mark-false-positive <finding_id>   # Mark false positive
```

---

## Implementation Tasks

### Task 1: Build Cron Job Scheduler
Create `autonomous/scheduler/cron_manager.py`:
- Job definition system (defensive/offensive/CVE checks)
- Schedule parser (daily, weekly, custom cron syntax)
- Job execution engine
- Logging and error handling
- macOS launchd integration for persistence

### Task 2: Create Job Definitions
Create `autonomous/scheduler/job_definitions.py`:
- Daily defensive scan job (all family projects)
- Weekly offensive scan job (authorized targets)
- Daily CVE check job (check for new CVEs)
- Daily report generation job
- Weekly summary report job

### Task 3: Build Watch Daemon
Create `autonomous/daemons/watch_daemon.py`:
- Git commit watcher (monitor for new commits)
- Secret detection on commit
- Real-time alerts for critical findings
- Process management (PID file, graceful shutdown)

### Task 4: Build Health Daemon
Create `autonomous/daemons/health_daemon.py`:
- Tool availability checks
- Database integrity checks
- Disk space monitoring
- Self-healing (restart failed components)
- Heartbeat to ZimMemory

### Task 5: Build Alert Manager
Create `autonomous/alerts/alert_manager.py`:
- Alert routing (severity-based)
- Deduplication (don't re-alert same issue)
- Rate limiting (max N alerts per hour)
- Alert queue management
- Escalation logic

### Task 6: Integrate ZimMemory Alerts
Create `autonomous/alerts/zim_alerter.py`:
- Send alerts to ZimMemory
- Agent routing (Dommo for backend, Banksy for QA, etc.)
- Priority mapping (Critical → high priority)
- Rich formatting for alerts

### Task 7: Build Triage Engine
Create `autonomous/triage/triage_engine.py`:
- Risk scoring algorithm (CVSS + exploitability + exposure)
- False positive detection (pattern matching)
- Auto-remediation logic (safe fixes only)
- Learning from user feedback

### Task 8: Add CLI Commands
Update `core/cli.py`:
- Add `schedule` command group
- Add `daemon` command group
- Add `alert` command group
- Add `triage` command group

### Task 9: Add Persistence Layer
- launchd plist files for macOS
- systemd service files for Linux (future)
- Auto-start on boot
- Log rotation
- State persistence across restarts

### Task 10: Update Documentation
- Update README.md with Phase 3 features
- Add autonomous operations guide
- Document cron job syntax
- Add daemon management guide
- Include troubleshooting section

---

## Tools & Dependencies

### macOS Integration
- **launchd** - Native macOS daemon management
- **launchctl** - Control launchd jobs
- **cron** (fallback) - Traditional cron if launchd fails

### Python Libraries
- **schedule** - Job scheduling
- **watchdog** - File system monitoring
- **psutil** - Process management
- **daemon** - Unix daemon helpers

### Install Command
```bash
pip3 install schedule watchdog psutil python-daemon
```

---

## Autonomous Operation Examples

### Daily Defensive Scan
```bash
# Runs every day at 2 AM
# Scans all family projects for secrets, vulnerable dependencies, SAST issues
# Stores findings in database
# Sends critical findings to ZimMemory immediately
# Generates daily report at 8 AM
```

### Weekly Offensive Scan
```bash
# Runs every Sunday at 1 AM
# Scans all authorized targets (web, network, API)
# Compares with previous week's findings
# Alerts on new vulnerabilities
# Generates weekly trend report
```

### Continuous Secret Monitoring
```bash
# Watch daemon monitors git commits in real-time
# Runs secret scan on every new commit
# Blocks push if secrets detected (pre-push hook)
# Immediate alert to author + ZimMemory
```

### CVE Monitoring
```bash
# Runs daily at 9 AM
# Checks for new CVEs affecting our stack:
#   - Python packages (from requirements.txt)
#   - npm packages (from package.json)
#   - System tools (nmap, nginx, etc.)
# Alerts on Critical/High CVEs immediately
# Weekly summary of all CVEs
```

---

## Safety & Reliability

### Fail-Safe Mechanisms
- **Rate limiting** - Max 1 offensive scan per target per day
- **Resource limits** - Max CPU/memory usage
- **Timeout enforcement** - Kill hung scans
- **Error recovery** - Retry with exponential backoff
- **Circuit breaker** - Disable failing jobs temporarily

### Observability
- **Structured logging** - JSON logs for all operations
- **Metrics collection** - Scan counts, durations, findings
- **Health endpoints** - HTTP health check for daemons
- **Status dashboard** - Web UI showing current status (future)

### Security
- **Least privilege** - Daemons run as non-root user
- **Sandboxing** - Isolate scan processes
- **Audit logging** - All autonomous actions logged
- **Manual override** - Can disable any autonomous feature

---

## Phase 3 Success Criteria

When all 10 tasks done:
- ✅ Cron job scheduler operational
- ✅ Job definitions for all scan types
- ✅ Watch daemon monitoring commits
- ✅ Health daemon self-checking
- ✅ Alert manager routing alerts
- ✅ ZimMemory integration sending alerts
- ✅ Triage engine prioritizing findings
- ✅ CLI commands for all autonomous features
- ✅ launchd integration for persistence
- ✅ Documentation complete
- ✅ Tests passing
- ✅ Git tagged as `v3.0-phase3`

---

## Quick Start for Fresh Session

**In new Claude Code session, run:**

```bash
cd ~/akali
cat PHASE3-HANDOFF.md
```

Then say:

> "Start Akali Phase 3 implementation. Handoff at ~/akali/PHASE3-HANDOFF.md. Phase 1 & 2 complete. Ready to build autonomous operations."

---

## Key Files Reference

**Phase 1 & 2 Complete:**
- Workspace: `/Users/sevs/akali/`
- CLI: `/Users/sevs/akali/akali`
- Defensive scanners: `/Users/sevs/akali/defensive/scanners/`
- Offensive scanners: `/Users/sevs/akali/offensive/scanners/`
- Findings DB: `/Users/sevs/akali/data/findings_db.py`

**Phase 3 To Create:**
- Scheduler: `/Users/sevs/akali/autonomous/scheduler/`
- Daemons: `/Users/sevs/akali/autonomous/daemons/`
- Alerts: `/Users/sevs/akali/autonomous/alerts/`
- Triage: `/Users/sevs/akali/autonomous/triage/`

---

## Notes

- Phase 1 & 2 took ~1 session each to implement
- Phase 3 is larger, estimate 1-2 sessions
- ZimMemory is online at 10.0.0.209:5001
- Mac Mini can run daemons 24/7
- launchd preferred over cron on macOS

---

**Phase 1 Complete** ✅ | **Phase 2 Complete** ✅ | **Phase 3 Ready** 🚀

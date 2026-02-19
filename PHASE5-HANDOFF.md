# Akali Phase 5: Incident Response - Handoff

**Date:** 2026-02-19
**Status:** Ready to start
**Context:** Phases 1-4 complete, Phase 5 planning ready

---

## Phase 4 Summary ✅

**Completed:** All 10 tasks (100%)
- CVE monitoring system (NVD + GitHub advisories)
- Dependency mapper (Python, Node.js, iOS)
- Threat intelligence hub (exploits, feeds, breaches)
- Supply chain auditor (inventory builder)
- Security scorecard (0-100 with component breakdown)
- Security observatory (MTTD/MTTR tracking)
- Findings database (JSON-based)
- Web dashboard (Flask at localhost:8765)
- CLI commands (intel, metrics, dashboard groups)
- Autonomous integration (4 new scheduled jobs)

**Git:** Tagged as `v4.0-phase4`
**Stats:** ~3915 lines of code added across 16 modules

---

## Phase 5: Incident Response - Scope

### Goal
Build incident response capabilities for rapid threat containment, forensic investigation, and post-incident analysis. Enable the family to quickly detect, respond to, and recover from security incidents.

### Philosophy
- **Speed over perfection** - Rapid response saves the day
- **Playbook-driven** - Consistent, repeatable responses
- **Evidence preservation** - Forensics before remediation
- **Learn from incidents** - Every incident improves defenses
- **Team coordination** - War room brings everyone together

### Phase 5 Features

#### 1. War Room Commander
- **War room activation** - Single command to activate incident response mode
- **Team notification** - Auto-alert all agents via ZimMemory (high priority)
- **Status dashboard** - Real-time incident timeline and status
- **Service isolation** - Lock down affected services (optional)
- **Communication channel** - Dedicated incident coordination
- **Escalation protocols** - Severity-based escalation rules

#### 2. Incident Playbooks
- **Playbook library** - Pre-defined response workflows for common incidents
- **Playbook types:**
  - SQL Injection response
  - Data breach response
  - Ransomware response
  - Account compromise response
  - DDoS attack response
  - Insider threat response
- **Step-by-step execution** - Guided response with checkpoints
- **Playbook customization** - Adapt to family-specific needs

#### 3. Forensics Investigator
- **Log collection** - Auto-gather logs from all systems
- **Timeline reconstruction** - Build attack timeline from logs
- **Pattern detection** - Identify attack signatures
- **Evidence preservation** - Chain of custody for evidence
- **Attack path analysis** - Trace attacker movements
- **Root cause analysis** - Determine initial compromise vector

#### 4. Incident Database
- **Incident tracking** - Complete incident lifecycle (detection → resolution → post-mortem)
- **Incident metadata** - Severity, type, status, timeline, affected systems
- **Evidence storage** - Store logs, screenshots, artifacts
- **Related findings** - Link incidents to security findings
- **Lessons learned** - Post-mortem documentation

#### 5. Response Automation
- **Auto-containment** - Automatic isolation of compromised systems
- **Account lockout** - Disable compromised accounts
- **Network segmentation** - Block malicious IPs/domains
- **Backup restoration** - Quick restore from clean backups
- **Notification automation** - Auto-notify stakeholders

---

## Architecture Plan

### New Directory Structure
```
~/akali/incident/
├── war_room/
│   ├── war_room_commander.py    # War room activation and coordination
│   ├── team_notifier.py          # Alert all agents via ZimMemory
│   ├── status_dashboard.py       # Real-time incident status
│   └── war_room_state.json       # Current war room state
├── playbooks/
│   ├── playbook_engine.py        # Playbook execution engine
│   ├── sql_injection.yaml        # SQL injection response playbook
│   ├── data_breach.yaml          # Data breach response playbook
│   ├── ransomware.yaml           # Ransomware response playbook
│   ├── account_compromise.yaml   # Account compromise playbook
│   ├── ddos.yaml                 # DDoS attack response playbook
│   └── insider_threat.yaml       # Insider threat response playbook
├── forensics/
│   ├── log_collector.py          # Collect logs from all systems
│   ├── timeline_builder.py       # Build attack timeline
│   ├── pattern_detector.py       # Detect attack patterns
│   ├── evidence_manager.py       # Preserve evidence chain
│   └── rca_analyzer.py           # Root cause analysis
├── incidents/
│   ├── incident_db.py            # Incident database (SQLite)
│   ├── incident_tracker.py       # Track incident lifecycle
│   └── post_mortem.py            # Post-mortem report generator
└── response/
    ├── containment.py            # Auto-containment actions
    ├── account_manager.py        # Account lockout/reset
    ├── network_blocker.py        # Block IPs/domains
    └── backup_restore.py         # Backup restoration
```

### New CLI Commands
```bash
# War Room Commands
akali war-room start <incident-id>               # Activate war room
akali war-room stop                               # Deactivate war room
akali war-room status                             # Show war room status
akali war-room timeline                           # Show incident timeline
akali war-room notify <message>                   # Broadcast to team

# Incident Commands
akali incident create <title>                     # Create new incident
akali incident list [--status=active]             # List incidents
akali incident show <incident-id>                 # Show incident details
akali incident update <incident-id> <status>      # Update incident status
akali incident close <incident-id>                # Close incident

# Playbook Commands
akali playbook list                               # List available playbooks
akali playbook run <playbook-name> <incident-id>  # Run playbook
akali playbook status <playbook-run-id>           # Check playbook status

# Forensics Commands
akali forensics collect <incident-id>             # Collect logs/evidence
akali forensics timeline <incident-id>            # Build attack timeline
akali forensics analyze <incident-id>             # Run forensic analysis
akali forensics report <incident-id>              # Generate forensics report

# Response Commands
akali response contain <system-id>                # Isolate system
akali response block <ip-or-domain>               # Block IP/domain
akali response lockout <account>                  # Lock account
akali response restore <backup-id>                # Restore from backup
```

---

## Implementation Tasks

### Task 1: Build War Room Commander
Create `incident/war_room/war_room_commander.py`:
- War room activation (creates incident, alerts team)
- War room state management (active/inactive)
- Team notification via ZimMemory (broadcast to all agents)
- Status dashboard (incident metadata, timeline)
- War room deactivation (cleanup, final report)

### Task 2: Build Team Notifier
Create `incident/war_room/team_notifier.py`:
- ZimMemory broadcast (send to all agents)
- Severity-based priority (critical → high priority)
- Rich message formatting (incident details, status, actions)
- Notification templates (war room start, update, close)

### Task 3: Build Playbook Engine
Create `incident/playbooks/playbook_engine.py`:
- YAML playbook parser
- Step-by-step execution engine
- Checkpoint system (save progress)
- Manual approval gates (wait for human decision)
- Playbook status tracking
- Parallel step execution (where safe)

### Task 4: Create Incident Playbooks
Create `incident/playbooks/*.yaml`:
- **SQL Injection Playbook:**
  1. Isolate affected service
  2. Review query logs
  3. Identify vulnerable endpoint
  4. Apply parameterized query fix
  5. Test fix
  6. Restore service
  7. Post-mortem

- **Data Breach Playbook:**
  1. Confirm breach scope
  2. Notify affected users
  3. Invalidate credentials
  4. Enable 2FA enforcement
  5. Review access logs
  6. Legal/compliance notification
  7. Post-mortem

- **Ransomware Playbook:**
  1. Isolate infected systems
  2. Identify ransomware variant
  3. Check for decryption tools
  4. Restore from clean backups
  5. Patch vulnerabilities
  6. Network segmentation review
  7. Post-mortem

- **Account Compromise Playbook:**
  1. Lock compromised account
  2. Review account activity logs
  3. Identify compromise vector
  4. Reset credentials
  5. Enable 2FA
  6. Check for lateral movement
  7. Post-mortem

- (Similar for DDoS, Insider Threat)

### Task 5: Build Forensics Investigator
Create `incident/forensics/`:
- **Log Collector** (`log_collector.py`):
  - Collect logs from all systems
  - Preserve original timestamps
  - Store in evidence directory
  - Chain of custody tracking

- **Timeline Builder** (`timeline_builder.py`):
  - Parse logs for security events
  - Build chronological timeline
  - Correlate events across systems
  - Visualize timeline (ASCII or HTML)

- **Pattern Detector** (`pattern_detector.py`):
  - Detect common attack patterns (brute force, port scan, SQL injection)
  - Identify attacker IPs/user agents
  - Flag suspicious activity

- **RCA Analyzer** (`rca_analyzer.py`):
  - Trace back to initial compromise
  - Identify vulnerability exploited
  - Map attack path
  - Generate RCA report

### Task 6: Build Incident Database
Create `incident/incidents/incident_db.py`:
- SQLite database schema:
  - `incidents` table (id, title, severity, status, created_at, closed_at, ...)
  - `incident_timeline` table (id, incident_id, timestamp, event, actor, ...)
  - `incident_evidence` table (id, incident_id, type, path, hash, ...)
  - `incident_actions` table (id, incident_id, action, status, result, ...)
- CRUD operations
- Incident search and filtering

### Task 7: Build Incident Tracker
Create `incident/incidents/incident_tracker.py`:
- Incident lifecycle management (new → active → contained → resolved → closed)
- Timeline event logging
- Evidence attachment
- Status updates
- Team member assignment
- Incident severity escalation

### Task 8: Build Response Automation
Create `incident/response/`:
- **Containment** (`containment.py`):
  - Isolate system (network disconnect)
  - Stop services
  - Take system snapshot
  - Quarantine files

- **Account Manager** (`account_manager.py`):
  - Lock accounts
  - Force password reset
  - Revoke API keys
  - Disable tokens

- **Network Blocker** (`network_blocker.py`):
  - Block IPs (iptables/firewall)
  - Block domains (DNS/hosts file)
  - Rate limit endpoints

- **Backup Restore** (`backup_restore.py`):
  - List available backups
  - Verify backup integrity
  - Restore from backup
  - Post-restore validation

### Task 9: Add CLI Commands
Update `core/cli.py`:
- Add `war-room` command group
- Add `incident` command group
- Add `playbook` command group
- Add `forensics` command group
- Add `response` command group

### Task 10: Build Post-Mortem Generator
Create `incident/incidents/post_mortem.py`:
- Template-based post-mortem reports
- Incident summary (what happened, when, impact)
- Timeline of events
- Root cause analysis
- Response actions taken
- Lessons learned
- Action items (prevent recurrence)
- Export to Markdown/PDF

---

## Playbook Format (YAML)

```yaml
playbook:
  id: sql-injection-response
  name: SQL Injection Response
  severity: critical
  description: Respond to SQL injection vulnerability or active attack
  version: 1.0

steps:
  - id: isolate
    name: Isolate Affected Service
    description: Take the vulnerable service offline to prevent further exploitation
    type: manual
    actions:
      - Stop application server
      - Enable maintenance mode
      - Notify users of downtime
    approval_required: true

  - id: review_logs
    name: Review Query Logs
    description: Analyze logs to identify malicious queries
    type: automated
    script: forensics/log_collector.py
    args:
      - --type=sql
      - --last=24h

  - id: identify_vuln
    name: Identify Vulnerable Endpoint
    description: Locate the vulnerable code causing SQL injection
    type: manual
    checklist:
      - Review recent code changes
      - Check user input handling
      - Identify unsafe SQL queries
      - Document file and line number

  - id: apply_fix
    name: Apply Parameterized Query Fix
    description: Replace vulnerable query with parameterized version
    type: manual
    code_template: |
      # Bad (vulnerable)
      query = f"SELECT * FROM users WHERE id = {user_input}"

      # Good (safe)
      query = "SELECT * FROM users WHERE id = %s"
      cursor.execute(query, (user_input,))

  - id: test_fix
    name: Test Fix
    description: Verify SQL injection is no longer possible
    type: automated
    script: offensive/scanners/web_vuln_scanner.py
    args:
      - --target=http://localhost:3000
      - --test=sqli

  - id: restore_service
    name: Restore Service
    description: Bring application back online
    type: manual
    actions:
      - Deploy fix to production
      - Start application server
      - Disable maintenance mode
      - Monitor for issues

  - id: post_mortem
    name: Post-Mortem
    description: Document incident and lessons learned
    type: manual
    template: incident/templates/post_mortem.md
```

---

## War Room Workflow Example

```bash
# 1. Incident detected (automated or manual)
akali incident create "Suspected SQL injection in booking API" --severity=critical

# 2. Activate war room
akali war-room start INCIDENT-001
# → Notifies all agents via ZimMemory
# → Creates coordination channel
# → Activates incident response mode

# 3. Run playbook
akali playbook run sql-injection-response INCIDENT-001
# → Guides through each step
# → Logs all actions
# → Collects evidence

# 4. Forensics investigation (parallel)
akali forensics collect INCIDENT-001
akali forensics timeline INCIDENT-001
akali forensics analyze INCIDENT-001

# 5. Containment actions (as needed)
akali response contain api-server-1
akali response block 192.168.1.100

# 6. Close incident
akali incident update INCIDENT-001 resolved
akali war-room stop
akali incident close INCIDENT-001

# 7. Generate post-mortem
akali forensics report INCIDENT-001
# → Creates comprehensive incident report
```

---

## ZimMemory Integration

**War Room Start Alert:**
```json
{
  "from_agent": "akali",
  "to_agent": "broadcast",
  "subject": "🚨 WAR ROOM ACTIVATED: SQL Injection Detected",
  "body": "War room activated for INCIDENT-001.\n\nSeverity: CRITICAL\nType: SQL Injection\nAffected: Booking API\n\nAll agents please join coordination channel.\nPlaybook: sql-injection-response\n\nStatus: http://localhost:8765/incidents/INCIDENT-001",
  "priority": "critical",
  "metadata": {
    "incident_id": "INCIDENT-001",
    "war_room_active": true,
    "playbook": "sql-injection-response"
  }
}
```

**Incident Status Update:**
```json
{
  "from_agent": "akali",
  "to_agent": "broadcast",
  "subject": "🛡️ INCIDENT-001 Update: Service Isolated",
  "body": "Booking API isolated successfully.\nVulnerable endpoint identified: /api/bookings\nApplying fix now...",
  "priority": "high",
  "metadata": {
    "incident_id": "INCIDENT-001",
    "status": "contained"
  }
}
```

---

## Success Criteria

When all 10 tasks done:
- ✅ War room commander operational
- ✅ Team notification via ZimMemory working
- ✅ Playbook engine executes YAML playbooks
- ✅ 6 incident playbooks created (SQL injection, data breach, ransomware, account compromise, DDoS, insider threat)
- ✅ Forensics investigator collects logs and builds timelines
- ✅ Incident database tracks incidents end-to-end
- ✅ Incident tracker manages lifecycle
- ✅ Response automation (containment, account lockout, network blocking, backup restore)
- ✅ CLI commands for war-room, incident, playbook, forensics, response
- ✅ Post-mortem generator creates incident reports
- ✅ Documentation complete
- ✅ Tests passing
- ✅ Git tagged as `v5.0-phase5`

---

## Key Principles

1. **Speed is critical** - Every minute counts in incident response
2. **Follow the playbook** - Consistent, repeatable responses reduce errors
3. **Preserve evidence** - Forensics before remediation
4. **Communicate constantly** - Keep team informed of status
5. **Learn and improve** - Every incident makes defenses stronger

---

## Quick Start for Fresh Session

**In new Claude Code session, run:**

```bash
cd ~/akali
cat PHASE5-HANDOFF.md
```

Then say:

> "Start Akali Phase 5 implementation. Handoff at ~/akali/PHASE5-HANDOFF.md. Phases 1-4 complete. Ready to build incident response system."

---

## Key Files Reference

**Phases 1-4 Complete:**
- Workspace: `/Users/sevs/akali/`
- CLI: `/Users/sevs/akali/akali`
- Intelligence: `/Users/sevs/akali/intelligence/`
- Metrics: `/Users/sevs/akali/metrics/`
- Dashboard: `/Users/sevs/akali/metrics/dashboard/`

**Phase 5 To Create:**
- War Room: `/Users/sevs/akali/incident/war_room/`
- Playbooks: `/Users/sevs/akali/incident/playbooks/`
- Forensics: `/Users/sevs/akali/incident/forensics/`
- Incidents: `/Users/sevs/akali/incident/incidents/`
- Response: `/Users/sevs/akali/incident/response/`

---

## Notes

- Phase 5 is critical infrastructure - handle carefully
- War room should be easy to activate (one command)
- Playbooks guide responders through stress
- Forensics preserve evidence for later analysis
- Post-mortems prevent future incidents
- Estimate: 1.5-2 sessions to complete

---

**Phase 1 Complete** ✅ | **Phase 2 Complete** ✅ | **Phase 3 Complete** ✅ | **Phase 4 Complete** ✅ | **Phase 5 Ready** 🚀

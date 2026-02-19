# Akali Phase 5: Incident Response

Complete incident response system with war room coordination, playbooks, forensics, and automated response.

## Overview

Phase 5 provides enterprise-grade incident response capabilities:

- **War Room Commander** - Activate coordinated incident response mode
- **Incident Tracker** - Full lifecycle management (detection → resolution → post-mortem)
- **Playbook Engine** - Execute YAML-based response workflows
- **Team Notifier** - Broadcast alerts to all agents via ZimMemory
- **Forensics Tools** - Log collection and evidence preservation
- **Response Automation** - Containment, account lockout, network blocking
- **Post-Mortem Generator** - Comprehensive incident reports

## Quick Start

### Create an Incident

```bash
akali incident create "SQL Injection in API" \
  --severity critical \
  --description "Suspicious SQL in booking endpoint" \
  --type sql_injection \
  --systems booking-api user-api
```

### Activate War Room

```bash
akali war-room start INCIDENT-001
# Automatically notifies all agents via ZimMemory
```

### Run Response Playbook

```bash
# List available playbooks
akali playbook list

# Execute playbook
akali playbook run sql-injection-response INCIDENT-001

# Check playbook status
akali playbook status run-20260219-123456
```

### Generate Post-Mortem

```bash
akali post-mortem INCIDENT-001
# Creates comprehensive report at ~/.akali/reports/
```

## Architecture

```
incident/
├── incidents/
│   ├── incident_db.py       # SQLite database
│   ├── incident_tracker.py  # Lifecycle management
│   └── post_mortem.py       # Report generator
├── war_room/
│   ├── war_room_commander.py  # War room activation
│   └── team_notifier.py       # ZimMemory broadcasting
├── playbooks/
│   ├── playbook_engine.py     # YAML playbook execution
│   ├── sql-injection.yaml
│   ├── data-breach.yaml
│   ├── ransomware.yaml
│   ├── account-compromise.yaml
│   ├── ddos.yaml
│   └── insider-threat.yaml
├── forensics/
│   └── log_collector.py      # Evidence collection
└── response/
    ├── containment.py        # System isolation
    ├── account_manager.py    # Account security
    └── network_blocker.py    # IP/domain blocking
```

## Available Playbooks

### 1. SQL Injection Response
- Isolate service
- Review query logs
- Identify vulnerable code
- Apply parameterized queries
- Test fix
- Restore service

### 2. Data Breach Response
- Confirm breach scope
- Contain breach
- Preserve evidence
- Invalidate credentials
- Notify affected users
- Legal/compliance notification

### 3. Ransomware Response
- Immediate isolation
- Identify ransomware variant
- Check for decryption tools
- Restore from backups
- Patch entry point
- Contact law enforcement

### 4. Account Compromise
- Lock account
- Review activity logs
- Identify compromise vector
- Check lateral movement
- Reset credentials
- Enable MFA

### 5. DDoS Attack Response
- Confirm DDoS
- Enable mitigation
- Block attack sources
- Scale infrastructure
- Contact ISP
- Document attack

### 6. Insider Threat Response
- Assess threat level
- Preserve evidence
- Consult legal
- Restrict access
- Monitor activity
- Terminate access if confirmed

## CLI Commands

### Incident Management

```bash
# Create incident
akali incident create "Title" --severity [low|medium|high|critical]

# List incidents
akali incident list
akali incident list --status active
akali incident list --severity critical

# Show details
akali incident show INCIDENT-001

# Update status
akali incident update INCIDENT-001 contained

# Close incident
akali incident close INCIDENT-001 "Resolution summary"
```

### War Room Operations

```bash
# Start war room
akali war-room start INCIDENT-001

# Check status
akali war-room status

# Stop war room
akali war-room stop --resolution "Incident resolved"
```

### Playbook Operations

```bash
# List playbooks
akali playbook list

# Run playbook
akali playbook run [playbook-id] [incident-id]

# Check status
akali playbook status [run-id]
```

### Post-Mortem

```bash
# Generate report
akali post-mortem INCIDENT-001
akali post-mortem INCIDENT-001 --output /path/to/report.md
```

## Database Schema

### Incidents Table
- `id`: Incident ID (INCIDENT-001, etc.)
- `title`: Incident title
- `severity`: low, medium, high, critical
- `status`: new, active, contained, resolved, closed
- `incident_type`: sql_injection, data_breach, etc.
- `affected_systems`: JSON array
- `war_room_active`: Boolean

### Timeline Table
- `incident_id`: Foreign key
- `timestamp`: Event timestamp
- `event_type`: status_change, action, note, alert
- `event`: Event description
- `actor`: Who/what caused event

### Evidence Table
- `incident_id`: Foreign key
- `evidence_type`: log, screenshot, file, network_capture
- `file_path`: Path to evidence
- `file_hash`: SHA256 for integrity
- `chain_of_custody`: JSON tracking

### Actions Table
- `incident_id`: Foreign key
- `action_type`: containment, investigation, remediation
- `action`: Action description
- `status`: pending, in_progress, completed, failed
- `result`: Action outcome

## ZimMemory Integration

War room notifications are automatically sent to all agents via ZimMemory at http://10.0.0.209:5001

**Message format:**
```json
{
  "from_agent": "akali",
  "to_agent": "broadcast",
  "message": "🚨 WAR ROOM ACTIVATED: SQL Injection Detected\n\nSeverity: CRITICAL\nAffected: Booking API\n\nAll agents join coordination channel.",
  "priority": "critical"
}
```

## Response Automation (DRY RUN Mode)

All response automation modules run in **DRY RUN** mode by default for safety. They show what commands would be executed without actually running them.

To use in production:
```python
from incident.response.containment import ContainmentManager

# Enable production mode
manager = ContainmentManager(dry_run=False)
```

## Development

### Testing

```bash
# Test individual modules
python3 incident/incidents/incident_db.py
python3 incident/incidents/incident_tracker.py
python3 incident/war_room/team_notifier.py
python3 incident/war_room/war_room_commander.py
python3 incident/playbooks/playbook_engine.py
python3 incident/response/containment.py
```

### Adding Custom Playbooks

Create YAML file in `incident/playbooks/`:

```yaml
playbook:
  id: custom-response
  name: Custom Response
  severity: high
  description: Custom incident response
  version: 1.0

steps:
  - id: step1
    name: First Step
    description: What to do
    type: manual  # or automated
    actions:
      - Action 1
      - Action 2
```

## Next Steps

See `PHASE6-HANDOFF.md` for next phase (Education & Advanced features).

---

**Phase 5 Status:** ✅ Complete
**Version:** v5.0
**Date:** 2026-02-19

# Akali Alert System

Autonomous alert routing, deduplication, and ZimMemory integration for Akali security findings.

## Overview

The alert system consists of two main components:

1. **AlertManager** - Handles alert creation, routing, deduplication, and escalation
2. **ZimAlerter** - Integrates with ZimMemory to send alerts to agents

## Features

### AlertManager

- **Severity-based routing** - Critical → immediate, Medium → hourly digest, Low → daily digest
- **Alert deduplication** - Don't re-alert on same finding within 24 hours
- **Rate limiting** - Max 10 alerts per hour to prevent spam
- **Alert queue management** - Persistent storage in `alert_queue.json`
- **Escalation logic** - If unacked for 24h, escalate to sevs
- **Alert history tracking** - Full audit trail of all alerts

### ZimAlerter

- **Agent routing** - Intelligent routing based on finding type:
  - Backend/API issues → dommo
  - QA/test issues → banksy
  - Platform/frontend → dommo
  - Security issues → akali
  - Unknown → sevs
- **Priority mapping** - Akali severity → ZimMemory priority
- **Rich message formatting** - Detailed alert messages with context
- **Retry logic** - 3 retries with exponential backoff on failure
- **Digest support** - Send daily/weekly digests instead of individual alerts

## Installation

```bash
# No additional dependencies required
# Uses standard Python libraries (json, urllib, datetime, logging)
```

## Usage

### Basic Alert Flow

```python
from data.findings_db import FindingsDB
from autonomous.alerts import AlertManager, ZimAlerter

# Initialize
db = FindingsDB()
manager = AlertManager(findings_db=db)
alerter = ZimAlerter()

# Create finding
finding = {
    "id": "vul-001",
    "title": "SQL Injection",
    "description": "Potential SQL injection in login",
    "severity": "critical",
    "scanner": "nuclei",
    "target": "app.goumuve.com",
    "status": "open"
}
db.add_finding(finding)

# Create alert (auto-routes to appropriate agent)
alert_result = manager.send_alert(finding["id"])

# Get alert details
alert = manager.get_alert(alert_result["alert_id"])

# Send to ZimMemory
zim_result = alerter.send_to_zim(finding, alert)

if zim_result["success"]:
    # Mark as sent
    manager.mark_sent(alert_result["alert_id"], success=True)
```

### Manual Agent Routing

```python
# Route to specific agent instead of auto-detection
alert_result = manager.send_alert(
    finding_id="vul-001",
    agent_id="banksy"  # Override routing
)
```

### Acknowledge Alert

```python
# Acknowledge an alert
manager.ack_alert(alert_id)
```

### List Alerts

```python
# Get all pending alerts
pending = manager.list_alerts(status="pending")

# Filter by severity
critical = manager.list_alerts(severity="critical")

# Filter by agent
dommo_alerts = manager.list_alerts(agent_id="dommo")
```

### Check for Escalations

```python
# Check for alerts that need escalation (unacked > 24h)
escalations = manager.check_escalations()

for alert in escalations:
    finding = db.get_finding(alert["finding_id"])
    alerter.send_escalation(alert, finding)
```

### Send Digest

```python
# Get low/medium alerts for daily digest
alerts = manager.list_alerts(severity="low")
findings = [db.get_finding(a["finding_id"]) for a in alerts]

# Send digest
alerter.send_digest(alerts, findings, digest_type="daily")
```

### Alert Statistics

```python
# Get alert stats
stats = manager.get_stats()
print(f"Pending: {stats['pending_alerts']}")
print(f"Total sent: {stats['total_sent']}")
```

## Agent Routing Logic

Alerts are automatically routed based on finding characteristics:

| Finding Type | Agent | Reason |
|--------------|-------|--------|
| API/nuclei scanner | dommo | Backend specialist |
| QA/test related | banksy | QA lead |
| Web/platform | dommo | Platform expertise |
| Critical/High security | akali | Security tracking |
| Unknown | sevs | Default escalation |

## Priority Mapping

Akali severity levels map to ZimMemory priorities:

| Akali Severity | ZimMemory Priority |
|----------------|-------------------|
| Critical | critical |
| High | critical |
| Medium | high |
| Low | normal |

## Alert Message Format

Alerts sent to ZimMemory include:

- Severity indicator (emoji)
- Finding title
- Scanner name
- Target system
- Finding ID
- Description
- Remediation steps (if available)
- File path and line number (if available)
- Acknowledgment command

Example:

```
🔴 **CRITICAL** Security Alert

**Title:** SQL Injection Vulnerability
**Scanner:** nuclei
**Target:** app.goumuve.com
**Finding ID:** vul-001

**Description:**
Potential SQL injection in login endpoint

**Remediation:**
Use parameterized queries

**File:** `/api/auth/login.py`
**Line:** 78

---
*Acknowledge with:* `akali alert ack alert-20260219-abc123`
```

## Configuration

### AlertManager Configuration

```python
manager = AlertManager(
    queue_path="~/akali/autonomous/alerts/alert_queue.json",
    findings_db=db
)

# Adjust settings
manager.max_alerts_per_hour = 10  # Rate limit
manager.escalation_threshold_hours = 24  # Escalation delay
manager.dedup_window_hours = 24  # Deduplication window
```

### ZimAlerter Configuration

```python
alerter = ZimAlerter(
    zim_url="http://10.0.0.209:5001",
    sender_id="akali",
    timeout=10
)
```

## Data Storage

### Alert Queue Format

```json
{
  "alerts": [
    {
      "id": "alert-20260219-abc123",
      "finding_id": "vul-001",
      "severity": "critical",
      "title": "SQL Injection",
      "description": "...",
      "scanner": "nuclei",
      "target": "app.goumuve.com",
      "created_at": "2026-02-19T10:00:00",
      "status": "pending",
      "agent_id": "dommo",
      "retry_count": 0
    }
  ],
  "history": [],
  "stats": {
    "total_sent": 0,
    "total_acknowledged": 0,
    "total_escalated": 0
  }
}
```

## Testing

Run the test suite:

```bash
cd ~/akali
python3 autonomous/alerts/test_alerts.py
```

Run example usage:

```bash
python3 autonomous/alerts/example_usage.py
```

## Error Handling

### ZimMemory Connection Failures

The alerter includes automatic retry logic:

- 3 retry attempts
- Exponential backoff (1s, 2s, 4s)
- Detailed error logging
- Failed alerts remain in queue

### Rate Limit Exceeded

When rate limit is hit:

- Alert is still created but marked as "queued"
- Will be sent in next available window
- Rate limit resets every hour

### Duplicate Detection

Duplicate alerts are:

- Detected within 24-hour window
- Logged but not created
- Returns error with `status: "skipped"`

## Maintenance

### Cleanup Old History

```python
# Remove alerts older than 30 days from history
removed = manager.cleanup_old_history(days=30)
```

### Check Escalations

Should be run periodically (e.g., hourly cron job):

```python
escalations = manager.check_escalations()
for alert in escalations:
    # Handle escalation
    pass
```

## Integration with Akali CLI

Alert commands will be added to the main Akali CLI:

```bash
akali alert send <finding_id> [--agent=<agent_id>]
akali alert list [--status=pending] [--severity=critical]
akali alert ack <alert_id>
akali alert stats
```

## Architecture

```
findings_db.py (data layer)
       ↓
alert_manager.py (alert logic)
       ↓
zim_alerter.py (ZimMemory integration)
       ↓
ZimMemory API (http://10.0.0.209:5001)
       ↓
Agent Inboxes (dommo, banksy, akali, sevs)
```

## Future Enhancements

- [ ] Email alerts for critical findings
- [ ] Slack integration
- [ ] SMS alerts for critical severity
- [ ] Web dashboard for alert management
- [ ] Machine learning for better routing
- [ ] Alert templates for common findings
- [ ] Custom routing rules via config file

## Troubleshooting

### ZimMemory Not Reachable

```python
# Test connection
alerter = ZimAlerter()
result = alerter.test_connection()

if not result["success"]:
    print(f"Error: {result['error']}")
```

### Alerts Not Being Sent

1. Check rate limit: `manager.get_stats()`
2. Check for duplicates: Look for recent history
3. Verify ZimMemory is running: `curl http://10.0.0.209:5001`
4. Check logs: Look for error messages

### Missing Findings

Ensure finding exists in database before creating alert:

```python
finding = db.get_finding(finding_id)
if not finding:
    print(f"Finding {finding_id} not found")
```

## See Also

- [Findings Database](../../data/findings_db.py)
- [ZimMemory Documentation](http://10.0.0.209:5001/docs)
- [Phase 3 Handoff](../../PHASE3-HANDOFF.md)

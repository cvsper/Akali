# Akali Triage Engine

Automated security finding triage with risk scoring, false positive detection, auto-remediation, and learning capabilities.

## Features

### 1. Risk Scoring Algorithm (0-10 scale)

- **Base score**: CVSS score if available, defaults to 5.0
- **+2**: Finding in production code path (src/, lib/, app/, api/, etc.)
- **+1**: Publicly accessible endpoint (API routes, controllers, public/)
- **+1**: Sensitive logic (auth, payment, credentials, admin, etc.)
- **-1**: Test or development code (test/, spec/, fixtures/)
- **Learned adjustments**: Applied based on user feedback patterns

**Severity Mapping:**
- Critical: 9-10
- High: 7-8
- Medium: 4-6
- Low: 1-3
- Info: 0

### 2. False Positive Detection

Built-in patterns:
- Test file secrets (test fixtures are usually not real secrets)
- Example .env files (.env.example, .env.template)
- Commented code (inactive code)
- Vendor dependencies (upstream issues)

**Manual Marking:**
```bash
python -m autonomous.triage.triage_engine feedback FINDING_ID false_positive --notes "Reason"
```

### 3. Auto-Remediation (SAFE operations only)

Supported remediations:
- **Remove committed .env files**: `git rm --cached .env && echo '.env' >> .gitignore`
- **Update vulnerable dependencies**: `pip install --upgrade PACKAGE` or `npm update PACKAGE`
- **Add security headers**: Guidance for web server configuration

All auto-fixes are:
- Non-destructive
- Logged for audit trail
- Reversible

### 4. Learning from Feedback

The engine learns from user actions:
- **Frequently dismissed findings**: Score adjusted downward (-1.0 after 3+ dismissals)
- **Frequently acted upon findings**: Score adjusted upward (+1.0 after 5+ acks/fixes)
- **False positive patterns**: Automatically suppress similar findings

## Usage

### CLI Commands

**Triage a single finding:**
```bash
python -m autonomous.triage.triage_engine triage FINDING_ID
```

**Batch triage all findings:**
```bash
python -m autonomous.triage.triage_engine batch --status open
```

**Record user feedback:**
```bash
python -m autonomous.triage.triage_engine feedback FINDING_ID <action> [--notes "..."]
```

Actions: `ack`, `dismiss`, `fix`, `false_positive`

**Add false positive pattern:**
```bash
python -m autonomous.triage.triage_engine add-fp-pattern \
  "pattern_name" \
  "regex_pattern" \
  --field file \
  --confidence 0.8 \
  --description "Description"
```

**View statistics:**
```bash
python -m autonomous.triage.triage_engine stats
```

### Python API

```python
from autonomous.triage.triage_engine import TriageEngine

engine = TriageEngine()

# Perform full triage
decision = engine.triage(finding)
print(f"Risk: {decision.risk_score}/10 ({decision.severity})")
print(f"False Positive: {decision.is_false_positive}")
print(f"Can Auto-Remediate: {decision.can_auto_remediate}")

# Record feedback
engine.record_feedback(finding_id, "ack", "Will fix this week")

# Check false positive
is_fp, reason, confidence = engine.is_false_positive(finding)

# Calculate risk score
score, severity = engine.score_finding(finding)

# Check auto-remediation
can_fix, action, command = engine.auto_remediate(finding)
```

## Data Storage

- **False Positives**: `~/.akali/data/false_positives.json`
- **User Feedback**: `~/.akali/data/feedback.json`
- **Triage Log**: `~/.akali/logs/triage.log`

## Integration

The triage engine integrates with:
- **Findings Database** (`data/findings_db.py`): Updates findings with triage results
- **ZimMemory** (future): Share triage decisions across agents
- **Autonomous Scheduler**: Automated batch triage on schedule
- **Alert Manager**: Prioritize alerts based on risk scores

## Testing

Run comprehensive test suite:
```bash
python autonomous/triage/test_triage.py
```

Tests cover:
- Risk scoring algorithm
- False positive detection
- Auto-remediation logic
- Learning from feedback
- Full triage workflow
- Manual false positive marking

## Decision Logging

All triage decisions are logged to `~/.akali/logs/triage.log`:

```json
{
  "timestamp": "2026-02-19T10:30:00",
  "finding_id": "AKALI-001",
  "finding_type": "sql_injection",
  "file": "src/api/auth.py",
  "risk_score": 10,
  "severity": "critical",
  "is_false_positive": false,
  "can_auto_remediate": false
}
```

## Safety Guarantees

1. **No destructive operations**: Auto-remediation only performs safe actions
2. **Audit trail**: All decisions logged with timestamps
3. **Reversible actions**: All auto-fixes can be undone
4. **Manual approval**: High-risk remediations require user confirmation
5. **False positive marking**: Users can override any decision

## Example Workflow

```bash
# Run batch triage
python -m autonomous.triage.triage_engine batch --status open

# Review critical findings
akali findings --severity critical --status open

# Triage specific finding
python -m autonomous.triage.triage_engine triage AKALI-001

# Mark false positive if needed
python -m autonomous.triage.triage_engine feedback AKALI-001 false_positive \
  --notes "Test data only"

# Check learning statistics
python -m autonomous.triage.triage_engine stats
```

## Future Enhancements

- CVSS score calculation from vulnerability details
- ML-based false positive detection
- Integration with vulnerability databases (NVD, CVE)
- Automated remediation execution (with approval workflow)
- Cross-project triage pattern sharing via ZimMemory

# Akali DLP System

Data Loss Prevention (DLP) system for detecting and preventing sensitive data leakage.

## Components

### 1. PII Detector (`pii_detector.py`)
Detects personally identifiable information (PII) in text using regex patterns and validation.

**Supported PII Types (12):**
- Social Security Numbers (SSN)
- Credit Card Numbers (with Luhn validation)
- Email Addresses
- Phone Numbers (US format)
- IP Addresses (IPv4/IPv6)
- Passport Numbers
- Driver's License Numbers
- Date of Birth
- Physical Addresses
- Medical Record IDs
- Bank Account Numbers
- API Keys and Tokens

**Features:**
- Configurable sensitivity (low/medium/high)
- Confidence scoring (0.0 to 1.0)
- Context-aware detection
- Luhn algorithm for credit card validation
- Deduplication

### 2. Content Inspector (`content_inspector.py`)
Scans files, git commits, and API payloads for PII violations.

**Capabilities:**
- File scanning (single file or directory)
- Git commit inspection (specific commit or range)
- Git staged changes (pre-commit)
- API request/response inspection
- Violation tracking and storage

**File Types Scanned:**
- Source code: .py, .js, .ts, .java, .go, .rb, .php
- Data files: .json, .yaml, .xml, .csv, .txt
- Config files: .env, .conf, .config
- Scripts: .sh, .bash, .zsh

### 3. Monitoring System (`monitors/`)
Real-time monitors for continuous DLP protection.

#### File Monitor (`file_monitor.py`)
- Watches file system for changes using watchdog
- Scans new/modified files automatically
- Configurable watch paths
- Real-time alerting to ZimMemory

#### Git Monitor (`git_monitor.py`)
- Pre-commit hook for blocking PII commits
- Commit history scanning
- Staged changes inspection
- Easy installation: `./akali dlp install-git-hook`

#### API Monitor (`api_monitor.py`)
- Flask middleware for API DLP
- Request and response inspection
- Automatic blocking/redaction
- Demo server included

### 4. Policy Engine (`policy_engine.py`)
Enforces DLP policies based on configurable rules.

**Policy Actions:**
- **WARN** - Log violation, allow operation
- **BLOCK** - Prevent operation (commit, API request)
- **REDACT** - Remove PII from data
- **ENCRYPT** - Encrypt sensitive data

**Default Policies:**
1. **Block Critical PII** - Block SSN, credit cards, passports in git/API
2. **Warn on High-Risk PII** - Alert on API keys, bank accounts
3. **Redact Email/Phone** - Auto-redact in API responses (opt-in)
4. **Encrypt Sensitive Files** - Auto-encrypt files with multiple PII (opt-in)

**Configuration:** `~/.akali/dlp_policies.yaml`

## Usage

### PII Detection

```python
from education.dlp.pii_detector import PIIDetector

detector = PIIDetector(sensitivity='medium')

# Detect PII in text
text = "John's SSN is 123-45-6789 and email is john@example.com"
matches = detector.detect(text)

for match in matches:
    print(f"{match.pii_type.value}: {match.value} (confidence: {match.confidence})")

# Detect PII in file
matches = detector.detect_file('/path/to/file.py')
```

### Content Inspection

```python
from education.dlp.content_inspector import ContentInspector

inspector = ContentInspector()

# Inspect file
violation = inspector.inspect_file('/path/to/file.py')

# Inspect directory
violations = inspector.inspect_directory('/path/to/project', recursive=True)

# Inspect git commit
violation = inspector.inspect_git_commit('HEAD')

# Inspect staged changes (pre-commit)
violation = inspector.inspect_git_staged()

# Inspect API payload
payload = {"user": {"ssn": "123-45-6789"}}
violation = inspector.inspect_api_request('/api/users', payload)
```

### File Monitoring

```bash
# Monitor specific directories
python3 education/dlp/monitors/file_monitor.py --paths ~/Documents ~/Desktop

# Adjust sensitivity
python3 education/dlp/monitors/file_monitor.py --sensitivity high
```

### Git Monitoring

```bash
# Install pre-commit hook
python3 education/dlp/monitors/git_monitor.py --install-hook

# Check staged changes
python3 education/dlp/monitors/git_monitor.py --staged

# Check specific commit
python3 education/dlp/monitors/git_monitor.py --commit abc123

# Scan commit range
python3 education/dlp/monitors/git_monitor.py --range main..feature-branch
```

### API Monitoring

```python
from flask import Flask
from education.dlp.monitors.api_monitor import DLPMiddleware

app = Flask(__name__)

# Add DLP middleware
dlp = DLPMiddleware(app)

@app.route('/api/users', methods=['POST'])
def create_user():
    # PII in request will be detected
    user = request.get_json()
    return jsonify({'id': 123})

# Run app
app.run()
```

**Demo Server:**
```bash
python3 education/dlp/monitors/api_monitor.py --demo --port 5050
```

### Policy Management

```python
from education.dlp.policy_engine import PolicyEngine

engine = PolicyEngine()

# List policies
policies = engine.list_policies()

# Enable/disable policy
engine.enable_policy('email_phone_redact')
engine.disable_policy('sensitive_file_encrypt')

# Get stats
stats = engine.get_stats()
```

## CLI Commands

Integration with `akali` CLI:

```bash
# Scan for PII
akali dlp scan [target]              # Scan file, directory, or git repo
akali dlp scan --file /path/to/file  # Scan specific file
akali dlp scan --git                 # Scan git staged changes
akali dlp scan --api [payload.json]  # Scan API payload

# Policy management
akali dlp policies list              # List all policies
akali dlp policies enable [id]       # Enable policy
akali dlp policies disable [id]      # Disable policy
akali dlp policies show [id]         # Show policy details

# Violations
akali dlp violations list            # List all violations
akali dlp violations show [id]       # Show violation details
akali dlp violations clear           # Clear violation history

# Monitoring
akali dlp monitor --file             # Start file monitor
akali dlp monitor --git              # Install git hook
akali dlp monitor --api              # Start API monitor demo
```

## Data Storage

**Violations:** `~/.akali/dlp_violations/`
- Each violation saved as JSON file
- Named: `DLP-[timestamp]-[random].json`
- Includes PII matches, severity, action taken

**Policies:** `~/.akali/dlp_policies.yaml`
- YAML configuration for policies
- Can be edited manually or via CLI
- Automatically created with defaults

## Integration

### ZimMemory Alerts

DLP system sends alerts to ZimMemory for violations:
- **Critical/High** → Dommo
- **Medium/Low** → Zim

Alert includes:
- Violation ID
- Source (file/git/api)
- Severity
- PII types found
- Action taken

### Git Hooks

Pre-commit hook blocks commits with critical PII:
1. Install hook: `akali dlp monitor --git`
2. Hook runs automatically on `git commit`
3. Blocks commit if policy says BLOCK
4. Allows commit if policy says WARN

### Flask Middleware

Add DLP to Flask apps:
```python
from education.dlp.monitors.api_monitor import DLPMiddleware

app = Flask(__name__)
dlp = DLPMiddleware(app)
```

Middleware inspects:
- Request payloads (before route handler)
- Response payloads (after route handler)
- Blocks requests/responses based on policy

## Testing

```bash
# Test PII detector
python3 education/dlp/pii_detector.py

# Test content inspector
python3 education/dlp/content_inspector.py

# Test policy engine
python3 education/dlp/policy_engine.py

# Test file monitor
python3 education/dlp/monitors/file_monitor.py --paths /tmp

# Test git monitor
python3 education/dlp/monitors/git_monitor.py --staged

# Test API monitor
python3 education/dlp/monitors/api_monitor.py
```

## Dependencies

```bash
# Core (included in Python)
- re, json, pathlib, datetime

# File monitoring
pip install watchdog

# Required (already in akali)
- yaml
- requests
- flask (for API monitoring)
```

## Configuration

Edit `~/.akali/dlp_policies.yaml` to customize policies:

```yaml
version: '1.0'

policies:
  critical_pii_block:
    name: Block Critical PII
    pii_types: [ssn, credit_card, passport]
    severity_threshold: critical
    action: block
    source_filters: [git, api]
    confidence_threshold: 0.7
    enabled: true

  custom_policy:
    name: My Custom Policy
    pii_types: [email, phone]
    severity_threshold: medium
    action: warn
    enabled: true

settings:
  send_alerts: true
  alert_recipient: dommo
  log_violations: true
  default_action: warn
```

## Security Best Practices

1. **Regular Scans** - Run periodic scans on codebases
2. **Pre-commit Hooks** - Install git hooks on all repos
3. **API Monitoring** - Add middleware to production APIs
4. **Policy Review** - Review and update policies quarterly
5. **False Positives** - Tune confidence thresholds to reduce noise
6. **Training** - Educate team on PII handling (use training system)

## Limitations

1. **Pattern-based** - May miss obfuscated PII
2. **No ML** - Pure regex, no machine learning (future enhancement)
3. **Performance** - Large files (>10MB) are skipped
4. **Languages** - Optimized for English text
5. **Redaction** - Currently logs only, doesn't actually redact (placeholder)
6. **Encryption** - Flags for encryption, doesn't perform it (placeholder)

## Future Enhancements

- Machine learning for better PII detection
- Support for more PII types (international formats)
- Actual redaction and encryption implementation
- Web dashboard for violations
- Integration with Phase 4 metrics dashboard
- Custom PII patterns via config
- Multi-language support
- Database storage for violations (SQLite)
- Automated remediation workflows

---

🥷 **Akali DLP System** - Protecting sensitive data across the family

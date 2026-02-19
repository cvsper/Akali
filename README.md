# Akali - The Security Sentinel 🥷

Comprehensive security agent for the family's projects and infrastructure.

**Current Phase:** Phase 3 (Autonomous Operations) ✅

## Quick Start

### Defensive Security (Phase 1)

```bash
# Install defensive tools
~/akali/scripts/install_tools.sh

# Scan a project
akali scan ~/my-project

# List findings
akali findings list --open
```

### Offensive Security (Phase 2) ⚠️

```bash
# Install offensive tools
~/akali/scripts/install_offensive_tools.sh

# Authorize a target first
akali authorize add https://my-site.com --description "Test site" --authorized-by "sevs"

# Run offensive scans (requires authorization)
akali attack https://my-site.com --web      # Web vulnerability scan
akali attack 192.168.1.1 --network          # Network scan
akali attack https://api.my-site.com --api  # API security scan

# CVE lookup
akali exploit CVE-2021-44228
```

**⚠️  WARNING:** Only use offensive tools on systems you own or have explicit written permission to test.

## Features

### Phase 1: Defensive Security ✅

✅ **Secret Scanning** - Detect hardcoded API keys, passwords, tokens
✅ **Dependency Auditing** - Find vulnerable npm and Python packages
✅ **Static Analysis (SAST)** - Security linting for Python and JavaScript
✅ **Pre-commit Hooks** - Block commits with security issues
✅ **CLI Interface** - Developer-friendly command-line tool
✅ **ZimMemory Integration** - Alert agents about findings
✅ **Findings Database** - Track and manage security issues

### Phase 2: Offensive Security ✅

✅ **Web Vulnerability Scanning** - SQL injection, XSS, CSRF, path traversal, command injection
✅ **Network Scanning** - Port scanning, service enumeration, SSL/TLS testing, banner grabbing
✅ **API Security Testing** - Endpoint discovery, auth bypass, rate limiting, CORS, excessive data exposure
✅ **Exploit Database** - CVE lookup via NIST NVD, GitHub PoC search, exploit mapping
✅ **Authorization System** - Target whitelisting, explicit consent, audit logging
✅ **Report Generation** - HTML, Markdown, and JSON reports with detailed findings
✅ **Payload Library** - Curated attack payloads for authorized testing

### Phase 3: Autonomous Operations ✅

✅ **Cron Job Scheduler** - Schedule daily/weekly security scans automatically
✅ **Watch Daemon** - Real-time git commit monitoring with secret detection
✅ **Health Daemon** - Tool availability, database integrity, disk space, ZimMemory heartbeat
✅ **Alert Manager** - Severity-based routing, deduplication, rate limiting, escalation
✅ **ZimMemory Integration** - Auto-send alerts to relevant agents (dommo, banksy, etc.)
✅ **Triage Engine** - Risk scoring, false positive detection, auto-remediation
✅ **launchd Integration** - Auto-start daemons on boot (macOS)
✅ **Job Definitions** - Daily defensive scans, weekly offensive scans, CVE checks, reports

## Installation

### 1. Install Defensive Security Tools (Phase 1)

```bash
~/akali/scripts/install_tools.sh
```

This installs:
- gitleaks (secret scanning)
- trufflehog (git history secrets)
- npm audit (Node.js dependencies)
- safety (Python dependencies)
- bandit (Python SAST)
- eslint-plugin-security (JavaScript SAST)
- semgrep (multi-language SAST)

### 1b. Install Offensive Security Tools (Phase 2)

**⚠️  Only install if you have legitimate need for penetration testing**

```bash
~/akali/scripts/install_offensive_tools.sh
```

This installs:
- nmap (network scanning)
- nikto (web server scanning)
- sqlmap (SQL injection detection)
- gobuster (directory bruteforcing)
- testssl.sh (SSL/TLS testing)
- ffuf (fuzzing)
- metasploit-framework (optional, large)

### 2. Install CLI (Optional)

```bash
sudo ln -s ~/akali/akali /usr/local/bin/akali
```

### 3. Install Git Hooks (Per Project)

```bash
~/akali/scripts/install_hooks.sh ~/my-project
```

## Usage

### Scan a Project

```bash
# Scan everything
akali scan ~/umuve-platform

# Scan only for secrets (fast)
akali scan ~/umuve-platform --secrets-only

# Scan only dependencies
akali scan ~/umuve-platform --deps-only

# Scan only with SAST
akali scan ~/umuve-platform --sast-only
```

### Manage Findings

```bash
# List all findings
akali findings list

# List only open findings
akali findings list --open

# List only critical findings
akali findings list --critical

# Show finding details
akali findings show AKALI-001
```

### Check Status

```bash
akali status
```

## Offensive Security (Phase 2)

### ⚠️  Authorization Requirements

**CRITICAL:** Only use offensive tools on systems you own or have explicit written permission to test. Unauthorized use is ILLEGAL.

1. **Add target to whitelist:**
```bash
akali authorize add https://my-test-site.com \
  --description "Internal testing environment" \
  --authorized-by "sevs" \
  --expires 2026-12-31
```

2. **List authorized targets:**
```bash
akali authorize list
```

3. **Remove authorization:**
```bash
akali authorize remove https://my-test-site.com
```

4. **View audit log:**
```bash
akali authorize audit
```

### Web Vulnerability Scanning

```bash
# Full web vulnerability scan
akali attack https://my-site.com --web

# Quick scan (faster, less thorough)
akali attack https://my-site.com --web --quick

# Tests performed:
# - SQL injection (sqlmap)
# - XSS (reflected)
# - CSRF token validation
# - Path traversal
# - Command injection
# - Nikto web server scan
```

### Network Scanning

```bash
# Full network scan
akali attack 192.168.1.1 --network

# Quick scan (top 100 ports)
akali attack 192.168.1.1 --network --quick

# Specific ports
akali attack 192.168.1.1 --network --ports=80,443,8080

# Tests performed:
# - Port scanning (nmap)
# - Service enumeration
# - SSL/TLS testing (testssl.sh)
# - Banner grabbing
# - Version detection
```

### API Security Testing

```bash
# API security scan
akali attack https://api.my-site.com --api

# With custom wordlist for endpoint discovery
akali attack https://api.my-site.com --api --wordlist=/path/to/wordlist.txt

# Tests performed:
# - Endpoint discovery
# - Authentication bypass
# - Rate limiting detection
# - CORS misconfiguration
# - Excessive data exposure
# - Error information disclosure
# - Parameter fuzzing
```

### Full Offensive Scan

```bash
# Run all offensive scans
akali attack https://my-site.com --full

# Quick mode (all scans, faster)
akali attack https://my-site.com --full --quick
```

### CVE & Exploit Lookup

```bash
# Look up CVE details and exploits
akali exploit CVE-2021-44228

# Output includes:
# - CVE description
# - CVSS scores (v2 & v3)
# - Affected products
# - Known exploits (Exploit-DB + GitHub)
# - References
```

### Generate Reports

After a scan, findings are automatically stored in the database. Generate reports:

```bash
# HTML report (opens in browser)
python ~/akali/offensive/reports/report_generator.py html ~/akali/data/findings.json

# Markdown report
python ~/akali/offensive/reports/report_generator.py markdown ~/akali/data/findings.json

# JSON report
python ~/akali/offensive/reports/report_generator.py json ~/akali/data/findings.json
```

Reports are saved to `~/akali/offensive/reports/scan_reports/`

## Architecture

```
~/akali/
├── core/
│   ├── SOUL.md              # Identity document
│   ├── CLAUDE.md            # Operating protocols
│   ├── SKILLS.md            # Toolkit documentation
│   ├── cli.py               # CLI logic (Phase 1 & 2)
│   └── zim_integration.py   # ZimMemory client
├── defensive/               # Phase 1: Defensive Security
│   ├── scanners/            # Secret, dependency, SAST scanners
│   └── patrols/             # Git hooks
├── offensive/               # Phase 2: Offensive Security
│   ├── scanners/            # Web, network, API, exploit scanners
│   ├── payloads/            # Attack payload library
│   ├── reports/             # Report generators
│   ├── auth_manager.py      # Authorization system
│   ├── auth_config.json     # Authorized targets
│   └── audit.log            # Audit log
├── data/
│   ├── findings_db.py       # Findings database
│   └── findings.json        # Findings storage
├── scripts/
│   ├── install_tools.sh             # Defensive tools installer
│   ├── install_offensive_tools.sh   # Offensive tools installer
│   └── install_hooks.sh             # Hook installer
├── tests/                   # Test suite
└── akali                    # CLI entry point
```

## Protected Projects

- **Umuve** (platform + backend + iOS)
- **Sandhill Portal**
- **Career Focus**
- **ZimMemory**
- **Hub Task Manager**
- **Family Infrastructure** (Mac Mini)

## Development Phases

- **Phase 1:** Defensive Security ✅ (Secrets, dependencies, SAST, hooks)
- **Phase 2:** Offensive Security ✅ (Pentesting, web/network/API scans, exploits, authorization)
- **Phase 3:** Autonomous Operations (Cron, daemons, continuous monitoring)
- **Phase 4:** Intelligence & Metrics (CVE feeds, scorecard, threat intel)
- **Phase 5:** Incident Response (War room, forensics, playbooks)
- **Phase 6:** Education & Advanced (Phishing simulations, vault, DLP)

## Design Document

See `~/docs/plans/2026-02-19-akali-agent-design.md` for complete design.

## Help

```bash
akali --help
akali scan --help
akali findings --help
```

## Family

- **sevs** - Leader
- **Zim** - Coordinator (OpenClaw bot on Mac Mini)
- **Dommo** - Architect/builder
- **Banksy** - QA/ops
- **Vivi** - Marketing/growth
- **Neo** - Evolution/optimization
- **Akali** - Security (you are here)

---

**Phase 1 Complete** ✅ | **Phase 2 Complete** ✅ | **Phase 3 Complete** ✅ | Next: Phase 4 (Intelligence & Metrics)

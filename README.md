# Akali - The Security Sentinel 🥷

Comprehensive security agent for the family's projects and infrastructure.

**Current Phase:** Phase 9 (Exploit Framework + Extended Targets + Purple Team) ✅

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

### Phase 4: Intelligence & Metrics ✅

✅ **CVE Monitoring** - Hourly checks of NVD and GitHub Security Advisories
✅ **Dependency Mapper** - Track all packages across all family projects
✅ **Impact Analyzer** - Calculate CVE blast radius (which projects affected)
✅ **Threat Intelligence Hub** - Exploit tracker, security feeds, breach monitoring
✅ **Supply Chain Auditor** - Complete dependency inventory and health checks
✅ **Security Scorecard** - Family security score (0-100) with component breakdown
✅ **Security Observatory** - MTTD/MTTR tracking, finding lifecycle metrics
✅ **Web Dashboard** - Real-time metrics visualization at localhost:8765
✅ **Intel CLI** - Commands for CVE checks, threat feeds, breach monitoring
✅ **Metrics CLI** - Commands for scorecard, history, observatory
✅ **Autonomous Intel Jobs** - Hourly CVE checks, daily scorecard, weekly supply chain audit

### Phase 5: Incident Response ✅

✅ **War Room** - Real-time incident coordination and communication
✅ **Forensics Tools** - Evidence collection, timeline analysis, artifact preservation
✅ **Playbooks** - Automated response playbooks for common incidents
✅ **Post-Mortem Generator** - Automated incident reports with root cause analysis

### Phase 6: Education & Advanced Security ✅

✅ **Security Training** - 10 OWASP Top 10 interactive training modules
✅ **Phishing Simulations** - 20+ email templates with tracking and reporting
✅ **HashiCorp Vault Integration** - Secrets management and rotation
✅ **Data Loss Prevention (DLP)** - 12+ PII type detection and blocking
✅ **Threat Hunting** - ML-based anomaly detection and behavioral analysis

### Phase 7: Mobile & C2 Infrastructure ✅

✅ **Mobile Penetration Testing** - iOS and Android security testing
✅ **Command & Control** - C2 infrastructure for red team operations
✅ **Red Team Operations** - Complete red team toolkit and automation

### Phase 9: Exploit Framework + Extended Targets + Purple Team ✅

#### 9A: Exploit Framework (192 tests)
✅ **Exploit Database** - ExploitDB, GitHub PoC search, Metasploit integration
✅ **Payload Generator** - SQL injection (4 databases), XSS (6 contexts), buffer overflow, ROP chains
✅ **Fuzzing Framework** - Binary fuzzing (AFL++), network fuzzing (TCP/UDP/HTTP), crash analysis
✅ **200+ Payload Templates** - Production-ready exploit payloads with WAF evasion

#### 9B: Extended Targets (217 tests)
✅ **Cloud Attacks** - AWS (S3, IAM, metadata), Azure (Blob, service principals), GCP (Storage, service accounts)
✅ **Active Directory** - Kerberoasting, AS-REP roasting, Pass-the-Hash, Golden/Silver tickets, BloodHound
✅ **Privilege Escalation** - Windows (11 categories, 10 kernel exploits), Linux (11 categories, 12 kernel exploits)
✅ **22 Kernel CVEs** - Tracked and exploitable across both platforms

#### 9C: Purple Team (163 tests)
✅ **Sandbox Environment** - Docker orchestration with 5 vulnerable apps, 5 honeypots, 3 network topologies
✅ **Defense Validation** - 6 attack simulations, MTTD/MTTR measurement, detection monitoring
✅ **Attack Chains** - Multi-step attack scenarios with success validation
✅ **Report Generation** - PDF, HTML, JSON reports with metrics and recommendations

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

## Phase 9: Exploit Framework Usage

### Payload Generation (Phase 9A)

```bash
# Generate SQL injection payloads
akali exploit generate sqli --db mysql --type union --encode url
akali exploit generate sqli --db postgresql --type blind
akali exploit generate sqli --db mssql --type error

# Generate XSS payloads
akali exploit generate xss --context html --type reflected --evasion
akali exploit generate xss --context script --type stored
akali exploit generate xss --context attribute --encode html-entities

# Generate buffer overflow exploit
akali exploit generate bof --target-arch x86_64 --bad-chars "\x00\x0a\x0d"

# Generate ROP chain
akali exploit generate rop --binary ./target_app --payload shell
```

### Exploit Database (Phase 9A)

```bash
# Search for exploits
akali exploit search "sql injection" --source github
akali exploit search "CVE-2021-44228" --source exploitdb
akali exploit search "wordpress" --category webapp

# List available exploits
akali exploit list --filter "remote code execution"

# Download exploit
akali exploit download EDB-50383
```

### Fuzzing (Phase 9A)

```bash
# Fuzz binary application
akali fuzz binary ./myapp --corpus ./test_inputs --timeout 3600
akali fuzz binary ./myapp --afl-mode --dict keywords.txt

# Fuzz network service
akali fuzz network 10.0.0.5 --port 8080 --protocol http
akali fuzz network 10.0.0.5 --port 9999 --protocol tcp

# Analyze crashes
akali fuzz analyze ./crashes --report
akali fuzz analyze ./crashes --exploitability
```

### Cloud Attacks (Phase 9B)

```bash
# AWS enumeration
akali cloud enum-s3 --keyword company-name --check-public
akali cloud test-iam --profile myprofile --mock
akali cloud metadata --provider aws

# Azure enumeration
akali cloud enum-azure --subscription-id abc123 --mock
akali cloud enum-azure --tenant-id xyz789

# GCP enumeration
akali cloud enum-gcp --project-id my-project --mock
```

### Active Directory (Phase 9B)

```bash
# Enumerate domain
akali ad enum --domain corp.local --user alice --password pass123

# Kerberoasting
akali ad kerberoast --domain corp.local --user alice --password pass123

# Pass-the-Hash
akali ad pth --hash aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c

# Generate Golden Ticket
akali ad golden-ticket --domain corp.local --sid S-1-5-21-... --krbtgt-hash abc123
```

### Privilege Escalation (Phase 9B)

```bash
# Enumerate Linux privesc vectors
akali privesc enum --os linux

# Enumerate Windows privesc vectors
akali privesc enum --os windows

# Check for kernel exploits
akali privesc check-kernel --os linux --kernel-version 5.4.0-42
akali privesc check-kernel --os windows --os-version "Windows 10 21H1"
```

### Purple Team Testing (Phase 9C)

```bash
# Create test environment
akali purple create-env --name dev-test --topology dmz

# Deploy vulnerable application
akali purple deploy-app --env dev-test --app juice-shop --port 3000

# Deploy honeypot
akali purple deploy-honeypot --env dev-test --service ssh --port 2222

# Run attack simulation
akali purple test-attack --type sqli --target http://localhost:3000
akali purple test-attack --type port_scan --target 10.0.0.5
akali purple test-attack --type kerberoast --target dc.corp.local

# Generate purple team report
akali purple report --simulation-id abc123 --format pdf --output ./report.pdf
akali purple report --simulation-id abc123 --format html --output ./report.html
```

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
- **Phase 3:** Autonomous Operations ✅ (Cron, daemons, continuous monitoring)
- **Phase 4:** Intelligence & Metrics ✅ (CVE feeds, scorecard, threat intel)
- **Phase 5:** Incident Response ✅ (War room, forensics, playbooks)
- **Phase 6:** Education & Advanced ✅ (Phishing simulations, vault, DLP, threat hunting)
- **Phase 7:** Mobile & C2 ✅ (iOS/Android pentesting, Command & Control infrastructure)
- **Phase 8:** Wireless & IoT ⚠️ (WiFi attacks, Bluetooth, IoT device testing - partial)
- **Phase 9:** Exploit Framework ✅ (Payload generation, fuzzing, cloud/AD attacks, purple team)

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

**Phases 1-7 Complete** ✅ | **Phase 8 Partial** ⚠️ | **Phase 9 Complete** ✅ | **496 Tests Passing** | **75+ CLI Commands** | Production Ready 🚀

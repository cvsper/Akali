# Akali - The Security Sentinel 🥷

Comprehensive security agent for the family's projects and infrastructure.

**Current Phase:** Phase 1 (Foundation) ✅

## Quick Start

```bash
# Install security tools
~/akali/scripts/install_tools.sh

# Run a scan
akali scan ~/my-project

# List findings
akali findings list --open

# Show Akali status
akali status
```

## Features (Phase 1)

✅ **Secret Scanning** - Detect hardcoded API keys, passwords, tokens
✅ **Dependency Auditing** - Find vulnerable npm and Python packages
✅ **Static Analysis (SAST)** - Security linting for Python and JavaScript
✅ **Pre-commit Hooks** - Block commits with security issues
✅ **CLI Interface** - Developer-friendly command-line tool
✅ **ZimMemory Integration** - Alert agents about findings
✅ **Findings Database** - Track and manage security issues

## Installation

### 1. Install Security Tools

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

## Architecture

```
~/akali/
├── core/
│   ├── SOUL.md              # Identity document
│   ├── CLAUDE.md            # Operating protocols
│   ├── SKILLS.md            # Toolkit documentation
│   ├── cli.py               # CLI logic
│   └── zim_integration.py   # ZimMemory client
├── defensive/
│   ├── scanners/            # Security scanners
│   └── patrols/             # Git hooks
├── data/
│   ├── findings_db.py       # Findings database
│   └── findings.json        # Findings storage
├── scripts/
│   ├── install_tools.sh     # Tool installer
│   └── install_hooks.sh     # Hook installer
└── akali                    # CLI entry point
```

## Protected Projects

- **Umuve** (platform + backend + iOS)
- **Sandhill Portal**
- **Career Focus**
- **ZimMemory**
- **Hub Task Manager**
- **Family Infrastructure** (Mac Mini)

## Future Phases

- **Phase 2:** Offensive ops (pentesting, exploits)
- **Phase 3:** Autonomous operations (cron, daemons)
- **Phase 4:** Intelligence & metrics (CVE, scorecard)
- **Phase 5:** Incident response (war room, forensics)
- **Phase 6:** Education & advanced (phishing, vault, DLP)

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

**Phase 1 Complete** ✅ | Next: Phase 2 (Offensive Ops)

# Akali Phase 2: Offensive Ops - Handoff

**Date:** 2026-02-19
**Status:** Ready to start in fresh session
**Context:** Phase 1 complete, Phase 2 planning ready

---

## Phase 1 Summary ✅

**Completed:** All 10 tasks (100%)
- Workspace structure
- Identity documents
- Security tools installed (gitleaks, trufflehog, safety, bandit, eslint, semgrep)
- Core scanner library (secrets, dependencies, SAST)
- Findings database (JSON-based)
- CLI interface (`akali` command)
- Pre-commit hooks
- ZimMemory integration (online ✅)
- Test suite (all passing ✅)
- README and documentation

**Git:** 12 commits, tagged as `v1.0-phase1`

---

## Phase 2: Offensive Ops - Scope

### Goal
Build offensive security capabilities to proactively hunt vulnerabilities before attackers do.

### Philosophy
- **Authorized only** - Pentesting with permission
- **Educational** - Teach while hunting
- **Responsible** - No destructive testing on production
- **Documented** - Clear reports with remediation steps

### Phase 2 Features

#### 1. Web Vulnerability Scanning
- **SQL Injection** detection
- **XSS** (Cross-Site Scripting) detection
- **CSRF** vulnerability checks
- **Path traversal** detection
- **SSRF** detection
- **Command injection** detection

#### 2. Network Scanning
- **Port scanning** (nmap integration)
- **Service enumeration**
- **SSL/TLS testing**
- **Open service detection**

#### 3. Web Application Testing
- **Directory bruteforcing**
- **Authentication testing**
- **Session management testing**
- **API endpoint discovery**

#### 4. Exploit Framework Integration
- **Metasploit** integration (for authorized testing)
- **Exploit database** lookup
- **CVE mapping**

---

## Architecture Plan

### New Directory Structure
```
~/akali/offensive/
├── scanners/
│   ├── web_vuln_scanner.py      # Web vulnerability scanner
│   ├── network_scanner.py       # Network/port scanner
│   ├── api_scanner.py           # API testing
│   └── exploit_scanner.py       # Exploit/CVE lookup
├── payloads/
│   ├── sql_injection.txt        # SQL injection payloads
│   ├── xss.txt                  # XSS payloads
│   └── command_injection.txt    # Command injection payloads
└── reports/
    └── scan_reports/            # Scan output reports
```

### New CLI Commands
```bash
akali attack <target> --web           # Web vulnerability scan
akali attack <target> --network       # Network scan
akali attack <target> --api           # API endpoint testing
akali attack <target> --full          # Full offensive scan

akali exploit <cve-id>                # Lookup exploit for CVE
akali report <scan-id>                # Generate scan report
```

---

## Tools Required

### Web Testing
- **sqlmap** - SQL injection detection
- **nikto** - Web server scanner
- **dirb** or **gobuster** - Directory bruteforcing
- **burpsuite** (community edition) - Web proxy/scanner

### Network Testing
- **nmap** - Port scanner
- **masscan** - Fast port scanner
- **testssl.sh** - SSL/TLS testing

### API Testing
- **ffuf** - Fuzzing tool
- **arjun** - HTTP parameter discovery

### Optional (Advanced)
- **metasploit-framework** - Exploitation framework
- **exploitdb** - Exploit database

---

## Implementation Tasks

### Task 1: Install Offensive Tools
Create `scripts/install_offensive_tools.sh`:
- Install nmap, nikto, sqlmap, dirb/gobuster
- Install testssl.sh
- Optional: metasploit-framework (large, slow)

### Task 2: Build Web Vulnerability Scanner
Create `offensive/scanners/web_vuln_scanner.py`:
- SQL injection detection (sqlmap wrapper)
- XSS detection (custom + nikto)
- CSRF token validation
- Path traversal checks
- Command injection detection

### Task 3: Build Network Scanner
Create `offensive/scanners/network_scanner.py`:
- Port scanning (nmap wrapper)
- Service enumeration
- SSL/TLS testing (testssl.sh wrapper)
- Banner grabbing

### Task 4: Build API Scanner
Create `offensive/scanners/api_scanner.py`:
- Endpoint discovery
- Authentication bypass testing
- Rate limiting detection
- Parameter fuzzing

### Task 5: Build Exploit Scanner
Create `offensive/scanners/exploit_scanner.py`:
- CVE lookup (NIST NVD API)
- Exploit database integration
- Vulnerability-to-exploit mapping

### Task 6: Add Attack CLI Commands
Update `core/cli.py`:
- Add `attack` command group
- Add `exploit` command
- Add `report` command for scan reports

### Task 7: Create Payload Library
Create payload files in `offensive/payloads/`:
- SQL injection payloads
- XSS payloads
- Command injection payloads
- Path traversal payloads

### Task 8: Add Findings Report Generator
Create `offensive/reports/report_generator.py`:
- HTML report generation
- PDF export (optional)
- Markdown summary

### Task 9: Add Authorization Checks
Create `offensive/auth_manager.py`:
- Require explicit authorization before offensive scans
- Scope limitation (whitelist targets)
- Audit logging

### Task 10: Update Documentation
- Update README.md with Phase 2 features
- Add offensive scanning guide
- Document authorization requirements
- Add example reports

---

## Security & Ethics Guidelines

### Authorization Requirements
- **Explicit permission** required before scanning any target
- **Written authorization** for production systems
- **Whitelist-based** targeting (never scan arbitrary hosts)

### Safety Measures
- **Rate limiting** on all offensive scans
- **No destructive payloads** (no data modification/deletion)
- **Production safeguards** (additional checks for prod environments)
- **Audit logging** of all offensive operations

### Responsible Disclosure
- **Private reporting** to project owners first
- **Grace period** for fixes before broader disclosure
- **Documented findings** with clear remediation steps

---

## Testing Strategy

### Test Targets
- **Localhost test apps** (intentionally vulnerable)
- **DVWA** (Damn Vulnerable Web Application)
- **WebGoat** (OWASP learning platform)
- **Family projects** (with explicit permission)

### Validation
- Test against known vulnerable apps
- Verify true positives vs false positives
- Ensure no false negatives on critical issues

---

## Phase 2 Success Criteria

When all 10 tasks done:
- ✅ Offensive tools installed
- ✅ Web vulnerability scanner functional
- ✅ Network scanner functional
- ✅ API scanner functional
- ✅ Exploit lookup working
- ✅ CLI attack commands working
- ✅ Payload library complete
- ✅ Report generation working
- ✅ Authorization checks enforced
- ✅ Documentation complete
- ✅ Tests passing (offensive scanners)
- ✅ Git tagged as `v2.0-phase2`

---

## Quick Start for Fresh Session

**In new Claude Code session, run:**

```bash
cd ~/akali
cat PHASE2-HANDOFF.md
```

Then say:

> "Start Akali Phase 2 implementation. Handoff at ~/akali/PHASE2-HANDOFF.md. Phase 1 complete (v1.0-phase1). Ready to build offensive security capabilities."

---

## Key Files Reference

**Phase 1 Complete:**
- Workspace: `/Users/sevs/akali/`
- CLI: `/Users/sevs/akali/akali`
- Scanners: `/Users/sevs/akali/defensive/scanners/`
- Database: `/Users/sevs/akali/data/findings_db.py`
- Tests: `/Users/sevs/akali/tests/`

**Phase 2 To Create:**
- Offensive scanners: `/Users/sevs/akali/offensive/scanners/`
- Payloads: `/Users/sevs/akali/offensive/payloads/`
- Reports: `/Users/sevs/akali/offensive/reports/`
- Auth manager: `/Users/sevs/akali/offensive/auth_manager.py`

---

## Notes

- Phase 1 took ~1 session to implement (all 10 tasks)
- Phase 2 is larger, estimate 1-2 sessions
- ZimMemory is online at 10.0.0.209:5001
- All security tools already installed from Phase 1
- Test suite framework already in place

---

**Phase 1 Complete** ✅ | **Phase 2 Ready** 🚀

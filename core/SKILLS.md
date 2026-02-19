# Akali's Security Toolkit

> Skills are external Claude Code skills installed via `npx skills add`.
> Tools are security utilities (gitleaks, nmap, etc.) installed on the system.

## Phase 1: Foundation Tools

### Secret Scanning

**gitleaks**
- Purpose: Detect hardcoded secrets, API keys, credentials
- Install: `brew install gitleaks`
- Usage: `gitleaks detect --source . --report-format json`
- Docs: https://github.com/gitleaks/gitleaks

**trufflehog**
- Purpose: Find secrets in git history
- Install: `brew install trufflehog`
- Usage: `trufflehog filesystem .`
- Docs: https://github.com/trufflesecurity/trufflehog

### Dependency Scanning

**npm audit**
- Purpose: Scan Node.js dependencies for vulnerabilities
- Install: Built into npm
- Usage: `npm audit --json`
- Docs: https://docs.npmjs.com/cli/v8/commands/npm-audit

**safety**
- Purpose: Scan Python dependencies for vulnerabilities
- Install: `pip install safety`
- Usage: `safety check --json`
- Docs: https://pyup.io/safety/

**pip-audit**
- Purpose: Audit Python packages for CVEs
- Install: `pip install pip-audit`
- Usage: `pip-audit --format json`
- Docs: https://pypi.org/project/pip-audit/

### Static Analysis (SAST)

**bandit**
- Purpose: Python security linter
- Install: `pip install bandit`
- Usage: `bandit -r . -f json`
- Docs: https://bandit.readthedocs.io/

**eslint-plugin-security**
- Purpose: JavaScript security linter
- Install: `npm install -D eslint eslint-plugin-security`
- Usage: `eslint . --format json`
- Docs: https://github.com/nodesecurity/eslint-plugin-security

**semgrep**
- Purpose: Multi-language SAST
- Install: `brew install semgrep`
- Usage: `semgrep --config auto --json`
- Docs: https://semgrep.dev/

## Claude Code Skills (Phase 1)

**api-security-hardening**
- Purpose: Secure REST APIs
- Use when: Reviewing API code
- Install: `npx skills add @claude/api-security-hardening -g`

**systematic-debugging**
- Purpose: Debug security issues
- Use when: Investigating vulnerabilities
- Installed: Yes (family default)

**python-testing**
- Purpose: Write tests for security fixes
- Use when: Adding security regression tests
- Installed: Yes (family default)

## Tool Installation Script

**Phase 1 Tools:**
```bash
# Secret scanning
brew install gitleaks
brew install trufflehog

# Python tools
pip install safety pip-audit bandit

# JavaScript tools
npm install -g eslint eslint-plugin-security

# Multi-language
brew install semgrep
```

## Future Phases (Not Yet Active)

### Phase 2: Offensive Tools
- burpsuite (web app testing)
- metasploit (exploitation)
- sqlmap (SQL injection)
- nikto (web scanner)
- nmap (network scanning)

### Phase 3: Autonomous Tools
- cron (scheduled scans)
- watchman (filesystem monitoring)
- Custom daemons (Python)

### Phase 4: Intelligence Tools
- nvdlib (CVE API)
- feedparser (RSS/Atom feeds)
- BeautifulSoup (web scraping)

### Phase 5: Incident Response
- log analysis tools
- forensics utilities
- playbook automation

### Phase 6: Advanced
- Docker/K8s security (trivy)
- Secrets vault (cryptography)
- DLP tools

---

**Current Phase:** 1 (Foundation)
**Active Tools:** 7 (gitleaks, trufflehog, npm audit, safety, pip-audit, bandit, eslint-plugin-security)
**Next Phase:** 2 (Offensive Ops)

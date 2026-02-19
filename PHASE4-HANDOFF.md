# Akali Phase 4: Intelligence & Metrics - Handoff

**Date:** 2026-02-19
**Status:** Ready to start
**Context:** Phases 1, 2, and 3 complete, Phase 4 planning ready

---

## Phase 3 Summary ✅

**Completed:** All 10 tasks (100%)
- Cron job scheduler with launchd integration
- Job definitions (daily defensive, weekly offensive, CVE checks, reports)
- Watch daemon (real-time git commit monitoring)
- Health daemon (tool checks, self-healing, heartbeat)
- Alert manager (routing, deduplication, escalation)
- ZimMemory integration (agent-routed alerts)
- Triage engine (risk scoring, false positive detection, auto-remediation)
- CLI commands (schedule, daemon, alert, triage groups)
- Persistence layer (launchd plists, log rotation)
- Complete documentation

**Git:** Tagged as `v3.0-phase3`

---

## Phase 4: Intelligence & Metrics - Scope

### Goal
Build intelligence gathering and metrics tracking to proactively monitor threats, track security posture, and provide visibility into security health through a comprehensive dashboard.

### Philosophy
- **Proactive, not reactive** - Know about CVEs before they're exploited
- **Data-driven decisions** - Metrics guide security priorities
- **Continuous visibility** - Always know the security score
- **Actionable intelligence** - Intel leads to specific improvements

### Phase 4 Features

#### 1. CVE Monitoring
- **Hourly CVE checks** - Monitor NVD, GitHub Security Advisories
- **Dependency mapping** - Track which projects use which packages
- **CVE impact analysis** - Calculate blast radius of new CVEs
- **Auto-alerts** - Notify relevant agents for Critical/High CVEs
- **Historical tracking** - CVE timeline and response history

#### 2. Threat Intelligence Hub
- **Exploit feeds** - Exploit-DB, GitHub PoC repositories
- **Security blogs** - RSS feeds from security researchers
- **Breach databases** - Check for family credentials in breaches
- **Vendor advisories** - Track security updates from our stack
- **Intelligence correlation** - Link CVEs to active exploits

#### 3. Supply Chain Auditor
- **Dependency inventory** - Complete package manifest across all projects
- **Typosquatting detection** - Check for malicious package names
- **Maintainer health** - Track abandoned or compromised packages
- **License compliance** - Ensure license compatibility
- **Update recommendations** - Prioritized update suggestions

#### 4. Security Scorecard
- **Family security score (0-100)** - Composite metric of security health
- **Component scores** - Breakdown by category (auth, deps, secrets, etc.)
- **Trend tracking** - Score history and momentum
- **Benchmark comparison** - Industry standards
- **Goal setting** - Target scores and milestones

#### 5. Security Observatory
- **MTTD tracking** - Mean Time To Detect (vulnerability discovery latency)
- **MTTR tracking** - Mean Time To Remediate (fix latency)
- **Finding lifecycle** - Track findings from open to resolved
- **Attack surface metrics** - Endpoints, services, dependencies count
- **Scan coverage** - % of projects scanned, last scan times

#### 6. Web Dashboard
- **Real-time metrics** - Live security score and findings
- **Visualizations** - Charts for trends, distributions, timelines
- **Finding explorer** - Browse and filter all findings
- **Intel feed** - Recent CVEs, threats, and advisories
- **Alert timeline** - Recent alerts and agent responses

---

## Architecture Plan

### New Directory Structure
```
~/akali/intelligence/
├── cve_monitor/
│   ├── cve_tracker.py          # NVD/GitHub API integration
│   ├── dependency_mapper.py    # Map packages to projects
│   ├── impact_analyzer.py      # Calculate CVE blast radius
│   └── cve_cache.json          # Cached CVE data
├── threat_hub/
│   ├── exploit_tracker.py      # Exploit-DB, GitHub PoCs
│   ├── feed_aggregator.py      # RSS/blog aggregation
│   ├── breach_monitor.py       # Breach database checks
│   └── intel_correlator.py     # Link CVEs to exploits
├── supply_chain/
│   ├── inventory_builder.py    # Build dependency manifest
│   ├── typosquat_detector.py   # Detect malicious packages
│   ├── maintainer_checker.py   # Package health checks
│   └── license_auditor.py      # License compliance
└── feeds/
    ├── feed_config.yaml        # RSS/API feed definitions
    └── feed_cache/             # Cached feed data

~/akali/metrics/
├── scorecard/
│   ├── score_calculator.py     # Calculate security score
│   ├── component_scores.py     # Individual category scores
│   ├── score_history.json      # Historical scores
│   └── benchmarks.yaml         # Industry benchmarks
├── observatory/
│   ├── mttd_tracker.py         # Mean Time To Detect
│   ├── mttr_tracker.py         # Mean Time To Remediate
│   ├── lifecycle_tracker.py    # Finding state transitions
│   └── coverage_tracker.py     # Scan coverage metrics
├── findings.db                 # SQLite findings database
└── dashboard/
    ├── server.py               # Flask dashboard server
    ├── static/
    │   ├── css/
    │   │   └── dashboard.css   # Dashboard styling
    │   └── js/
    │       └── dashboard.js    # Dashboard interactivity
    └── templates/
        ├── index.html          # Main dashboard
        ├── findings.html       # Finding explorer
        ├── intel.html          # Intelligence feed
        └── metrics.html        # Detailed metrics
```

### New CLI Commands
```bash
# Intelligence Commands
akali intel cve-check                          # Check for new CVEs
akali intel cve-lookup <CVE-ID>                # Lookup CVE details
akali intel threat-feed                        # Show threat intelligence
akali intel supply-chain                       # Show supply chain status
akali intel breach-check                       # Check for breached credentials

# Metrics Commands
akali metrics                                  # Show all metrics
akali metrics score                            # Show security score
akali metrics mttd                             # Show Mean Time To Detect
akali metrics mttr                             # Show Mean Time To Remediate
akali metrics coverage                         # Show scan coverage
akali metrics history [--days=30]              # Show historical metrics

# Dashboard Commands
akali dashboard start                          # Start dashboard server
akali dashboard stop                           # Stop dashboard server
akali dashboard status                         # Check dashboard status
akali dashboard export                         # Export dashboard data
```

---

## Implementation Tasks

### Task 1: Build CVE Monitoring System
Create `intelligence/cve_monitor/cve_tracker.py`:
- NVD API integration (https://nvd.nist.gov/developers/vulnerabilities)
- GitHub Security Advisories API integration
- CVE filtering by affected packages
- Impact analysis (which projects affected)
- CVE cache to avoid API rate limits
- Auto-alert on Critical/High CVEs

### Task 2: Build Dependency Mapper
Create `intelligence/cve_monitor/dependency_mapper.py`:
- Scan all family projects for dependencies:
  - Python: `requirements.txt`, `Pipfile`, `pyproject.toml`
  - Node.js: `package.json`, `package-lock.json`
  - iOS: `Podfile`, `Podfile.lock`, Swift packages
- Build dependency inventory (package → projects mapping)
- Version tracking
- Update recommendations

### Task 3: Build Threat Intelligence Hub
Create `intelligence/threat_hub/`:
- Exploit tracker (`exploit_tracker.py`):
  - Exploit-DB API/scraper
  - GitHub PoC search (filter for real exploits vs proofs)
  - Link exploits to CVEs
- Feed aggregator (`feed_aggregator.py`):
  - RSS feeds (security blogs, vendor advisories)
  - Parse and extract relevant intel
  - Deduplication
- Breach monitor (`breach_monitor.py`):
  - HaveIBeenPwned API integration
  - Check family emails/domains
  - Alert on new breaches

### Task 4: Build Supply Chain Auditor
Create `intelligence/supply_chain/`:
- Inventory builder (`inventory_builder.py`):
  - Complete package manifest across all projects
  - Dependency tree visualization
- Typosquat detector (`typosquat_detector.py`):
  - Check for similar package names
  - Flag suspicious packages
- Maintainer checker (`maintainer_checker.py`):
  - Check last update date
  - Identify abandoned packages
  - Check for compromised maintainer accounts
- License auditor (`license_auditor.py`):
  - Extract license info
  - Check license compatibility
  - Flag risky licenses (e.g., GPL in proprietary code)

### Task 5: Build Security Scorecard
Create `metrics/scorecard/score_calculator.py`:
- Component scores (each 0-100):
  - Dependencies up-to-date (20% weight)
  - No hardcoded secrets (15% weight)
  - Auth properly implemented (15% weight)
  - HTTPS enforced (10% weight)
  - Rate limiting active (10% weight)
  - Input validation (10% weight)
  - Security headers (10% weight)
  - Backups encrypted (10% weight)
- Overall score: weighted average
- Trend analysis (daily score history)
- Goal tracking (target score, ETA)

### Task 6: Build Security Observatory
Create `metrics/observatory/`:
- MTTD tracker (`mttd_tracker.py`):
  - Track time from vulnerability existence to detection
  - Calculate mean, median, p95
  - Trend over time
- MTTR tracker (`mttr_tracker.py`):
  - Track time from detection to remediation
  - Calculate mean, median, p95
  - Breakdown by severity
- Lifecycle tracker (`lifecycle_tracker.py`):
  - Finding state machine (open → triaged → fixed → verified → closed)
  - State transition history
  - Time spent in each state
- Coverage tracker (`coverage_tracker.py`):
  - % of projects scanned in last 24h
  - Last scan timestamp per project
  - Scan frequency by project

### Task 7: Build Findings Database
Create `metrics/findings.db` (SQLite):
- Schema:
  - `findings` table (id, type, severity, status, created_at, detected_at, fixed_at, ...)
  - `projects` table (id, name, path, last_scan, ...)
  - `dependencies` table (id, project_id, package, version, ...)
  - `cves` table (id, cve_id, cvss_score, published_at, ...)
  - `metrics_history` table (id, date, score, mttd, mttr, ...)
- Migrate existing JSON findings to SQLite
- Provide backward compatibility with JSON export

### Task 8: Build Web Dashboard
Create `metrics/dashboard/`:
- Flask server (`server.py`):
  - Routes: `/`, `/findings`, `/intel`, `/metrics`
  - REST API endpoints for data
  - WebSocket for real-time updates (optional)
- Main dashboard (`templates/index.html`):
  - Security score gauge
  - Open findings by severity (bar chart)
  - MTTD/MTTR trend (line chart)
  - Recent scans timeline
  - Attack surface summary
  - Recent alerts feed
- Finding explorer (`templates/findings.html`):
  - Sortable/filterable findings table
  - Severity filters
  - Status filters
  - Search by project, type, description
  - Click to see full details
- Intel feed (`templates/intel.html`):
  - Recent CVEs affecting family
  - Recent exploits
  - Security advisories
  - Breach notifications
- Metrics page (`templates/metrics.html`):
  - Detailed metrics breakdown
  - Historical charts (30d, 90d, 1y)
  - Component score breakdown
  - Coverage heatmap

### Task 9: Add CLI Commands
Update `core/cli.py`:
- Add `intel` command group
- Add `metrics` command group
- Add `dashboard` command group
- Format output (tables, colors, charts in terminal)

### Task 10: Integrate with Autonomous System
Update `autonomous/scheduler/job_definitions.py`:
- Add hourly CVE check job
- Add daily intel update job
- Add daily scorecard calculation job
- Add weekly supply chain audit job
Update alert manager to route CVE alerts
Update ZimMemory integration to send metrics summaries

---

## Data Sources

### CVE Sources
1. **NVD (National Vulnerability Database)** - https://nvd.nist.gov/developers/vulnerabilities
   - Primary CVE source
   - CVSS scores, descriptions, references
   - API rate limit: 5 requests / 30 seconds (no key), 50 requests / 30 seconds (with key)

2. **GitHub Security Advisories** - https://docs.github.com/en/graphql/reference/objects#securityadvisory
   - Language-specific CVEs
   - Ecosystem info (npm, pip, etc.)
   - GitHub GraphQL API

3. **OSV (Open Source Vulnerabilities)** - https://osv.dev/
   - Aggregates multiple sources
   - Good for Python, npm, Go, Rust
   - REST API

### Exploit Sources
1. **Exploit-DB** - https://www.exploit-db.com/
   - Exploit archive
   - Can scrape or use Google CSE API

2. **GitHub Code Search** - https://docs.github.com/en/rest/search/search
   - Search for "CVE-XXXX-XXXX exploit" or "poc"
   - Filter for repos with code (not just docs)

### Threat Intelligence
1. **HaveIBeenPwned** - https://haveibeenpwned.com/API/v3
   - Breach notifications
   - Compromised password checks
   - API requires API key (free)

2. **RSS Feeds** (open, no auth):
   - US-CERT: https://www.cisa.gov/cybersecurity-advisories/all.xml
   - GitHub Security Blog: https://github.blog/category/security/feed/
   - Krebs on Security: https://krebsonsecurity.com/feed/
   - Schneier on Security: https://www.schneier.com/feed/

### Supply Chain
1. **Libraries.io** - https://libraries.io/api
   - Package metadata
   - Dependency info
   - Maintainer info

2. **npm/PyPI APIs** - Built-in package registry APIs
   - npm: https://registry.npmjs.org/
   - PyPI: https://pypi.org/pypi/<package>/json

---

## Scorecard Formula

```python
def calculate_family_score(projects):
    """
    Calculate overall family security score (0-100)
    """
    component_scores = {
        'dependencies': calculate_dependency_score(projects),      # 20% weight
        'secrets': calculate_secrets_score(projects),              # 15% weight
        'auth': calculate_auth_score(projects),                    # 15% weight
        'https': calculate_https_score(projects),                  # 10% weight
        'rate_limiting': calculate_rate_limiting_score(projects),  # 10% weight
        'input_validation': calculate_input_val_score(projects),   # 10% weight
        'security_headers': calculate_headers_score(projects),     # 10% weight
        'backups': calculate_backup_score(projects),               # 10% weight
    }

    weights = {
        'dependencies': 0.20,
        'secrets': 0.15,
        'auth': 0.15,
        'https': 0.10,
        'rate_limiting': 0.10,
        'input_validation': 0.10,
        'security_headers': 0.10,
        'backups': 0.10,
    }

    overall = sum(score * weights[category]
                  for category, score in component_scores.items())

    # Penalty for critical/high open findings
    penalty = min(20, len([f for f in findings if f.severity in ['critical', 'high']]) * 2)

    return max(0, overall - penalty)
```

### Component Score Examples

**Dependencies Score:**
```python
def calculate_dependency_score(projects):
    total_deps = count_all_dependencies(projects)
    vulnerable_deps = count_vulnerable_dependencies(projects)
    outdated_deps = count_outdated_dependencies(projects)

    # Start at 100
    score = 100

    # -10 points per vulnerable dependency (capped at -50)
    score -= min(50, vulnerable_deps * 10)

    # -1 point per outdated dependency (capped at -30)
    score -= min(30, outdated_deps * 1)

    return max(0, score)
```

**Secrets Score:**
```python
def calculate_secrets_score(projects):
    # Scan all projects for secrets
    findings = scan_for_secrets(projects)

    if len(findings) == 0:
        return 100  # Perfect score
    elif len(findings) == 1:
        return 75   # One secret found
    elif len(findings) <= 3:
        return 50   # Few secrets
    else:
        return 0    # Many secrets, critical issue
```

---

## Dashboard Mockup

```
╔════════════════════════════════════════════════════════════════╗
║                     AKALI SECURITY DASHBOARD                   ║
╠════════════════════════════════════════════════════════════════╣
║                                                                ║
║  Security Score: 87/100 ↑ (+3 this week)                     ║
║  ██████████████████████████████████████░░░░░░░                ║
║                                                                ║
║  Open Findings: 12                    Last Scan: 2 hours ago  ║
║  ├─ Critical: 3                       Coverage: 100%          ║
║  ├─ High: 5                           MTTD: 4.2 hours         ║
║  └─ Medium: 4                         MTTR: 18.5 hours        ║
║                                                                ║
╠════════════════════════════════════════════════════════════════╣
║  RECENT ACTIVITY                                               ║
║  ────────────────────────────────────────────────────────────  ║
║  🔴 [14:30] CVE-2024-1234 affects Flask 2.x - CRITICAL        ║
║  🟡 [12:15] Outdated dependency: requests 2.28.0 → 2.31.0     ║
║  🟢 [10:45] Fixed SQL injection in booking.py                 ║
║  🔵 [09:20] Daily defensive scan complete - 0 new issues      ║
║                                                                ║
╠════════════════════════════════════════════════════════════════╣
║  ATTACK SURFACE                                                ║
║  ────────────────────────────────────────────────────────────  ║
║  Endpoints: 47      Services: 18      Dependencies: 342       ║
║  Projects: 6        APIs: 3           External Integrations: 8║
║                                                                ║
╠════════════════════════════════════════════════════════════════╣
║  THREAT INTELLIGENCE                                           ║
║  ────────────────────────────────────────────────────────────  ║
║  • New CVE affecting Python 3.11: CVE-2024-5678 (CVSS 7.5)   ║
║  • GitHub PoC published for CVE-2023-9999                     ║
║  • US-CERT advisory: Critical Nginx vulnerability             ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
```

---

## Tools & Dependencies

### Python Libraries (New)
```bash
pip3 install nvdlib requests feedparser beautifulsoup4 flask pandas matplotlib
```

### APIs Requiring Keys (Optional)
- **NVD API** - Free key for higher rate limits (50 req/30s)
- **HaveIBeenPwned** - Free API key for breach checks
- **GitHub API** - Use existing token for higher rate limits

### Configuration
Create `intelligence/feeds/feed_config.yaml`:
```yaml
cve_sources:
  - name: NVD
    url: https://services.nvd.nist.gov/rest/json/cves/2.0
    enabled: true
  - name: GitHub
    url: https://api.github.com/graphql
    enabled: true
  - name: OSV
    url: https://osv.dev/v1/query
    enabled: true

threat_feeds:
  - name: US-CERT
    url: https://www.cisa.gov/cybersecurity-advisories/all.xml
    type: rss
  - name: GitHub Security
    url: https://github.blog/category/security/feed/
    type: rss
  - name: Krebs
    url: https://krebsonsecurity.com/feed/
    type: rss

breach_monitoring:
  - name: HaveIBeenPwned
    url: https://haveibeenpwned.com/api/v3
    enabled: true
    check_emails:
      - sevs@example.com
      # Add other family emails
```

---

## Phase 4 Success Criteria

When all 10 tasks done:
- ✅ CVE monitoring operational (hourly checks)
- ✅ Dependency mapper tracks all projects
- ✅ Threat intelligence hub aggregates exploits/feeds
- ✅ Supply chain auditor checks packages
- ✅ Security scorecard calculates family score (0-100)
- ✅ Observatory tracks MTTD/MTTR/coverage
- ✅ Findings database migrated to SQLite
- ✅ Web dashboard operational at localhost:8765
- ✅ CLI commands for intel/metrics/dashboard
- ✅ Integration with autonomous scheduler
- ✅ Documentation complete
- ✅ Tests passing
- ✅ Git tagged as `v4.0-phase4`

---

## Quick Start for Fresh Session

**In new Claude Code session, run:**

```bash
cd ~/akali
cat PHASE4-HANDOFF.md
```

Then say:

> "Start Akali Phase 4 implementation. Handoff at ~/akali/PHASE4-HANDOFF.md. Phases 1-3 complete. Ready to build intelligence and metrics system."

---

## Key Files Reference

**Phases 1-3 Complete:**
- Workspace: `/Users/sevs/akali/`
- CLI: `/Users/sevs/akali/akali`
- Defensive scanners: `/Users/sevs/akali/defensive/scanners/`
- Offensive scanners: `/Users/sevs/akali/offensive/scanners/`
- Autonomous: `/Users/sevs/akali/autonomous/`
- Findings DB: `/Users/sevs/akali/data/findings_db.py`

**Phase 4 To Create:**
- Intelligence: `/Users/sevs/akali/intelligence/`
- Metrics: `/Users/sevs/akali/metrics/`
- Dashboard: `/Users/sevs/akali/metrics/dashboard/`
- Findings DB: `/Users/sevs/akali/metrics/findings.db` (SQLite)

---

## Notes

- Phase 4 is larger than previous phases, estimate 1.5-2 sessions
- Dashboard can start simple (static HTML) and evolve
- CVE monitoring is highest priority (proactive security)
- Scorecard provides motivation and visibility
- NVD API has rate limits, need caching strategy
- ZimMemory is online at 10.0.0.209:5001
- Mac Mini can serve dashboard 24/7

---

**Phase 1 Complete** ✅ | **Phase 2 Complete** ✅ | **Phase 3 Complete** ✅ | **Phase 4 Ready** 🚀

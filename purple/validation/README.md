# Purple Team Validation Module

Automated defense validation and testing for Akali Phase 9C.

## Overview

The Purple Team Validation module provides automated attack simulation and defense measurement capabilities, enabling organizations to:

- Execute controlled attack simulations
- Monitor detection systems for alerts
- Measure Mean Time To Detect (MTTD) and Mean Time To Respond (MTTR)
- Generate comprehensive validation reports
- Run multi-step attack chains
- Calculate security metrics (detection rate, false positive rate, coverage)

## Architecture

```
purple/validation/
├── defense_tester.py       # Main orchestrator
├── attack_simulator.py     # Attack execution
├── detection_monitor.py    # Detection monitoring
├── metrics_collector.py    # Metrics calculation
└── report_generator.py     # Report generation
```

## Supported Attack Types

| Attack Type | Description | Expected Detections |
|-------------|-------------|---------------------|
| `sqli` | SQL Injection | WAF, IDS, Application Logs |
| `xss` | Cross-Site Scripting | WAF, CSP Violation |
| `port_scan` | Network Port Scan | IDS, Firewall |
| `brute_force` | SSH Brute Force | Fail2ban, IDS, Auth Logs |
| `kerberoast` | Kerberoasting Attack | EDR, Domain Controller Logs |
| `privilege_escalation` | Privilege Escalation | EDR, System Logs |

## CLI Commands

### Test Attack

Run a single attack simulation:

```bash
akali purple test-attack --type sqli --target http://localhost:8080

akali purple test-attack --type port_scan --target 10.0.0.5

akali purple test-attack --type brute_force --target 10.0.0.5:22 --duration 300
```

### Test Attack Chain

Execute multi-step attack chain:

```bash
akali purple test-chain --chain-file attack_chain.json
```

Example `attack_chain.json`:

```json
{
  "chain_id": "lateral_movement",
  "steps": [
    {
      "step": 1,
      "attack": "port_scan",
      "target": "10.0.0.5",
      "wait_for_detection": false
    },
    {
      "step": 2,
      "attack": "sqli",
      "target": "http://10.0.0.5/login",
      "wait_for_detection": true
    },
    {
      "step": 3,
      "attack": "privilege_escalation",
      "target": "10.0.0.5",
      "wait_for_detection": true
    }
  ]
}
```

### Measure MTTD

Calculate Mean Time To Detect from log files:

```bash
akali purple measure-mttd --attack-log attack.log --detection-log alerts.log
```

Attack log format:
```
2026-02-20 10:00:00 - Attack started
```

Detection log format:
```
2026-02-20 10:00:05 - Alert: SQL injection detected
```

### Measure MTTR

Calculate Mean Time To Respond from incident log:

```bash
akali purple measure-mttr --incident-log incident.log
```

Incident log format:
```
2026-02-20 10:00:05 - Incident detected
2026-02-20 10:02:30 - Incident contained
2026-02-20 10:05:00 - Incident resolved
```

### Monitor Detection

Monitor for detection events in real-time:

```bash
akali purple monitor --target http://localhost:8080 --duration 600

akali purple monitor --target 10.0.0.5 --attack-type port_scan --duration 300
```

### Generate Report

Generate purple team validation report:

```bash
# PDF report
akali purple report --simulation-id sim-001 --output report.pdf

# HTML report
akali purple report --simulation-id sim-001 --output report.html --format html

# JSON report
akali purple report --simulation-id sim-001 --output report.json --format json
```

## Python API

### DefenseTester

Main orchestrator for purple team validation:

```python
from purple.validation.defense_tester import DefenseTester

tester = DefenseTester()

# Run attack simulation
result = tester.run_attack_simulation('sqli', 'http://localhost:8080', duration=300)
print(f"MTTD: {result['mttd']}s")
print(f"Detections: {len(result['detections'])}")

# Run attack chain
chain = [
    {'step': 1, 'attack': 'port_scan', 'target': '10.0.0.5'},
    {'step': 2, 'attack': 'sqli', 'target': 'http://10.0.0.5/login'}
]
result = tester.run_attack_chain(chain)

# Generate report
tester.generate_report('sim-001', 'report.pdf', format='pdf')
```

### AttackSimulator

Execute individual attacks:

```python
from purple.validation.attack_simulator import AttackSimulator

simulator = AttackSimulator()

# List available attacks
attacks = simulator.list_available_attacks()

# Execute attack
result = simulator.execute_attack('sqli', 'http://localhost:8080')
print(f"Success: {result['success']}")

# Execute with options
options = {'timeout': 30, 'threads': 10}
result = simulator.execute_attack('port_scan', '10.0.0.5', options=options)

# Concurrent attacks
attacks = [
    ('port_scan', '10.0.0.5'),
    ('sqli', 'http://localhost:8080')
]
results = simulator.execute_concurrent_attacks(attacks)
```

### DetectionMonitor

Monitor detection sources:

```python
from purple.validation.detection_monitor import DetectionMonitor

monitor = DetectionMonitor()

# Monitor log file
detections = monitor.monitor_log_file('/var/log/syslog', 'brute_force', timeout=60)

# Monitor SIEM
detections = monitor.monitor_siem('splunk', 'sqli', timeout=300)

# Monitor EDR
detections = monitor.monitor_edr('privilege_escalation', timeout=600)

# Start continuous monitoring
config = {
    'source': '/var/log/syslog',
    'attack_type': 'brute_force',
    'callback': lambda d: print(f"Detection: {d}")
}
monitor_id = monitor.start_continuous_monitoring(config)

# Stop monitoring
monitor.stop_continuous_monitoring(monitor_id)
```

### MetricsCollector

Calculate security metrics:

```python
from purple.validation.metrics_collector import MetricsCollector
from datetime import datetime

collector = MetricsCollector()

# Calculate MTTD
attack_start = datetime(2026, 2, 20, 10, 0, 0)
detection_time = datetime(2026, 2, 20, 10, 0, 5)
mttd = collector.calculate_mttd(attack_start, detection_time)  # 5.0 seconds

# Calculate detection rate
rate = collector.calculate_detection_rate(100, 85)  # 85%

# Calculate false positive rate
fp_rate = collector.calculate_false_positive_rate(120, 20)  # 16.67%

# Calculate coverage
coverage = collector.calculate_coverage(
    ['sqli', 'xss', 'port_scan'],
    ['sqli', 'xss']
)  # 66.67%

# Comprehensive summary
data = {
    'total_attacks': 100,
    'detected_attacks': 85,
    'total_alerts': 120,
    'false_positives': 20,
    'attack_types': ['sqli', 'xss', 'port_scan'],
    'detected_types': ['sqli', 'xss'],
    'mttd_values': [5.0, 10.0, 15.0],
    'mttr_values': [60.0, 120.0, 180.0]
}
summary = collector.calculate_metrics_summary(data)
```

### ReportGenerator

Generate validation reports:

```python
from purple.validation.report_generator import ReportGenerator

generator = ReportGenerator()

simulation_data = {
    'simulation_id': 'sim-001',
    'timestamp': '2026-02-20T10:00:00Z',
    'attacks': [...],
    'detections': [...],
    'metrics': {
        'mttd': 5.0,
        'mttr': 295.0,
        'detection_rate': 100.0
    }
}

# Generate PDF
generator.generate_pdf_report(simulation_data, 'report.pdf')

# Generate HTML
generator.generate_html_report(simulation_data, 'report.html')

# Generate JSON
generator.generate_json_report(simulation_data, 'report.json')

# Generate executive summary
summary = generator.generate_executive_summary(simulation_data)
print(summary)
```

## Detection Sources

### Log Files

Supported log formats:
- **Syslog**: Standard syslog format
- **JSON**: Structured JSON logs
- **CEF**: Common Event Format

Log file paths (configurable):
```python
DETECTION_SOURCES = {
    "logs": {
        "syslog": "/var/log/syslog",
        "auth": "/var/log/auth.log",
        "apache": "/var/log/apache2/access.log",
        "nginx": "/var/log/nginx/access.log"
    }
}
```

### SIEM Integration

Supported SIEM platforms:
- **Splunk**: HTTP Event Collector API
- **Elasticsearch**: REST API

Configuration:
```python
DETECTION_SOURCES = {
    "siem": {
        "splunk": "http://localhost:8089",
        "elasticsearch": "http://localhost:9200"
    }
}
```

### EDR Integration

Generic EDR endpoint monitoring:
```python
DETECTION_SOURCES = {
    "edr": {
        "endpoint": "http://localhost:8000/api/alerts"
    }
}
```

## Metrics

### MTTD (Mean Time To Detect)

Time from attack start to first detection:
```
MTTD = Detection Time - Attack Start Time
```

Lower is better. Target: < 60 seconds

### MTTR (Mean Time To Respond)

Time from detection to resolution:
```
MTTR = Resolution Time - Detection Time
```

Lower is better. Target: < 5 minutes

### Detection Rate

Percentage of attacks detected:
```
Detection Rate = (Detected Attacks / Total Attacks) × 100
```

Higher is better. Target: > 80%

### False Positive Rate

Percentage of false alerts:
```
False Positive Rate = (False Positives / Total Alerts) × 100
```

Lower is better. Target: < 20%

### Coverage

Percentage of attack types detected:
```
Coverage = (Detected Attack Types / Total Attack Types) × 100
```

Higher is better. Target: 100%

## Report Contents

Generated reports include:

1. **Executive Summary**
   - Overall metrics
   - Detection rate
   - MTTD/MTTR averages
   - Key findings

2. **Attack Timeline**
   - Chronological attack events
   - Attack success/failure
   - Duration

3. **Detection Timeline**
   - Detection events
   - Detection sources
   - Severity levels

4. **Metrics Dashboard**
   - MTTD/MTTR statistics
   - Detection rate
   - False positive rate
   - Coverage matrix

5. **Coverage Matrix**
   - Attack types tested
   - Detection status per type
   - Gap analysis

6. **Recommendations**
   - Based on metrics
   - Tuning suggestions
   - Improvement areas

7. **Charts**
   - Timeline visualization
   - Metrics bar charts
   - Coverage heatmap

## Testing

Run tests:

```bash
python3 -m pytest tests/purple/validation/ -v
```

Test coverage: 74+ passing tests across all modules.

## Integration with Phase 9A/9B

The validation module integrates with existing Akali attack modules:

- **Phase 9A (Exploits)**: `exploits.generator`, `exploits.fuzzer`
- **Phase 9B (Extended Targets)**: `extended.ad`, `extended.cloud`, `extended.privesc`

Attack orchestration uses these modules internally for realistic simulations.

## Best Practices

1. **Always get authorization** before running attack simulations
2. **Use isolated environments** (lab/test networks)
3. **Document baselines** before making detection changes
4. **Run chains gradually** to isolate detection gaps
5. **Review false positives** to tune detection rules
6. **Schedule regular validation** (monthly recommended)
7. **Track metrics over time** to measure improvement

## Examples

### Full Purple Team Validation Workflow

```python
from purple.validation.defense_tester import DefenseTester

# Initialize
tester = DefenseTester()

# 1. Run individual attack tests
print("Testing SQL Injection detection...")
result_sqli = tester.run_attack_simulation('sqli', 'http://localhost:8080')

print("Testing Port Scan detection...")
result_scan = tester.run_attack_simulation('port_scan', '10.0.0.5')

# 2. Run attack chain
chain = tester.load_attack_chain('lateral_movement.json')
result_chain = tester.run_attack_chain(chain['steps'])

# 3. Measure metrics
mttd = tester.measure_mttd('attack.log', 'detection.log')
mttr = tester.measure_mttr('incident.log')

# 4. Generate reports
tester.generate_report('sim-001', 'report.pdf', format='pdf')
tester.generate_report('sim-001', 'report.html', format='html')
```

## Troubleshooting

**Issue**: No detections found
- **Solution**: Check detection source paths, verify logs are being written, increase timeout

**Issue**: MTTD calculation fails
- **Solution**: Verify log timestamp formats match expected patterns

**Issue**: Report generation fails
- **Solution**: Ensure simulation ID exists, check file permissions for output path

## Future Enhancements

- Real-time WebSocket monitoring
- Additional SIEM integrations (Sentinel, QRadar)
- Machine learning for anomaly detection
- Automated remediation validation
- Comparison with industry benchmarks
- Integration with MITRE ATT&CK framework

## License

Part of Akali Security Platform - Internal Use Only

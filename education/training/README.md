# Akali Training System

Interactive security training platform with OWASP Top 10 modules, progress tracking, and certificates.

## Components

### 1. Training Engine (`training_engine.py`)
Core framework for delivering YAML-based training modules:
- Interactive lesson delivery
- Quiz engine with scoring
- Session management
- Progress tracking integration

### 2. Progress Tracker (`progress_tracker.py`)
SQLite-based progress tracking:
- Session history
- Module completion status
- Quiz scores and statistics
- Leaderboard functionality

Database: `~/.akali/training.db`

### 3. Certificate Generator (`certificate_generator.py`)
Professional PDF certificate generation:
- Branded certificates with Akali theme
- Achievement badges for high scores
- Requires: `pip install reportlab`

Output directory: `~/.akali/certificates/`

## Available Modules

All 10 OWASP Top 10 training modules:

1. **Injection Attacks** - SQL, NoSQL, OS injection prevention
2. **Broken Authentication** - Secure auth systems and password handling
3. **Sensitive Data Exposure** - Data protection at rest and in transit
4. **XML External Entities (XXE)** - XXE vulnerabilities and prevention
5. **Broken Access Control** - Authorization and IDOR prevention
6. **Security Misconfiguration** - System hardening and secure defaults
7. **Cross-Site Scripting (XSS)** - XSS types and prevention
8. **Insecure Deserialization** - Safe serialization practices
9. **Vulnerable Components** - Dependency management and CVE monitoring
10. **Insufficient Logging** - Security logging and monitoring

Each module includes:
- 3 lessons with examples and code samples
- 4-5 quiz questions
- Estimated completion time: 18-25 minutes
- Difficulty rating (beginner/intermediate/advanced)

## Usage

### Run Training Interactively

```bash
cd ~/akali
python3 education/training/training_engine.py
```

### Programmatic Usage

```python
from education.training.training_engine import TrainingEngine
from education.training.progress_tracker import ProgressTracker
from education.training.certificate_generator import CertificateGenerator

# Start training
engine = TrainingEngine()
results = engine.start_training('owasp_01_injection', agent_id='dommo')

# Track progress
tracker = ProgressTracker()
session_id = tracker.record_session(results)

# Generate certificate (if passed)
if results['passed']:
    generator = CertificateGenerator()
    cert_path = generator.generate_certificate(
        agent_id=results['agent_id'],
        module_title="OWASP #1: Injection Attacks",
        module_id=results['module_id'],
        score=results['score'],
        total_questions=results['total_questions'],
        percentage=results['percentage']
    )
    tracker.mark_certificate_issued(
        results['agent_id'],
        results['module_id'],
        cert_path
    )
```

### View Progress

```python
from education.training.progress_tracker import ProgressTracker

tracker = ProgressTracker()
progress = tracker.get_agent_progress('dommo')

print(f"Completed: {progress['stats']['completed_modules']} modules")
print(f"Average Score: {progress['stats']['average_score']:.1f}%")
print(f"Certificates: {progress['stats']['certificates_earned']}")
```

## Module Format

Training modules are YAML files in `modules/` directory:

```yaml
id: owasp_01_injection
title: "OWASP #1: Injection Attacks"
description: "Learn how injection attacks work"
difficulty: beginner
estimated_time: "25 minutes"
tags:
  - owasp
  - sql-injection

lessons:
  - title: "What is Injection?"
    content:
      - type: text
        value: "Explanation text..."
      - type: code
        language: python
        value: "code example"
      - type: warning
        value: "Warning message"
      - type: tip
        value: "Helpful tip"
    takeaways:
      - "Key point 1"
      - "Key point 2"

quiz:
  - question: "Question text?"
    options:
      - "Option A"
      - "Option B"
      - "Option C"
    correct_answer: "Option A"
    explanation: "Why A is correct..."
```

## Requirements

```bash
# Core dependencies (included in Python)
- yaml
- sqlite3
- pathlib
- datetime

# Optional for certificates
pip install reportlab
```

## CLI Integration

Training commands will be integrated into `akali` CLI:

```bash
akali train list                    # List modules
akali train start [module-id]       # Start training
akali train progress [@agent]       # View progress
akali train certificate [@agent]    # Generate certificate
```

(CLI integration in progress - Task #4)

## Database Schema

### training_sessions
- Session history with timestamps, scores, answers

### module_progress
- Aggregated progress per agent/module
- Best scores, attempt counts, completion status

### certificates
- Issued certificates with paths

## Testing

```bash
# Test training engine
python3 education/training/training_engine.py

# Test progress tracker
python3 education/training/progress_tracker.py

# Test certificate generator
python3 education/training/certificate_generator.py
```

## Future Enhancements

- Web-based training interface
- Team training campaigns
- Custom module creation tool
- Skill paths (beginner → advanced)
- Gamification (badges, achievements, XP)
- Integration with ZimMemory for notifications
- Automated training reminders
- Training analytics dashboard

---

🥷 **Akali Training System** - Protecting the family through education

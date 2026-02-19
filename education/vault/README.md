# Akali Secrets Vault Integration

**HashiCorp Vault client and secret management automation for Akali.**

## Features

- **Vault Client** (`vault_client.py`) - Connect to HashiCorp Vault (KV v2)
- **Secret Rotation** (`rotation_policies.py`) - Automated rotation policies
- **Secret Scanner** (`secret_scanner.py`) - Find hardcoded secrets in code
- **CLI Commands** - Developer-friendly vault operations
- **CI/CD Integration** - GitHub Actions, GitLab CI examples

## Installation

```bash
# Install HashiCorp Vault client library
pip install hvac

# Optional: Install local Vault for testing
brew install vault  # macOS
# or download from https://www.vaultproject.io/downloads
```

## Quick Start

### 1. Set up Vault credentials

```bash
export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN="your-vault-token"
```

### 2. Use the Vault client

```python
from education.vault.vault_client import VaultClient

# Initialize client
vault = VaultClient()

# Store a secret
vault.set_secret("app/database", {
    "host": "db.example.com",
    "username": "app_user",
    "password": "secret123"
})

# Retrieve a secret
secret = vault.get_secret("app/database")
print(secret["password"])

# List secrets
secrets = vault.list_secrets("app/")
print(secrets)
```

### 3. Set up rotation policies

```python
from education.vault.rotation_policies import RotationManager, RotationType

# Initialize manager
manager = RotationManager(vault)

# Create time-based rotation policy (every 30 days)
manager.create_policy(
    policy_id="db-password-rotation",
    secret_path="app/database",
    rotation_type=RotationType.TIME_BASED,
    rotation_interval_days=30
)

# Check for due rotations
due = manager.check_due_rotations()

# Rotate a secret
log = manager.rotate_secret("db-password-rotation")
```

### 4. Scan code for secrets

```bash
# Scan a directory
python education/vault/secret_scanner.py /path/to/project

# Scan and output JSON
python education/vault/secret_scanner.py /path/to/project --json

# Adjust entropy threshold
python education/vault/secret_scanner.py /path/to/project --entropy 5.0
```

## CLI Commands

```bash
# Vault operations
akali vault get app/database              # Get secret
akali vault set app/api '{"key":"value"}' # Set secret
akali vault list app/                     # List secrets
akali vault rotate db-password-rotation   # Rotate secret

# Secret scanning
akali vault scan /path/to/project         # Scan for hardcoded secrets
akali vault scan . --quick                # Quick scan (current dir)
```

## Mock Mode (Testing)

If you don't have a Vault server, use mock mode:

```python
from education.vault.vault_client import get_vault_client

# Get mock client
vault = get_vault_client(mock=True)

# Use as normal - data stored in memory
vault.set_secret("test/secret", {"key": "value"})
secret = vault.get_secret("test/secret")
```

## Authentication Methods

### Token Authentication (default)

```bash
export VAULT_TOKEN="s.abc123..."
```

### AppRole Authentication

```python
from education.vault.vault_client import VaultClient

vault = VaultClient.from_approle(
    role_id="your-role-id",
    secret_id="your-secret-id"
)
```

## Rotation Handlers

Built-in handlers:

- **random_string** - Generate random passwords/tokens
- **database_password** - Rotate database credentials
- **api_key** - Rotate API keys

Custom handler example:

```python
def custom_handler(secret_path: str, old_secret: dict) -> dict:
    """Custom rotation logic."""
    new_secret = old_secret.copy()
    # ... generate new credentials ...
    new_secret["rotated_at"] = datetime.utcnow().isoformat()
    return new_secret

manager.register_handler("custom", custom_handler)

manager.create_policy(
    policy_id="custom-rotation",
    secret_path="app/custom",
    rotation_type=RotationType.TIME_BASED,
    rotation_interval_days=7,
    rotation_handler="custom"
)
```

## Secret Scanner

### Detected Secret Types

- AWS access keys, secret keys
- GitHub tokens (PAT, OAuth)
- Slack tokens, webhooks
- Google API keys
- Stripe API keys
- JWT tokens
- Private keys (RSA, EC, etc.)
- Database connection strings
- Generic high-entropy strings

### Configuration

```python
from education.vault.secret_scanner import SecretScanner

scanner = SecretScanner(
    entropy_threshold=4.5  # Adjust sensitivity
)

findings = scanner.scan("/path/to/project")
report = scanner.generate_report(findings)
```

### False Positives

The scanner automatically skips:
- Placeholders (example, sample, test, dummy)
- Comments
- File paths and URLs
- Common variable names

## CI/CD Integration

### GitHub Actions

Create `.github/workflows/vault-secrets.yml`:

```yaml
name: Vault Secret Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'

      - name: Install dependencies
        run: |
          pip install hvac

      - name: Scan for secrets
        run: |
          python education/vault/secret_scanner.py . --json > secrets-report.json

      - name: Check for high-confidence findings
        run: |
          python -c "
          import json
          with open('secrets-report.json') as f:
              report = json.load(f)
          high = report['by_confidence'].get('high', 0)
          if high > 0:
              print(f'❌ Found {high} high-confidence secrets!')
              exit(1)
          print('✅ No high-confidence secrets found')
          "

      - name: Upload report
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: secrets-report
          path: secrets-report.json
```

### GitLab CI

Create `.gitlab-ci.yml`:

```yaml
vault_scan:
  stage: test
  image: python:3.9
  before_script:
    - pip install hvac
  script:
    - python education/vault/secret_scanner.py . --json > secrets-report.json
    - |
      python -c "
      import json, sys
      with open('secrets-report.json') as f:
          report = json.load(f)
      high = report['by_confidence'].get('high', 0)
      if high > 0:
          print(f'❌ Found {high} high-confidence secrets!')
          sys.exit(1)
      print('✅ No secrets found')
      "
  artifacts:
    reports:
      junit: secrets-report.json
    when: always
```

### Pre-commit Hook

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: vault-secret-scan
        name: Scan for hardcoded secrets
        entry: python education/vault/secret_scanner.py
        language: python
        pass_filenames: false
        args: ['.', '--no-recursive']
```

## Rotation Scheduling

Use with Akali's autonomous scheduler:

```python
from autonomous.scheduler.cron_manager import CronManager

manager = CronManager()

# Schedule daily rotation checks
manager.register_job(
    job_id="vault-rotation-check",
    name="Check for due secret rotations",
    schedule="0 9 * * *",  # Daily at 9 AM
    command="python education/vault/rotation_policies.py check && python education/vault/rotation_policies.py rotate --all"
)
```

## Security Best Practices

1. **Never commit secrets** - Use Vault for all sensitive data
2. **Rotate regularly** - Set up time-based rotation policies
3. **Use AppRole in production** - More secure than token auth
4. **Audit rotation logs** - Monitor rotation history
5. **Scan before commit** - Use pre-commit hooks
6. **Encrypt Vault transit** - Use HTTPS for Vault connections
7. **Limit token TTL** - Use short-lived tokens
8. **Monitor access** - Track who accesses which secrets

## Troubleshooting

### Connection Refused

```bash
# Check if Vault is running
vault status

# Start local dev server
vault server -dev
```

### Authentication Failed

```bash
# Check token
vault token lookup

# Login again
vault login
```

### hvac Import Error

```bash
pip install hvac
```

### Mock Mode

If Vault is unavailable:

```python
vault = get_vault_client(mock=True)
```

## Architecture

```
education/vault/
├── vault_client.py          # Vault KV v2 client
├── rotation_policies.py     # Rotation automation
├── secret_scanner.py        # Hardcoded secret detector
└── README.md                # This file

Data files (stored in ~/akali/data/):
├── rotation_policies.json   # Rotation policy definitions
└── rotation_logs.json       # Rotation execution history
```

## API Reference

### VaultClient

```python
client = VaultClient(url, token, namespace, mount_point)

# Methods
client.is_authenticated() -> bool
client.health_check() -> dict
client.get_secret(path, version=None) -> dict
client.set_secret(path, data) -> bool
client.delete_secret(path, versions=None) -> bool
client.list_secrets(path) -> list
client.get_secret_metadata(path) -> dict
client.rotate_secret(path, new_data) -> bool
```

### RotationManager

```python
manager = RotationManager(vault_client)

# Methods
manager.create_policy(policy_id, secret_path, rotation_type, ...) -> RotationPolicy
manager.delete_policy(policy_id) -> bool
manager.list_policies(enabled_only=False) -> list
manager.check_due_rotations() -> list
manager.rotate_secret(policy_id, new_secret=None, force=False) -> RotationLog
manager.get_rotation_history(policy_id=None, limit=50) -> list
manager.register_handler(name, handler_func)
```

### SecretScanner

```python
scanner = SecretScanner(entropy_threshold=4.5)

# Methods
scanner.scan(target, recursive=True) -> list[SecretFinding]
scanner.scan_file(file_path) -> list[SecretFinding]
scanner.scan_directory(directory, recursive=True) -> list[SecretFinding]
scanner.generate_report(findings) -> dict
scanner.calculate_entropy(text) -> float
scanner.is_high_entropy_string(text, min_length=20) -> bool
```

## Examples

See `examples/` directory for:
- Basic Vault operations
- Custom rotation handlers
- CI/CD integration scripts
- Pre-commit hook setup

## License

Part of Akali - The Security Sentinel.

---

**Built by Akali 🥷 - Protecting the family's secrets since 2026.**

# Cloud Attacks Module

Cloud infrastructure pentesting and enumeration for AWS, Azure, and GCP.

## Overview

The Cloud Attacks module provides comprehensive enumeration and exploitation capabilities for cloud infrastructure:

- **AWS**: S3 bucket enumeration, IAM permission testing, EC2 metadata exploitation
- **Azure**: Blob storage enumeration, service principal testing, managed identity exploitation
- **GCP**: Storage bucket enumeration, service account testing, metadata service exploitation

## Features

### Security Features

- **Mock Mode**: Enabled by default - test functionality without making real API calls
- **Authorization Prompts**: Requires explicit authorization before enumeration
- **Stealth Mode**: Add delays between requests to avoid detection
- **Rate Limiting**: Configurable rate limiting to avoid triggering alerts
- **Proxy Support**: Route traffic through proxy for anonymity
- **User-Agent Randomization**: Randomize user agents to avoid fingerprinting

### Cloud Provider Coverage

#### AWS
- S3 bucket enumeration with common naming patterns
- Public bucket detection
- IAM permission enumeration
- EC2 instance enumeration
- Metadata service (169.254.169.254) exploitation
- Assume role exploitation

#### Azure
- Blob storage container enumeration
- Public container detection
- Service principal permission testing
- Azure AD enumeration
- Managed identity enumeration
- Metadata service exploitation

#### GCP
- Storage bucket enumeration
- Public bucket detection via IAM policies
- Service account enumeration
- Metadata service exploitation
- Service account token extraction

## Installation

### Required Dependencies

```bash
# AWS support
pip install boto3

# Azure support
pip install azure-storage-blob azure-identity azure-mgmt-resource

# GCP support
pip install google-cloud-storage google-cloud-iam
```

**Note**: All dependencies are optional. The module will work in mock mode without them.

## Usage

### Python API

```python
from extended.cloud import CloudAttacker

# Initialize (mock mode by default for safety)
attacker = CloudAttacker(mock_mode=True)

# Enumerate S3 buckets
results = attacker.enumerate_s3_buckets("mycompany", check_public=True)

# Test IAM permissions
perms = attacker.test_iam_permissions(
    access_key="AKIA...",
    secret_key="..."
)

# Enumerate Azure blobs
azure_results = attacker.enumerate_azure_blobs("mycompany")

# Enumerate GCP buckets
gcp_results = attacker.enumerate_gcp_buckets("mycompany")

# Check for metadata service
metadata = attacker.check_metadata_service("169.254.169.254")

# Save results
attacker.save_results(results, "cloud_scan_results.json")
```

### Advanced Features

```python
# Disable mock mode (requires authorization)
attacker.set_mock_mode(False, authorized=True)

# Enable stealth mode
attacker.enable_stealth_mode(delay=2.0)  # 2 second delay between requests

# Set proxy
attacker.set_proxy("http://127.0.0.1:8080")

# Enable rate limiting
attacker.enable_rate_limiting(max_requests=5, per_seconds=1)
```

### CLI Commands

```bash
# Enumerate S3 buckets
akali cloud enum-s3 --keyword mycompany --check-public

# Test IAM permissions
akali cloud test-iam --access-key AKIA... --secret-key ...

# Enumerate Azure blobs
akali cloud enum-azure --keyword mycompany

# Test Azure permissions
akali cloud test-azure-perms --tenant-id ... --client-id ... --secret ...

# Enumerate GCP buckets
akali cloud enum-gcp --keyword mycompany

# Check metadata service
akali cloud metadata --target 169.254.169.254

# Enable stealth mode
akali cloud enum-s3 --keyword mycompany --stealth --delay 3.0

# Save results to file
akali cloud enum-s3 --keyword mycompany --output results.json
```

## Mock Mode

Mock mode is **enabled by default** for safety. It returns realistic-looking results without making actual API calls.

### When to Use Mock Mode

- Testing and development
- Training and demonstration
- Learning cloud attack patterns
- CI/CD testing

### Disabling Mock Mode

Only disable mock mode when you have **explicit authorization** to test the target infrastructure:

```python
# Requires authorized=True parameter
attacker.set_mock_mode(False, authorized=True)
```

## Bucket Naming Patterns

The module generates common bucket naming patterns:

### AWS S3
- `{keyword}`
- `{keyword}-{suffix}` (prod, dev, staging, backup, logs, etc.)
- `{keyword}.{suffix}`
- `{keyword}_{suffix}`
- `{prefix}-{keyword}` (www, app, api, cdn, storage)

### Azure Storage
- `{keyword}` (lowercased, no special chars)
- `{keyword}{suffix}` (Azure doesn't allow dashes in storage account names)

### GCP Storage
- `{keyword}`
- `{keyword}-{suffix}`
- `{keyword}_{suffix}`

## Metadata Service Exploitation

The module can detect and exploit cloud metadata services:

### AWS (169.254.169.254)
- AMI ID extraction
- IAM role credentials
- User data

### Azure (169.254.169.254)
- VM information
- Managed identity tokens
- Subscription details

### GCP (metadata.google.internal)
- Instance information
- Service account tokens
- Project metadata

## Error Handling

The module handles errors gracefully:

- Missing dependencies → Returns error message
- Invalid credentials → Returns error in results
- Rate limiting → Automatically retries
- Network errors → Returns error details

## Testing

```bash
# Run all tests
pytest tests/extended/cloud/ -v

# Run specific test file
pytest tests/extended/cloud/test_cloud_attacker.py -v

# Run with coverage
pytest tests/extended/cloud/ --cov=extended.cloud --cov-report=html
```

## Security Considerations

⚠️ **Important Security Notes**:

1. **Authorization Required**: Only test infrastructure you own or have explicit permission to test
2. **Mock Mode Default**: Mock mode is enabled by default to prevent accidental attacks
3. **Logging**: All enumeration attempts should be logged
4. **Rate Limiting**: Use rate limiting to avoid triggering security alerts
5. **Legal**: Unauthorized access to cloud infrastructure is illegal

## Examples

### Find Public S3 Buckets

```python
attacker = CloudAttacker(mock_mode=False, authorized=True)
results = attacker.enumerate_s3_buckets("target-company", check_public=True)

public_buckets = [r for r in results if r.get('public') == True]
print(f"Found {len(public_buckets)} public buckets")
```

### Test IAM Key Permissions

```python
perms = attacker.test_iam_permissions(
    access_key="AKIA...",
    secret_key="..."
)

print(f"User: {perms.get('user')}")
print(f"Policies: {perms.get('attached_policies')}")
```

### Enumerate All Cloud Providers

```python
keyword = "target-company"

# AWS
aws_results = attacker.enumerate_s3_buckets(keyword)

# Azure
azure_results = attacker.enumerate_azure_blobs(keyword)

# GCP
gcp_results = attacker.enumerate_gcp_buckets(keyword)

# Save all results
all_results = {
    'aws': aws_results,
    'azure': azure_results,
    'gcp': gcp_results
}
attacker.save_results(all_results, "cloud_enum_results.json")
```

## Architecture

```
extended/cloud/
├── __init__.py              # Module exports
├── cloud_attacker.py        # Main CloudAttacker class
├── aws_enum.py              # AWS enumeration logic
├── azure_enum.py            # Azure enumeration logic
├── gcp_enum.py              # GCP enumeration logic
└── README.md                # This file

tests/extended/cloud/
├── test_cloud_attacker.py   # CloudAttacker tests
├── test_aws_enum.py         # AWS enumeration tests
├── test_azure_enum.py       # Azure enumeration tests
└── test_gcp_enum.py         # GCP enumeration tests
```

## Contributing

When adding new cloud providers or features:

1. Add enumeration logic to appropriate file
2. Add mock mode support
3. Write comprehensive tests
4. Update CLI integration
5. Update this README

## License

Part of the Akali security platform.

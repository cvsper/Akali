# Purple Team Sandbox

Isolated attack simulation environments for safe testing and training.

## Overview

The Purple Team Sandbox provides Docker-based isolated environments for:
- Deploying vulnerable applications for testing
- Setting up honeypot services
- Creating network topologies
- Running safe, controlled attack simulations

## Features

- **Isolated Environments**: Network-isolated Docker containers
- **Vulnerable Apps**: DVWA, OWASP Juice Shop, WebGoat, Metasploitable, and more
- **Honeypots**: SSH, HTTP, FTP, SMTP, RDP honeypots
- **Network Topologies**: Single host, DMZ, multi-tier architectures
- **Mock Mode**: Test without Docker for CI/CD environments
- **Resource Limits**: CPU and memory constraints for safety

## Prerequisites

### Docker (for real environments)
```bash
# macOS
brew install docker

# Linux
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh

# Start Docker daemon
docker ps  # Should work without errors
```

### Python Dependencies
```bash
pip install docker
```

## Quick Start

### Create an Environment
```python
from purple.sandbox import PurpleTeamSandbox

# Initialize sandbox
sandbox = PurpleTeamSandbox()

# Create isolated environment
result = sandbox.create_environment(
    target_type="webapp",
    network_isolated=True
)
env_id = result["env_id"]
```

### Deploy Vulnerable Application
```python
# Deploy DVWA
result = sandbox.deploy_vulnerable_app(env_id, "dvwa", port=8080)

# Access at http://localhost:8080
# Default creds: admin/password
print(result["access_url"])
```

### Deploy Honeypot
```python
# Deploy SSH honeypot
result = sandbox.deploy_honeypot(env_id, "ssh", port=2222)

# Now SSH attempts to localhost:2222 will be logged
```

### Create Network Topology
```python
# Create DMZ topology
result = sandbox.create_network_topology("dmz")

# Returns networks: external, dmz, internal
topology_id = result["topology_id"]
```

### Cleanup
```python
# Stop and remove everything
sandbox.stop_environment(env_id)
sandbox.delete_environment(env_id)
```

## CLI Usage

```bash
# Create environment
akali purple create-env --type webapp

# Deploy vulnerable app
akali purple deploy-app --name dvwa --port 8080

# Deploy honeypot
akali purple deploy-honeypot --service ssh --port 2222

# Create network topology
akali purple create-topology --type dmz

# List environments
akali purple list

# Get environment info
akali purple info --env-id env-abc123

# Start environment
akali purple start --env-id env-abc123

# Stop environment
akali purple stop --env-id env-abc123
```

## Available Vulnerable Apps

| Name | Description | Default Port | Default Creds |
|------|-------------|-------------|---------------|
| `dvwa` | Damn Vulnerable Web Application | 80 | admin/password |
| `juice-shop` | OWASP Juice Shop | 3000 | - |
| `webgoat` | OWASP WebGoat | 8080 | - |
| `metasploitable` | Metasploitable3 | 22 | - |
| `vuln-node` | Vulnerable Node.js App | 9090 | - |

## Available Honeypots

| Service | Port | Description |
|---------|------|-------------|
| `ssh` | 2222 | SSH honeypot (Cowrie) |
| `http` | 8080 | HTTP/Web honeypot |
| `ftp` | 21 | FTP honeypot |
| `smtp` | 25 | SMTP honeypot |
| `rdp` | 3389 | RDP honeypot |

## Network Topologies

### Single Host
- **Description**: Single vulnerable host
- **Containers**: 1
- **Networks**: 1 (bridge)

### DMZ
- **Description**: DMZ with web server and internal network
- **Containers**: 3
- **Networks**: 3 (external, dmz, internal)

### Multi-Tier
- **Description**: Web tier, app tier, database tier
- **Containers**: 5
- **Networks**: 3 (web, app, db)

## Mock Mode

For testing without Docker:

```python
sandbox = PurpleTeamSandbox(mock_mode=True)

# All operations will be simulated
result = sandbox.create_environment("webapp")
# Returns mock data without creating containers
```

## Security Features

- **Network Isolation**: Containers run in isolated networks by default
- **No Host Networking**: Prevents container escape
- **Resource Limits**: CPU and memory constraints
- **Automatic Cleanup**: Containers removed on stop
- **Read-Only Filesystems**: Where possible
- **Dropped Capabilities**: Minimal container permissions

## API Reference

### PurpleTeamSandbox

#### `create_environment(target_type, network_isolated=True, timeout=None, cpu_limit=None, memory_limit=None)`
Create an isolated test environment.

**Parameters:**
- `target_type` (str): Type of target (webapp, api, network, etc.)
- `network_isolated` (bool): Create isolated network (default: True)
- `timeout` (int): Environment timeout in seconds (optional)
- `cpu_limit` (str): CPU limit, e.g., "1.0" (optional)
- `memory_limit` (str): Memory limit, e.g., "512m" (optional)

**Returns:** Dict with env_id and environment details

#### `deploy_vulnerable_app(env_id, app_name, port=None)`
Deploy a vulnerable application to an environment.

**Parameters:**
- `env_id` (str): Environment ID
- `app_name` (str): Application name (dvwa, juice-shop, etc.)
- `port` (int): Host port to map to (optional, uses default if not specified)

**Returns:** Dict with container_id, port, and access_url

#### `deploy_honeypot(env_id, service_type, port)`
Deploy a honeypot service to an environment.

**Parameters:**
- `env_id` (str): Environment ID
- `service_type` (str): Honeypot type (ssh, http, ftp, smtp, rdp)
- `port` (int): Port to bind to

**Returns:** Dict with container_id and service details

#### `create_network_topology(topology_type)`
Create a network topology.

**Parameters:**
- `topology_type` (str): Topology type (single_host, dmz, multi_tier)

**Returns:** Dict with topology_id and network details

#### `start_environment(env_id)`
Start a sandbox environment.

**Returns:** Dict with status

#### `stop_environment(env_id)`
Stop and cleanup an environment.

**Returns:** Dict with cleanup details

#### `get_environment_info(env_id)`
Get environment information.

**Returns:** Dict with environment details

#### `list_environments()`
List all environments.

**Returns:** Dict with list of environments

#### `delete_environment(env_id)`
Delete an environment.

**Returns:** Dict with operation result

## Examples

### Example 1: Web App Testing
```python
sandbox = PurpleTeamSandbox()

# Create environment
env = sandbox.create_environment("webapp")
env_id = env["env_id"]

# Deploy DVWA and Juice Shop
sandbox.deploy_vulnerable_app(env_id, "dvwa", port=8080)
sandbox.deploy_vulnerable_app(env_id, "juice-shop", port=3000)

# Start testing
sandbox.start_environment(env_id)

# ... perform tests ...

# Cleanup
sandbox.stop_environment(env_id)
```

### Example 2: Honeypot Deployment
```python
sandbox = PurpleTeamSandbox()

# Create environment
env = sandbox.create_environment("network")
env_id = env["env_id"]

# Deploy multiple honeypots
sandbox.deploy_honeypot(env_id, "ssh", port=2222)
sandbox.deploy_honeypot(env_id, "http", port=8080)
sandbox.deploy_honeypot(env_id, "ftp", port=2121)

# Start environment
sandbox.start_environment(env_id)

# Monitor logs
# docker logs <container_id>
```

### Example 3: DMZ Topology
```python
sandbox = PurpleTeamSandbox()

# Create DMZ topology
topology = sandbox.create_network_topology("dmz")
topology_id = topology["topology_id"]

# Networks available:
# - external: public-facing
# - dmz: semi-trusted zone
# - internal: private network

# Deploy apps to different zones
# ... (deploy containers and connect to appropriate networks)
```

## Troubleshooting

### Docker daemon not running
```bash
# Check Docker status
docker ps

# Start Docker Desktop (macOS)
open -a Docker

# Start Docker service (Linux)
sudo systemctl start docker
```

### Port already in use
```bash
# Find process using port
lsof -i :8080

# Kill process
kill -9 <PID>

# Or use a different port
sandbox.deploy_vulnerable_app(env_id, "dvwa", port=8081)
```

### Container won't start
```bash
# Check logs
docker logs <container_id>

# Inspect container
docker inspect <container_id>
```

### Cannot pull image
```bash
# Pull manually
docker pull vulnerables/web-dvwa

# Or use mock mode
sandbox = PurpleTeamSandbox(mock_mode=True)
```

## Storage

Environment metadata is stored at:
```
~/.akali/sandbox/environments.json
```

## Testing

Run tests:
```bash
# All tests (requires Docker)
pytest tests/purple/sandbox/

# Mock mode only (no Docker required)
pytest tests/purple/sandbox/ -m "not requires_docker_sdk"
```

## Contributing

When adding new vulnerable apps:
1. Add entry to `VULNERABLE_APPS` in `vulnerable_apps.py`
2. Test deployment manually
3. Add tests to `test_vulnerable_apps.py`

When adding new honeypots:
1. Add entry to `HONEYPOT_SERVICES` in `honeypots.py`
2. Test deployment manually
3. Add tests to `test_honeypots.py`

## License

Part of the Akali security platform.

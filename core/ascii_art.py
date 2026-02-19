"""ASCII art banners for Akali CLI."""

# Main Akali banner (ninja theme)
AKALI_BANNER = r"""
    ___    __            ___
   /   |  / /____  _____/ (_)
  / /| | / //_/ / / / __  / /
 / ___ |/ ,< / /_/ / /_/ / /
/_/  |_/_/|_|\__,_/\__,_/_/

    The Security Sentinel 🥷
"""

# Compact version for status
AKALI_COMPACT = r"""
  ▄▀█ █▄▀ ▄▀█ █░░ █
  █▀█ █░█ █▀█ █▄▄ █
   Security Sentinel 🥷
"""

# Phase completion banners
PHASE_COMPLETE = r"""
╔═══════════════════════════════════╗
║   🎉 PHASE COMPLETE 🎉            ║
╚═══════════════════════════════════╝
"""

# Alert banner (for critical findings)
CRITICAL_ALERT = r"""
╔═══════════════════════════════════╗
║  ⚠️  CRITICAL SECURITY ALERT ⚠️   ║
╚═══════════════════════════════════╝
"""

# Scan complete banner
SCAN_COMPLETE = r"""
┌─────────────────────────────────┐
│  ✅ Scan Complete               │
└─────────────────────────────────┘
"""

# Training banner
TRAINING_BANNER = r"""
  ╔════════════════════════╗
  ║  🎓 Security Training  ║
  ╚════════════════════════╝
"""

# Vault banner
VAULT_BANNER = r"""
  ╔═══════════════════════╗
  ║  🔐 Secrets Vault     ║
  ╚═══════════════════════╝
"""

# DLP banner
DLP_BANNER = r"""
  ╔════════════════════════╗
  ║  🛡️  Data Protection   ║
  ╚════════════════════════╝
"""

# Threat hunting banner
HUNT_BANNER = r"""
  ╔═══════════════════════════╗
  ║  🎯 Advanced Threat Hunt  ║
  ╚═══════════════════════════╝
"""

# Incident response banner
INCIDENT_BANNER = r"""
  ╔═══════════════════════════╗
  ║  🚨 Incident Response     ║
  ╚═══════════════════════════╝
"""

# Ninja art (for fun)
NINJA = r"""
        _
       /(|
      (  :
     __\  \  _____
   (____)  `|
  (____)|   |
   (____).__|
    (___)__.|_____

     Shadow Warrior
"""

# Color codes for terminal output
class Colors:
    """ANSI color codes for terminal output."""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def print_banner(banner: str, color: str = None):
    """Print a banner with optional color."""
    if color:
        print(color + banner + Colors.ENDC)
    else:
        print(banner)


def print_header(text: str):
    """Print a colored header."""
    print(f"\n{Colors.BOLD}{Colors.OKBLUE}{text}{Colors.ENDC}\n")


def print_success(text: str):
    """Print success message in green."""
    print(f"{Colors.OKGREEN}{text}{Colors.ENDC}")


def print_warning(text: str):
    """Print warning message in yellow."""
    print(f"{Colors.WARNING}{text}{Colors.ENDC}")


def print_error(text: str):
    """Print error message in red."""
    print(f"{Colors.FAIL}{text}{Colors.ENDC}")


def print_critical(text: str):
    """Print critical alert with banner."""
    print_banner(CRITICAL_ALERT, Colors.FAIL)
    print(f"{Colors.FAIL}{Colors.BOLD}{text}{Colors.ENDC}\n")

"""Base scanner class for all security scanners."""

import json
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import List, Dict, Any, Optional
from enum import Enum


class Severity(Enum):
    """Severity levels matching CVSS ranges."""
    CRITICAL = "critical"  # 9.0-10.0
    HIGH = "high"          # 7.0-8.9
    MEDIUM = "medium"      # 4.0-6.9
    LOW = "low"            # 0.1-3.9
    INFO = "info"          # 0.0


@dataclass
class Finding:
    """Represents a security finding."""
    id: str
    timestamp: str
    severity: str
    type: str
    title: str
    description: str
    file: Optional[str] = None
    line: Optional[int] = None
    cvss: Optional[float] = None
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    fix: Optional[str] = None
    status: str = "open"
    scanner: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return {k: v for k, v in asdict(self).items() if v is not None}


class Scanner(ABC):
    """Base class for all security scanners."""

    def __init__(self, name: str):
        self.name = name
        self.findings: List[Finding] = []

    @abstractmethod
    def check_available(self) -> bool:
        """Check if scanner tool is available."""
        pass

    @abstractmethod
    def scan(self, target: str) -> List[Finding]:
        """Run scan on target and return findings."""
        pass

    def run_command(self, cmd: List[str], timeout: int = 300) -> subprocess.CompletedProcess:
        """Run a command and return result."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )
            return result
        except subprocess.TimeoutExpired:
            raise TimeoutError(f"Command timed out after {timeout}s: {' '.join(cmd)}")
        except FileNotFoundError:
            raise FileNotFoundError(f"Command not found: {cmd[0]}")

    def generate_finding_id(self) -> str:
        """Generate unique finding ID."""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        return f"AKALI-{timestamp}-{len(self.findings) + 1:03d}"

    def severity_from_cvss(self, cvss: float) -> Severity:
        """Convert CVSS score to severity level."""
        if cvss >= 9.0:
            return Severity.CRITICAL
        elif cvss >= 7.0:
            return Severity.HIGH
        elif cvss >= 4.0:
            return Severity.MEDIUM
        elif cvss > 0.0:
            return Severity.LOW
        else:
            return Severity.INFO

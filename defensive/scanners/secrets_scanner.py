"""Secrets scanner using gitleaks."""

import json
import shutil
from pathlib import Path
from typing import List
from datetime import datetime

from scanner_base import Scanner, Finding, Severity


class SecretsScanner(Scanner):
    """Scanner for hardcoded secrets using gitleaks."""

    def __init__(self):
        super().__init__("secrets")

    def check_available(self) -> bool:
        """Check if gitleaks is installed."""
        return shutil.which("gitleaks") is not None

    def scan(self, target: str) -> List[Finding]:
        """Scan target for secrets."""
        if not self.check_available():
            raise RuntimeError("gitleaks not installed. Run: brew install gitleaks")

        target_path = Path(target).resolve()
        if not target_path.exists():
            raise FileNotFoundError(f"Target not found: {target}")

        # Run gitleaks
        cmd = [
            "gitleaks",
            "detect",
            "--source", str(target_path),
            "--report-format", "json",
            "--no-git",  # Scan files, not git history (faster)
            "--redact"   # Redact secrets in output
        ]

        result = self.run_command(cmd)

        # gitleaks exits with code 1 if secrets found, 0 if clean
        if result.returncode > 1:
            raise RuntimeError(f"gitleaks failed: {result.stderr}")

        # Parse results
        if result.returncode == 1 and result.stdout:
            try:
                leaks = json.loads(result.stdout)
                self.findings = [self._leak_to_finding(leak) for leak in leaks]
            except json.JSONDecodeError:
                raise RuntimeError(f"Failed to parse gitleaks output: {result.stdout}")

        return self.findings

    def _leak_to_finding(self, leak: dict) -> Finding:
        """Convert gitleaks leak to Finding."""
        return Finding(
            id=self.generate_finding_id(),
            timestamp=datetime.now().isoformat(),
            severity=Severity.CRITICAL.value,  # Secrets are always critical
            type="hardcoded_secret",
            title=f"Hardcoded {leak.get('RuleID', 'secret')} detected",
            description=leak.get("Description", "Hardcoded secret found"),
            file=leak.get("File"),
            line=leak.get("StartLine"),
            cvss=9.5,  # Hardcoded secrets are high severity
            cwe="CWE-798",  # Use of Hard-coded Credentials
            owasp="A02:2021 - Cryptographic Failures",
            fix="Remove secret from code. Use environment variables or secrets manager.",
            scanner=self.name
        )

"""Dependency scanner for npm and Python packages."""

import json
import shutil
from pathlib import Path
from typing import List
from datetime import datetime

from .scanner_base import Scanner, Finding, Severity


class DependencyScanner(Scanner):
    """Scanner for vulnerable dependencies in npm and Python."""

    def __init__(self):
        super().__init__("dependencies")

    def check_available(self) -> bool:
        """Check if npm and safety are available."""
        return shutil.which("npm") is not None and shutil.which("safety") is not None

    def scan(self, target: str) -> List[Finding]:
        """Scan target for vulnerable dependencies."""
        target_path = Path(target).resolve()
        if not target_path.exists():
            raise FileNotFoundError(f"Target not found: {target}")

        findings = []

        # Scan Node.js dependencies if package.json exists
        package_json = target_path / "package.json" if target_path.is_dir() else target_path.parent / "package.json"
        if package_json.exists():
            findings.extend(self._scan_npm(package_json.parent))

        # Scan Python dependencies if requirements.txt exists
        requirements = target_path / "requirements.txt" if target_path.is_dir() else target_path.parent / "requirements.txt"
        if requirements.exists():
            findings.extend(self._scan_python(requirements.parent))

        self.findings = findings
        return findings

    def _scan_npm(self, project_dir: Path) -> List[Finding]:
        """Scan npm dependencies."""
        if not shutil.which("npm"):
            return []

        cmd = ["npm", "audit", "--json", "--prefix", str(project_dir)]
        result = self.run_command(cmd)

        # npm audit exits with non-zero if vulns found
        if not result.stdout:
            return []

        try:
            audit = json.loads(result.stdout)
            findings = []

            for vuln_id, vuln in audit.get("vulnerabilities", {}).items():
                severity = vuln.get("severity", "low").lower()
                cvss = self._npm_severity_to_cvss(severity)

                finding = Finding(
                    id=self.generate_finding_id(),
                    timestamp=datetime.now().isoformat(),
                    severity=severity,
                    type="vulnerable_dependency",
                    title=f"Vulnerable npm package: {vuln.get('name')}",
                    description=f"{vuln.get('name')} has known vulnerabilities. {vuln.get('via', [{}])[0].get('title', '')}",
                    cvss=cvss,
                    cwe="CWE-1104",  # Use of Unmaintained Third Party Components
                    owasp="A06:2021 - Vulnerable and Outdated Components",
                    fix=f"Update to {vuln.get('fixAvailable', {}).get('version', 'latest')}. Run: npm update {vuln.get('name')}",
                    scanner=self.name
                )
                findings.append(finding)

            return findings
        except json.JSONDecodeError:
            return []

    def _scan_python(self, project_dir: Path) -> List[Finding]:
        """Scan Python dependencies."""
        if not shutil.which("safety"):
            return []

        requirements = project_dir / "requirements.txt"
        cmd = ["safety", "check", "--file", str(requirements), "--json"]
        result = self.run_command(cmd)

        if not result.stdout:
            return []

        try:
            vulns = json.loads(result.stdout)
            findings = []

            for vuln in vulns:
                cvss = vuln.get("cvssv3", {}).get("base_score", 5.0)
                severity = self.severity_from_cvss(cvss).value

                finding = Finding(
                    id=self.generate_finding_id(),
                    timestamp=datetime.now().isoformat(),
                    severity=severity,
                    type="vulnerable_dependency",
                    title=f"Vulnerable Python package: {vuln.get('package')}",
                    description=vuln.get("vulnerability", "Known vulnerability"),
                    cvss=cvss,
                    cwe="CWE-1104",
                    owasp="A06:2021 - Vulnerable and Outdated Components",
                    fix=f"Update to {vuln.get('latest_version', 'latest')}. Run: pip install {vuln.get('package')}=={vuln.get('latest_version')}",
                    scanner=self.name
                )
                findings.append(finding)

            return findings
        except json.JSONDecodeError:
            return []

    def _npm_severity_to_cvss(self, severity: str) -> float:
        """Convert npm severity to approximate CVSS."""
        severity_map = {
            "critical": 9.5,
            "high": 7.5,
            "moderate": 5.0,
            "low": 3.0,
            "info": 0.0
        }
        return severity_map.get(severity, 5.0)

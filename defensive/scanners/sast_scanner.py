"""Static Application Security Testing (SAST) scanner."""

import json
import shutil
from pathlib import Path
from typing import List
from datetime import datetime

from .scanner_base import Scanner, Finding, Severity


class SASTScanner(Scanner):
    """Scanner for static code analysis security issues."""

    def __init__(self):
        super().__init__("sast")

    def check_available(self) -> bool:
        """Check if SAST tools are available."""
        return shutil.which("bandit") is not None or shutil.which("eslint") is not None

    def scan(self, target: str) -> List[Finding]:
        """Scan target for security issues with SAST."""
        target_path = Path(target).resolve()
        if not target_path.exists():
            raise FileNotFoundError(f"Target not found: {target}")

        findings = []

        # Scan Python files with bandit
        if self._has_python_files(target_path):
            findings.extend(self._scan_bandit(target_path))

        # Scan JavaScript files with eslint
        if self._has_js_files(target_path):
            findings.extend(self._scan_eslint(target_path))

        self.findings = findings
        return findings

    def _has_python_files(self, path: Path) -> bool:
        """Check if target has Python files."""
        if path.is_file():
            return path.suffix == ".py"
        return any(path.rglob("*.py"))

    def _has_js_files(self, path: Path) -> bool:
        """Check if target has JavaScript files."""
        if path.is_file():
            return path.suffix in [".js", ".jsx", ".ts", ".tsx"]
        return any(path.rglob("*.js")) or any(path.rglob("*.jsx"))

    def _scan_bandit(self, target: Path) -> List[Finding]:
        """Scan Python code with bandit."""
        if not shutil.which("bandit"):
            return []

        cmd = ["bandit", "-r", str(target), "-f", "json", "-q"]
        result = self.run_command(cmd)

        if not result.stdout:
            return []

        try:
            report = json.loads(result.stdout)
            findings = []

            for issue in report.get("results", []):
                severity_map = {
                    "HIGH": Severity.HIGH.value,
                    "MEDIUM": Severity.MEDIUM.value,
                    "LOW": Severity.LOW.value
                }
                severity = severity_map.get(issue.get("issue_severity"), "low")

                finding = Finding(
                    id=self.generate_finding_id(),
                    timestamp=datetime.now().isoformat(),
                    severity=severity,
                    type="sast_issue",
                    title=f"{issue.get('test_name')}: {issue.get('issue_text')}",
                    description=issue.get("issue_text"),
                    file=issue.get("filename"),
                    line=issue.get("line_number"),
                    cwe=issue.get("test_id"),  # Bandit test ID
                    fix=issue.get("more_info", "Review code for security best practices"),
                    scanner=self.name
                )
                findings.append(finding)

            return findings
        except json.JSONDecodeError:
            return []

    def _scan_eslint(self, target: Path) -> List[Finding]:
        """Scan JavaScript code with eslint."""
        if not shutil.which("eslint"):
            return []

        # Check if eslint config exists
        eslintrc = target / ".eslintrc.json" if target.is_dir() else target.parent / ".eslintrc.json"
        if not eslintrc.exists():
            # Create minimal config with security plugin
            eslintrc.write_text(json.dumps({
                "plugins": ["security"],
                "extends": ["plugin:security/recommended"]
            }))

        cmd = ["eslint", str(target), "--format", "json"]
        result = self.run_command(cmd)

        if not result.stdout:
            return []

        try:
            reports = json.loads(result.stdout)
            findings = []

            for report in reports:
                for message in report.get("messages", []):
                    # Only include security-related rules
                    if not message.get("ruleId", "").startswith("security/"):
                        continue

                    severity_map = {
                        2: Severity.HIGH.value,  # error
                        1: Severity.MEDIUM.value,  # warning
                        0: Severity.LOW.value   # info
                    }
                    severity = severity_map.get(message.get("severity"), "low")

                    finding = Finding(
                        id=self.generate_finding_id(),
                        timestamp=datetime.now().isoformat(),
                        severity=severity,
                        type="sast_issue",
                        title=f"{message.get('ruleId')}: {message.get('message')}",
                        description=message.get("message"),
                        file=report.get("filePath"),
                        line=message.get("line"),
                        fix="Review code for security best practices. See ESLint security plugin docs.",
                        scanner=self.name
                    )
                    findings.append(finding)

            return findings
        except json.JSONDecodeError:
            return []

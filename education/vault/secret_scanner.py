#!/usr/bin/env python3
"""
Akali Secret Scanner - Find hardcoded secrets in code

Scans source code for:
- API keys and tokens
- Passwords and credentials
- Private keys
- Database connection strings
- AWS/GCP/Azure credentials
- Generic secrets (entropy-based)
"""

import os
import re
from typing import List, Dict, Any, Optional
from pathlib import Path
from dataclasses import dataclass
import json
import math
from collections import Counter


@dataclass
class SecretFinding:
    """Represents a found secret."""
    file_path: str
    line_number: int
    secret_type: str
    matched_text: str
    confidence: str  # high, medium, low
    context: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "secret_type": self.secret_type,
            "matched_text": self.matched_text[:50] + "..." if len(self.matched_text) > 50 else self.matched_text,
            "confidence": self.confidence,
            "context": self.context
        }


class SecretScanner:
    """Scans code for hardcoded secrets."""

    # Regex patterns for different secret types
    PATTERNS = {
        "aws_access_key": {
            "pattern": r"AKIA[0-9A-Z]{16}",
            "confidence": "high"
        },
        "aws_secret_key": {
            "pattern": r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]",
            "confidence": "medium"
        },
        "github_token": {
            "pattern": r"ghp_[0-9a-zA-Z]{36}",
            "confidence": "high"
        },
        "github_oauth": {
            "pattern": r"gho_[0-9a-zA-Z]{36}",
            "confidence": "high"
        },
        "slack_token": {
            "pattern": r"xox[baprs]-([0-9a-zA-Z]{10,48})",
            "confidence": "high"
        },
        "slack_webhook": {
            "pattern": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
            "confidence": "high"
        },
        "google_api_key": {
            "pattern": r"AIza[0-9A-Za-z-_]{35}",
            "confidence": "high"
        },
        "google_oauth": {
            "pattern": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
            "confidence": "high"
        },
        "heroku_api_key": {
            "pattern": r"[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
            "confidence": "high"
        },
        "mailgun_api_key": {
            "pattern": r"key-[0-9a-zA-Z]{32}",
            "confidence": "medium"
        },
        "stripe_api_key": {
            "pattern": r"sk_live_[0-9a-zA-Z]{24}",
            "confidence": "high"
        },
        "stripe_restricted_key": {
            "pattern": r"rk_live_[0-9a-zA-Z]{24}",
            "confidence": "high"
        },
        "square_oauth": {
            "pattern": r"sq0atp-[0-9A-Za-z\-_]{22}",
            "confidence": "high"
        },
        "square_access_token": {
            "pattern": r"sqOatp-[0-9A-Za-z\-_]{22}",
            "confidence": "high"
        },
        "twilio_api_key": {
            "pattern": r"SK[0-9a-fA-F]{32}",
            "confidence": "medium"
        },
        "jwt": {
            "pattern": r"eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
            "confidence": "medium"
        },
        "private_key": {
            "pattern": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            "confidence": "high"
        },
        "password_in_url": {
            "pattern": r"[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}[\"'\\s]",
            "confidence": "high"
        },
        "generic_api_key": {
            "pattern": r"(?i)(api[_-]?key|apikey|api[_-]?secret)['\"]?\s*[:=]\s*['\"]([0-9a-zA-Z\-_]{20,})['\"]",
            "confidence": "medium"
        },
        "generic_token": {
            "pattern": r"(?i)(token|auth[_-]?token)['\"]?\s*[:=]\s*['\"]([0-9a-zA-Z\-_.]{20,})['\"]",
            "confidence": "medium"
        },
        "generic_password": {
            "pattern": r"(?i)(password|passwd|pwd)['\"]?\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
            "confidence": "low"  # High false positive rate
        },
        "database_connection": {
            "pattern": r"(?i)(mongodb|mysql|postgres|postgresql)://[^\s'\"]+",
            "confidence": "high"
        }
    }

    # File extensions to scan
    SCANNABLE_EXTENSIONS = {
        ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php",
        ".env", ".ini", ".yaml", ".yml", ".json", ".xml", ".sh", ".bash",
        ".config", ".conf", ".properties", ".tf", ".tfvars"
    }

    # Files/directories to ignore
    IGNORE_PATTERNS = {
        ".git", "node_modules", "__pycache__", ".venv", "venv",
        "dist", "build", ".next", "coverage", ".pytest_cache"
    }

    def __init__(self, entropy_threshold: float = 4.5):
        """Initialize scanner.

        Args:
            entropy_threshold: Shannon entropy threshold for generic secrets
        """
        self.entropy_threshold = entropy_threshold

    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string.

        Args:
            text: String to analyze

        Returns:
            Entropy value
        """
        if not text:
            return 0.0

        # Calculate character frequency
        counter = Counter(text)
        length = len(text)

        # Calculate entropy
        entropy = 0.0
        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    def is_high_entropy_string(self, text: str, min_length: int = 20) -> bool:
        """Check if string has high entropy (likely a secret).

        Args:
            text: String to check
            min_length: Minimum string length to consider

        Returns:
            True if high entropy, False otherwise
        """
        if len(text) < min_length:
            return False

        # Skip if looks like a file path or URL
        if "/" in text or "\\" in text:
            return False

        # Skip common patterns
        if text.startswith("http") or text.startswith("//"):
            return False

        entropy = self.calculate_entropy(text)
        return entropy >= self.entropy_threshold

    def should_scan_file(self, file_path: Path) -> bool:
        """Check if file should be scanned.

        Args:
            file_path: File path

        Returns:
            True if should scan, False otherwise
        """
        # Check extension
        if file_path.suffix not in self.SCANNABLE_EXTENSIONS:
            return False

        # Check ignore patterns
        for ignore in self.IGNORE_PATTERNS:
            if ignore in file_path.parts:
                return False

        # Skip if file is too large (> 1MB)
        try:
            if file_path.stat().st_size > 1_000_000:
                return False
        except Exception:
            return False

        return True

    def scan_line(self, line: str, line_num: int, file_path: str) -> List[SecretFinding]:
        """Scan a single line for secrets.

        Args:
            line: Line content
            line_num: Line number
            file_path: File path

        Returns:
            List of findings
        """
        findings = []

        # Check against all patterns
        for secret_type, config in self.PATTERNS.items():
            pattern = config["pattern"]
            confidence = config["confidence"]

            matches = re.finditer(pattern, line)
            for match in matches:
                # Skip if it's in a comment or looks like a placeholder
                matched_text = match.group(0)

                # Skip obvious placeholders
                if any(placeholder in matched_text.lower() for placeholder in [
                    "example", "sample", "test", "dummy", "fake", "placeholder",
                    "xxx", "yyy", "zzz", "changeme", "your_", "my_"
                ]):
                    continue

                finding = SecretFinding(
                    file_path=file_path,
                    line_number=line_num,
                    secret_type=secret_type,
                    matched_text=matched_text,
                    confidence=confidence,
                    context=line.strip()
                )
                findings.append(finding)

        # Check for high-entropy strings (generic secrets)
        # Extract quoted strings
        quoted_pattern = r'["\']([^"\']{20,})["\']'
        for match in re.finditer(quoted_pattern, line):
            quoted_text = match.group(1)
            if self.is_high_entropy_string(quoted_text):
                finding = SecretFinding(
                    file_path=file_path,
                    line_number=line_num,
                    secret_type="high_entropy_string",
                    matched_text=quoted_text,
                    confidence="low",
                    context=line.strip()
                )
                findings.append(finding)

        return findings

    def scan_file(self, file_path: Path) -> List[SecretFinding]:
        """Scan a single file for secrets.

        Args:
            file_path: File to scan

        Returns:
            List of findings
        """
        findings = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line_findings = self.scan_line(
                        line,
                        line_num,
                        str(file_path)
                    )
                    findings.extend(line_findings)
        except Exception as e:
            print(f"⚠️  Error scanning {file_path}: {e}")

        return findings

    def scan_directory(self, directory: Path, recursive: bool = True) -> List[SecretFinding]:
        """Scan a directory for secrets.

        Args:
            directory: Directory to scan
            recursive: Scan subdirectories

        Returns:
            List of findings
        """
        findings = []

        if recursive:
            for root, dirs, files in os.walk(directory):
                # Remove ignored directories from search
                dirs[:] = [d for d in dirs if d not in self.IGNORE_PATTERNS]

                for file in files:
                    file_path = Path(root) / file
                    if self.should_scan_file(file_path):
                        file_findings = self.scan_file(file_path)
                        findings.extend(file_findings)
        else:
            for file_path in directory.iterdir():
                if file_path.is_file() and self.should_scan_file(file_path):
                    file_findings = self.scan_file(file_path)
                    findings.extend(file_findings)

        return findings

    def scan(self, target: str, recursive: bool = True) -> List[SecretFinding]:
        """Scan a file or directory.

        Args:
            target: File or directory path
            recursive: Scan subdirectories (for directories)

        Returns:
            List of findings
        """
        target_path = Path(target)

        if not target_path.exists():
            raise ValueError(f"Target does not exist: {target}")

        if target_path.is_file():
            return self.scan_file(target_path)
        elif target_path.is_dir():
            return self.scan_directory(target_path, recursive=recursive)
        else:
            raise ValueError(f"Target is not a file or directory: {target}")

    def generate_report(self, findings: List[SecretFinding]) -> Dict[str, Any]:
        """Generate a scan report.

        Args:
            findings: List of findings

        Returns:
            Report dictionary
        """
        if not findings:
            return {
                "total_findings": 0,
                "by_confidence": {},
                "by_type": {},
                "findings": []
            }

        # Count by confidence
        by_confidence = {"high": 0, "medium": 0, "low": 0}
        for finding in findings:
            by_confidence[finding.confidence] = by_confidence.get(finding.confidence, 0) + 1

        # Count by type
        by_type = {}
        for finding in findings:
            by_type[finding.secret_type] = by_type.get(finding.secret_type, 0) + 1

        return {
            "total_findings": len(findings),
            "by_confidence": by_confidence,
            "by_type": by_type,
            "findings": [f.to_dict() for f in findings]
        }


def main():
    """CLI interface."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Akali Secret Scanner - Find hardcoded secrets"
    )
    parser.add_argument("target", help="File or directory to scan")
    parser.add_argument("--no-recursive", action="store_true", help="Don't scan subdirectories")
    parser.add_argument("--json", action="store_true", help="Output JSON report")
    parser.add_argument("--entropy", type=float, default=4.5, help="Entropy threshold (default: 4.5)")

    args = parser.parse_args()

    # Create scanner
    scanner = SecretScanner(entropy_threshold=args.entropy)

    # Scan
    print(f"🔍 Scanning {args.target}...")
    findings = scanner.scan(args.target, recursive=not args.no_recursive)

    # Generate report
    report = scanner.generate_report(findings)

    if args.json:
        # JSON output
        print(json.dumps(report, indent=2))
    else:
        # Human-readable output
        print(f"\n🥷 Akali Secret Scanner Results\n")
        print(f"Total findings: {report['total_findings']}")

        if report['total_findings'] > 0:
            print(f"\nBy confidence:")
            for confidence in ["high", "medium", "low"]:
                count = report['by_confidence'].get(confidence, 0)
                if count > 0:
                    emoji = {"high": "🔴", "medium": "🟡", "low": "🔵"}[confidence]
                    print(f"  {emoji} {confidence}: {count}")

            print(f"\nBy type:")
            for secret_type, count in sorted(report['by_type'].items(), key=lambda x: -x[1])[:10]:
                print(f"  • {secret_type}: {count}")

            print(f"\n📋 Detailed Findings:\n")
            for finding in findings[:50]:  # Show first 50
                conf_emoji = {"high": "🔴", "medium": "🟡", "low": "🔵"}[finding.confidence]
                print(f"{conf_emoji} {finding.secret_type}")
                print(f"   File: {finding.file_path}:{finding.line_number}")
                print(f"   Match: {finding.matched_text[:60]}...")
                print()

            if len(findings) > 50:
                print(f"... and {len(findings) - 50} more findings")
        else:
            print("\n✅ No secrets found!")


if __name__ == "__main__":
    main()

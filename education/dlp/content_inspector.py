"""Content Inspection Engine for Akali DLP System.

Scans files, git commits, and API payloads for sensitive data violations.
Integrates with PII detector and policy engine for comprehensive DLP.
"""

import os
import sys
import json
import subprocess
from typing import List, Dict, Any, Optional
from pathlib import Path
from dataclasses import dataclass, asdict
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path.home() / "akali"))

from education.dlp.pii_detector import PIIDetector, PIIMatch


@dataclass
class Violation:
    """A DLP policy violation."""
    violation_id: str
    timestamp: str
    source: str  # 'file', 'git', 'api'
    source_path: str  # File path, commit hash, or API endpoint
    pii_matches: List[Dict[str, Any]]
    severity: str  # 'critical', 'high', 'medium', 'low'
    action_taken: Optional[str] = None  # 'warn', 'block', 'redact', 'encrypt'
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


class ContentInspector:
    """Inspects content for DLP violations."""

    # File extensions to scan
    SCANNABLE_EXTENSIONS = {
        '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rb', '.php',
        '.json', '.yaml', '.yml', '.xml', '.env', '.conf', '.config',
        '.sql', '.sh', '.bash', '.zsh', '.txt', '.md', '.csv'
    }

    # Files to always skip
    SKIP_FILES = {
        '.git', 'node_modules', '__pycache__', '.venv', 'venv',
        'build', 'dist', '.next', 'out', 'target', 'bin'
    }

    def __init__(self, pii_detector: Optional[PIIDetector] = None):
        """Initialize content inspector.

        Args:
            pii_detector: PII detector instance (creates new if None)
        """
        self.pii_detector = pii_detector or PIIDetector(sensitivity='medium')
        self.violations_dir = Path.home() / '.akali' / 'dlp_violations'
        self.violations_dir.mkdir(parents=True, exist_ok=True)

    def inspect_file(self, file_path: str) -> Optional[Violation]:
        """Inspect a single file for PII.

        Args:
            file_path: Path to file to inspect

        Returns:
            Violation object if PII found, None otherwise
        """
        # Skip non-scannable files
        if not self._should_scan_file(file_path):
            return None

        # Detect PII
        matches = self.pii_detector.detect_file(file_path)

        if not matches:
            return None

        # Create violation
        violation = Violation(
            violation_id=self._generate_violation_id(),
            timestamp=datetime.utcnow().isoformat() + 'Z',
            source='file',
            source_path=file_path,
            pii_matches=[match.to_dict() for match in matches],
            severity=self._calculate_severity(matches),
            metadata={'total_matches': len(matches)}
        )

        # Save violation
        self._save_violation(violation)

        return violation

    def inspect_directory(self, directory: str, recursive: bool = True) -> List[Violation]:
        """Inspect all files in a directory.

        Args:
            directory: Directory path to scan
            recursive: Scan subdirectories

        Returns:
            List of Violation objects
        """
        violations = []
        directory_path = Path(directory)

        if not directory_path.exists():
            print(f"❌ Directory not found: {directory}")
            return violations

        # Get files to scan
        if recursive:
            files = [f for f in directory_path.rglob('*') if f.is_file()]
        else:
            files = [f for f in directory_path.glob('*') if f.is_file()]

        print(f"🔍 Scanning {len(files)} files in {directory}...")

        for file_path in files:
            # Skip files in excluded directories
            if any(skip in file_path.parts for skip in self.SKIP_FILES):
                continue

            violation = self.inspect_file(str(file_path))
            if violation:
                violations.append(violation)

        return violations

    def inspect_git_commit(self, commit_hash: str = 'HEAD', repo_path: str = '.') -> Optional[Violation]:
        """Inspect a git commit for PII in changed files.

        Args:
            commit_hash: Git commit hash (default: HEAD)
            repo_path: Path to git repository

        Returns:
            Violation object if PII found, None otherwise
        """
        try:
            # Get diff of commit
            result = subprocess.run(
                ['git', 'show', commit_hash],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                print(f"❌ Failed to get commit diff: {result.stderr}")
                return None

            diff_text = result.stdout

            # Detect PII in diff
            matches = self.pii_detector.detect(diff_text)

            if not matches:
                return None

            # Create violation
            violation = Violation(
                violation_id=self._generate_violation_id(),
                timestamp=datetime.utcnow().isoformat() + 'Z',
                source='git',
                source_path=commit_hash,
                pii_matches=[match.to_dict() for match in matches],
                severity=self._calculate_severity(matches),
                metadata={
                    'repo_path': repo_path,
                    'total_matches': len(matches)
                }
            )

            # Save violation
            self._save_violation(violation)

            return violation

        except subprocess.TimeoutExpired:
            print("❌ Git command timed out")
            return None
        except Exception as e:
            print(f"❌ Error inspecting commit: {e}")
            return None

    def inspect_git_staged(self, repo_path: str = '.') -> Optional[Violation]:
        """Inspect staged changes (pre-commit).

        Args:
            repo_path: Path to git repository

        Returns:
            Violation object if PII found, None otherwise
        """
        try:
            # Get staged diff
            result = subprocess.run(
                ['git', 'diff', '--cached'],
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                print(f"❌ Failed to get staged diff: {result.stderr}")
                return None

            diff_text = result.stdout

            if not diff_text.strip():
                return None  # No staged changes

            # Detect PII in diff
            matches = self.pii_detector.detect(diff_text)

            if not matches:
                return None

            # Create violation
            violation = Violation(
                violation_id=self._generate_violation_id(),
                timestamp=datetime.utcnow().isoformat() + 'Z',
                source='git',
                source_path='staged',
                pii_matches=[match.to_dict() for match in matches],
                severity=self._calculate_severity(matches),
                metadata={
                    'repo_path': repo_path,
                    'total_matches': len(matches)
                }
            )

            # Save violation
            self._save_violation(violation)

            return violation

        except subprocess.TimeoutExpired:
            print("❌ Git command timed out")
            return None
        except Exception as e:
            print(f"❌ Error inspecting staged changes: {e}")
            return None

    def inspect_api_request(self, endpoint: str, payload: Dict[str, Any]) -> Optional[Violation]:
        """Inspect API request payload for PII.

        Args:
            endpoint: API endpoint path
            payload: Request payload (dict)

        Returns:
            Violation object if PII found, None otherwise
        """
        # Convert payload to string for scanning
        payload_str = json.dumps(payload, indent=2)

        # Detect PII
        matches = self.pii_detector.detect(payload_str)

        if not matches:
            return None

        # Create violation
        violation = Violation(
            violation_id=self._generate_violation_id(),
            timestamp=datetime.utcnow().isoformat() + 'Z',
            source='api',
            source_path=endpoint,
            pii_matches=[match.to_dict() for match in matches],
            severity=self._calculate_severity(matches),
            metadata={
                'payload_size': len(payload_str),
                'total_matches': len(matches)
            }
        )

        # Save violation
        self._save_violation(violation)

        return violation

    def inspect_api_response(self, endpoint: str, response: Dict[str, Any]) -> Optional[Violation]:
        """Inspect API response for PII leakage.

        Args:
            endpoint: API endpoint path
            response: Response payload (dict)

        Returns:
            Violation object if PII found, None otherwise
        """
        # Convert response to string for scanning
        response_str = json.dumps(response, indent=2)

        # Detect PII
        matches = self.pii_detector.detect(response_str)

        if not matches:
            return None

        # Create violation
        violation = Violation(
            violation_id=self._generate_violation_id(),
            timestamp=datetime.utcnow().isoformat() + 'Z',
            source='api',
            source_path=f"{endpoint} (response)",
            pii_matches=[match.to_dict() for match in matches],
            severity=self._calculate_severity(matches),
            metadata={
                'response_size': len(response_str),
                'total_matches': len(matches),
                'is_response': True
            }
        )

        # Save violation
        self._save_violation(violation)

        return violation

    def _should_scan_file(self, file_path: str) -> bool:
        """Check if file should be scanned."""
        path = Path(file_path)

        # Check if file exists
        if not path.exists() or not path.is_file():
            return False

        # Check extension
        if path.suffix not in self.SCANNABLE_EXTENSIONS:
            return False

        # Check if in excluded directory
        if any(skip in path.parts for skip in self.SKIP_FILES):
            return False

        # Check file size (skip files > 10MB)
        try:
            if path.stat().st_size > 10 * 1024 * 1024:
                return False
        except Exception:
            return False

        return True

    def _calculate_severity(self, matches: List[PIIMatch]) -> str:
        """Calculate violation severity based on PII matches.

        Critical: SSN, Credit Card, Passport, Medical ID
        High: Email, Phone, Bank Account, API Key
        Medium: DOB, Address, Driver's License
        Low: IP Address
        """
        critical_types = {'ssn', 'credit_card', 'passport', 'medical_id'}
        high_types = {'email', 'phone', 'bank_account', 'api_key'}
        medium_types = {'date_of_birth', 'address', 'driver_license'}

        for match in matches:
            pii_type = match.pii_type.value
            if pii_type in critical_types:
                return 'critical'

        for match in matches:
            pii_type = match.pii_type.value
            if pii_type in high_types:
                return 'high'

        for match in matches:
            pii_type = match.pii_type.value
            if pii_type in medium_types:
                return 'medium'

        return 'low'

    def _generate_violation_id(self) -> str:
        """Generate unique violation ID."""
        timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
        return f"DLP-{timestamp}-{os.urandom(4).hex()}"

    def _save_violation(self, violation: Violation):
        """Save violation to disk."""
        file_name = f"{violation.violation_id}.json"
        file_path = self.violations_dir / file_name

        with open(file_path, 'w') as f:
            json.dump(violation.to_dict(), f, indent=2)

    def get_violations(self, severity: Optional[str] = None) -> List[Violation]:
        """Get all saved violations.

        Args:
            severity: Filter by severity (optional)

        Returns:
            List of Violation objects
        """
        violations = []

        for file_path in self.violations_dir.glob('*.json'):
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    violation = Violation(**data)

                    if severity is None or violation.severity == severity:
                        violations.append(violation)
            except Exception as e:
                print(f"⚠️  Failed to load violation {file_path}: {e}")

        # Sort by timestamp (newest first)
        violations.sort(key=lambda v: v.timestamp, reverse=True)

        return violations

    def clear_violations(self):
        """Clear all saved violations."""
        for file_path in self.violations_dir.glob('*.json'):
            file_path.unlink()


def main():
    """Test content inspector with sample data."""
    inspector = ContentInspector()

    print("🔍 Testing Content Inspector\n")
    print("=" * 70)

    # Test 1: Inspect sample text
    print("\nTest 1: Inspect text content")
    test_text = """
    User record:
    - SSN: 123-45-6789
    - Email: john@example.com
    - Phone: (555) 123-4567
    - Credit Card: 4532-1234-5678-9010
    """

    matches = inspector.pii_detector.detect(test_text)
    if matches:
        print(f"   Found {len(matches)} PII match(es):")
        for match in matches:
            print(f"   - {match.pii_type.value}: {match.value}")
    else:
        print("   ✅ No PII detected")

    # Test 2: Check if we can inspect git (optional)
    print("\nTest 2: Git inspection capability")
    try:
        result = subprocess.run(
            ['git', '--version'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            print(f"   ✅ Git available: {result.stdout.strip()}")
        else:
            print("   ⚠️  Git not available")
    except Exception as e:
        print(f"   ⚠️  Git not available: {e}")

    # Test 3: API payload inspection
    print("\nTest 3: API payload inspection")
    test_payload = {
        "user": {
            "name": "John Doe",
            "email": "john@example.com",
            "ssn": "123-45-6789",
            "phone": "(555) 123-4567"
        }
    }

    violation = inspector.inspect_api_request("/api/users", test_payload)
    if violation:
        print(f"   ⚠️  Violation detected: {violation.violation_id}")
        print(f"   Severity: {violation.severity}")
        print(f"   Matches: {len(violation.pii_matches)}")
    else:
        print("   ✅ No violations")

    # Summary
    all_violations = inspector.get_violations()
    print("\n" + "=" * 70)
    print(f"\n📊 Total violations stored: {len(all_violations)}")

    if all_violations:
        print("\nRecent violations:")
        for v in all_violations[:5]:
            print(f"   - {v.violation_id}: {v.source} ({v.severity})")


if __name__ == '__main__':
    main()

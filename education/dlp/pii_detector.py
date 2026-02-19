"""PII Detection Engine for Akali DLP System.

Detects personally identifiable information (PII) in text using regex patterns
and validation libraries. Supports 10+ PII types with configurable sensitivity.
"""

import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum


class PIIType(Enum):
    """Types of PII that can be detected."""
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    EMAIL = "email"
    PHONE = "phone"
    IP_ADDRESS = "ip_address"
    PASSPORT = "passport"
    DRIVER_LICENSE = "driver_license"
    DATE_OF_BIRTH = "date_of_birth"
    ADDRESS = "address"
    MEDICAL_ID = "medical_id"
    BANK_ACCOUNT = "bank_account"
    API_KEY = "api_key"


@dataclass
class PIIMatch:
    """A detected PII match."""
    pii_type: PIIType
    value: str
    confidence: float  # 0.0 to 1.0
    start_pos: int
    end_pos: int
    context: str  # Surrounding text
    line_number: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = asdict(self)
        result['pii_type'] = self.pii_type.value
        return result


class PIIDetector:
    """Detects PII in text using regex patterns and validation."""

    # Regex patterns for PII detection
    PATTERNS = {
        PIIType.SSN: [
            r'\b\d{3}-\d{2}-\d{4}\b',  # 123-45-6789
            r'\b\d{3}\s\d{2}\s\d{4}\b',  # 123 45 6789
            r'\b\d{9}\b',  # 123456789 (lower confidence)
        ],
        PIIType.CREDIT_CARD: [
            r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
            r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
        ],
        PIIType.EMAIL: [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        ],
        PIIType.PHONE: [
            r'\b(?:\+?1[-.]?)?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\b',  # US phone
            r'\b\d{3}-\d{3}-\d{4}\b',
            r'\b\(\d{3}\)\s?\d{3}-\d{4}\b',
        ],
        PIIType.IP_ADDRESS: [
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',  # IPv6
        ],
        PIIType.PASSPORT: [
            r'\b[A-Z]{1,2}[0-9]{6,9}\b',  # US passport: A12345678
        ],
        PIIType.DRIVER_LICENSE: [
            r'\b[A-Z]{1,2}[0-9]{5,8}\b',  # Varies by state
        ],
        PIIType.DATE_OF_BIRTH: [
            r'\b(?:0?[1-9]|1[0-2])[-/](?:0?[1-9]|[12][0-9]|3[01])[-/](?:19|20)\d{2}\b',  # MM/DD/YYYY
            r'\b(?:19|20)\d{2}[-/](?:0?[1-9]|1[0-2])[-/](?:0?[1-9]|[12][0-9]|3[01])\b',  # YYYY-MM-DD
        ],
        PIIType.ADDRESS: [
            r'\b\d+\s+[A-Z][a-z]+\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way|Court|Ct)\b',
        ],
        PIIType.MEDICAL_ID: [
            r'\b[A-Z]{2}\d{6,10}\b',  # Medical record numbers
        ],
        PIIType.BANK_ACCOUNT: [
            r'\b\d{8,17}\b',  # Bank account numbers (broad)
        ],
        PIIType.API_KEY: [
            r'(?i)(api[_-]?key|apikey|access[_-]?key|secret[_-]?key)[\s:=]+["\']?([a-zA-Z0-9_\-]{20,})["\']?',
            r'(?i)(bearer|token)[\s:]+[a-zA-Z0-9_\-\.]{20,}',
        ],
    }

    # Keywords that indicate nearby PII (for context-aware detection)
    CONTEXT_KEYWORDS = {
        PIIType.SSN: ['ssn', 'social security', 'social-security-number'],
        PIIType.CREDIT_CARD: ['credit card', 'card number', 'cc', 'visa', 'mastercard'],
        PIIType.EMAIL: ['email', 'e-mail', 'contact'],
        PIIType.PHONE: ['phone', 'telephone', 'mobile', 'cell'],
        PIIType.DATE_OF_BIRTH: ['dob', 'date of birth', 'birthdate', 'birthday'],
        PIIType.ADDRESS: ['address', 'street', 'city', 'zip'],
        PIIType.PASSPORT: ['passport', 'passport number', 'passport#'],
        PIIType.MEDICAL_ID: ['mrn', 'medical record', 'patient id'],
        PIIType.BANK_ACCOUNT: ['account number', 'bank account', 'routing'],
        PIIType.API_KEY: ['api key', 'secret', 'token', 'credential'],
    }

    def __init__(self, sensitivity: str = 'medium'):
        """Initialize PII detector.

        Args:
            sensitivity: Detection sensitivity (low/medium/high)
                low: Only high-confidence matches
                medium: Balanced detection
                high: Include low-confidence matches
        """
        self.sensitivity = sensitivity
        self.compiled_patterns = self._compile_patterns()

    def _compile_patterns(self) -> Dict[PIIType, List[re.Pattern]]:
        """Compile regex patterns for better performance."""
        compiled = {}
        for pii_type, patterns in self.PATTERNS.items():
            compiled[pii_type] = [re.compile(pattern) for pattern in patterns]
        return compiled

    def detect(self, text: str, line_number: Optional[int] = None) -> List[PIIMatch]:
        """Detect PII in text.

        Args:
            text: Text to scan for PII
            line_number: Optional line number for context

        Returns:
            List of PIIMatch objects
        """
        matches = []

        for pii_type, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                for match in pattern.finditer(text):
                    value = match.group(0)
                    start_pos = match.start()
                    end_pos = match.end()

                    # Calculate confidence based on pattern and context
                    confidence = self._calculate_confidence(
                        pii_type, value, text, start_pos, end_pos
                    )

                    # Filter by sensitivity
                    if self._should_include(confidence):
                        context = self._extract_context(text, start_pos, end_pos)

                        matches.append(PIIMatch(
                            pii_type=pii_type,
                            value=value,
                            confidence=confidence,
                            start_pos=start_pos,
                            end_pos=end_pos,
                            context=context,
                            line_number=line_number
                        ))

        # Remove duplicates (same PII type and value)
        matches = self._deduplicate_matches(matches)

        return matches

    def detect_file(self, file_path: str) -> List[PIIMatch]:
        """Detect PII in a file.

        Args:
            file_path: Path to file to scan

        Returns:
            List of PIIMatch objects with line numbers
        """
        matches = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line_matches = self.detect(line, line_number=line_num)
                    matches.extend(line_matches)
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")

        return matches

    def _calculate_confidence(
        self,
        pii_type: PIIType,
        value: str,
        text: str,
        start_pos: int,
        end_pos: int
    ) -> float:
        """Calculate confidence score for a PII match.

        Factors:
        - Pattern specificity (formatted vs unformatted)
        - Context keywords nearby
        - Validation checks (Luhn for credit cards, etc.)
        """
        confidence = 0.5  # Base confidence

        # Boost confidence for formatted patterns
        if pii_type == PIIType.SSN and '-' in value:
            confidence += 0.3
        elif pii_type == PIIType.CREDIT_CARD:
            if self._luhn_check(value.replace(' ', '').replace('-', '')):
                confidence += 0.4
        elif pii_type == PIIType.EMAIL and '@' in value and '.' in value:
            confidence += 0.3

        # Check for context keywords
        context_window = text[max(0, start_pos - 50):min(len(text), end_pos + 50)].lower()
        keywords = self.CONTEXT_KEYWORDS.get(pii_type, [])

        for keyword in keywords:
            if keyword in context_window:
                confidence += 0.2
                break

        return min(1.0, confidence)

    def _luhn_check(self, card_number: str) -> bool:
        """Validate credit card number using Luhn algorithm."""
        if not card_number.isdigit():
            return False

        digits = [int(d) for d in card_number]
        checksum = 0

        for i in range(len(digits) - 2, -1, -2):
            digits[i] *= 2
            if digits[i] > 9:
                digits[i] -= 9

        checksum = sum(digits)
        return checksum % 10 == 0

    def _should_include(self, confidence: float) -> bool:
        """Determine if match should be included based on sensitivity."""
        thresholds = {
            'low': 0.8,
            'medium': 0.6,
            'high': 0.4
        }
        return confidence >= thresholds.get(self.sensitivity, 0.6)

    def _extract_context(self, text: str, start_pos: int, end_pos: int, window: int = 30) -> str:
        """Extract surrounding context for a match."""
        context_start = max(0, start_pos - window)
        context_end = min(len(text), end_pos + window)

        context = text[context_start:context_end]

        # Add ellipsis if truncated
        if context_start > 0:
            context = '...' + context
        if context_end < len(text):
            context = context + '...'

        return context

    def _deduplicate_matches(self, matches: List[PIIMatch]) -> List[PIIMatch]:
        """Remove duplicate matches (same type and value at same position)."""
        seen = set()
        unique_matches = []

        for match in matches:
            key = (match.pii_type, match.value, match.start_pos)
            if key not in seen:
                seen.add(key)
                unique_matches.append(match)

        return unique_matches

    def get_summary(self, matches: List[PIIMatch]) -> Dict[str, Any]:
        """Generate summary statistics for matches.

        Args:
            matches: List of PIIMatch objects

        Returns:
            Summary dictionary with counts by type and severity
        """
        summary = {
            'total_matches': len(matches),
            'by_type': {},
            'by_confidence': {
                'high': 0,
                'medium': 0,
                'low': 0
            }
        }

        for match in matches:
            # Count by type
            pii_type_str = match.pii_type.value
            summary['by_type'][pii_type_str] = summary['by_type'].get(pii_type_str, 0) + 1

            # Count by confidence
            if match.confidence >= 0.8:
                summary['by_confidence']['high'] += 1
            elif match.confidence >= 0.6:
                summary['by_confidence']['medium'] += 1
            else:
                summary['by_confidence']['low'] += 1

        return summary


def main():
    """Test PII detector with sample data."""
    detector = PIIDetector(sensitivity='medium')

    # Test samples
    test_texts = [
        "John's SSN is 123-45-6789 and email is john@example.com",
        "Credit card: 4532-1234-5678-9010, expires 12/25",
        "Call me at (555) 123-4567 or email support@company.com",
        "Patient DOB: 01/15/1985, MRN: AB1234567",
        "IP address: 192.168.1.100, API key: sk_live_abcdef123456789012345678",
        "Home address: 123 Main Street, Anytown",
        "Passport: A12345678, Driver's License: D1234567",
    ]

    print("🔍 Testing PII Detector\n")
    print("=" * 70)

    for i, text in enumerate(test_texts, 1):
        print(f"\nTest {i}: {text[:50]}...")
        matches = detector.detect(text)

        if matches:
            print(f"   Found {len(matches)} PII match(es):")
            for match in matches:
                print(f"   - {match.pii_type.value}: '{match.value}' (confidence: {match.confidence:.2f})")
        else:
            print("   ✅ No PII detected")

    # Summary
    all_matches = []
    for text in test_texts:
        all_matches.extend(detector.detect(text))

    summary = detector.get_summary(all_matches)
    print("\n" + "=" * 70)
    print(f"\n📊 Summary: {summary['total_matches']} total PII matches")
    print(f"\nBy Type:")
    for pii_type, count in summary['by_type'].items():
        print(f"   {pii_type}: {count}")
    print(f"\nBy Confidence:")
    for level, count in summary['by_confidence'].items():
        print(f"   {level}: {count}")


if __name__ == '__main__':
    main()

"""WPA/WPA2/WPA3 encryption analyzer."""

from typing import Literal


SecurityLevel = Literal["strong", "moderate", "weak", "insecure"]


class WPAAnalyzer:
    """Analyze WPA encryption methods and security levels"""

    def identify_encryption(self, encryption_string: str) -> str:
        """Identify WPA encryption type from string"""
        enc = encryption_string.upper()

        if "WPA3" in enc and "SAE" in enc:
            return "WPA3-SAE"
        elif "WPA2" in enc and "PSK" in enc:
            return "WPA2-PSK"
        elif "WPA" in enc and "PSK" in enc:
            return "WPA-PSK"
        elif "WEP" in enc:
            return "WEP"
        elif "OPEN" in enc or not enc.strip():
            return "Open"
        else:
            return encryption_string

    def assess_security(self, encryption_type: str) -> SecurityLevel:
        """Assess security level of encryption type"""
        enc = encryption_type.upper()

        # Strong: WPA3
        if "WPA3" in enc:
            return "strong"

        # Moderate: WPA2
        if "WPA2" in enc:
            return "moderate"

        # Weak: WPA1, WEP
        if "WPA-" in enc or "WPA " in enc or "WEP" in enc:
            return "weak"

        # Insecure: Open/None
        if "OPEN" in enc or not enc.strip():
            return "insecure"

        # Unknown/other defaults to weak
        return "weak"

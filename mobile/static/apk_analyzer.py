import subprocess
import xml.etree.ElementTree as ET
import re
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

@dataclass
class DecompileResult:
    success: bool
    output_dir: Path
    error: Optional[str] = None

@dataclass
class AndroidManifest:
    package_name: str
    permissions: list[str]
    min_sdk_version: int
    target_sdk_version: int
    debuggable: bool
    activities: list[str]

@dataclass
class Secret:
    type: str
    value: str
    file_path: Path
    line_number: int
    severity: str

# Secret patterns
SECRET_PATTERNS = {
    'api_key': [
        r'api[_-]?key.*?["\']([a-zA-Z0-9_-]{20,})["\']',
        r'apikey.*?["\']([a-zA-Z0-9_-]{20,})["\']',
    ],
    'aws_key': [
        r'AKIA[0-9A-Z]{16}',
    ],
    'password': [
        r'password.*?["\']([^"\']{8,})["\']',
    ],
    'token': [
        r'token.*?["\']([a-zA-Z0-9_-]{20,})["\']',
        r'auth.*?["\']([a-zA-Z0-9_-]{20,})["\']',
    ],
    'private_key': [
        r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
    ]
}

class APKAnalyzer:
    """Android APK static analysis"""

    def __init__(self):
        self.temp_dir = Path("/tmp/akali/apk_analysis")
        self.temp_dir.mkdir(parents=True, exist_ok=True)

    def decompile(self, apk_path: Path) -> DecompileResult:
        """Decompile APK using apktool"""
        output_dir = self.temp_dir / apk_path.stem

        try:
            cmd = ["apktool", "d", str(apk_path), "-o", str(output_dir), "-f"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)

            return DecompileResult(
                success=True,
                output_dir=output_dir
            )
        except subprocess.CalledProcessError as e:
            return DecompileResult(
                success=False,
                output_dir=output_dir,
                error=str(e)
            )

    def parse_manifest(self, manifest_path: Path) -> AndroidManifest:
        """Parse AndroidManifest.xml"""
        tree = ET.parse(manifest_path)
        root = tree.getroot()

        # Extract package name
        package_name = root.get('package', '')

        # Extract permissions
        permissions = [
            perm.get('{http://schemas.android.com/apk/res/android}name', '')
            for perm in root.findall('.//uses-permission')
        ]

        # Extract SDK versions
        uses_sdk = root.find('.//uses-sdk')
        min_sdk = int(uses_sdk.get('{http://schemas.android.com/apk/res/android}minSdkVersion', 1)) if uses_sdk is not None else 1
        target_sdk = int(uses_sdk.get('{http://schemas.android.com/apk/res/android}targetSdkVersion', 1)) if uses_sdk is not None else 1

        # Check if debuggable
        application = root.find('.//application')
        debuggable = application.get('{http://schemas.android.com/apk/res/android}debuggable', 'false') == 'true' if application is not None else False

        # Extract activities
        activities = [
            activity.get('{http://schemas.android.com/apk/res/android}name', '')
            for activity in root.findall('.//activity')
        ]

        return AndroidManifest(
            package_name=package_name,
            permissions=permissions,
            min_sdk_version=min_sdk,
            target_sdk_version=target_sdk,
            debuggable=debuggable,
            activities=activities
        )

    def find_secrets(self, code_dir: Path) -> list[Secret]:
        """Scan for hardcoded secrets in decompiled code"""
        secrets = []

        # Scan all Java, Kotlin, XML files
        for ext in ['*.java', '*.kt', '*.xml']:
            for file_path in code_dir.rglob(ext):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()

                    for line_num, line in enumerate(lines, 1):
                        for secret_type, patterns in SECRET_PATTERNS.items():
                            for pattern in patterns:
                                match = re.search(pattern, line, re.IGNORECASE)
                                if match:
                                    value = match.group(1) if match.groups() else match.group(0)

                                    # Severity based on type
                                    severity = 'critical' if secret_type in ['aws_key', 'private_key'] else 'high'

                                    secrets.append(Secret(
                                        type=secret_type,
                                        value=value[:50],  # Truncate for safety
                                        file_path=file_path,
                                        line_number=line_num,
                                        severity=severity
                                    ))
                except Exception:
                    continue

        return secrets

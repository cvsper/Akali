import subprocess
import xml.etree.ElementTree as ET
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

import subprocess
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

@dataclass
class DecompileResult:
    success: bool
    output_dir: Path
    error: Optional[str] = None

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

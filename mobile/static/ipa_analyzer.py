import zipfile
import shutil
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

@dataclass
class ExtractionResult:
    success: bool
    app_dir: Path
    error: Optional[str] = None

class IPAAnalyzer:
    """iOS IPA static analysis"""

    def __init__(self):
        self.temp_dir = Path("/tmp/akali/ipa_analysis")
        self.temp_dir.mkdir(parents=True, exist_ok=True)

    def extract(self, ipa_path: Path) -> ExtractionResult:
        """Extract IPA file (it's just a ZIP)"""
        output_dir = self.temp_dir / ipa_path.stem

        try:
            # Clean previous extraction
            if output_dir.exists():
                shutil.rmtree(output_dir)

            # Extract IPA
            with zipfile.ZipFile(ipa_path, 'r') as zip_ref:
                zip_ref.extractall(output_dir)

            # Find .app directory (inside Payload/)
            payload_dir = output_dir / "Payload"
            app_dirs = list(payload_dir.glob("*.app"))

            if not app_dirs:
                return ExtractionResult(
                    success=False,
                    app_dir=output_dir,
                    error="No .app directory found in Payload/"
                )

            return ExtractionResult(
                success=True,
                app_dir=app_dirs[0]
            )
        except Exception as e:
            return ExtractionResult(
                success=False,
                app_dir=output_dir,
                error=str(e)
            )

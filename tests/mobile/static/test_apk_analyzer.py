import pytest
from pathlib import Path
from mobile.static.apk_analyzer import APKAnalyzer

def test_apk_decompilation():
    """Test APK can be decompiled"""
    analyzer = APKAnalyzer()
    test_apk = Path("tests/fixtures/test.apk")

    result = analyzer.decompile(test_apk)

    assert result.success is True
    assert result.output_dir.exists()
    assert (result.output_dir / "AndroidManifest.xml").exists()

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

def test_parse_manifest():
    """Test AndroidManifest.xml parsing"""
    analyzer = APKAnalyzer()
    manifest_path = Path("tests/fixtures/AndroidManifest.xml")

    manifest = analyzer.parse_manifest(manifest_path)

    assert manifest.package_name is not None
    assert isinstance(manifest.permissions, list)
    assert manifest.min_sdk_version is not None

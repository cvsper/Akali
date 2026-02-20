import pytest
from pathlib import Path
from mobile.static.ipa_analyzer import IPAAnalyzer

def test_ipa_extraction():
    """Test IPA can be extracted"""
    analyzer = IPAAnalyzer()
    test_ipa = Path("tests/fixtures/test.ipa")

    result = analyzer.extract(test_ipa)

    assert result.success is True
    assert result.app_dir.exists()
    assert (result.app_dir / "Info.plist").exists()

def test_parse_plist():
    """Test Info.plist parsing"""
    analyzer = IPAAnalyzer()
    plist_path = Path("tests/fixtures/Info.plist")

    plist = analyzer.parse_plist(plist_path)

    assert plist.bundle_id is not None
    assert isinstance(plist.permissions, dict)
    assert plist.version is not None

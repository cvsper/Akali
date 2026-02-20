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

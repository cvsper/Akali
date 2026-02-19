#!/usr/bin/env python3
"""Quick test of phishing simulation system"""

import sys
from pathlib import Path

# Add to path
sys.path.insert(0, str(Path.home() / "akali"))

from education.phishing.campaign_manager import CampaignManager
from education.phishing.report_generator import ReportGenerator

def test_templates():
    """Test template loading"""
    print("Testing template loading...")
    manager = CampaignManager()
    templates = manager.list_templates()

    print(f"✅ Loaded {len(templates)} templates")

    # Test loading specific template
    template = manager.get_template('password_reset')
    assert template is not None
    assert template['id'] == 'password_reset'
    print("✅ Template loading works")

def test_campaign_creation():
    """Test campaign creation"""
    print("\nTesting campaign creation...")
    manager = CampaignManager()

    targets = [
        {'email': 'test1@example.com', 'name': 'Test User 1'},
        {'email': 'test2@example.com', 'name': 'Test User 2'}
    ]

    campaign_id = manager.create_campaign(
        name="Test Campaign",
        template_id="password_reset",
        targets=targets,
        description="Test campaign for validation"
    )

    print(f"✅ Created campaign: {campaign_id}")

    # Verify campaign
    campaign = manager.get_campaign(campaign_id)
    assert campaign is not None
    assert campaign.name == "Test Campaign"
    assert campaign.status == "draft"
    print("✅ Campaign creation works")

    # Test getting targets
    campaign_targets = manager.get_campaign_targets(campaign_id)
    assert len(campaign_targets) == 2
    print("✅ Target tracking works")

    # Test results
    results = manager.get_campaign_results(campaign_id)
    assert results['total_targets'] == 2
    assert results['emails_sent'] == 0
    print("✅ Results tracking works")

    return campaign_id

def test_reporting(campaign_id):
    """Test report generation"""
    print("\nTesting report generation...")
    generator = ReportGenerator()

    report = generator.generate_campaign_report(campaign_id)
    assert 'campaign' in report
    assert 'metrics' in report
    assert 'analysis' in report
    print("✅ Report generation works")

    # Test export
    report_path = generator.export_json_report(campaign_id)
    assert Path(report_path).exists()
    print(f"✅ JSON export works: {report_path}")

def main():
    print("\n🥷 Akali Phishing System Test\n")
    print("="*60)

    try:
        test_templates()
        campaign_id = test_campaign_creation()
        test_reporting(campaign_id)

        print("\n" + "="*60)
        print("✅ All tests passed!")
        print("="*60 + "\n")

    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()

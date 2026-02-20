import pytest
import tempfile
from pathlib import Path
from redteam.campaigns.orchestrator import CampaignOrchestrator

@pytest.fixture
def orchestrator():
    """Create orchestrator with temporary database"""
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = f.name

    o = CampaignOrchestrator(db_path=db_path)
    yield o

    # Cleanup
    Path(db_path).unlink(missing_ok=True)

def test_create_campaign(orchestrator):
    """Test campaign creation"""
    campaign_id = orchestrator.create_campaign(
        name="mobile-test",
        target="com.example.app",
        mode="purple"
    )

    assert campaign_id is not None
    campaign = orchestrator.get_campaign(campaign_id)
    assert campaign.name == "mobile-test"
    assert campaign.mode == "purple"

import pytest
import tempfile
from pathlib import Path
from redteam.c2.commander import C2Commander

@pytest.fixture
def commander():
    """Create commander with temporary database"""
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = f.name

    c = C2Commander(db_path=db_path)
    yield c

    # Cleanup
    Path(db_path).unlink(missing_ok=True)

def test_register_agent(commander):
    """Test agent registration"""
    agent_id = commander.register_agent(
        hostname="test-device",
        platform="android",
        mode="zim"
    )

    assert agent_id is not None
    assert len(commander.list_agents()) == 1

def test_send_task(commander):
    """Test sending task to agent"""
    agent_id = commander.register_agent("test", "linux", "zim")

    task_id = commander.send_task(agent_id, "shell", "ls -la")

    assert task_id is not None
    # Task should be in database (ZimMemory may or may not be available)

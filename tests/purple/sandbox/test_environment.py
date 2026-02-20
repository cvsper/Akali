"""Tests for PurpleTeamSandbox environment"""
import pytest
import json
from unittest.mock import Mock, MagicMock, patch
from pathlib import Path
from purple.sandbox.environment import PurpleTeamSandbox


@pytest.fixture
def mock_docker_manager():
    """Mock Docker manager"""
    manager = MagicMock()
    manager.create_container.return_value = {
        "success": True,
        "container_id": "container-123",
        "name": "test-container",
        "status": "running"
    }
    manager.create_network.return_value = {
        "success": True,
        "network_id": "network-123",
        "name": "test-network"
    }
    manager.stop_container.return_value = {"success": True}
    manager.remove_container.return_value = {"success": True}
    manager.remove_network.return_value = {"success": True}
    manager.get_container_info.return_value = {
        "success": True,
        "id": "container-123",
        "ip_address": "172.17.0.2",
        "ports": {"80/tcp": [{"HostPort": "8080"}]},
        "status": "running"
    }
    manager.check_docker_available.return_value = True
    return manager


@pytest.fixture
def mock_vulnerable_apps():
    """Mock VulnerableApps"""
    apps = MagicMock()
    apps.deploy_app.return_value = {
        "success": True,
        "app_name": "dvwa",
        "container_id": "app-container-123",
        "port": 8080,
        "access_url": "http://localhost:8080"
    }
    apps.stop_app.return_value = {"success": True}
    apps.remove_app.return_value = {"success": True}
    apps.get_app_status.return_value = {"success": True, "status": "running"}
    return apps


@pytest.fixture
def mock_honeypots():
    """Mock Honeypots"""
    honeypots = MagicMock()
    honeypots.deploy_honeypot.return_value = {
        "success": True,
        "service_type": "ssh",
        "container_id": "honeypot-container-123",
        "port": 2222
    }
    honeypots.stop_honeypot.return_value = {"success": True}
    honeypots.remove_honeypot.return_value = {"success": True}
    return honeypots


@pytest.fixture
def mock_network_simulator():
    """Mock NetworkSimulator"""
    simulator = MagicMock()
    simulator.create_topology.return_value = {
        "success": True,
        "topology_type": "single_host",
        "topology_id": "topology-123",
        "networks": [{"name": "test-network", "id": "network-123"}]
    }
    simulator.destroy_topology.return_value = {"success": True}
    return simulator


@pytest.fixture
def sandbox(tmp_path, mock_docker_manager, mock_vulnerable_apps,
            mock_honeypots, mock_network_simulator):
    """PurpleTeamSandbox with all mocks"""
    with patch('purple.sandbox.environment.DockerManager', return_value=mock_docker_manager), \
         patch('purple.sandbox.environment.VulnerableApps', return_value=mock_vulnerable_apps), \
         patch('purple.sandbox.environment.Honeypots', return_value=mock_honeypots), \
         patch('purple.sandbox.environment.NetworkSimulator', return_value=mock_network_simulator):

        sandbox = PurpleTeamSandbox(
            mock_mode=False,
            storage_path=str(tmp_path)
        )
        return sandbox


@pytest.fixture
def mock_sandbox(tmp_path):
    """PurpleTeamSandbox in mock mode"""
    return PurpleTeamSandbox(mock_mode=True, storage_path=str(tmp_path))


class TestPurpleTeamSandbox:
    """Test PurpleTeamSandbox class"""

    def test_init_mock_mode(self, tmp_path):
        """Test initialization in mock mode"""
        sandbox = PurpleTeamSandbox(mock_mode=True, storage_path=str(tmp_path))

        assert sandbox.mock_mode is True
        assert sandbox.storage_path == str(tmp_path)

    def test_init_real_mode(self, sandbox):
        """Test initialization in real mode"""
        assert sandbox.mock_mode is False
        assert sandbox.docker_manager is not None

    def test_create_environment_webapp(self, sandbox):
        """Test creating webapp environment"""
        result = sandbox.create_environment(target_type="webapp")

        assert result["success"] is True
        assert result["env_id"] is not None
        assert result["target_type"] == "webapp"
        assert result["network_isolated"] is True

    def test_create_environment_not_isolated(self, sandbox):
        """Test creating non-isolated environment"""
        result = sandbox.create_environment(
            target_type="webapp",
            network_isolated=False
        )

        assert result["success"] is True
        assert result["network_isolated"] is False

    def test_create_environment_api(self, sandbox):
        """Test creating API environment"""
        result = sandbox.create_environment(target_type="api")

        assert result["success"] is True
        assert result["target_type"] == "api"

    def test_create_environment_network(self, sandbox):
        """Test creating network environment"""
        result = sandbox.create_environment(target_type="network")

        assert result["success"] is True
        assert result["target_type"] == "network"

    def test_deploy_vulnerable_app(self, sandbox):
        """Test deploying vulnerable app"""
        # Create environment first
        env_result = sandbox.create_environment(target_type="webapp")
        env_id = env_result["env_id"]

        result = sandbox.deploy_vulnerable_app(env_id, "dvwa")

        assert result["success"] is True
        assert result["app_name"] == "dvwa"

    def test_deploy_vulnerable_app_custom_port(self, sandbox):
        """Test deploying app with custom port"""
        env_result = sandbox.create_environment(target_type="webapp")
        env_id = env_result["env_id"]

        result = sandbox.deploy_vulnerable_app(env_id, "dvwa", port=9090)

        assert result["success"] is True

    def test_deploy_vulnerable_app_invalid_env(self, sandbox):
        """Test deploying app to invalid environment"""
        result = sandbox.deploy_vulnerable_app("invalid-env-id", "dvwa")

        assert result["success"] is False
        assert "not found" in result["error"].lower()

    def test_deploy_honeypot(self, sandbox):
        """Test deploying honeypot"""
        env_result = sandbox.create_environment(target_type="network")
        env_id = env_result["env_id"]

        result = sandbox.deploy_honeypot(env_id, "ssh", port=2222)

        assert result["success"] is True
        assert result["service_type"] == "ssh"

    def test_deploy_honeypot_invalid_env(self, sandbox):
        """Test deploying honeypot to invalid environment"""
        result = sandbox.deploy_honeypot("invalid-env-id", "ssh", port=2222)

        assert result["success"] is False

    def test_create_network_topology(self, tmp_path):
        """Test creating network topology"""
        # Create a fresh sandbox with mocked network simulator
        mock_network_sim = MagicMock()
        mock_network_sim.create_topology.return_value = {
            "success": True,
            "topology_type": "dmz",
            "topology_id": "topology-123",
            "networks": []
        }

        with patch('purple.sandbox.environment.NetworkSimulator', return_value=mock_network_sim):
            sandbox = PurpleTeamSandbox(mock_mode=True, storage_path=str(tmp_path))
            result = sandbox.create_network_topology("dmz")

            assert result["success"] is True
            assert result["topology_type"] == "dmz"

    def test_start_environment(self, sandbox):
        """Test starting environment"""
        # Create and deploy
        env_result = sandbox.create_environment(target_type="webapp")
        env_id = env_result["env_id"]
        sandbox.deploy_vulnerable_app(env_id, "dvwa")

        result = sandbox.start_environment(env_id)

        assert result["success"] is True
        assert result["env_id"] == env_id
        assert result["status"] == "running"

    def test_start_environment_invalid(self, sandbox):
        """Test starting invalid environment"""
        result = sandbox.start_environment("invalid-env-id")

        assert result["success"] is False

    def test_stop_environment(self, sandbox):
        """Test stopping environment"""
        # Create and start
        env_result = sandbox.create_environment(target_type="webapp")
        env_id = env_result["env_id"]
        sandbox.deploy_vulnerable_app(env_id, "dvwa")
        sandbox.start_environment(env_id)

        result = sandbox.stop_environment(env_id)

        assert result["success"] is True
        assert result["env_id"] == env_id

    def test_stop_environment_invalid(self, sandbox):
        """Test stopping invalid environment"""
        result = sandbox.stop_environment("invalid-env-id")

        assert result["success"] is False

    def test_get_environment_info(self, sandbox):
        """Test getting environment info"""
        env_result = sandbox.create_environment(target_type="webapp")
        env_id = env_result["env_id"]

        result = sandbox.get_environment_info(env_id)

        assert result["success"] is True
        assert result["env_id"] == env_id
        assert "target_type" in result
        assert "status" in result

    def test_get_environment_info_invalid(self, sandbox):
        """Test getting info for invalid environment"""
        result = sandbox.get_environment_info("invalid-env-id")

        assert result["success"] is False

    def test_list_environments(self, sandbox):
        """Test listing environments"""
        # Create some environments
        sandbox.create_environment(target_type="webapp")
        sandbox.create_environment(target_type="api")

        result = sandbox.list_environments()

        assert result["success"] is True
        assert len(result["environments"]) == 2

    def test_list_environments_empty(self, sandbox):
        """Test listing when no environments"""
        result = sandbox.list_environments()

        assert result["success"] is True
        assert len(result["environments"]) == 0

    def test_delete_environment(self, sandbox):
        """Test deleting environment"""
        env_result = sandbox.create_environment(target_type="webapp")
        env_id = env_result["env_id"]

        result = sandbox.delete_environment(env_id)

        assert result["success"] is True

    def test_delete_environment_invalid(self, sandbox):
        """Test deleting invalid environment"""
        result = sandbox.delete_environment("invalid-env-id")

        assert result["success"] is False

    def test_environment_persistence(self, sandbox):
        """Test environment data persistence"""
        # Create environment
        env_result = sandbox.create_environment(target_type="webapp")
        env_id = env_result["env_id"]

        # Load environments
        envs = sandbox._load_environments()

        assert env_id in envs
        assert envs[env_id]["target_type"] == "webapp"

    def test_cleanup_on_stop(self, sandbox):
        """Test cleanup when stopping environment"""
        env_result = sandbox.create_environment(target_type="webapp")
        env_id = env_result["env_id"]
        sandbox.deploy_vulnerable_app(env_id, "dvwa")
        sandbox.start_environment(env_id)

        result = sandbox.stop_environment(env_id)

        assert result["success"] is True
        assert result["cleanup_performed"] is True

    def test_mock_mode_create_environment(self, mock_sandbox):
        """Test creating environment in mock mode"""
        result = mock_sandbox.create_environment(target_type="webapp")

        assert result["success"] is True
        assert "env-" in result["env_id"]  # env- prefix, not mock-env

    def test_mock_mode_deploy_app(self, mock_sandbox):
        """Test deploying app in mock mode"""
        env_result = mock_sandbox.create_environment(target_type="webapp")
        env_id = env_result["env_id"]

        result = mock_sandbox.deploy_vulnerable_app(env_id, "dvwa")

        assert result["success"] is True

    def test_docker_unavailable(self, tmp_path):
        """Test handling when Docker is unavailable"""
        with patch('purple.sandbox.environment.DockerManager') as mock_dm_class:
            mock_dm = MagicMock()
            mock_dm.check_docker_available.return_value = False
            mock_dm_class.return_value = mock_dm

            sandbox = PurpleTeamSandbox(mock_mode=False, storage_path=str(tmp_path))
            result = sandbox.create_environment(target_type="webapp")

            # Should fall back to mock mode or error gracefully
            assert "success" in result

    def test_environment_timeout(self, sandbox):
        """Test environment with timeout"""
        result = sandbox.create_environment(
            target_type="webapp",
            timeout=3600  # 1 hour
        )

        assert result["success"] is True
        assert result["timeout"] == 3600

    def test_multiple_apps_in_environment(self, sandbox):
        """Test deploying multiple apps in one environment"""
        env_result = sandbox.create_environment(target_type="webapp")
        env_id = env_result["env_id"]

        result1 = sandbox.deploy_vulnerable_app(env_id, "dvwa")
        result2 = sandbox.deploy_vulnerable_app(env_id, "juice-shop")

        assert result1["success"] is True
        assert result2["success"] is True

    def test_environment_resource_limits(self, sandbox):
        """Test creating environment with resource limits"""
        result = sandbox.create_environment(
            target_type="webapp",
            cpu_limit="1.0",
            memory_limit="512m"
        )

        assert result["success"] is True

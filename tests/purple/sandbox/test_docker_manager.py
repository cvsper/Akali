"""Tests for Docker manager"""
import pytest
from unittest.mock import Mock, MagicMock, patch
from purple.sandbox.docker_manager import DockerManager

# Check if Docker SDK is available
try:
    import docker
    DOCKER_SDK_AVAILABLE = True
except ImportError:
    DOCKER_SDK_AVAILABLE = False

# Decorator for tests that require Docker SDK
requires_docker_sdk = pytest.mark.skipif(
    not DOCKER_SDK_AVAILABLE,
    reason="Docker SDK not installed"
)


@pytest.fixture
def mock_docker_client():
    """Mock Docker client"""
    client = MagicMock()

    # Mock container
    container = MagicMock()
    container.id = "test-container-id"
    container.name = "test-container"
    container.status = "running"
    container.attrs = {
        "NetworkSettings": {
            "IPAddress": "172.17.0.2",
            "Ports": {"80/tcp": [{"HostPort": "8080"}]}
        }
    }

    # Mock network
    network = MagicMock()
    network.id = "test-network-id"
    network.name = "test-network"

    client.containers.run.return_value = container
    client.containers.get.return_value = container
    client.containers.list.return_value = [container]
    client.networks.create.return_value = network
    client.networks.get.return_value = network
    client.networks.list.return_value = [network]
    client.ping.return_value = True

    return client


@pytest.fixture
def docker_manager(mock_docker_client):
    """Docker manager with mocked client"""
    with patch('purple.sandbox.docker_manager.docker.from_env', return_value=mock_docker_client):
        manager = DockerManager(mock_mode=False)
        manager.client = mock_docker_client
        return manager


@pytest.fixture
def mock_docker_manager():
    """Docker manager in mock mode"""
    return DockerManager(mock_mode=True)


class TestDockerManager:
    """Test DockerManager class"""

    def test_init_mock_mode(self):
        """Test initialization in mock mode"""
        manager = DockerManager(mock_mode=True)
        assert manager.mock_mode is True
        assert manager.client is None

    @requires_docker_sdk
    def test_init_real_mode(self, mock_docker_client):
        """Test initialization in real mode"""
        with patch('docker.from_env', return_value=mock_docker_client):
            manager = DockerManager(mock_mode=False)
            assert manager.mock_mode is False
            assert manager.client is not None

    @requires_docker_sdk
    @requires_docker_sdk
    def test_check_docker_available(self, docker_manager):
        """Test Docker availability check"""
        result = docker_manager.check_docker_available()
        assert result is True

    @requires_docker_sdk
    def test_check_docker_unavailable(self):
        """Test Docker unavailable"""
        with patch('docker.from_env', side_effect=Exception("Docker not available")):
            manager = DockerManager(mock_mode=False)
            # Should fall back to mock mode
            result = manager.check_docker_available()
            assert result is True  # Returns True because it falls back to mock

    @requires_docker_sdk
    def test_create_container(self, docker_manager):
        """Test container creation"""
        result = docker_manager.create_container(
            image="nginx:latest",
            name="test-nginx",
            ports={"80/tcp": 8080}
        )

        assert result["success"] is True
        assert result["container_id"] == "test-container-id"
        assert result["name"] == "test-container"
        assert result["status"] == "running"

    def test_create_container_mock_mode(self, mock_docker_manager):
        """Test container creation in mock mode"""
        result = mock_docker_manager.create_container(
            image="nginx:latest",
            name="test-nginx",
            ports={"80/tcp": 8080}
        )

        assert result["success"] is True
        assert "mock-container" in result["container_id"]
        assert result["name"] == "test-nginx"
        assert result["status"] == "running"

    @requires_docker_sdk
    def test_create_container_with_environment(self, docker_manager):
        """Test container creation with environment variables"""
        result = docker_manager.create_container(
            image="nginx:latest",
            name="test-nginx",
            environment={"ENV_VAR": "value"}
        )

        assert result["success"] is True
        docker_manager.client.containers.run.assert_called_once()

    @requires_docker_sdk
    def test_create_container_with_network(self, docker_manager):
        """Test container creation with custom network"""
        result = docker_manager.create_container(
            image="nginx:latest",
            name="test-nginx",
            network="custom-network"
        )

        assert result["success"] is True

    @requires_docker_sdk
    def test_create_container_error(self, docker_manager):
        """Test container creation error handling"""
        docker_manager.client.containers.run.side_effect = Exception("Container error")

        result = docker_manager.create_container(
            image="nginx:latest",
            name="test-nginx"
        )

        assert result["success"] is False
        assert "error" in result

    @requires_docker_sdk
    def test_stop_container(self, docker_manager):
        """Test stopping container"""
        result = docker_manager.stop_container("test-container-id")

        assert result["success"] is True
        assert result["container_id"] == "test-container-id"

    def test_stop_container_mock_mode(self, mock_docker_manager):
        """Test stopping container in mock mode"""
        result = mock_docker_manager.stop_container("mock-container-123")

        assert result["success"] is True
        assert result["container_id"] == "mock-container-123"

    @requires_docker_sdk
    def test_remove_container(self, docker_manager):
        """Test removing container"""
        result = docker_manager.remove_container("test-container-id")

        assert result["success"] is True

    @requires_docker_sdk
    def test_remove_container_force(self, docker_manager):
        """Test force removing container"""
        result = docker_manager.remove_container("test-container-id", force=True)

        assert result["success"] is True
        docker_manager.client.containers.get.return_value.remove.assert_called_with(force=True)

    @requires_docker_sdk
    def test_get_container_info(self, docker_manager):
        """Test getting container info"""
        result = docker_manager.get_container_info("test-container-id")

        assert result["success"] is True
        assert result["id"] == "test-container-id"
        assert result["status"] == "running"
        assert "ip_address" in result
        assert "ports" in result

    def test_get_container_info_mock_mode(self, mock_docker_manager):
        """Test getting container info in mock mode"""
        result = mock_docker_manager.get_container_info("mock-container-123")

        assert result["success"] is True
        assert "mock-container-123" in result["id"]  # Could be exact or in the name

    @requires_docker_sdk
    def test_list_containers(self, docker_manager):
        """Test listing containers"""
        result = docker_manager.list_containers()

        assert result["success"] is True
        assert len(result["containers"]) > 0

    @requires_docker_sdk
    def test_list_containers_with_filter(self, docker_manager):
        """Test listing containers with label filter"""
        result = docker_manager.list_containers(filters={"label": "akali.sandbox"})

        assert result["success"] is True

    @requires_docker_sdk
    def test_create_network(self, docker_manager):
        """Test network creation"""
        result = docker_manager.create_network(
            name="test-network",
            driver="bridge"
        )

        assert result["success"] is True
        assert result["network_id"] == "test-network-id"
        assert result["name"] == "test-network"

    def test_create_network_mock_mode(self, mock_docker_manager):
        """Test network creation in mock mode"""
        result = mock_docker_manager.create_network(
            name="test-network",
            driver="bridge"
        )

        assert result["success"] is True
        assert "mock-network" in result["network_id"]

    @requires_docker_sdk
    def test_remove_network(self, docker_manager):
        """Test network removal"""
        result = docker_manager.remove_network("test-network-id")

        assert result["success"] is True

    @requires_docker_sdk
    def test_connect_container_to_network(self, docker_manager):
        """Test connecting container to network"""
        result = docker_manager.connect_container_to_network(
            "test-container-id",
            "test-network-id"
        )

        assert result["success"] is True

    @requires_docker_sdk
    def test_disconnect_container_from_network(self, docker_manager):
        """Test disconnecting container from network"""
        result = docker_manager.disconnect_container_from_network(
            "test-container-id",
            "test-network-id"
        )

        assert result["success"] is True

    @requires_docker_sdk
    def test_pull_image(self, docker_manager):
        """Test pulling Docker image"""
        result = docker_manager.pull_image("nginx:latest")

        assert result["success"] is True
        assert result["image"] == "nginx:latest"

    def test_pull_image_mock_mode(self, mock_docker_manager):
        """Test pulling image in mock mode"""
        result = mock_docker_manager.pull_image("nginx:latest")

        assert result["success"] is True

    @requires_docker_sdk
    def test_check_port_available(self, docker_manager):
        """Test checking if port is available"""
        with patch('purple.sandbox.docker_manager.socket.socket') as mock_socket:
            mock_sock = MagicMock()
            mock_socket.return_value.__enter__.return_value = mock_sock
            mock_sock.connect_ex.return_value = 1  # Port available

            result = docker_manager.check_port_available(8080)
            assert result is True

    @requires_docker_sdk
    def test_check_port_unavailable(self, docker_manager):
        """Test checking if port is unavailable"""
        with patch('purple.sandbox.docker_manager.socket.socket') as mock_socket:
            mock_sock = MagicMock()
            mock_socket.return_value.__enter__.return_value = mock_sock
            mock_sock.connect_ex.return_value = 0  # Port in use

            result = docker_manager.check_port_available(8080)
            assert result is False

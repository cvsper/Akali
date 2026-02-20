"""Tests for network topology simulation"""
import pytest
from unittest.mock import Mock, MagicMock
from purple.sandbox.network_simulator import NetworkSimulator, NETWORK_TOPOLOGIES


@pytest.fixture
def mock_docker_manager():
    """Mock Docker manager"""
    manager = MagicMock()
    manager.create_network.return_value = {
        "success": True,
        "network_id": "network-123",
        "name": "test-network"
    }
    manager.remove_network.return_value = {"success": True}
    manager.connect_container_to_network.return_value = {"success": True}
    manager.disconnect_container_from_network.return_value = {"success": True}
    return manager


@pytest.fixture
def network_simulator(mock_docker_manager):
    """NetworkSimulator with mocked Docker manager"""
    return NetworkSimulator(docker_manager=mock_docker_manager)


class TestNetworkSimulator:
    """Test NetworkSimulator class"""

    def test_list_available_topologies(self, network_simulator):
        """Test listing available topologies"""
        topologies = network_simulator.list_available_topologies()

        assert len(topologies) > 0
        assert "single_host" in topologies
        assert "dmz" in topologies
        assert "multi_tier" in topologies

    def test_get_topology_info(self, network_simulator):
        """Test getting topology info"""
        info = network_simulator.get_topology_info("single_host")

        assert info is not None
        assert "description" in info
        assert "containers" in info
        assert "network" in info

    def test_get_topology_info_invalid(self, network_simulator):
        """Test getting info for invalid topology"""
        info = network_simulator.get_topology_info("invalid-topology")

        assert info is None

    def test_create_single_host_topology(self, network_simulator):
        """Test creating single host topology"""
        result = network_simulator.create_topology("single_host")

        assert result["success"] is True
        assert result["topology_type"] == "single_host"
        assert "topology_id" in result
        assert "networks" in result

    def test_create_dmz_topology(self, network_simulator):
        """Test creating DMZ topology"""
        result = network_simulator.create_topology("dmz")

        assert result["success"] is True
        assert result["topology_type"] == "dmz"
        assert len(result["networks"]) == 3  # external, dmz, internal

    def test_create_multi_tier_topology(self, network_simulator):
        """Test creating multi-tier topology"""
        result = network_simulator.create_topology("multi_tier")

        assert result["success"] is True
        assert result["topology_type"] == "multi_tier"
        assert len(result["networks"]) == 3  # web, app, db

    def test_create_topology_invalid(self, network_simulator):
        """Test creating invalid topology"""
        result = network_simulator.create_topology("invalid-topology")

        assert result["success"] is False
        assert "unknown" in result["error"].lower()

    def test_create_network(self, network_simulator):
        """Test creating a network"""
        result = network_simulator.create_network(
            name="test-network",
            subnet="172.20.0.0/16"
        )

        assert result["success"] is True
        assert result["network_id"] == "network-123"

    def test_remove_network(self, network_simulator):
        """Test removing a network"""
        result = network_simulator.remove_network("network-123")

        assert result["success"] is True

    def test_connect_container(self, network_simulator):
        """Test connecting container to network"""
        result = network_simulator.connect_container(
            "container-123",
            "network-123"
        )

        assert result["success"] is True

    def test_disconnect_container(self, network_simulator):
        """Test disconnecting container from network"""
        result = network_simulator.disconnect_container(
            "container-123",
            "network-123"
        )

        assert result["success"] is True

    def test_destroy_topology(self, network_simulator):
        """Test destroying topology"""
        # First create a topology
        create_result = network_simulator.create_topology("single_host")
        topology_id = create_result["topology_id"]

        # Then destroy it
        result = network_simulator.destroy_topology(topology_id)

        assert result["success"] is True

    def test_get_topology_status(self, network_simulator):
        """Test getting topology status"""
        # Create a topology first
        create_result = network_simulator.create_topology("single_host")
        topology_id = create_result["topology_id"]

        result = network_simulator.get_topology_status(topology_id)

        assert result["success"] is True
        assert result["topology_id"] == topology_id

    def test_list_networks(self, network_simulator):
        """Test listing networks in topology"""
        # Create a topology first
        create_result = network_simulator.create_topology("dmz")
        topology_id = create_result["topology_id"]

        result = network_simulator.list_networks(topology_id)

        assert result["success"] is True
        assert len(result["networks"]) > 0

    def test_network_topologies_constant(self):
        """Test NETWORK_TOPOLOGIES constant structure"""
        assert isinstance(NETWORK_TOPOLOGIES, dict)
        assert len(NETWORK_TOPOLOGIES) >= 3

        for topology_name, topology_info in NETWORK_TOPOLOGIES.items():
            assert "description" in topology_info
            assert "containers" in topology_info
            assert "network" in topology_info or "networks" in topology_info

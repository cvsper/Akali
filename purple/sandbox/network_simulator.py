"""Network topology simulation"""
import uuid
from typing import Dict, List, Optional, Any
from .docker_manager import DockerManager


# Network topology configurations
NETWORK_TOPOLOGIES = {
    "single_host": {
        "description": "Single vulnerable host",
        "containers": 1,
        "network": "bridge",
        "networks": [
            {"name": "default", "subnet": "172.20.0.0/16"}
        ]
    },
    "dmz": {
        "description": "DMZ with web server and internal network",
        "containers": 3,
        "networks": [
            {"name": "external", "subnet": "172.21.0.0/16"},
            {"name": "dmz", "subnet": "172.22.0.0/16"},
            {"name": "internal", "subnet": "172.23.0.0/16"}
        ]
    },
    "multi_tier": {
        "description": "Web tier, app tier, database tier",
        "containers": 5,
        "networks": [
            {"name": "web", "subnet": "172.24.0.0/16"},
            {"name": "app", "subnet": "172.25.0.0/16"},
            {"name": "db", "subnet": "172.26.0.0/16"}
        ]
    }
}


class NetworkSimulator:
    """Manages network topology simulation"""

    def __init__(self, docker_manager: Optional[DockerManager] = None):
        """
        Initialize NetworkSimulator

        Args:
            docker_manager: Docker manager instance (creates one if not provided)
        """
        self.docker_manager = docker_manager or DockerManager()
        self.topologies = {}  # Track created topologies

    def list_available_topologies(self) -> List[str]:
        """
        List available network topologies

        Returns:
            List of topology names
        """
        return list(NETWORK_TOPOLOGIES.keys())

    def get_topology_info(self, topology_type: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a network topology

        Args:
            topology_type: Topology type

        Returns:
            Topology info dict or None if not found
        """
        return NETWORK_TOPOLOGIES.get(topology_type)

    def create_topology(self, topology_type: str) -> Dict[str, Any]:
        """
        Create a network topology

        Args:
            topology_type: Type of topology to create

        Returns:
            Dict with topology info
        """
        # Validate topology type
        topology_info = self.get_topology_info(topology_type)
        if not topology_info:
            return {
                "success": False,
                "error": f"Unknown topology type: {topology_type}"
            }

        topology_id = f"topology-{uuid.uuid4().hex[:8]}"
        created_networks = []

        try:
            # Create networks
            if "networks" in topology_info:
                for network_config in topology_info["networks"]:
                    network_name = f"{topology_id}-{network_config['name']}"
                    subnet = network_config.get("subnet")

                    result = self.docker_manager.create_network(
                        name=network_name,
                        driver="bridge",
                        subnet=subnet,
                        labels={"akali.sandbox": "true", "akali.topology": topology_id}
                    )

                    if result["success"]:
                        created_networks.append({
                            "name": network_name,
                            "id": result["network_id"],
                            "subnet": subnet,
                            "type": network_config['name']
                        })
                    else:
                        # Cleanup on error
                        for net in created_networks:
                            self.docker_manager.remove_network(net["id"])
                        return {
                            "success": False,
                            "error": f"Failed to create network: {result.get('error')}"
                        }

            # Store topology info
            self.topologies[topology_id] = {
                "topology_type": topology_type,
                "networks": created_networks,
                "containers": []
            }

            return {
                "success": True,
                "topology_id": topology_id,
                "topology_type": topology_type,
                "networks": created_networks
            }

        except Exception as e:
            # Cleanup on error
            for net in created_networks:
                self.docker_manager.remove_network(net["id"])
            return {
                "success": False,
                "error": str(e)
            }

    def create_network(
        self,
        name: str,
        subnet: Optional[str] = None,
        driver: str = "bridge"
    ) -> Dict[str, Any]:
        """
        Create a custom network

        Args:
            name: Network name
            subnet: Network subnet
            driver: Network driver

        Returns:
            Dict with network info
        """
        return self.docker_manager.create_network(
            name=name,
            driver=driver,
            subnet=subnet,
            labels={"akali.sandbox": "true"}
        )

    def remove_network(self, network_id: str) -> Dict[str, Any]:
        """
        Remove a network

        Args:
            network_id: Network ID or name

        Returns:
            Dict with operation result
        """
        return self.docker_manager.remove_network(network_id)

    def connect_container(
        self,
        container_id: str,
        network_id: str
    ) -> Dict[str, Any]:
        """
        Connect a container to a network

        Args:
            container_id: Container ID or name
            network_id: Network ID or name

        Returns:
            Dict with operation result
        """
        result = self.docker_manager.connect_container_to_network(
            container_id,
            network_id
        )

        # Track connection in topology
        for topology in self.topologies.values():
            for network in topology["networks"]:
                if network["id"] == network_id or network["name"] == network_id:
                    if container_id not in topology["containers"]:
                        topology["containers"].append(container_id)

        return result

    def disconnect_container(
        self,
        container_id: str,
        network_id: str
    ) -> Dict[str, Any]:
        """
        Disconnect a container from a network

        Args:
            container_id: Container ID or name
            network_id: Network ID or name

        Returns:
            Dict with operation result
        """
        return self.docker_manager.disconnect_container_from_network(
            container_id,
            network_id
        )

    def destroy_topology(self, topology_id: str) -> Dict[str, Any]:
        """
        Destroy a topology and all its networks

        Args:
            topology_id: Topology ID

        Returns:
            Dict with operation result
        """
        if topology_id not in self.topologies:
            return {
                "success": False,
                "error": f"Topology not found: {topology_id}"
            }

        topology = self.topologies[topology_id]
        errors = []
        removed_networks = []

        # Remove networks
        for network in topology["networks"]:
            result = self.docker_manager.remove_network(network["id"])
            if result["success"]:
                removed_networks.append(network["id"])
            else:
                errors.append(f"Failed to remove network {network['name']}: {result.get('error')}")

        # Remove from tracking even if some networks failed
        del self.topologies[topology_id]

        if errors:
            return {
                "success": False,
                "partial": True,
                "removed_networks": removed_networks,
                "error": "; ".join(errors)
            }

        return {
            "success": True,
            "topology_id": topology_id,
            "removed_networks": removed_networks
        }

    def get_topology_status(self, topology_id: str) -> Dict[str, Any]:
        """
        Get topology status

        Args:
            topology_id: Topology ID

        Returns:
            Dict with topology status
        """
        if topology_id not in self.topologies:
            return {
                "success": False,
                "error": f"Topology not found: {topology_id}"
            }

        topology = self.topologies[topology_id]
        return {
            "success": True,
            "topology_id": topology_id,
            "topology_type": topology["topology_type"],
            "networks": topology["networks"],
            "containers": topology["containers"]
        }

    def list_networks(self, topology_id: str) -> Dict[str, Any]:
        """
        List networks in a topology

        Args:
            topology_id: Topology ID

        Returns:
            Dict with network list
        """
        if topology_id not in self.topologies:
            return {
                "success": False,
                "error": f"Topology not found: {topology_id}"
            }

        topology = self.topologies[topology_id]
        return {
            "success": True,
            "topology_id": topology_id,
            "networks": topology["networks"]
        }

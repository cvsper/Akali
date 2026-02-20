"""Docker container orchestration for sandbox environments"""
import socket
import uuid
from typing import Dict, List, Optional, Any

try:
    import docker
    from docker.errors import DockerException, NotFound, APIError
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False


class DockerManager:
    """Manages Docker containers and networks for sandbox environments"""

    def __init__(self, mock_mode: bool = False):
        """
        Initialize Docker manager

        Args:
            mock_mode: If True, simulate Docker operations without actual Docker
        """
        self.mock_mode = mock_mode
        self.client = None
        self.mock_containers = {}
        self.mock_networks = {}

        if not mock_mode and DOCKER_AVAILABLE:
            try:
                self.client = docker.from_env()
                # Test connection
                self.client.ping()
            except Exception as e:
                print(f"Warning: Could not connect to Docker daemon: {e}")
                self.mock_mode = True
                self.client = None

    def check_docker_available(self) -> bool:
        """
        Check if Docker daemon is available

        Returns:
            True if Docker is available, False otherwise
        """
        if self.mock_mode:
            return True

        try:
            if self.client:
                self.client.ping()
                return True
        except Exception:
            pass

        return False

    def create_container(
        self,
        image: str,
        name: str,
        ports: Optional[Dict[str, int]] = None,
        environment: Optional[Dict[str, str]] = None,
        network: Optional[str] = None,
        command: Optional[str] = None,
        detach: bool = True,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Create and start a Docker container

        Args:
            image: Docker image to use
            name: Container name
            ports: Port mappings {container_port: host_port}
            environment: Environment variables
            network: Network to connect to
            command: Command to run
            detach: Run in detached mode
            **kwargs: Additional docker.containers.run arguments

        Returns:
            Dict with container info
        """
        if self.mock_mode:
            container_id = f"mock-container-{uuid.uuid4().hex[:8]}"
            self.mock_containers[container_id] = {
                "id": container_id,
                "name": name,
                "image": image,
                "status": "running",
                "ports": ports or {},
                "environment": environment or {},
                "network": network
            }
            return {
                "success": True,
                "container_id": container_id,
                "name": name,
                "status": "running"
            }

        try:
            # Prepare port bindings
            port_bindings = {}
            if ports:
                for container_port, host_port in ports.items():
                    port_bindings[container_port] = host_port

            # Create container
            container = self.client.containers.run(
                image,
                name=name,
                ports=port_bindings if port_bindings else None,
                environment=environment,
                network=network,
                command=command,
                detach=detach,
                remove=False,
                **kwargs
            )

            return {
                "success": True,
                "container_id": container.id,
                "name": container.name,
                "status": container.status
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def stop_container(self, container_id: str, timeout: int = 10) -> Dict[str, Any]:
        """
        Stop a running container

        Args:
            container_id: Container ID or name
            timeout: Timeout in seconds

        Returns:
            Dict with operation result
        """
        if self.mock_mode:
            # In mock mode, always succeed
            if container_id in self.mock_containers:
                self.mock_containers[container_id]["status"] = "stopped"
            return {
                "success": True,
                "container_id": container_id
            }

        try:
            container = self.client.containers.get(container_id)
            container.stop(timeout=timeout)
            return {
                "success": True,
                "container_id": container_id
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def remove_container(self, container_id: str, force: bool = False) -> Dict[str, Any]:
        """
        Remove a container

        Args:
            container_id: Container ID or name
            force: Force removal

        Returns:
            Dict with operation result
        """
        if self.mock_mode:
            if container_id in self.mock_containers:
                del self.mock_containers[container_id]
                return {
                    "success": True,
                    "container_id": container_id
                }
            return {
                "success": False,
                "error": "Container not found"
            }

        try:
            container = self.client.containers.get(container_id)
            container.remove(force=force)
            return {
                "success": True,
                "container_id": container_id
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def get_container_info(self, container_id: str) -> Dict[str, Any]:
        """
        Get container information

        Args:
            container_id: Container ID or name

        Returns:
            Dict with container info
        """
        if self.mock_mode:
            # In mock mode, return mock data
            if container_id in self.mock_containers:
                container = self.mock_containers[container_id]
                return {
                    "success": True,
                    "id": container["id"],
                    "name": container["name"],
                    "status": container["status"],
                    "ip_address": "172.17.0.2",
                    "ports": container["ports"]
                }
            # Return generic mock info for unknown containers
            return {
                "success": True,
                "id": container_id,
                "name": f"mock-{container_id}",
                "status": "running",
                "ip_address": "172.17.0.2",
                "ports": {}
            }

        try:
            container = self.client.containers.get(container_id)
            container.reload()

            # Extract network info
            network_settings = container.attrs.get("NetworkSettings", {})
            ip_address = network_settings.get("IPAddress", "")
            ports = network_settings.get("Ports", {})

            return {
                "success": True,
                "id": container.id,
                "name": container.name,
                "status": container.status,
                "ip_address": ip_address,
                "ports": ports
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def list_containers(self, filters: Optional[Dict] = None) -> Dict[str, Any]:
        """
        List containers

        Args:
            filters: Filters to apply

        Returns:
            Dict with container list
        """
        if self.mock_mode:
            containers = [
                {
                    "id": c["id"],
                    "name": c["name"],
                    "status": c["status"]
                }
                for c in self.mock_containers.values()
            ]
            return {
                "success": True,
                "containers": containers
            }

        try:
            containers = self.client.containers.list(all=True, filters=filters)
            container_list = [
                {
                    "id": c.id,
                    "name": c.name,
                    "status": c.status
                }
                for c in containers
            ]
            return {
                "success": True,
                "containers": container_list
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def create_network(
        self,
        name: str,
        driver: str = "bridge",
        subnet: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Create a Docker network

        Args:
            name: Network name
            driver: Network driver (bridge, overlay, etc.)
            subnet: Network subnet (e.g., "172.20.0.0/16")
            **kwargs: Additional network options

        Returns:
            Dict with network info
        """
        if self.mock_mode:
            network_id = f"mock-network-{uuid.uuid4().hex[:8]}"
            self.mock_networks[network_id] = {
                "id": network_id,
                "name": name,
                "driver": driver,
                "subnet": subnet
            }
            return {
                "success": True,
                "network_id": network_id,
                "name": name
            }

        try:
            ipam_config = None
            if subnet:
                ipam_pool = docker.types.IPAMPool(subnet=subnet)
                ipam_config = docker.types.IPAMConfig(pool_configs=[ipam_pool])

            network = self.client.networks.create(
                name,
                driver=driver,
                ipam=ipam_config,
                **kwargs
            )

            return {
                "success": True,
                "network_id": network.id,
                "name": network.name
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def remove_network(self, network_id: str) -> Dict[str, Any]:
        """
        Remove a Docker network

        Args:
            network_id: Network ID or name

        Returns:
            Dict with operation result
        """
        if self.mock_mode:
            if network_id in self.mock_networks:
                del self.mock_networks[network_id]
                return {
                    "success": True,
                    "network_id": network_id
                }
            return {
                "success": False,
                "error": "Network not found"
            }

        try:
            network = self.client.networks.get(network_id)
            network.remove()
            return {
                "success": True,
                "network_id": network_id
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def connect_container_to_network(
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
        if self.mock_mode:
            return {
                "success": True,
                "container_id": container_id,
                "network_id": network_id
            }

        try:
            network = self.client.networks.get(network_id)
            network.connect(container_id)
            return {
                "success": True,
                "container_id": container_id,
                "network_id": network_id
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def disconnect_container_from_network(
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
        if self.mock_mode:
            return {
                "success": True,
                "container_id": container_id,
                "network_id": network_id
            }

        try:
            network = self.client.networks.get(network_id)
            network.disconnect(container_id)
            return {
                "success": True,
                "container_id": container_id,
                "network_id": network_id
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def pull_image(self, image: str) -> Dict[str, Any]:
        """
        Pull a Docker image

        Args:
            image: Image name (e.g., "nginx:latest")

        Returns:
            Dict with operation result
        """
        if self.mock_mode:
            return {
                "success": True,
                "image": image
            }

        try:
            self.client.images.pull(image)
            return {
                "success": True,
                "image": image
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    @staticmethod
    def check_port_available(port: int, host: str = "127.0.0.1") -> bool:
        """
        Check if a port is available

        Args:
            port: Port number
            host: Host to check

        Returns:
            True if port is available, False if in use
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            result = sock.connect_ex((host, port))
            return result != 0  # 0 means port is in use

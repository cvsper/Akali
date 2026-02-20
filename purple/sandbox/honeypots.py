"""Honeypot service deployment"""
from typing import Dict, List, Optional, Any
from .docker_manager import DockerManager


# Honeypot services catalog
HONEYPOT_SERVICES = {
    "ssh": {
        "port": 2222,
        "container": "cowrie/cowrie",
        "description": "SSH honeypot using Cowrie"
    },
    "http": {
        "port": 8080,
        "container": "mkuchin/docker-snare",
        "description": "HTTP/Web honeypot using SNARE"
    },
    "ftp": {
        "port": 21,
        "container": "vimagick/honeytrap",
        "description": "FTP honeypot"
    },
    "smtp": {
        "port": 25,
        "container": "mailhoney/mailhoney",
        "description": "SMTP honeypot"
    },
    "rdp": {
        "port": 3389,
        "container": "gosecure/rdp-honeypot",
        "description": "RDP honeypot"
    }
}


class Honeypots:
    """Manages honeypot service deployment"""

    def __init__(self, docker_manager: Optional[DockerManager] = None):
        """
        Initialize Honeypots

        Args:
            docker_manager: Docker manager instance (creates one if not provided)
        """
        self.docker_manager = docker_manager or DockerManager()

    def list_available_services(self) -> List[str]:
        """
        List available honeypot services

        Returns:
            List of service names
        """
        return list(HONEYPOT_SERVICES.keys())

    def get_service_info(self, service_type: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a honeypot service

        Args:
            service_type: Service type

        Returns:
            Service info dict or None if not found
        """
        return HONEYPOT_SERVICES.get(service_type)

    def deploy_honeypot(
        self,
        service_type: str,
        port: Optional[int] = None,
        network: Optional[str] = None,
        environment: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Deploy a honeypot service

        Args:
            service_type: Type of honeypot service
            port: Host port to bind to (uses default if not specified)
            network: Docker network to connect to
            environment: Additional environment variables

        Returns:
            Dict with deployment info
        """
        # Validate service type
        service_info = self.get_service_info(service_type)
        if not service_info:
            return {
                "success": False,
                "error": f"Unknown honeypot service: {service_type}"
            }

        # Determine port
        default_port = service_info["port"]
        host_port = port or default_port

        # Check if port is available
        if not self.docker_manager.check_port_available(host_port):
            return {
                "success": False,
                "error": f"Port {host_port} is already in use"
            }

        # Pull image first
        pull_result = self.docker_manager.pull_image(service_info["container"])
        if not pull_result["success"]:
            return {
                "success": False,
                "error": f"Failed to pull image: {pull_result.get('error', 'Unknown error')}"
            }

        # Create container
        container_name = f"{service_type}-honeypot-{host_port}"
        ports = {f"{default_port}/tcp": host_port}

        result = self.docker_manager.create_container(
            image=service_info["container"],
            name=container_name,
            ports=ports,
            network=network,
            environment=environment,
            labels={"akali.sandbox": "true", "akali.honeypot": service_type}
        )

        if result["success"]:
            # Add deployment info
            result.update({
                "service_type": service_type,
                "port": host_port,
                "description": service_info["description"]
            })

        return result

    def stop_honeypot(self, container_id: str) -> Dict[str, Any]:
        """
        Stop a running honeypot

        Args:
            container_id: Container ID or name

        Returns:
            Dict with operation result
        """
        return self.docker_manager.stop_container(container_id)

    def remove_honeypot(self, container_id: str) -> Dict[str, Any]:
        """
        Remove a honeypot container

        Args:
            container_id: Container ID or name

        Returns:
            Dict with operation result
        """
        return self.docker_manager.remove_container(container_id, force=True)

    def get_honeypot_status(self, container_id: str) -> Dict[str, Any]:
        """
        Get honeypot status

        Args:
            container_id: Container ID or name

        Returns:
            Dict with status info
        """
        return self.docker_manager.get_container_info(container_id)

    def get_honeypot_logs(
        self,
        container_id: str,
        tail: int = 100
    ) -> Dict[str, Any]:
        """
        Get honeypot logs

        Args:
            container_id: Container ID or name
            tail: Number of lines to retrieve

        Returns:
            Dict with logs
        """
        if self.docker_manager.mock_mode:
            return {
                "success": True,
                "logs": "Mock log output"
            }

        try:
            container = self.docker_manager.client.containers.get(container_id)
            logs = container.logs(tail=tail).decode('utf-8')
            return {
                "success": True,
                "logs": logs
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

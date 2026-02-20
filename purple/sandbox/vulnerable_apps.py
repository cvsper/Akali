"""Vulnerable application deployment"""
from typing import Dict, List, Optional, Any
from .docker_manager import DockerManager


# Vulnerable applications catalog
VULNERABLE_APPS = {
    "dvwa": {
        "name": "Damn Vulnerable Web Application",
        "docker_image": "vulnerables/web-dvwa",
        "port": 80,
        "default_creds": {"username": "admin", "password": "password"}
    },
    "juice-shop": {
        "name": "OWASP Juice Shop",
        "docker_image": "bkimminich/juice-shop",
        "port": 3000
    },
    "webgoat": {
        "name": "OWASP WebGoat",
        "docker_image": "webgoat/webgoat",
        "port": 8080
    },
    "metasploitable": {
        "name": "Metasploitable3",
        "docker_image": "tleemcjr/metasploitable3-ub1404",
        "port": 22
    },
    "vuln-node": {
        "name": "Vulnerable Node.js App",
        "docker_image": "bkimminich/dvna",
        "port": 9090
    }
}


class VulnerableApps:
    """Manages vulnerable application deployment"""

    def __init__(self, docker_manager: Optional[DockerManager] = None):
        """
        Initialize VulnerableApps

        Args:
            docker_manager: Docker manager instance (creates one if not provided)
        """
        self.docker_manager = docker_manager or DockerManager()

    def list_available_apps(self) -> List[str]:
        """
        List available vulnerable applications

        Returns:
            List of app names
        """
        return list(VULNERABLE_APPS.keys())

    def get_app_info(self, app_name: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a vulnerable app

        Args:
            app_name: Application name

        Returns:
            App info dict or None if not found
        """
        return VULNERABLE_APPS.get(app_name)

    def deploy_app(
        self,
        app_name: str,
        port: Optional[int] = None,
        network: Optional[str] = None,
        environment: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Deploy a vulnerable application

        Args:
            app_name: Name of the app to deploy
            port: Host port to map to (uses default if not specified)
            network: Docker network to connect to
            environment: Additional environment variables

        Returns:
            Dict with deployment info
        """
        # Validate app name
        app_info = self.get_app_info(app_name)
        if not app_info:
            return {
                "success": False,
                "error": f"Unknown application: {app_name}"
            }

        # Determine port
        container_port = app_info["port"]
        host_port = port or container_port

        # Check if port is available
        if not self.docker_manager.check_port_available(host_port):
            return {
                "success": False,
                "error": f"Port {host_port} is already in use"
            }

        # Pull image first
        pull_result = self.docker_manager.pull_image(app_info["docker_image"])
        if not pull_result["success"]:
            return {
                "success": False,
                "error": f"Failed to pull image: {pull_result.get('error', 'Unknown error')}"
            }

        # Create container
        container_name = f"{app_name}-{host_port}"
        ports = {f"{container_port}/tcp": host_port}

        result = self.docker_manager.create_container(
            image=app_info["docker_image"],
            name=container_name,
            ports=ports,
            network=network,
            environment=environment,
            labels={"akali.sandbox": "true", "akali.app": app_name}
        )

        if result["success"]:
            # Add deployment info
            result.update({
                "app_name": app_name,
                "port": host_port,
                "access_url": f"http://localhost:{host_port}",
                "default_creds": app_info.get("default_creds")
            })

        return result

    def stop_app(self, container_id: str) -> Dict[str, Any]:
        """
        Stop a running app

        Args:
            container_id: Container ID or name

        Returns:
            Dict with operation result
        """
        return self.docker_manager.stop_container(container_id)

    def remove_app(self, container_id: str) -> Dict[str, Any]:
        """
        Remove an app container

        Args:
            container_id: Container ID or name

        Returns:
            Dict with operation result
        """
        return self.docker_manager.remove_container(container_id, force=True)

    def get_app_status(self, container_id: str) -> Dict[str, Any]:
        """
        Get app status

        Args:
            container_id: Container ID or name

        Returns:
            Dict with status info
        """
        return self.docker_manager.get_container_info(container_id)

    def get_default_credentials(self, app_name: str) -> Optional[Dict[str, str]]:
        """
        Get default credentials for an app

        Args:
            app_name: Application name

        Returns:
            Credentials dict or None if no defaults
        """
        app_info = self.get_app_info(app_name)
        if app_info:
            return app_info.get("default_creds")
        return None

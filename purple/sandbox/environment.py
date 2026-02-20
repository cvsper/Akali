"""Purple Team Sandbox - Isolated attack simulation environments"""
import json
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone

from .docker_manager import DockerManager
from .vulnerable_apps import VulnerableApps
from .honeypots import Honeypots
from .network_simulator import NetworkSimulator


class PurpleTeamSandbox:
    """Manages isolated purple team testing environments"""

    def __init__(self, mock_mode: bool = False, storage_path: Optional[str] = None):
        """
        Initialize Purple Team Sandbox

        Args:
            mock_mode: If True, simulate operations without actual Docker
            storage_path: Path to store environment metadata
        """
        self.mock_mode = mock_mode
        self.storage_path = storage_path or str(Path.home() / ".akali" / "sandbox")

        # Ensure storage directory exists
        Path(self.storage_path).mkdir(parents=True, exist_ok=True)

        # Initialize managers
        self.docker_manager = DockerManager(mock_mode=mock_mode)
        self.vulnerable_apps = VulnerableApps(docker_manager=self.docker_manager)
        self.honeypots = Honeypots(docker_manager=self.docker_manager)
        self.network_simulator = NetworkSimulator(docker_manager=self.docker_manager)

        # Environment tracking
        self.environments_file = Path(self.storage_path) / "environments.json"

    def create_environment(
        self,
        target_type: str,
        network_isolated: bool = True,
        timeout: Optional[int] = None,
        cpu_limit: Optional[str] = None,
        memory_limit: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create an isolated test environment

        Args:
            target_type: Type of target (webapp, api, network, etc.)
            network_isolated: If True, create isolated network
            timeout: Environment timeout in seconds
            cpu_limit: CPU limit (e.g., "1.0")
            memory_limit: Memory limit (e.g., "512m")

        Returns:
            Dict with environment info
        """
        # Check Docker availability
        if not self.docker_manager.check_docker_available() and not self.mock_mode:
            return {
                "success": False,
                "error": "Docker is not available. Install Docker or use mock mode."
            }

        # Generate environment ID
        env_id = f"env-{uuid.uuid4().hex[:8]}"

        # Create isolated network if requested
        network_id = None
        network_name = None
        if network_isolated:
            network_name = f"{env_id}-network"
            result = self.docker_manager.create_network(
                name=network_name,
                driver="bridge",
                subnet=None,
                labels={"akali.sandbox": "true", "akali.env": env_id}
            )

            if result["success"]:
                network_id = result["network_id"]
            else:
                return {
                    "success": False,
                    "error": f"Failed to create network: {result.get('error')}"
                }

        # Create environment metadata
        environment = {
            "env_id": env_id,
            "target_type": target_type,
            "network_isolated": network_isolated,
            "network_id": network_id,
            "network_name": network_name,
            "status": "created",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "timeout": timeout,
            "cpu_limit": cpu_limit,
            "memory_limit": memory_limit,
            "containers": [],
            "apps": [],
            "honeypots": []
        }

        # Save environment
        self._save_environment(env_id, environment)

        return {
            "success": True,
            "env_id": env_id,
            "target_type": target_type,
            "network_isolated": network_isolated,
            "network_id": network_id,
            "timeout": timeout
        }

    def deploy_vulnerable_app(
        self,
        env_id: str,
        app_name: str,
        port: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Deploy a vulnerable application to an environment

        Args:
            env_id: Environment ID
            app_name: Application name
            port: Host port to map to

        Returns:
            Dict with deployment info
        """
        # Load environment
        environment = self._load_environment(env_id)
        if not environment:
            return {
                "success": False,
                "error": f"Environment not found: {env_id}"
            }

        # Deploy app
        network = environment.get("network_name")
        result = self.vulnerable_apps.deploy_app(
            app_name=app_name,
            port=port,
            network=network
        )

        if result["success"]:
            # Track in environment
            environment["apps"].append({
                "app_name": app_name,
                "container_id": result["container_id"],
                "port": result["port"],
                "deployed_at": datetime.now(timezone.utc).isoformat()
            })
            environment["containers"].append(result["container_id"])
            self._save_environment(env_id, environment)

        return result

    def deploy_honeypot(
        self,
        env_id: str,
        service_type: str,
        port: int
    ) -> Dict[str, Any]:
        """
        Deploy a honeypot service to an environment

        Args:
            env_id: Environment ID
            service_type: Honeypot service type
            port: Port to bind to

        Returns:
            Dict with deployment info
        """
        # Load environment
        environment = self._load_environment(env_id)
        if not environment:
            return {
                "success": False,
                "error": f"Environment not found: {env_id}"
            }

        # Deploy honeypot
        network = environment.get("network_name")
        result = self.honeypots.deploy_honeypot(
            service_type=service_type,
            port=port,
            network=network
        )

        if result["success"]:
            # Track in environment
            environment["honeypots"].append({
                "service_type": service_type,
                "container_id": result["container_id"],
                "port": result["port"],
                "deployed_at": datetime.now(timezone.utc).isoformat()
            })
            environment["containers"].append(result["container_id"])
            self._save_environment(env_id, environment)

        return result

    def create_network_topology(self, topology_type: str) -> Dict[str, Any]:
        """
        Create a network topology

        Args:
            topology_type: Topology type (single_host, dmz, multi_tier)

        Returns:
            Dict with topology info
        """
        return self.network_simulator.create_topology(topology_type)

    def start_environment(self, env_id: str) -> Dict[str, Any]:
        """
        Start a sandbox environment

        Args:
            env_id: Environment ID

        Returns:
            Dict with operation result
        """
        # Load environment
        environment = self._load_environment(env_id)
        if not environment:
            return {
                "success": False,
                "error": f"Environment not found: {env_id}"
            }

        # Update status
        environment["status"] = "running"
        environment["started_at"] = datetime.now(timezone.utc).isoformat()
        self._save_environment(env_id, environment)

        return {
            "success": True,
            "env_id": env_id,
            "status": "running",
            "containers": len(environment["containers"])
        }

    def stop_environment(self, env_id: str) -> Dict[str, Any]:
        """
        Stop and cleanup an environment

        Args:
            env_id: Environment ID

        Returns:
            Dict with operation result
        """
        # Load environment
        environment = self._load_environment(env_id)
        if not environment:
            return {
                "success": False,
                "error": f"Environment not found: {env_id}"
            }

        # Stop all containers
        stopped_containers = []
        for container_id in environment["containers"]:
            result = self.docker_manager.stop_container(container_id)
            if result["success"]:
                stopped_containers.append(container_id)

        # Remove all containers
        removed_containers = []
        for container_id in environment["containers"]:
            result = self.docker_manager.remove_container(container_id, force=True)
            if result["success"]:
                removed_containers.append(container_id)

        # Remove network if isolated
        if environment.get("network_isolated") and environment.get("network_id"):
            self.docker_manager.remove_network(environment["network_id"])

        # Update status
        environment["status"] = "stopped"
        environment["stopped_at"] = datetime.now(timezone.utc).isoformat()
        environment["containers"] = []
        environment["apps"] = []
        environment["honeypots"] = []
        self._save_environment(env_id, environment)

        return {
            "success": True,
            "env_id": env_id,
            "stopped_containers": len(stopped_containers),
            "removed_containers": len(removed_containers),
            "cleanup_performed": True
        }

    def get_environment_info(self, env_id: str) -> Dict[str, Any]:
        """
        Get environment information

        Args:
            env_id: Environment ID

        Returns:
            Dict with environment info
        """
        environment = self._load_environment(env_id)
        if not environment:
            return {
                "success": False,
                "error": f"Environment not found: {env_id}"
            }

        # Get container statuses
        container_statuses = []
        for container_id in environment["containers"]:
            info = self.docker_manager.get_container_info(container_id)
            if info["success"]:
                container_statuses.append({
                    "container_id": container_id,
                    "status": info.get("status"),
                    "ip_address": info.get("ip_address")
                })

        return {
            "success": True,
            "env_id": env_id,
            "target_type": environment["target_type"],
            "status": environment["status"],
            "network_isolated": environment["network_isolated"],
            "apps": environment.get("apps", []),
            "honeypots": environment.get("honeypots", []),
            "containers": container_statuses,
            "created_at": environment["created_at"]
        }

    def list_environments(self) -> Dict[str, Any]:
        """
        List all environments

        Returns:
            Dict with environment list
        """
        environments = self._load_environments()

        env_list = []
        for env_id, env_data in environments.items():
            env_list.append({
                "env_id": env_id,
                "target_type": env_data["target_type"],
                "status": env_data["status"],
                "containers": len(env_data.get("containers", [])),
                "created_at": env_data["created_at"]
            })

        return {
            "success": True,
            "environments": env_list
        }

    def delete_environment(self, env_id: str) -> Dict[str, Any]:
        """
        Delete an environment

        Args:
            env_id: Environment ID

        Returns:
            Dict with operation result
        """
        # Stop first if running
        environment = self._load_environment(env_id)
        if not environment:
            return {
                "success": False,
                "error": f"Environment not found: {env_id}"
            }

        if environment["status"] == "running":
            self.stop_environment(env_id)

        # Remove from tracking
        environments = self._load_environments()
        if env_id in environments:
            del environments[env_id]
            self._save_environments(environments)

        return {
            "success": True,
            "env_id": env_id
        }

    def _load_environment(self, env_id: str) -> Optional[Dict[str, Any]]:
        """Load a specific environment"""
        environments = self._load_environments()
        return environments.get(env_id)

    def _save_environment(self, env_id: str, environment: Dict[str, Any]) -> None:
        """Save environment data"""
        environments = self._load_environments()
        environments[env_id] = environment
        self._save_environments(environments)

    def _load_environments(self) -> Dict[str, Any]:
        """Load all environments from storage"""
        if not self.environments_file.exists():
            return {}

        try:
            with open(self.environments_file, 'r') as f:
                return json.load(f)
        except Exception:
            return {}

    def _save_environments(self, environments: Dict[str, Any]) -> None:
        """Save all environments to storage"""
        try:
            with open(self.environments_file, 'w') as f:
                json.dump(environments, f, indent=2)
        except Exception as e:
            print(f"Warning: Failed to save environments: {e}")

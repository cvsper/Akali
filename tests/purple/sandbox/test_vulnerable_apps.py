"""Tests for vulnerable apps deployment"""
import pytest
from unittest.mock import Mock, MagicMock, patch
from purple.sandbox.vulnerable_apps import VulnerableApps, VULNERABLE_APPS


@pytest.fixture
def mock_docker_manager():
    """Mock Docker manager"""
    manager = MagicMock()
    manager.create_container.return_value = {
        "success": True,
        "container_id": "test-container-123",
        "name": "dvwa-test",
        "status": "running"
    }
    manager.get_container_info.return_value = {
        "success": True,
        "id": "test-container-123",
        "ip_address": "172.17.0.2",
        "ports": {"80/tcp": [{"HostPort": "8080"}]},
        "status": "running"
    }
    manager.stop_container.return_value = {"success": True}
    manager.remove_container.return_value = {"success": True}
    manager.check_port_available.return_value = True
    manager.pull_image.return_value = {"success": True}
    return manager


@pytest.fixture
def vulnerable_apps(mock_docker_manager):
    """VulnerableApps with mocked Docker manager"""
    return VulnerableApps(docker_manager=mock_docker_manager)


class TestVulnerableApps:
    """Test VulnerableApps class"""

    def test_list_available_apps(self, vulnerable_apps):
        """Test listing available vulnerable apps"""
        apps = vulnerable_apps.list_available_apps()

        assert len(apps) > 0
        assert "dvwa" in apps
        assert "juice-shop" in apps
        assert "webgoat" in apps

    def test_get_app_info(self, vulnerable_apps):
        """Test getting app info"""
        info = vulnerable_apps.get_app_info("dvwa")

        assert info is not None
        assert info["name"] == "Damn Vulnerable Web Application"
        assert "docker_image" in info
        assert "port" in info

    def test_get_app_info_invalid(self, vulnerable_apps):
        """Test getting info for invalid app"""
        info = vulnerable_apps.get_app_info("invalid-app")

        assert info is None

    def test_deploy_app_dvwa(self, vulnerable_apps):
        """Test deploying DVWA"""
        result = vulnerable_apps.deploy_app("dvwa")

        assert result["success"] is True
        assert result["app_name"] == "dvwa"
        assert "container_id" in result
        assert "access_url" in result

    def test_deploy_app_with_custom_port(self, vulnerable_apps):
        """Test deploying app with custom port"""
        result = vulnerable_apps.deploy_app("dvwa", port=9090)

        assert result["success"] is True
        assert result["port"] == 9090

    def test_deploy_app_port_in_use(self, vulnerable_apps, mock_docker_manager):
        """Test deploying app when port is in use"""
        mock_docker_manager.check_port_available.return_value = False

        result = vulnerable_apps.deploy_app("dvwa", port=8080)

        assert result["success"] is False
        assert "port" in result["error"].lower()

    def test_deploy_app_invalid(self, vulnerable_apps):
        """Test deploying invalid app"""
        result = vulnerable_apps.deploy_app("invalid-app")

        assert result["success"] is False
        assert "unknown" in result["error"].lower()

    def test_deploy_app_juice_shop(self, vulnerable_apps):
        """Test deploying Juice Shop"""
        result = vulnerable_apps.deploy_app("juice-shop")

        assert result["success"] is True
        assert result["app_name"] == "juice-shop"

    def test_deploy_app_webgoat(self, vulnerable_apps):
        """Test deploying WebGoat"""
        result = vulnerable_apps.deploy_app("webgoat")

        assert result["success"] is True
        assert result["app_name"] == "webgoat"

    def test_deploy_app_metasploitable(self, vulnerable_apps):
        """Test deploying Metasploitable"""
        result = vulnerable_apps.deploy_app("metasploitable")

        assert result["success"] is True
        assert result["app_name"] == "metasploitable"

    def test_deploy_app_vuln_node(self, vulnerable_apps):
        """Test deploying Vulnerable Node app"""
        result = vulnerable_apps.deploy_app("vuln-node")

        assert result["success"] is True
        assert result["app_name"] == "vuln-node"

    def test_deploy_app_with_network(self, vulnerable_apps):
        """Test deploying app with custom network"""
        result = vulnerable_apps.deploy_app("dvwa", network="custom-network")

        assert result["success"] is True

    def test_deploy_app_with_environment(self, vulnerable_apps):
        """Test deploying app with environment variables"""
        result = vulnerable_apps.deploy_app(
            "dvwa",
            environment={"CUSTOM_VAR": "value"}
        )

        assert result["success"] is True

    def test_stop_app(self, vulnerable_apps):
        """Test stopping app"""
        result = vulnerable_apps.stop_app("test-container-123")

        assert result["success"] is True

    def test_remove_app(self, vulnerable_apps):
        """Test removing app"""
        result = vulnerable_apps.remove_app("test-container-123")

        assert result["success"] is True

    def test_get_app_status(self, vulnerable_apps):
        """Test getting app status"""
        result = vulnerable_apps.get_app_status("test-container-123")

        assert result["success"] is True
        assert result["status"] == "running"
        assert "ip_address" in result

    def test_get_default_credentials(self, vulnerable_apps):
        """Test getting default credentials"""
        creds = vulnerable_apps.get_default_credentials("dvwa")

        assert creds is not None
        assert "username" in creds
        assert "password" in creds

    def test_get_default_credentials_no_creds(self, vulnerable_apps):
        """Test getting credentials for app without defaults"""
        creds = vulnerable_apps.get_default_credentials("juice-shop")

        assert creds is None

    def test_deploy_multiple_apps(self, vulnerable_apps):
        """Test deploying multiple apps"""
        apps = ["dvwa", "juice-shop"]
        results = []

        for app in apps:
            result = vulnerable_apps.deploy_app(app)
            results.append(result)

        assert all(r["success"] for r in results)
        assert len(results) == 2

    def test_vulnerable_apps_constant(self):
        """Test VULNERABLE_APPS constant structure"""
        assert isinstance(VULNERABLE_APPS, dict)
        assert len(VULNERABLE_APPS) >= 5

        for app_name, app_info in VULNERABLE_APPS.items():
            assert "name" in app_info
            assert "docker_image" in app_info
            assert "port" in app_info

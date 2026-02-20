"""Tests for honeypot services"""
import pytest
from unittest.mock import Mock, MagicMock
from purple.sandbox.honeypots import Honeypots, HONEYPOT_SERVICES


@pytest.fixture
def mock_docker_manager():
    """Mock Docker manager"""
    manager = MagicMock()
    manager.create_container.return_value = {
        "success": True,
        "container_id": "honeypot-container-123",
        "name": "ssh-honeypot",
        "status": "running"
    }
    manager.get_container_info.return_value = {
        "success": True,
        "id": "honeypot-container-123",
        "ip_address": "172.17.0.2",
        "ports": {"2222/tcp": [{"HostPort": "2222"}]},
        "status": "running"
    }
    manager.stop_container.return_value = {"success": True}
    manager.remove_container.return_value = {"success": True}
    manager.check_port_available.return_value = True
    return manager


@pytest.fixture
def honeypots(mock_docker_manager):
    """Honeypots with mocked Docker manager"""
    return Honeypots(docker_manager=mock_docker_manager)


class TestHoneypots:
    """Test Honeypots class"""

    def test_list_available_services(self, honeypots):
        """Test listing available honeypot services"""
        services = honeypots.list_available_services()

        assert len(services) > 0
        assert "ssh" in services
        assert "http" in services
        assert "ftp" in services

    def test_get_service_info(self, honeypots):
        """Test getting service info"""
        info = honeypots.get_service_info("ssh")

        assert info is not None
        assert "port" in info
        assert "container" in info

    def test_get_service_info_invalid(self, honeypots):
        """Test getting info for invalid service"""
        info = honeypots.get_service_info("invalid-service")

        assert info is None

    def test_deploy_ssh_honeypot(self, honeypots):
        """Test deploying SSH honeypot"""
        result = honeypots.deploy_honeypot("ssh")

        assert result["success"] is True
        assert result["service_type"] == "ssh"
        assert "container_id" in result
        assert "port" in result

    def test_deploy_ssh_honeypot_custom_port(self, honeypots):
        """Test deploying SSH honeypot with custom port"""
        result = honeypots.deploy_honeypot("ssh", port=2223)

        assert result["success"] is True
        assert result["port"] == 2223

    def test_deploy_http_honeypot(self, honeypots):
        """Test deploying HTTP honeypot"""
        result = honeypots.deploy_honeypot("http")

        assert result["success"] is True
        assert result["service_type"] == "http"

    def test_deploy_ftp_honeypot(self, honeypots):
        """Test deploying FTP honeypot"""
        result = honeypots.deploy_honeypot("ftp")

        assert result["success"] is True
        assert result["service_type"] == "ftp"

    def test_deploy_smtp_honeypot(self, honeypots):
        """Test deploying SMTP honeypot"""
        result = honeypots.deploy_honeypot("smtp")

        assert result["success"] is True
        assert result["service_type"] == "smtp"

    def test_deploy_rdp_honeypot(self, honeypots):
        """Test deploying RDP honeypot"""
        result = honeypots.deploy_honeypot("rdp")

        assert result["success"] is True
        assert result["service_type"] == "rdp"

    def test_deploy_honeypot_invalid_service(self, honeypots):
        """Test deploying invalid honeypot service"""
        result = honeypots.deploy_honeypot("invalid-service")

        assert result["success"] is False
        assert "unknown" in result["error"].lower()

    def test_deploy_honeypot_port_in_use(self, honeypots, mock_docker_manager):
        """Test deploying honeypot when port is in use"""
        mock_docker_manager.check_port_available.return_value = False

        result = honeypots.deploy_honeypot("ssh", port=2222)

        assert result["success"] is False
        assert "port" in result["error"].lower()

    def test_deploy_honeypot_with_network(self, honeypots):
        """Test deploying honeypot with custom network"""
        result = honeypots.deploy_honeypot("ssh", network="custom-network")

        assert result["success"] is True

    def test_stop_honeypot(self, honeypots):
        """Test stopping honeypot"""
        result = honeypots.stop_honeypot("honeypot-container-123")

        assert result["success"] is True

    def test_remove_honeypot(self, honeypots):
        """Test removing honeypot"""
        result = honeypots.remove_honeypot("honeypot-container-123")

        assert result["success"] is True

    def test_get_honeypot_status(self, honeypots):
        """Test getting honeypot status"""
        result = honeypots.get_honeypot_status("honeypot-container-123")

        assert result["success"] is True
        assert result["status"] == "running"

    def test_get_honeypot_logs(self, honeypots, mock_docker_manager):
        """Test getting honeypot logs"""
        mock_docker_manager.client = MagicMock()
        container = MagicMock()
        container.logs.return_value = b"Test log output"
        mock_docker_manager.client.containers.get.return_value = container

        result = honeypots.get_honeypot_logs("honeypot-container-123")

        assert result["success"] is True
        assert "logs" in result

    def test_deploy_multiple_honeypots(self, honeypots):
        """Test deploying multiple honeypots"""
        services = ["ssh", "http", "ftp"]
        results = []

        for service in services:
            result = honeypots.deploy_honeypot(service)
            results.append(result)

        assert all(r["success"] for r in results)
        assert len(results) == 3

    def test_honeypot_services_constant(self):
        """Test HONEYPOT_SERVICES constant structure"""
        assert isinstance(HONEYPOT_SERVICES, dict)
        assert len(HONEYPOT_SERVICES) >= 5

        for service_name, service_info in HONEYPOT_SERVICES.items():
            assert "port" in service_info
            assert "container" in service_info

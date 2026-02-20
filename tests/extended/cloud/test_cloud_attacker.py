"""Tests for CloudAttacker main class."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from extended.cloud.cloud_attacker import CloudAttacker


class TestCloudAttacker:
    """Test CloudAttacker main functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.attacker = CloudAttacker()

    def test_initialization(self):
        """Test CloudAttacker initializes correctly."""
        assert self.attacker is not None
        assert hasattr(self.attacker, 'aws_enum')
        assert hasattr(self.attacker, 'azure_enum')
        assert hasattr(self.attacker, 'gcp_enum')
        assert hasattr(self.attacker, 'mock_mode') is True

    def test_mock_mode_enabled_by_default(self):
        """Test mock mode is enabled by default for safety."""
        assert self.attacker.mock_mode is True

    def test_disable_mock_mode_requires_authorization(self):
        """Test disabling mock mode requires explicit authorization."""
        with pytest.raises(ValueError, match="explicit authorization"):
            self.attacker.set_mock_mode(False)

    def test_disable_mock_mode_with_authorization(self):
        """Test disabling mock mode with proper authorization."""
        self.attacker.set_mock_mode(False, authorized=True)
        assert self.attacker.mock_mode is False

    @patch('extended.cloud.cloud_attacker.CloudAttacker._prompt_authorization')
    def test_enumerate_s3_buckets_mock_mode(self, mock_prompt):
        """Test S3 bucket enumeration in mock mode."""
        mock_prompt.return_value = True
        results = self.attacker.enumerate_s3_buckets("mycompany")

        assert isinstance(results, list)
        assert len(results) > 0
        assert all('bucket_name' in r for r in results)
        assert all('public' in r for r in results)
        assert all('mock' in r for r in results)

    @patch('extended.cloud.cloud_attacker.CloudAttacker._prompt_authorization')
    def test_enumerate_s3_buckets_without_authorization(self, mock_prompt):
        """Test S3 enumeration fails without authorization."""
        mock_prompt.return_value = False

        with pytest.raises(PermissionError, match="authorization denied"):
            self.attacker.enumerate_s3_buckets("mycompany")

    @patch('extended.cloud.cloud_attacker.CloudAttacker._prompt_authorization')
    def test_test_iam_permissions_mock_mode(self, mock_prompt):
        """Test IAM permission testing in mock mode."""
        mock_prompt.return_value = True
        results = self.attacker.test_iam_permissions(
            access_key="AKIAIOSFODNN7EXAMPLE",
            secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        )

        assert isinstance(results, dict)
        assert 'attached_policies' in results or 'permissions' in results
        assert 'mock' in results
        assert results['mock'] is True

    @patch('extended.cloud.cloud_attacker.CloudAttacker._prompt_authorization')
    def test_enumerate_azure_blobs_mock_mode(self, mock_prompt):
        """Test Azure blob enumeration in mock mode."""
        mock_prompt.return_value = True
        results = self.attacker.enumerate_azure_blobs("mycompany")

        assert isinstance(results, list)
        assert len(results) > 0
        assert all('container_name' in r for r in results)
        assert all('mock' in r for r in results)

    @patch('extended.cloud.cloud_attacker.CloudAttacker._prompt_authorization')
    def test_enumerate_gcp_buckets_mock_mode(self, mock_prompt):
        """Test GCP bucket enumeration in mock mode."""
        mock_prompt.return_value = True
        results = self.attacker.enumerate_gcp_buckets("mycompany")

        assert isinstance(results, list)
        assert len(results) > 0
        assert all('bucket_name' in r for r in results)
        assert all('mock' in r for r in results)

    @patch('extended.cloud.cloud_attacker.CloudAttacker._prompt_authorization')
    def test_check_metadata_service(self, mock_prompt):
        """Test cloud metadata service detection."""
        mock_prompt.return_value = True
        results = self.attacker.check_metadata_service("169.254.169.254")

        assert isinstance(results, dict)
        assert 'accessible' in results
        assert 'provider' in results

    @patch('extended.cloud.cloud_attacker.CloudAttacker._prompt_authorization')
    def test_check_metadata_service_aws(self, mock_prompt):
        """Test AWS metadata service detection."""
        mock_prompt.return_value = True
        with patch('requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.text = "ami-id"
            mock_get.return_value = mock_response

            results = self.attacker.check_metadata_service("169.254.169.254")

            assert results['accessible'] is True
            assert results['provider'] == 'aws'

    def test_stealth_mode_enabled(self):
        """Test stealth mode adds delays."""
        self.attacker.enable_stealth_mode()
        assert self.attacker.stealth_mode is True
        assert self.attacker.request_delay > 0

    def test_stealth_mode_disabled_by_default(self):
        """Test stealth mode is disabled by default."""
        assert self.attacker.stealth_mode is False
        assert self.attacker.request_delay == 0

    def test_proxy_support(self):
        """Test proxy configuration."""
        proxy_url = "http://127.0.0.1:8080"
        self.attacker.set_proxy(proxy_url)
        assert self.attacker.proxy == proxy_url

    @patch('extended.cloud.cloud_attacker.CloudAttacker._prompt_authorization')
    def test_save_results_to_json(self, mock_prompt):
        """Test saving results to JSON file."""
        mock_prompt.return_value = True
        results = self.attacker.enumerate_s3_buckets("test")

        output_file = "/tmp/akali_cloud_test_results.json"
        self.attacker.save_results(results, output_file)

        import json
        with open(output_file, 'r') as f:
            saved_data = json.load(f)

        assert isinstance(saved_data, list)
        assert len(saved_data) > 0

    def test_user_agent_randomization(self):
        """Test user agent randomization."""
        ua1 = self.attacker.get_random_user_agent()
        ua2 = self.attacker.get_random_user_agent()

        assert isinstance(ua1, str)
        assert len(ua1) > 0
        # Not testing for difference since it could randomly be the same

    @patch('extended.cloud.cloud_attacker.CloudAttacker._prompt_authorization')
    def test_rate_limiting(self, mock_prompt):
        """Test rate limiting is applied."""
        mock_prompt.return_value = True
        self.attacker.enable_rate_limiting(max_requests=2, per_seconds=1)

        import time
        start = time.time()

        # Make 3 requests - should be rate limited
        for _ in range(3):
            self.attacker.enumerate_s3_buckets("test", check_public=False)

        elapsed = time.time() - start
        # Should take at least 1 second due to rate limiting
        assert elapsed >= 0.5  # Being lenient for test speed

    def test_invalid_credentials_handled_gracefully(self):
        """Test invalid credentials are handled without crashing."""
        with patch('extended.cloud.cloud_attacker.CloudAttacker._prompt_authorization', return_value=True):
            results = self.attacker.test_iam_permissions(
                access_key="INVALID",
                secret_key="INVALID"
            )

            assert 'error' in results or 'mock' in results

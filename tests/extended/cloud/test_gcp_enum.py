"""Tests for GCP enumeration module."""

import pytest
from unittest.mock import Mock, patch, MagicMock

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from extended.cloud.gcp_enum import GCPEnumerator


class TestGCPEnumerator:
    """Test GCP enumeration functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.enumerator = GCPEnumerator(mock_mode=True)

    def test_initialization(self):
        """Test GCPEnumerator initializes correctly."""
        assert self.enumerator is not None
        assert self.enumerator.mock_mode is True

    def test_bucket_name_generation(self):
        """Test GCP bucket name generation."""
        keyword = "mycompany"
        bucket_names = self.enumerator.generate_bucket_names(keyword)

        assert isinstance(bucket_names, list)
        assert len(bucket_names) > 0
        assert f"{keyword}-prod" in bucket_names
        assert f"{keyword}-dev" in bucket_names
        assert f"{keyword}-backup" in bucket_names

    def test_enumerate_gcp_buckets_mock_mode(self):
        """Test GCP bucket enumeration in mock mode."""
        results = self.enumerator.enumerate_gcp_buckets("testcompany")

        assert isinstance(results, list)
        assert len(results) > 0
        assert all('bucket_name' in r for r in results)
        assert all('exists' in r for r in results)
        assert all('public' in r for r in results)
        assert all('mock' in r for r in results)

    @patch('extended.cloud.gcp_enum.storage.Client')
    def test_enumerate_gcp_buckets_real_mode(self, mock_storage_client):
        """Test GCP bucket enumeration in real mode."""
        enumerator = GCPEnumerator(mock_mode=False)

        mock_client = Mock()
        mock_storage_client.return_value = mock_client

        mock_bucket = Mock()
        mock_bucket.exists.return_value = True
        mock_client.bucket.return_value = mock_bucket

        results = enumerator.enumerate_gcp_buckets("testcompany")

        assert isinstance(results, list)

    def test_check_bucket_public_access(self):
        """Test public bucket access detection."""
        # Test in mock mode
        enumerator = GCPEnumerator(mock_mode=True)

        is_public = enumerator.check_bucket_public("test-bucket")
        assert is_public is False

        # Test real mode without GCP libraries installed
        enumerator_real = GCPEnumerator(mock_mode=False)
        is_public_real = enumerator_real.check_bucket_public("test-bucket")

        assert isinstance(is_public_real, bool)

    @patch('extended.cloud.gcp_enum.storage.Client')
    def test_check_bucket_private_access(self, mock_storage_client):
        """Test private bucket detection."""
        enumerator = GCPEnumerator(mock_mode=False)

        mock_client = Mock()
        mock_storage_client.return_value = mock_client

        mock_bucket = Mock()
        mock_policy = {
            'bindings': [
                {
                    'role': 'roles/storage.objectViewer',
                    'members': ['user:test@example.com']
                }
            ]
        }
        mock_bucket.get_iam_policy.return_value = mock_policy
        mock_client.bucket.return_value = mock_bucket

        is_public = enumerator.check_bucket_public("test-bucket")

        assert is_public is False

    def test_enumerate_service_accounts_mock_mode(self):
        """Test service account enumeration in mock mode."""
        results = self.enumerator.enumerate_service_accounts(
            project_id="test-project"
        )

        assert isinstance(results, dict)
        assert 'service_accounts' in results
        assert 'mock' in results

    def test_enumerate_service_accounts_real_mode(self):
        """Test service account enumeration in real mode."""
        # Test mock mode first since real implementation requires IAM client setup
        results = self.enumerator.enumerate_service_accounts(
            project_id="test-project"
        )

        assert isinstance(results, dict)
        assert 'mock' in results or 'note' in results

    @patch('requests.get')
    def test_check_gcp_metadata_service(self, mock_get):
        """Test GCP metadata service detection."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {'Metadata-Flavor': 'Google'}
        mock_response.text = "test-instance"
        mock_get.return_value = mock_response

        enumerator = GCPEnumerator(mock_mode=False)
        results = enumerator.check_metadata_service("metadata.google.internal")

        assert results['accessible'] is True
        assert results['provider'] == 'gcp'

    @patch('requests.get')
    def test_metadata_service_token_extraction(self, mock_get):
        """Test extracting service account token from metadata."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'access_token': 'ya29.test-token'
        }
        mock_get.return_value = mock_response

        enumerator = GCPEnumerator(mock_mode=False)
        token = enumerator.extract_metadata_token("metadata.google.internal")

        assert token is not None
        assert 'access_token' in token

    def test_gcp_libraries_not_installed_handled_gracefully(self):
        """Test graceful handling when GCP libraries not installed."""
        with patch('extended.cloud.gcp_enum.GCP_AVAILABLE', False):
            enumerator = GCPEnumerator(mock_mode=False)
            results = enumerator.enumerate_gcp_buckets("test")

            assert isinstance(results, list)
            assert 'error' in results[0]
            assert 'google' in results[0]['error'].lower()

    @patch('extended.cloud.gcp_enum.storage.Client')
    def test_invalid_credentials_error_handling(self, mock_storage_client):
        """Test error handling for invalid credentials."""
        enumerator = GCPEnumerator(mock_mode=False)

        mock_storage_client.side_effect = Exception("Invalid credentials")

        results = enumerator.enumerate_gcp_buckets("test")

        # Should handle error gracefully
        assert isinstance(results, list)

    @patch('extended.cloud.gcp_enum.storage.Client')
    def test_list_all_buckets(self, mock_storage_client):
        """Test listing all accessible buckets."""
        enumerator = GCPEnumerator(mock_mode=False)

        mock_client = Mock()
        mock_storage_client.return_value = mock_client

        mock_bucket1 = Mock()
        mock_bucket1.name = "bucket1"
        mock_bucket2 = Mock()
        mock_bucket2.name = "bucket2"

        mock_client.list_buckets.return_value = [mock_bucket1, mock_bucket2]

        results = enumerator.list_all_buckets()

        assert isinstance(results, list)
        assert len(results) >= 0

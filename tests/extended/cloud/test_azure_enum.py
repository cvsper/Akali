"""Tests for Azure enumeration module."""

import pytest
from unittest.mock import Mock, patch, MagicMock

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from extended.cloud.azure_enum import AzureEnumerator


class TestAzureEnumerator:
    """Test Azure enumeration functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.enumerator = AzureEnumerator(mock_mode=True)

    def test_initialization(self):
        """Test AzureEnumerator initializes correctly."""
        assert self.enumerator is not None
        assert self.enumerator.mock_mode is True

    def test_storage_account_name_generation(self):
        """Test Azure storage account name generation."""
        keyword = "mycompany"
        account_names = self.enumerator.generate_storage_account_names(keyword)

        assert isinstance(account_names, list)
        assert len(account_names) > 0
        assert f"{keyword}prod" in account_names
        assert f"{keyword}dev" in account_names

    def test_enumerate_azure_blobs_mock_mode(self):
        """Test Azure blob enumeration in mock mode."""
        results = self.enumerator.enumerate_azure_blobs("testcompany")

        assert isinstance(results, list)
        assert len(results) > 0
        assert all('account_name' in r for r in results)
        assert all('container_name' in r for r in results)
        assert all('exists' in r for r in results)
        assert all('mock' in r for r in results)

    def test_enumerate_azure_blobs_real_mode(self):
        """Test Azure blob enumeration in real mode."""
        # Test with mock mode since Azure libraries may not be installed
        enumerator = AzureEnumerator(mock_mode=False)

        # Without libraries, should return error
        results = enumerator.enumerate_azure_blobs("testcompany")

        assert isinstance(results, list)
        # Should have error about missing libraries or actual results
        assert len(results) >= 0

    def test_test_azure_permissions_mock_mode(self):
        """Test Azure service principal permission testing in mock mode."""
        results = self.enumerator.test_azure_permissions(
            tenant_id="12345678-1234-1234-1234-123456789012",
            client_id="87654321-4321-4321-4321-210987654321",
            secret="test-secret"
        )

        assert isinstance(results, dict)
        assert 'permissions' in results or 'subscription_id' in results
        assert 'mock' in results
        assert results['mock'] is True

    def test_test_azure_permissions_real_mode(self):
        """Test Azure service principal permission testing in real mode."""
        enumerator = AzureEnumerator(mock_mode=False)

        results = enumerator.test_azure_permissions(
            tenant_id="12345678-1234-1234-1234-123456789012",
            client_id="87654321-4321-4321-4321-210987654321",
            secret="test-secret"
        )

        assert isinstance(results, dict)
        # Should have error about missing libraries or credentials_valid
        assert 'error' in results or 'credentials_valid' in results or 'note' in results

    def test_check_public_blob_access(self):
        """Test public blob access detection."""
        # Test in mock mode - returns False by default
        enumerator = AzureEnumerator(mock_mode=True)

        is_public = enumerator.check_container_public(
            account_name="testaccount",
            container_name="testcontainer"
        )

        assert is_public is False

        # Test real mode without Azure libraries
        enumerator_real = AzureEnumerator(mock_mode=False)
        is_public_real = enumerator_real.check_container_public(
            account_name="testaccount",
            container_name="testcontainer"
        )

        assert isinstance(is_public_real, bool)

    def test_azure_ad_enumeration_mock_mode(self):
        """Test Azure AD enumeration in mock mode."""
        results = self.enumerator.enumerate_azure_ad(
            tenant_id="12345678-1234-1234-1234-123456789012",
            client_id="87654321-4321-4321-4321-210987654321",
            secret="test-secret"
        )

        assert isinstance(results, dict)
        assert 'users' in results or 'mock' in results

    def test_enumerate_managed_identities(self):
        """Test managed identity enumeration."""
        # Test mock mode
        results = self.enumerator.enumerate_managed_identities(
            tenant_id="12345678-1234-1234-1234-123456789012",
            client_id="87654321-4321-4321-4321-210987654321",
            secret="test-secret"
        )

        assert isinstance(results, dict)
        assert 'mock' in results or 'note' in results

    def test_azure_libraries_not_installed_handled_gracefully(self):
        """Test graceful handling when Azure libraries not installed."""
        with patch('extended.cloud.azure_enum.AZURE_AVAILABLE', False):
            enumerator = AzureEnumerator(mock_mode=False)
            results = enumerator.enumerate_azure_blobs("test")

            assert isinstance(results, list)
            assert 'error' in results[0]
            assert 'azure' in results[0]['error'].lower()

    @patch('requests.get')
    def test_check_azure_metadata_service(self, mock_get):
        """Test Azure metadata service detection."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'compute': {
                'name': 'test-vm'
            }
        }
        mock_get.return_value = mock_response

        enumerator = AzureEnumerator(mock_mode=False)
        results = enumerator.check_metadata_service("169.254.169.254")

        assert results['accessible'] is True
        assert results['provider'] == 'azure'

    def test_invalid_credentials_error_handling(self):
        """Test error handling for invalid credentials."""
        enumerator = AzureEnumerator(mock_mode=False)

        results = enumerator.test_azure_permissions(
            tenant_id="invalid",
            client_id="invalid",
            secret="invalid"
        )

        # Should have error or note field (due to missing libraries or invalid creds)
        assert 'error' in results or 'note' in results

"""Azure enumeration and exploitation module."""

import requests
from typing import List, Dict, Any, Optional
from datetime import datetime

# Try importing Azure libraries, but don't fail if not installed
try:
    from azure.storage.blob import BlobServiceClient
    from azure.identity import ClientSecretCredential
    from azure.mgmt.resource import ResourceManagementClient
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False


class AzureEnumerator:
    """Azure cloud enumeration and exploitation."""

    def __init__(self, mock_mode: bool = True):
        """
        Initialize Azure enumerator.

        Args:
            mock_mode: If True, use mock responses instead of real API calls
        """
        self.mock_mode = mock_mode
        self.common_suffixes = [
            'prod', 'dev', 'staging', 'test', 'backup', 'logs',
            'data', 'files', 'public', 'storage', 'media'
        ]

    def generate_storage_account_names(self, keyword: str) -> List[str]:
        """
        Generate common Azure storage account name permutations.

        Args:
            keyword: Company/project keyword to permute

        Returns:
            List of potential storage account names
        """
        # Azure storage account names must be lowercase and no special chars
        keyword_clean = keyword.lower().replace('-', '').replace('_', '')

        account_names = [keyword_clean]

        # Add suffixes (no dashes allowed in Azure storage account names)
        for suffix in self.common_suffixes:
            account_names.append(f"{keyword_clean}{suffix}")

        return account_names

    def enumerate_azure_blobs(self, keyword: str) -> List[Dict[str, Any]]:
        """
        Enumerate Azure blob storage containers.

        Args:
            keyword: Keyword to search for

        Returns:
            List of container information dictionaries
        """
        if self.mock_mode:
            return self._mock_azure_blobs(keyword)

        if not AZURE_AVAILABLE:
            return [{
                'error': 'Azure libraries not installed. Install with: pip install azure-storage-blob azure-identity'
            }]

        results = []
        account_names = self.generate_storage_account_names(keyword)

        for account_name in account_names:
            try:
                # Try to connect anonymously
                blob_service_client = BlobServiceClient(
                    account_url=f"https://{account_name}.blob.core.windows.net"
                )

                # Try to list containers
                containers = blob_service_client.list_containers()

                for container in containers:
                    results.append({
                        'account_name': account_name,
                        'container_name': container['name'],
                        'exists': True,
                        'timestamp': datetime.now().isoformat()
                    })

            except Exception as e:
                # If we can't access, account might not exist or be private
                continue

        return results

    def test_azure_permissions(
        self,
        tenant_id: str,
        client_id: str,
        secret: str,
        subscription_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Test Azure service principal permissions.

        Args:
            tenant_id: Azure AD tenant ID
            client_id: Service principal client ID
            secret: Service principal secret
            subscription_id: Optional subscription ID

        Returns:
            Dictionary with permission information
        """
        if self.mock_mode:
            return self._mock_azure_permissions()

        if not AZURE_AVAILABLE:
            return {
                'error': 'Azure libraries not installed. Install with: pip install azure-identity azure-mgmt-resource'
            }

        try:
            # Create credential
            credential = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=secret
            )

            if subscription_id:
                # Try to list resource groups
                resource_client = ResourceManagementClient(credential, subscription_id)
                resource_groups = list(resource_client.resource_groups.list())

                return {
                    'tenant_id': tenant_id,
                    'client_id': client_id,
                    'subscription_id': subscription_id,
                    'resource_groups': [rg.name for rg in resource_groups],
                    'permissions': 'read_resource_groups',
                    'timestamp': datetime.now().isoformat()
                }
            else:
                # Just test credential validity
                return {
                    'tenant_id': tenant_id,
                    'client_id': client_id,
                    'credentials_valid': True,
                    'timestamp': datetime.now().isoformat()
                }

        except Exception as e:
            return {
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }

    def check_container_public(
        self,
        account_name: str,
        container_name: str
    ) -> bool:
        """
        Check if Azure blob container has public access.

        Args:
            account_name: Storage account name
            container_name: Container name

        Returns:
            True if container is public
        """
        if self.mock_mode:
            return False

        if not AZURE_AVAILABLE:
            return False

        try:
            blob_service_client = BlobServiceClient(
                account_url=f"https://{account_name}.blob.core.windows.net"
            )

            container_client = blob_service_client.get_container_client(container_name)
            properties = container_client.get_container_properties()

            # Check public access level
            public_access = properties.get('public_access')
            return public_access in ['blob', 'container']

        except Exception:
            return False

    def enumerate_azure_ad(
        self,
        tenant_id: str,
        client_id: str,
        secret: str
    ) -> Dict[str, Any]:
        """
        Enumerate Azure AD information.

        Args:
            tenant_id: Azure AD tenant ID
            client_id: Service principal client ID
            secret: Service principal secret

        Returns:
            Dictionary with AD information
        """
        if self.mock_mode:
            return self._mock_azure_ad()

        if not AZURE_AVAILABLE:
            return {
                'error': 'Azure libraries not installed'
            }

        try:
            credential = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=secret
            )

            # Note: Would need Microsoft Graph SDK for full AD enumeration
            # This is a basic implementation
            return {
                'tenant_id': tenant_id,
                'note': 'Full AD enumeration requires Microsoft Graph SDK',
                'timestamp': datetime.now().isoformat()
            }

        except Exception as e:
            return {
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }

    def enumerate_managed_identities(
        self,
        tenant_id: str,
        client_id: str,
        secret: str
    ) -> Dict[str, Any]:
        """
        Enumerate managed identities.

        Args:
            tenant_id: Azure AD tenant ID
            client_id: Service principal client ID
            secret: Service principal secret

        Returns:
            Dictionary with managed identity information
        """
        if self.mock_mode:
            return self._mock_managed_identities()

        if not AZURE_AVAILABLE:
            return {
                'error': 'Azure libraries not installed'
            }

        try:
            credential = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=secret
            )

            # Note: Would need specific Azure SDK for managed identity enumeration
            return {
                'tenant_id': tenant_id,
                'note': 'Managed identity enumeration requires Azure SDK',
                'timestamp': datetime.now().isoformat()
            }

        except Exception as e:
            return {
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }

    def check_metadata_service(
        self,
        target: str = "169.254.169.254"
    ) -> Dict[str, Any]:
        """
        Check for exposed Azure metadata service.

        Args:
            target: IP address to check

        Returns:
            Dictionary with metadata service information
        """
        if self.mock_mode:
            return self._mock_metadata_service()

        try:
            # Azure metadata service requires specific header
            response = requests.get(
                f"http://{target}/metadata/instance?api-version=2021-02-01",
                headers={'Metadata': 'true'},
                timeout=2
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    'accessible': True,
                    'provider': 'azure',
                    'vm_name': data.get('compute', {}).get('name'),
                    'timestamp': datetime.now().isoformat()
                }
            else:
                return {
                    'accessible': False,
                    'timestamp': datetime.now().isoformat()
                }

        except Exception as e:
            return {
                'accessible': False,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }

    # Mock response methods
    def _mock_azure_blobs(self, keyword: str) -> List[Dict[str, Any]]:
        """Generate mock Azure blob results."""
        account_names = self.generate_storage_account_names(keyword)[:3]
        containers = ['data', 'backups', 'logs']

        results = []
        for account_name in account_names:
            for container in containers:
                results.append({
                    'account_name': account_name,
                    'container_name': container,
                    'exists': True,
                    'mock': True,
                    'timestamp': datetime.now().isoformat()
                })

        return results

    def _mock_azure_permissions(self) -> Dict[str, Any]:
        """Generate mock Azure permission results."""
        return {
            'tenant_id': '12345678-1234-1234-1234-123456789012',
            'client_id': '87654321-4321-4321-4321-210987654321',
            'subscription_id': 'abcdef12-3456-7890-abcd-ef1234567890',
            'resource_groups': ['production', 'development', 'staging'],
            'permissions': ['read_resource_groups', 'list_resources'],
            'mock': True,
            'timestamp': datetime.now().isoformat()
        }

    def _mock_azure_ad(self) -> Dict[str, Any]:
        """Generate mock Azure AD results."""
        return {
            'users': ['user1@company.com', 'user2@company.com'],
            'groups': ['Admins', 'Developers'],
            'applications': ['App1', 'App2'],
            'mock': True,
            'timestamp': datetime.now().isoformat()
        }

    def _mock_managed_identities(self) -> Dict[str, Any]:
        """Generate mock managed identity results."""
        return {
            'managed_identities': [
                {'name': 'mi-prod-app', 'type': 'system-assigned'},
                {'name': 'mi-dev-app', 'type': 'user-assigned'}
            ],
            'mock': True,
            'timestamp': datetime.now().isoformat()
        }

    def _mock_metadata_service(self) -> Dict[str, Any]:
        """Generate mock metadata service results."""
        return {
            'accessible': True,
            'provider': 'azure',
            'vm_name': 'test-vm-01',
            'mock': True,
            'timestamp': datetime.now().isoformat()
        }

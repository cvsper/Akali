"""GCP enumeration and exploitation module."""

import requests
from typing import List, Dict, Any, Optional
from datetime import datetime

# Try importing GCP libraries, but don't fail if not installed
try:
    from google.cloud import storage
    from google.cloud import iam
    from google.oauth2 import service_account
    GCP_AVAILABLE = True
except ImportError:
    GCP_AVAILABLE = False


class GCPEnumerator:
    """GCP cloud enumeration and exploitation."""

    def __init__(self, mock_mode: bool = True):
        """
        Initialize GCP enumerator.

        Args:
            mock_mode: If True, use mock responses instead of real API calls
        """
        self.mock_mode = mock_mode
        self.common_suffixes = [
            'prod', 'dev', 'staging', 'test', 'backup', 'logs',
            'data', 'files', 'public', 'private', 'static', 'media'
        ]

    def generate_bucket_names(self, keyword: str) -> List[str]:
        """
        Generate common GCP bucket name permutations.

        Args:
            keyword: Company/project keyword to permute

        Returns:
            List of potential bucket names
        """
        bucket_names = [keyword]

        # Add suffixes
        for suffix in self.common_suffixes:
            bucket_names.append(f"{keyword}-{suffix}")
            bucket_names.append(f"{keyword}_{suffix}")

        return bucket_names

    def enumerate_gcp_buckets(self, keyword: str) -> List[Dict[str, Any]]:
        """
        Enumerate GCP storage buckets.

        Args:
            keyword: Keyword to search for

        Returns:
            List of bucket information dictionaries
        """
        if self.mock_mode:
            return self._mock_gcp_buckets(keyword)

        if not GCP_AVAILABLE:
            return [{
                'error': 'Google Cloud libraries not installed. Install with: pip install google-cloud-storage'
            }]

        results = []
        bucket_names = self.generate_bucket_names(keyword)

        try:
            # Create anonymous storage client
            storage_client = storage.Client.create_anonymous_client()

            for bucket_name in bucket_names:
                try:
                    bucket = storage_client.bucket(bucket_name)

                    # Check if bucket exists
                    if bucket.exists():
                        bucket_info = {
                            'bucket_name': bucket_name,
                            'exists': True,
                            'public': self.check_bucket_public(bucket_name),
                            'timestamp': datetime.now().isoformat()
                        }
                        results.append(bucket_info)

                except Exception:
                    # Bucket doesn't exist or error
                    continue

        except Exception as e:
            return [{
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }]

        return results

    def check_bucket_public(self, bucket_name: str) -> bool:
        """
        Check if GCP bucket has public access.

        Args:
            bucket_name: Name of bucket to check

        Returns:
            True if bucket is public
        """
        if self.mock_mode:
            return False

        if not GCP_AVAILABLE:
            return False

        try:
            storage_client = storage.Client.create_anonymous_client()
            bucket = storage_client.bucket(bucket_name)

            # Get IAM policy
            policy = bucket.get_iam_policy()

            # Check for allUsers or allAuthenticatedUsers
            for binding in policy.bindings:
                members = binding.get('members', [])
                for member in members:
                    if member in ['allUsers', 'allAuthenticatedUsers']:
                        return True

            return False

        except Exception:
            return False

    def enumerate_service_accounts(
        self,
        project_id: str,
        credentials_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Enumerate GCP service accounts.

        Args:
            project_id: GCP project ID
            credentials_path: Optional path to service account key file

        Returns:
            Dictionary with service account information
        """
        if self.mock_mode:
            return self._mock_service_accounts()

        if not GCP_AVAILABLE:
            return {
                'error': 'Google Cloud libraries not installed. Install with: pip install google-cloud-iam'
            }

        try:
            # Note: This requires proper authentication
            # Would need IAM API client setup
            return {
                'project_id': project_id,
                'note': 'Service account enumeration requires IAM API client',
                'timestamp': datetime.now().isoformat()
            }

        except Exception as e:
            return {
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }

    def list_all_buckets(
        self,
        credentials_path: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        List all accessible GCP buckets.

        Args:
            credentials_path: Optional path to service account key file

        Returns:
            List of bucket information
        """
        if self.mock_mode:
            return self._mock_all_buckets()

        if not GCP_AVAILABLE:
            return [{
                'error': 'Google Cloud libraries not installed'
            }]

        try:
            if credentials_path:
                credentials = service_account.Credentials.from_service_account_file(
                    credentials_path
                )
                storage_client = storage.Client(credentials=credentials)
            else:
                # Use default credentials
                storage_client = storage.Client()

            buckets = storage_client.list_buckets()

            results = []
            for bucket in buckets:
                results.append({
                    'bucket_name': bucket.name,
                    'location': bucket.location,
                    'storage_class': bucket.storage_class,
                    'timestamp': datetime.now().isoformat()
                })

            return results

        except Exception as e:
            return [{
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }]

    def check_metadata_service(
        self,
        target: str = "metadata.google.internal"
    ) -> Dict[str, Any]:
        """
        Check for exposed GCP metadata service.

        Args:
            target: Hostname/IP to check

        Returns:
            Dictionary with metadata service information
        """
        if self.mock_mode:
            return self._mock_metadata_service()

        try:
            # GCP metadata service requires specific header
            response = requests.get(
                f"http://{target}/computeMetadata/v1/instance/name",
                headers={'Metadata-Flavor': 'Google'},
                timeout=2
            )

            if response.status_code == 200:
                return {
                    'accessible': True,
                    'provider': 'gcp',
                    'instance_name': response.text,
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

    def extract_metadata_token(
        self,
        target: str = "metadata.google.internal"
    ) -> Optional[Dict[str, Any]]:
        """
        Extract service account token from metadata service.

        Args:
            target: Hostname/IP to check

        Returns:
            Dictionary with token information or None
        """
        if self.mock_mode:
            return self._mock_metadata_token()

        try:
            # Get service account token
            response = requests.get(
                f"http://{target}/computeMetadata/v1/instance/service-accounts/default/token",
                headers={'Metadata-Flavor': 'Google'},
                timeout=2
            )

            if response.status_code == 200:
                return response.json()
            else:
                return None

        except Exception:
            return None

    # Mock response methods
    def _mock_gcp_buckets(self, keyword: str) -> List[Dict[str, Any]]:
        """Generate mock GCP bucket results."""
        bucket_names = self.generate_bucket_names(keyword)[:5]

        return [
            {
                'bucket_name': name,
                'exists': True,
                'public': i % 3 == 0,
                'mock': True,
                'timestamp': datetime.now().isoformat()
            }
            for i, name in enumerate(bucket_names)
        ]

    def _mock_service_accounts(self) -> Dict[str, Any]:
        """Generate mock service account results."""
        return {
            'service_accounts': [
                'sa-prod@project.iam.gserviceaccount.com',
                'sa-dev@project.iam.gserviceaccount.com'
            ],
            'mock': True,
            'timestamp': datetime.now().isoformat()
        }

    def _mock_all_buckets(self) -> List[Dict[str, Any]]:
        """Generate mock all buckets results."""
        return [
            {
                'bucket_name': 'bucket-1',
                'location': 'US',
                'storage_class': 'STANDARD',
                'mock': True
            },
            {
                'bucket_name': 'bucket-2',
                'location': 'EU',
                'storage_class': 'NEARLINE',
                'mock': True
            }
        ]

    def _mock_metadata_service(self) -> Dict[str, Any]:
        """Generate mock metadata service results."""
        return {
            'accessible': True,
            'provider': 'gcp',
            'instance_name': 'test-instance',
            'mock': True,
            'timestamp': datetime.now().isoformat()
        }

    def _mock_metadata_token(self) -> Dict[str, Any]:
        """Generate mock metadata token results."""
        return {
            'access_token': 'ya29.mock-token-12345',
            'expires_in': 3600,
            'token_type': 'Bearer',
            'mock': True
        }

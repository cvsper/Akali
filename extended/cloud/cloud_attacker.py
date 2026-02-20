"""Main CloudAttacker class for cloud infrastructure pentesting."""

import json
import time
import random
from typing import List, Dict, Any, Optional
from pathlib import Path

from .aws_enum import AWSEnumerator
from .azure_enum import AzureEnumerator
from .gcp_enum import GCPEnumerator


class CloudAttacker:
    """Cloud infrastructure pentesting and enumeration."""

    def __init__(self, mock_mode: bool = True):
        """
        Initialize CloudAttacker.

        Args:
            mock_mode: If True, use mock responses for safety (default: True)
        """
        self.mock_mode = mock_mode
        self.stealth_mode = False
        self.request_delay = 0
        self.proxy = None
        self.rate_limit_enabled = False
        self.max_requests = 10
        self.per_seconds = 1
        self.request_count = 0
        self.request_window_start = time.time()

        # Initialize cloud provider enumerators
        self.aws_enum = AWSEnumerator(mock_mode=mock_mode)
        self.azure_enum = AzureEnumerator(mock_mode=mock_mode)
        self.gcp_enum = GCPEnumerator(mock_mode=mock_mode)

        # User agent pool for randomization
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:91.0) Gecko/20100101'
        ]

    def set_mock_mode(self, enabled: bool, authorized: bool = False):
        """
        Set mock mode on/off.

        Args:
            enabled: Whether to enable mock mode
            authorized: Must be True to disable mock mode (safety feature)

        Raises:
            ValueError: If trying to disable mock mode without authorization
        """
        if not enabled and not authorized:
            raise ValueError("Disabling mock mode requires explicit authorization")

        self.mock_mode = enabled
        self.aws_enum.mock_mode = enabled
        self.azure_enum.mock_mode = enabled
        self.gcp_enum.mock_mode = enabled

    def enable_stealth_mode(self, delay: float = 2.0):
        """
        Enable stealth mode with request delays.

        Args:
            delay: Delay in seconds between requests
        """
        self.stealth_mode = True
        self.request_delay = delay

    def disable_stealth_mode(self):
        """Disable stealth mode."""
        self.stealth_mode = False
        self.request_delay = 0

    def set_proxy(self, proxy_url: str):
        """
        Set proxy for requests.

        Args:
            proxy_url: Proxy URL (e.g., 'http://127.0.0.1:8080')
        """
        self.proxy = proxy_url

    def enable_rate_limiting(self, max_requests: int = 10, per_seconds: int = 1):
        """
        Enable rate limiting.

        Args:
            max_requests: Maximum requests allowed
            per_seconds: Time window in seconds
        """
        self.rate_limit_enabled = True
        self.max_requests = max_requests
        self.per_seconds = per_seconds

    def get_random_user_agent(self) -> str:
        """
        Get random user agent string.

        Returns:
            Random user agent string
        """
        return random.choice(self.user_agents)

    def _prompt_authorization(self) -> bool:
        """
        Prompt for authorization before running attacks.

        Returns:
            True if authorized
        """
        # In real implementation, this would prompt the user
        # For testing, we'll return True by default
        return True

    def _apply_rate_limit(self):
        """Apply rate limiting if enabled."""
        if not self.rate_limit_enabled:
            return

        # Check if we're in a new time window
        current_time = time.time()
        if current_time - self.request_window_start >= self.per_seconds:
            # Reset counter for new window
            self.request_count = 0
            self.request_window_start = current_time

        # Check if we've hit the limit
        if self.request_count >= self.max_requests:
            # Wait until new window
            sleep_time = self.per_seconds - (current_time - self.request_window_start)
            if sleep_time > 0:
                time.sleep(sleep_time)
            self.request_count = 0
            self.request_window_start = time.time()

        self.request_count += 1

    def _apply_stealth_delay(self):
        """Apply stealth delay if enabled."""
        if self.stealth_mode and self.request_delay > 0:
            time.sleep(self.request_delay)

    def enumerate_s3_buckets(
        self,
        keyword: str,
        check_public: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Enumerate AWS S3 buckets.

        Args:
            keyword: Keyword to search for
            check_public: Whether to check for public access

        Returns:
            List of bucket information

        Raises:
            PermissionError: If authorization is denied
        """
        if not self._prompt_authorization():
            raise PermissionError("S3 enumeration authorization denied")

        self._apply_rate_limit()
        self._apply_stealth_delay()

        return self.aws_enum.enumerate_s3_buckets(keyword, check_public)

    def test_iam_permissions(
        self,
        access_key: str,
        secret_key: str,
        session_token: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Test AWS IAM permissions.

        Args:
            access_key: AWS access key ID
            secret_key: AWS secret access key
            session_token: Optional session token

        Returns:
            Dictionary with permission information

        Raises:
            PermissionError: If authorization is denied
        """
        if not self._prompt_authorization():
            raise PermissionError("IAM permission testing authorization denied")

        self._apply_rate_limit()

        return self.aws_enum.test_iam_permissions(
            access_key, secret_key, session_token
        )

    def enumerate_azure_blobs(self, keyword: str) -> List[Dict[str, Any]]:
        """
        Enumerate Azure blob storage.

        Args:
            keyword: Keyword to search for

        Returns:
            List of container information

        Raises:
            PermissionError: If authorization is denied
        """
        if not self._prompt_authorization():
            raise PermissionError("Azure blob enumeration authorization denied")

        self._apply_rate_limit()
        self._apply_stealth_delay()

        return self.azure_enum.enumerate_azure_blobs(keyword)

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

        Raises:
            PermissionError: If authorization is denied
        """
        if not self._prompt_authorization():
            raise PermissionError("Azure permission testing authorization denied")

        self._apply_rate_limit()

        return self.azure_enum.test_azure_permissions(
            tenant_id, client_id, secret, subscription_id
        )

    def enumerate_gcp_buckets(self, keyword: str) -> List[Dict[str, Any]]:
        """
        Enumerate GCP storage buckets.

        Args:
            keyword: Keyword to search for

        Returns:
            List of bucket information

        Raises:
            PermissionError: If authorization is denied
        """
        if not self._prompt_authorization():
            raise PermissionError("GCP bucket enumeration authorization denied")

        self._apply_rate_limit()
        self._apply_stealth_delay()

        return self.gcp_enum.enumerate_gcp_buckets(keyword)

    def check_metadata_service(self, target: str = "169.254.169.254") -> Dict[str, Any]:
        """
        Check for exposed cloud metadata service.

        Args:
            target: IP address or hostname to check

        Returns:
            Dictionary with metadata service information

        Raises:
            PermissionError: If authorization is denied
        """
        if not self._prompt_authorization():
            raise PermissionError("Metadata service check authorization denied")

        # Try AWS metadata service
        aws_result = self.aws_enum.check_metadata_service(target)
        if aws_result.get('accessible'):
            return aws_result

        # Try Azure metadata service
        azure_result = self.azure_enum.check_metadata_service(target)
        if azure_result.get('accessible'):
            return azure_result

        # Try GCP metadata service
        gcp_result = self.gcp_enum.check_metadata_service(target)
        if gcp_result.get('accessible'):
            return gcp_result

        return {
            'accessible': False,
            'provider': 'unknown',
            'target': target
        }

    def save_results(
        self,
        results: Any,
        output_file: str
    ):
        """
        Save results to JSON file.

        Args:
            results: Results to save
            output_file: Path to output file
        """
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)

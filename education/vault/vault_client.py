#!/usr/bin/env python3
"""
Akali Vault Client - HashiCorp Vault integration

Provides a developer-friendly interface to HashiCorp Vault for:
- Secret storage and retrieval (KV v2)
- Authentication (token, AppRole)
- Secret rotation
- Health checks

Requires: pip install hvac
"""

import os
import sys
from typing import Dict, List, Optional, Any
from datetime import datetime
import json

try:
    import hvac
    HVAC_AVAILABLE = True
except ImportError:
    HVAC_AVAILABLE = False


class VaultClient:
    """HashiCorp Vault client for secret management"""

    def __init__(
        self,
        url: Optional[str] = None,
        token: Optional[str] = None,
        namespace: Optional[str] = None,
        mount_point: str = "secret"
    ):
        """Initialize Vault client.

        Args:
            url: Vault server URL (default: VAULT_ADDR env var)
            token: Vault token (default: VAULT_TOKEN env var)
            namespace: Vault namespace (default: VAULT_NAMESPACE env var)
            mount_point: KV mount point (default: 'secret')
        """
        if not HVAC_AVAILABLE:
            raise ImportError(
                "hvac library not available. Install with: pip install hvac"
            )

        self.url = url or os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
        self.token = token or os.getenv("VAULT_TOKEN")
        self.namespace = namespace or os.getenv("VAULT_NAMESPACE")
        self.mount_point = mount_point

        if not self.token:
            raise ValueError(
                "Vault token required. Set VAULT_TOKEN env var or pass token parameter."
            )

        # Initialize hvac client
        self.client = hvac.Client(
            url=self.url,
            token=self.token,
            namespace=self.namespace
        )

    def is_authenticated(self) -> bool:
        """Check if client is authenticated."""
        try:
            return self.client.is_authenticated()
        except Exception as e:
            print(f"❌ Authentication check failed: {e}", file=sys.stderr)
            return False

    def health_check(self) -> Dict[str, Any]:
        """Check Vault server health.

        Returns:
            Dict with health status (initialized, sealed, standby, etc.)
        """
        try:
            health = self.client.sys.read_health_status(method="GET")
            return {
                "initialized": health.get("initialized", False),
                "sealed": health.get("sealed", False),
                "standby": health.get("standby", False),
                "server_time": health.get("server_time_utc"),
                "version": health.get("version"),
                "healthy": not health.get("sealed", True)
            }
        except Exception as e:
            return {
                "initialized": False,
                "sealed": True,
                "standby": False,
                "healthy": False,
                "error": str(e)
            }

    def get_secret(self, path: str, version: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """Read a secret from Vault KV v2.

        Args:
            path: Secret path (e.g., 'app/database')
            version: Secret version (default: latest)

        Returns:
            Secret data dict or None if not found
        """
        try:
            response = self.client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point=self.mount_point,
                version=version
            )
            return response["data"]["data"]
        except hvac.exceptions.InvalidPath:
            return None
        except Exception as e:
            print(f"❌ Error reading secret '{path}': {e}", file=sys.stderr)
            return None

    def set_secret(self, path: str, data: Dict[str, Any]) -> bool:
        """Write a secret to Vault KV v2.

        Args:
            path: Secret path (e.g., 'app/database')
            data: Secret data dict

        Returns:
            True if successful, False otherwise
        """
        try:
            self.client.secrets.kv.v2.create_or_update_secret(
                path=path,
                secret=data,
                mount_point=self.mount_point
            )
            return True
        except Exception as e:
            print(f"❌ Error writing secret '{path}': {e}", file=sys.stderr)
            return False

    def delete_secret(self, path: str, versions: Optional[List[int]] = None) -> bool:
        """Delete secret versions.

        Args:
            path: Secret path
            versions: List of versions to delete (default: all versions)

        Returns:
            True if successful, False otherwise
        """
        try:
            if versions:
                # Delete specific versions
                self.client.secrets.kv.v2.delete_secret_versions(
                    path=path,
                    versions=versions,
                    mount_point=self.mount_point
                )
            else:
                # Delete all metadata
                self.client.secrets.kv.v2.delete_metadata_and_all_versions(
                    path=path,
                    mount_point=self.mount_point
                )
            return True
        except Exception as e:
            print(f"❌ Error deleting secret '{path}': {e}", file=sys.stderr)
            return False

    def list_secrets(self, path: str = "") -> List[str]:
        """List secrets at a path.

        Args:
            path: Directory path (e.g., 'app/')

        Returns:
            List of secret keys
        """
        try:
            response = self.client.secrets.kv.v2.list_secrets(
                path=path,
                mount_point=self.mount_point
            )
            return response["data"]["keys"]
        except hvac.exceptions.InvalidPath:
            return []
        except Exception as e:
            print(f"❌ Error listing secrets at '{path}': {e}", file=sys.stderr)
            return []

    def get_secret_metadata(self, path: str) -> Optional[Dict[str, Any]]:
        """Get secret metadata (versions, created_time, etc.).

        Args:
            path: Secret path

        Returns:
            Metadata dict or None if not found
        """
        try:
            response = self.client.secrets.kv.v2.read_secret_metadata(
                path=path,
                mount_point=self.mount_point
            )
            return response["data"]
        except hvac.exceptions.InvalidPath:
            return None
        except Exception as e:
            print(f"❌ Error reading metadata for '{path}': {e}", file=sys.stderr)
            return None

    def rotate_secret(self, path: str, new_data: Dict[str, Any]) -> bool:
        """Rotate a secret (create new version).

        Args:
            path: Secret path
            new_data: New secret data

        Returns:
            True if successful, False otherwise
        """
        try:
            # KV v2 automatically versions on write
            return self.set_secret(path, new_data)
        except Exception as e:
            print(f"❌ Error rotating secret '{path}': {e}", file=sys.stderr)
            return False

    @classmethod
    def from_approle(
        cls,
        role_id: str,
        secret_id: str,
        url: Optional[str] = None,
        namespace: Optional[str] = None,
        mount_point: str = "secret"
    ) -> "VaultClient":
        """Create Vault client using AppRole authentication.

        Args:
            role_id: AppRole role ID
            secret_id: AppRole secret ID
            url: Vault server URL
            namespace: Vault namespace
            mount_point: KV mount point

        Returns:
            Authenticated VaultClient instance
        """
        if not HVAC_AVAILABLE:
            raise ImportError("hvac library not available")

        vault_url = url or os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
        vault_namespace = namespace or os.getenv("VAULT_NAMESPACE")

        # Create unauthenticated client
        client = hvac.Client(url=vault_url, namespace=vault_namespace)

        # Authenticate with AppRole
        try:
            response = client.auth.approle.login(
                role_id=role_id,
                secret_id=secret_id
            )
            token = response["auth"]["client_token"]

            # Create authenticated client
            return cls(
                url=vault_url,
                token=token,
                namespace=vault_namespace,
                mount_point=mount_point
            )
        except Exception as e:
            raise ValueError(f"AppRole authentication failed: {e}")


class MockVaultClient:
    """Mock Vault client for testing without a real Vault server."""

    def __init__(self, **kwargs):
        """Initialize mock client."""
        self.secrets = {}
        self.metadata = {}
        self.url = kwargs.get("url", "http://mock-vault:8200")
        self.mount_point = kwargs.get("mount_point", "secret")

    def is_authenticated(self) -> bool:
        """Always authenticated in mock mode."""
        return True

    def health_check(self) -> Dict[str, Any]:
        """Return healthy status."""
        return {
            "initialized": True,
            "sealed": False,
            "standby": False,
            "healthy": True,
            "version": "mock-1.0.0",
            "server_time": datetime.utcnow().isoformat()
        }

    def get_secret(self, path: str, version: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """Get mock secret."""
        if path in self.secrets:
            versions = self.secrets[path]
            if version and version <= len(versions):
                return versions[version - 1]
            return versions[-1]  # Latest version
        return None

    def set_secret(self, path: str, data: Dict[str, Any]) -> bool:
        """Store mock secret."""
        if path not in self.secrets:
            self.secrets[path] = []
            self.metadata[path] = {
                "created_time": datetime.utcnow().isoformat(),
                "current_version": 0
            }

        self.secrets[path].append(data)
        self.metadata[path]["current_version"] = len(self.secrets[path])
        self.metadata[path]["updated_time"] = datetime.utcnow().isoformat()
        return True

    def delete_secret(self, path: str, versions: Optional[List[int]] = None) -> bool:
        """Delete mock secret."""
        if path in self.secrets:
            if versions:
                # Delete specific versions
                for v in versions:
                    if 0 < v <= len(self.secrets[path]):
                        self.secrets[path][v - 1] = None
            else:
                # Delete all
                del self.secrets[path]
                del self.metadata[path]
            return True
        return False

    def list_secrets(self, path: str = "") -> List[str]:
        """List mock secrets."""
        if not path:
            return list(self.secrets.keys())

        # Filter by path prefix
        prefix = path.rstrip("/") + "/"
        return [k for k in self.secrets.keys() if k.startswith(prefix)]

    def get_secret_metadata(self, path: str) -> Optional[Dict[str, Any]]:
        """Get mock metadata."""
        return self.metadata.get(path)

    def rotate_secret(self, path: str, new_data: Dict[str, Any]) -> bool:
        """Rotate mock secret."""
        return self.set_secret(path, new_data)

    @classmethod
    def from_approle(cls, role_id: str, secret_id: str, **kwargs) -> "MockVaultClient":
        """Create mock client (ignores AppRole credentials)."""
        return cls(**kwargs)


def get_vault_client(mock: bool = False, **kwargs) -> VaultClient:
    """Factory function to get Vault client (real or mock).

    Args:
        mock: Use mock client instead of real Vault
        **kwargs: Client initialization arguments

    Returns:
        VaultClient or MockVaultClient instance
    """
    if mock or not HVAC_AVAILABLE:
        if not mock and not HVAC_AVAILABLE:
            print("⚠️  hvac not available, using mock client", file=sys.stderr)
        return MockVaultClient(**kwargs)

    return VaultClient(**kwargs)


def main():
    """CLI test interface."""
    import argparse

    parser = argparse.ArgumentParser(description="Akali Vault Client")
    parser.add_argument("--mock", action="store_true", help="Use mock client")
    parser.add_argument("--url", help="Vault URL")
    parser.add_argument("--token", help="Vault token")

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Health command
    subparsers.add_parser("health", help="Check Vault health")

    # Get command
    get_parser = subparsers.add_parser("get", help="Get secret")
    get_parser.add_argument("path", help="Secret path")
    get_parser.add_argument("--version", type=int, help="Secret version")

    # Set command
    set_parser = subparsers.add_parser("set", help="Set secret")
    set_parser.add_argument("path", help="Secret path")
    set_parser.add_argument("data", help="Secret data (JSON)")

    # List command
    list_parser = subparsers.add_parser("list", help="List secrets")
    list_parser.add_argument("path", nargs="?", default="", help="Directory path")

    # Delete command
    delete_parser = subparsers.add_parser("delete", help="Delete secret")
    delete_parser.add_argument("path", help="Secret path")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    # Create client
    try:
        client = get_vault_client(
            mock=args.mock,
            url=args.url,
            token=args.token
        )
    except Exception as e:
        print(f"❌ Failed to initialize client: {e}")
        sys.exit(1)

    # Execute command
    if args.command == "health":
        health = client.health_check()
        print(f"\n🥷 Vault Health Check:")
        print(f"   URL: {client.url}")
        print(f"   Healthy: {'✅' if health['healthy'] else '❌'}")
        print(f"   Initialized: {health['initialized']}")
        print(f"   Sealed: {health['sealed']}")
        if health.get("version"):
            print(f"   Version: {health['version']}")
        if health.get("error"):
            print(f"   Error: {health['error']}")

    elif args.command == "get":
        secret = client.get_secret(args.path, version=args.version)
        if secret:
            print(f"\n🔐 Secret at '{args.path}':")
            print(json.dumps(secret, indent=2))
        else:
            print(f"❌ Secret not found: {args.path}")

    elif args.command == "set":
        try:
            data = json.loads(args.data)
            if client.set_secret(args.path, data):
                print(f"✅ Secret stored at '{args.path}'")
            else:
                print(f"❌ Failed to store secret")
        except json.JSONDecodeError:
            print("❌ Invalid JSON data")

    elif args.command == "list":
        secrets = client.list_secrets(args.path)
        if secrets:
            print(f"\n📋 Secrets at '{args.path or '/'}':")
            for secret in secrets:
                print(f"   • {secret}")
        else:
            print(f"No secrets found at '{args.path or '/'}'")

    elif args.command == "delete":
        if client.delete_secret(args.path):
            print(f"✅ Secret deleted: {args.path}")
        else:
            print(f"❌ Failed to delete secret")


if __name__ == "__main__":
    main()

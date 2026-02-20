"""AWS enumeration and exploitation module."""

import time
import requests
from typing import List, Dict, Any, Optional
from datetime import datetime

# Try importing boto3, but don't fail if not installed
try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False


class AWSEnumerator:
    """AWS cloud enumeration and exploitation."""

    def __init__(self, mock_mode: bool = True):
        """
        Initialize AWS enumerator.

        Args:
            mock_mode: If True, use mock responses instead of real API calls
        """
        self.mock_mode = mock_mode
        self.common_suffixes = [
            'prod', 'dev', 'staging', 'test', 'backup', 'logs',
            'data', 'files', 'public', 'private', 'static', 'media',
            'images', 'assets', 'uploads', 'downloads', 'archive'
        ]
        self.common_prefixes = ['www', 'app', 'api', 'cdn', 'storage']

    def generate_bucket_names(self, keyword: str) -> List[str]:
        """
        Generate common S3 bucket name permutations.

        Args:
            keyword: Company/project keyword to permute

        Returns:
            List of potential bucket names
        """
        bucket_names = [keyword]

        # Add suffixes
        for suffix in self.common_suffixes:
            bucket_names.append(f"{keyword}-{suffix}")
            bucket_names.append(f"{keyword}.{suffix}")
            bucket_names.append(f"{keyword}_{suffix}")

        # Add prefixes
        for prefix in self.common_prefixes:
            bucket_names.append(f"{prefix}-{keyword}")
            bucket_names.append(f"{prefix}.{keyword}")

        return bucket_names

    def enumerate_s3_buckets(
        self,
        keyword: str,
        check_public: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Enumerate S3 buckets by keyword.

        Args:
            keyword: Keyword to search for
            check_public: Whether to check for public access

        Returns:
            List of bucket information dictionaries
        """
        if self.mock_mode:
            return self._mock_s3_buckets(keyword, check_public)

        if not BOTO3_AVAILABLE:
            return [{
                'error': 'boto3 not installed. Install with: pip install boto3'
            }]

        results = []
        bucket_names = self.generate_bucket_names(keyword)

        # Create anonymous S3 client for existence checks
        s3 = boto3.client('s3', region_name='us-east-1')

        for bucket_name in bucket_names:
            try:
                # Try to check if bucket exists
                s3.head_bucket(Bucket=bucket_name)

                bucket_info = {
                    'bucket_name': bucket_name,
                    'exists': True,
                    'region': self._get_bucket_region(s3, bucket_name),
                    'timestamp': datetime.now().isoformat()
                }

                if check_public:
                    bucket_info['public'] = self.check_bucket_public(s3, bucket_name)

                results.append(bucket_info)

            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == '404':
                    # Bucket doesn't exist
                    continue
                elif error_code == '403':
                    # Bucket exists but we don't have permission
                    results.append({
                        'bucket_name': bucket_name,
                        'exists': True,
                        'accessible': False,
                        'error': 'Permission denied',
                        'timestamp': datetime.now().isoformat()
                    })
            except Exception as e:
                # Other errors - skip
                continue

        return results

    def check_bucket_public(self, s3_client, bucket_name: str) -> bool:
        """
        Check if S3 bucket has public access.

        Args:
            s3_client: Boto3 S3 client
            bucket_name: Name of bucket to check

        Returns:
            True if bucket is public
        """
        try:
            acl = s3_client.get_bucket_acl(Bucket=bucket_name)

            for grant in acl.get('Grants', []):
                grantee = grant.get('Grantee', {})
                if grantee.get('Type') == 'Group':
                    uri = grantee.get('URI', '')
                    if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                        return True

            return False

        except Exception:
            return False

    def _get_bucket_region(self, s3_client, bucket_name: str) -> Optional[str]:
        """Get bucket region."""
        try:
            response = s3_client.get_bucket_location(Bucket=bucket_name)
            region = response.get('LocationConstraint')
            return region if region else 'us-east-1'
        except Exception:
            return None

    def test_iam_permissions(
        self,
        access_key: str,
        secret_key: str,
        session_token: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Test IAM permissions for given credentials.

        Args:
            access_key: AWS access key ID
            secret_key: AWS secret access key
            session_token: Optional session token

        Returns:
            Dictionary with permission information
        """
        if self.mock_mode:
            return self._mock_iam_permissions(access_key)

        if not BOTO3_AVAILABLE:
            return {
                'error': 'boto3 not installed. Install with: pip install boto3'
            }

        try:
            # Create IAM client with credentials
            iam = boto3.client(
                'iam',
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                aws_session_token=session_token
            )

            # Try to get user info
            user_response = iam.get_user()
            user_name = user_response['User']['UserName']

            # Get attached policies
            policies = iam.list_attached_user_policies(UserName=user_name)
            inline_policies = iam.list_user_policies(UserName=user_name)

            # Get groups
            groups = iam.list_groups_for_user(UserName=user_name)

            return {
                'user': user_name,
                'attached_policies': [p['PolicyName'] for p in policies.get('AttachedPolicies', [])],
                'inline_policies': inline_policies.get('PolicyNames', []),
                'groups': [g['GroupName'] for g in groups.get('Groups', [])],
                'timestamp': datetime.now().isoformat()
            }

        except Exception as e:
            return {
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }

    def enumerate_ec2_instances(
        self,
        access_key: str,
        secret_key: str,
        region: str = 'us-east-1'
    ) -> List[Dict[str, Any]]:
        """
        Enumerate EC2 instances.

        Args:
            access_key: AWS access key ID
            secret_key: AWS secret access key
            region: AWS region

        Returns:
            List of EC2 instance information
        """
        if self.mock_mode:
            return self._mock_ec2_instances()

        if not BOTO3_AVAILABLE:
            return [{'error': 'boto3 not installed'}]

        try:
            ec2 = boto3.client(
                'ec2',
                region_name=region,
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key
            )

            response = ec2.describe_instances()

            instances = []
            for reservation in response.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instances.append({
                        'instance_id': instance.get('InstanceId'),
                        'state': instance.get('State', {}).get('Name'),
                        'type': instance.get('InstanceType'),
                        'public_ip': instance.get('PublicIpAddress'),
                        'private_ip': instance.get('PrivateIpAddress'),
                        'region': region
                    })

            return instances

        except Exception as e:
            return [{'error': str(e)}]

    def check_metadata_service(self, target: str = "169.254.169.254") -> Dict[str, Any]:
        """
        Check for exposed AWS metadata service.

        Args:
            target: IP address to check (default: 169.254.169.254)

        Returns:
            Dictionary with metadata service information
        """
        if self.mock_mode:
            return self._mock_metadata_service()

        try:
            # Try to access AWS metadata service
            response = requests.get(
                f"http://{target}/latest/meta-data/ami-id",
                timeout=2
            )

            if response.status_code == 200:
                return {
                    'accessible': True,
                    'provider': 'aws',
                    'ami_id': response.text,
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

    def test_assume_role(
        self,
        role_arn: str,
        access_key: str,
        secret_key: str,
        role_session_name: str = "akali-session"
    ) -> Dict[str, Any]:
        """
        Test assume role exploitation.

        Args:
            role_arn: ARN of role to assume
            access_key: AWS access key ID
            secret_key: AWS secret access key
            role_session_name: Session name

        Returns:
            Dictionary with assumed role credentials or error
        """
        if self.mock_mode:
            return self._mock_assume_role()

        if not BOTO3_AVAILABLE:
            return {'error': 'boto3 not installed'}

        try:
            sts = boto3.client(
                'sts',
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key
            )

            response = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName=role_session_name
            )

            return {
                'success': True,
                'credentials': {
                    'access_key': response['Credentials']['AccessKeyId'],
                    'secret_key': response['Credentials']['SecretAccessKey'],
                    'session_token': response['Credentials']['SessionToken'],
                    'expiration': response['Credentials']['Expiration'].isoformat()
                },
                'timestamp': datetime.now().isoformat()
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }

    # Mock response methods
    def _mock_s3_buckets(self, keyword: str, check_public: bool) -> List[Dict[str, Any]]:
        """Generate mock S3 bucket results."""
        bucket_names = self.generate_bucket_names(keyword)[:5]  # Limit to 5 for testing

        return [
            {
                'bucket_name': name,
                'exists': True,
                'public': i % 2 == 0 if check_public else None,
                'region': 'us-east-1',
                'mock': True,
                'timestamp': datetime.now().isoformat()
            }
            for i, name in enumerate(bucket_names)
        ]

    def _mock_iam_permissions(self, access_key: str) -> Dict[str, Any]:
        """Generate mock IAM permission results."""
        return {
            'user': 'mock-user',
            'attached_policies': ['ReadOnlyAccess', 'S3FullAccess'],
            'inline_policies': ['custom-policy'],
            'groups': ['Developers', 'Admins'],
            'mock': True,
            'timestamp': datetime.now().isoformat()
        }

    def _mock_ec2_instances(self) -> List[Dict[str, Any]]:
        """Generate mock EC2 instance results."""
        return [
            {
                'instance_id': 'i-1234567890abcdef0',
                'state': 'running',
                'type': 't2.micro',
                'public_ip': '1.2.3.4',
                'private_ip': '10.0.1.10',
                'region': 'us-east-1',
                'mock': True
            }
        ]

    def _mock_metadata_service(self) -> Dict[str, Any]:
        """Generate mock metadata service results."""
        return {
            'accessible': True,
            'provider': 'aws',
            'ami_id': 'ami-12345678',
            'mock': True,
            'timestamp': datetime.now().isoformat()
        }

    def _mock_assume_role(self) -> Dict[str, Any]:
        """Generate mock assume role results."""
        return {
            'success': True,
            'credentials': {
                'access_key': 'ASIATEMP123456789',
                'secret_key': 'mock-secret-key',
                'session_token': 'mock-session-token',
                'expiration': datetime.now().isoformat()
            },
            'mock': True,
            'timestamp': datetime.now().isoformat()
        }

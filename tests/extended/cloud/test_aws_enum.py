"""Tests for AWS enumeration module."""

import pytest
from unittest.mock import Mock, patch, MagicMock

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from extended.cloud.aws_enum import AWSEnumerator


class TestAWSEnumerator:
    """Test AWS enumeration functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.enumerator = AWSEnumerator(mock_mode=True)

    def test_initialization(self):
        """Test AWSEnumerator initializes correctly."""
        assert self.enumerator is not None
        assert self.enumerator.mock_mode is True

    def test_s3_bucket_name_generation(self):
        """Test S3 bucket name permutation generation."""
        keyword = "mycompany"
        bucket_names = self.enumerator.generate_bucket_names(keyword)

        assert isinstance(bucket_names, list)
        assert len(bucket_names) > 0
        assert f"{keyword}" in bucket_names
        assert f"{keyword}-prod" in bucket_names
        assert f"{keyword}-dev" in bucket_names
        assert f"{keyword}-backup" in bucket_names

    def test_s3_bucket_name_generation_with_variations(self):
        """Test bucket name generation includes common variations."""
        keyword = "test"
        bucket_names = self.enumerator.generate_bucket_names(keyword)

        # Should include common suffixes
        expected_suffixes = ['prod', 'dev', 'staging', 'backup', 'logs', 'data', 'files', 'public']
        for suffix in expected_suffixes:
            assert f"{keyword}-{suffix}" in bucket_names

    @patch('extended.cloud.aws_enum.boto3')
    def test_enumerate_s3_buckets_mock_mode(self, mock_boto3):
        """Test S3 bucket enumeration in mock mode."""
        results = self.enumerator.enumerate_s3_buckets("testcompany")

        assert isinstance(results, list)
        assert len(results) > 0
        assert all('bucket_name' in r for r in results)
        assert all('exists' in r for r in results)
        assert all('public' in r for r in results)
        assert all('mock' in r for r in results)

        # Should NOT call boto3 in mock mode
        mock_boto3.assert_not_called()

    @patch('extended.cloud.aws_enum.boto3.client')
    def test_enumerate_s3_buckets_real_mode(self, mock_boto3_client):
        """Test S3 bucket enumeration in real mode."""
        enumerator = AWSEnumerator(mock_mode=False)

        # Mock S3 client
        mock_s3 = Mock()
        mock_boto3_client.return_value = mock_s3
        mock_s3.head_bucket.return_value = {}

        results = enumerator.enumerate_s3_buckets("testcompany", check_public=False)

        assert isinstance(results, list)
        mock_boto3_client.assert_called()

    @patch('extended.cloud.aws_enum.boto3.client')
    def test_check_bucket_public_access(self, mock_boto3_client):
        """Test public access detection for S3 buckets."""
        enumerator = AWSEnumerator(mock_mode=False)

        mock_s3 = Mock()
        mock_boto3_client.return_value = mock_s3

        # Mock public bucket
        mock_s3.get_bucket_acl.return_value = {
            'Grants': [
                {
                    'Grantee': {
                        'Type': 'Group',
                        'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'
                    },
                    'Permission': 'READ'
                }
            ]
        }

        is_public = enumerator.check_bucket_public(mock_s3, "test-bucket")
        assert is_public is True

    @patch('extended.cloud.aws_enum.boto3.client')
    def test_check_bucket_private_access(self, mock_boto3_client):
        """Test private bucket detection."""
        enumerator = AWSEnumerator(mock_mode=False)

        mock_s3 = Mock()
        mock_boto3_client.return_value = mock_s3

        # Mock private bucket
        mock_s3.get_bucket_acl.return_value = {
            'Grants': [
                {
                    'Grantee': {
                        'Type': 'CanonicalUser',
                        'ID': 'abc123'
                    },
                    'Permission': 'FULL_CONTROL'
                }
            ]
        }

        is_public = enumerator.check_bucket_public(mock_s3, "test-bucket")
        assert is_public is False

    @patch('extended.cloud.aws_enum.boto3.client')
    def test_test_iam_permissions_mock_mode(self, mock_boto3_client):
        """Test IAM permission enumeration in mock mode."""
        results = self.enumerator.test_iam_permissions(
            access_key="AKIAIOSFODNN7EXAMPLE",
            secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        )

        assert isinstance(results, dict)
        assert 'attached_policies' in results or 'permissions' in results
        assert 'mock' in results
        assert results['mock'] is True

        # Should NOT call boto3 in mock mode
        mock_boto3_client.assert_not_called()

    @patch('extended.cloud.aws_enum.boto3.client')
    def test_test_iam_permissions_real_mode(self, mock_boto3_client):
        """Test IAM permission enumeration in real mode."""
        enumerator = AWSEnumerator(mock_mode=False)

        mock_iam = Mock()
        mock_boto3_client.return_value = mock_iam

        # Mock IAM responses
        mock_iam.get_user.return_value = {'User': {'UserName': 'test-user'}}
        mock_iam.list_attached_user_policies.return_value = {'AttachedPolicies': []}
        mock_iam.list_user_policies.return_value = {'PolicyNames': []}
        mock_iam.list_groups_for_user.return_value = {'Groups': []}

        results = enumerator.test_iam_permissions(
            access_key="AKIAIOSFODNN7EXAMPLE",
            secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        )

        assert isinstance(results, dict)
        assert 'user' in results
        mock_boto3_client.assert_called()

    @patch('extended.cloud.aws_enum.boto3.client')
    def test_enumerate_ec2_instances(self, mock_boto3_client):
        """Test EC2 instance enumeration."""
        mock_ec2 = Mock()
        mock_boto3_client.return_value = mock_ec2

        mock_ec2.describe_instances.return_value = {
            'Reservations': [
                {
                    'Instances': [
                        {
                            'InstanceId': 'i-1234567890abcdef0',
                            'State': {'Name': 'running'},
                            'PublicIpAddress': '1.2.3.4'
                        }
                    ]
                }
            ]
        }

        enumerator = AWSEnumerator(mock_mode=False)
        results = enumerator.enumerate_ec2_instances(
            access_key="AKIAIOSFODNN7EXAMPLE",
            secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        )

        assert isinstance(results, list)
        mock_boto3_client.assert_called()

    @patch('requests.get')
    def test_check_metadata_service(self, mock_get):
        """Test AWS metadata service detection."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "ami-12345678"
        mock_get.return_value = mock_response

        enumerator = AWSEnumerator(mock_mode=False)
        results = enumerator.check_metadata_service("169.254.169.254")

        assert results['accessible'] is True
        assert results['provider'] == 'aws'
        mock_get.assert_called()

    @patch('requests.get')
    def test_metadata_service_not_accessible(self, mock_get):
        """Test metadata service when not accessible."""
        mock_get.side_effect = Exception("Connection timeout")

        enumerator = AWSEnumerator(mock_mode=False)
        results = enumerator.check_metadata_service("169.254.169.254")

        assert results['accessible'] is False

    @patch('extended.cloud.aws_enum.boto3.client')
    def test_assume_role_exploitation(self, mock_boto3_client):
        """Test assume role exploitation."""
        mock_sts = Mock()
        mock_boto3_client.return_value = mock_sts

        mock_sts.assume_role.return_value = {
            'Credentials': {
                'AccessKeyId': 'ASIATEMP',
                'SecretAccessKey': 'secret',
                'SessionToken': 'token'
            }
        }

        enumerator = AWSEnumerator(mock_mode=False)
        results = enumerator.test_assume_role(
            role_arn="arn:aws:iam::123456789012:role/test-role",
            access_key="AKIAIOSFODNN7EXAMPLE",
            secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        )

        assert 'credentials' in results or 'error' in results

    def test_boto3_not_installed_handled_gracefully(self):
        """Test graceful handling when boto3 not installed."""
        with patch('extended.cloud.aws_enum.BOTO3_AVAILABLE', False):
            enumerator = AWSEnumerator(mock_mode=False)
            results = enumerator.enumerate_s3_buckets("test")

            assert 'error' in results[0]
            assert 'boto3' in results[0]['error'].lower()

    @patch('extended.cloud.aws_enum.boto3.client')
    def test_invalid_credentials_error_handling(self, mock_boto3_client):
        """Test error handling for invalid credentials."""
        enumerator = AWSEnumerator(mock_mode=False)

        mock_iam = Mock()
        mock_boto3_client.return_value = mock_iam
        mock_iam.get_user.side_effect = Exception("Invalid credentials")

        results = enumerator.test_iam_permissions(
            access_key="INVALID",
            secret_key="INVALID"
        )

        assert 'error' in results

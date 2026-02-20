"""Tests for BloodHound helper module."""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock, mock_open
from extended.ad.bloodhound_helper import BloodHoundHelper


class TestBloodHoundHelper:
    """Test suite for BloodHound integration."""

    def test_init(self):
        """Test BloodHoundHelper initialization"""
        helper = BloodHoundHelper()

        assert helper is not None

    def test_check_available_with_bloodhound(self):
        """Test availability check when bloodhound-python is installed"""
        helper = BloodHoundHelper()

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(returncode=0)

            assert helper.check_available() is True

    def test_check_available_without_bloodhound(self):
        """Test availability check when bloodhound-python is not installed"""
        helper = BloodHoundHelper()

        with patch('subprocess.run', side_effect=FileNotFoundError):
            assert helper.check_available() is False

    def test_collect_data_basic(self):
        """Test basic BloodHound data collection"""
        helper = BloodHoundHelper()

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="Collection complete"
            )

            result = helper.collect_data(
                domain="corp.local",
                username="admin",
                password="password123",
                dc_ip="10.0.0.1"
            )

            assert result is not None
            assert result.get("success") is True

    def test_collect_data_all_methods(self):
        """Test BloodHound collection with all methods"""
        helper = BloodHoundHelper()

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="Collecting All"
            )

            result = helper.collect_data(
                domain="corp.local",
                username="admin",
                password="password123",
                dc_ip="10.0.0.1",
                collection_methods=["All"]
            )

            assert result["success"] is True

    def test_collect_data_specific_methods(self):
        """Test BloodHound collection with specific methods"""
        helper = BloodHoundHelper()

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="Collection done"
            )

            result = helper.collect_data(
                domain="corp.local",
                username="admin",
                password="password123",
                dc_ip="10.0.0.1",
                collection_methods=["Session", "ACL", "Trusts"]
            )

            assert result["success"] is True

    def test_parse_bloodhound_json(self):
        """Test parsing BloodHound JSON output"""
        helper = BloodHoundHelper()

        json_data = {
            "users": [
                {"name": "admin@CORP.LOCAL", "enabled": True},
                {"name": "user1@CORP.LOCAL", "enabled": True}
            ],
            "computers": [
                {"name": "DC01.CORP.LOCAL", "os": "Windows Server 2019"}
            ],
            "groups": [
                {"name": "DOMAIN ADMINS@CORP.LOCAL"}
            ]
        }

        with patch('builtins.open', mock_open(read_data=json.dumps(json_data))):
            result = helper.parse_json_output("/tmp/bloodhound_output.json")

            assert isinstance(result, dict)
            assert "users" in result or len(result) > 0

    def test_find_path_to_da(self):
        """Test finding path to Domain Admins"""
        helper = BloodHoundHelper()

        mock_paths = [
            {
                "start": "USER1@CORP.LOCAL",
                "end": "DOMAIN ADMINS@CORP.LOCAL",
                "path": ["USER1", "GROUP1", "DOMAIN ADMINS"],
                "edges": ["MemberOf", "MemberOf"]
            }
        ]

        with patch.object(helper, '_query_bloodhound_api', return_value=mock_paths):
            result = helper.find_path_to_da(
                start_user="user1@corp.local",
                api_url="http://localhost:7687"
            )

            assert isinstance(result, list)

    def test_find_shortest_path(self):
        """Test finding shortest path between two nodes"""
        helper = BloodHoundHelper()

        with patch.object(helper, '_query_bloodhound_api') as mock_query:
            mock_query.return_value = {"path": ["NODE1", "NODE2", "NODE3"]}

            result = helper.find_shortest_path(
                start="user1@corp.local",
                end="admin@corp.local",
                api_url="http://localhost:7687"
            )

            assert result is not None

    def test_find_computers_with_unconstrained_delegation(self):
        """Test finding computers with unconstrained delegation"""
        helper = BloodHoundHelper()

        json_data = {
            "computers": [
                {
                    "name": "SERVER01.CORP.LOCAL",
                    "properties": {"unconstraineddelegation": True}
                },
                {
                    "name": "SERVER02.CORP.LOCAL",
                    "properties": {"unconstraineddelegation": False}
                }
            ]
        }

        with patch('builtins.open', mock_open(read_data=json.dumps(json_data))):
            result = helper.find_unconstrained_delegation("/tmp/computers.json")

            assert isinstance(result, list)

    def test_find_kerberoastable_users(self):
        """Test finding Kerberoastable users"""
        helper = BloodHoundHelper()

        json_data = {
            "users": [
                {
                    "name": "svc_sql@CORP.LOCAL",
                    "properties": {"hasspn": True, "enabled": True}
                },
                {
                    "name": "user1@CORP.LOCAL",
                    "properties": {"hasspn": False, "enabled": True}
                }
            ]
        }

        with patch('builtins.open', mock_open(read_data=json.dumps(json_data))):
            result = helper.find_kerberoastable_users("/tmp/users.json")

            assert isinstance(result, list)
            assert len(result) >= 1

    def test_find_asreproastable_users(self):
        """Test finding AS-REP roastable users"""
        helper = BloodHoundHelper()

        json_data = {
            "users": [
                {
                    "name": "user_no_preauth@CORP.LOCAL",
                    "properties": {"dontreqpreauth": True, "enabled": True}
                }
            ]
        }

        with patch('builtins.open', mock_open(read_data=json.dumps(json_data))):
            result = helper.find_asreproastable_users("/tmp/users.json")

            assert isinstance(result, list)
            assert len(result) >= 1

    def test_find_high_value_targets(self):
        """Test finding high value targets"""
        helper = BloodHoundHelper()

        json_data = {
            "users": [
                {"name": "admin@CORP.LOCAL", "properties": {"highvalue": True}},
                {"name": "user1@CORP.LOCAL", "properties": {"highvalue": False}}
            ],
            "computers": [
                {"name": "DC01.CORP.LOCAL", "properties": {"highvalue": True}}
            ]
        }

        with patch('builtins.open', mock_open(read_data=json.dumps(json_data))):
            result = helper.find_high_value_targets("/tmp/bloodhound_data.json")

            assert isinstance(result, dict)
            assert "users" in result or "computers" in result

    def test_analyze_acls(self):
        """Test ACL analysis"""
        helper = BloodHoundHelper()

        json_data = {
            "acls": [
                {
                    "principal": "USER1@CORP.LOCAL",
                    "right": "GenericAll",
                    "target": "ADMIN@CORP.LOCAL"
                }
            ]
        }

        with patch('builtins.open', mock_open(read_data=json.dumps(json_data))):
            result = helper.analyze_acls("/tmp/acls.json")

            assert isinstance(result, list) or isinstance(result, dict)

    def test_export_cypher_query(self):
        """Test exporting custom Cypher query"""
        helper = BloodHoundHelper()

        with patch.object(helper, '_query_bloodhound_api') as mock_query:
            mock_query.return_value = {"results": []}

            result = helper.run_cypher_query(
                query="MATCH (u:User) RETURN u.name",
                api_url="http://localhost:7687"
            )

            assert result is not None

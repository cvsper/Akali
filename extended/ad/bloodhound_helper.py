"""BloodHound integration for Active Directory analysis."""

import json
import subprocess
from typing import List, Dict, Optional, Any
from pathlib import Path


class BloodHoundHelper:
    """BloodHound data collection and analysis helper."""

    def __init__(self):
        """Initialize BloodHound helper."""
        pass

    def check_available(self) -> bool:
        """Check if bloodhound-python is available.

        Returns:
            True if bloodhound-python is installed
        """
        try:
            result = subprocess.run(
                ["bloodhound-python", "--help"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0

        except FileNotFoundError:
            return False
        except Exception:
            return False

    def collect_data(
        self,
        domain: str,
        username: str,
        password: str,
        dc_ip: str,
        collection_methods: Optional[List[str]] = None,
        output_dir: Optional[str] = None
    ) -> Dict[str, Any]:
        """Collect BloodHound data from Active Directory.

        Args:
            domain: Target domain
            username: Domain username
            password: User password
            dc_ip: Domain Controller IP
            collection_methods: Collection methods (default: ["Default"])
            output_dir: Output directory for JSON files

        Returns:
            Dictionary with collection results
        """
        try:
            # Default collection methods
            if collection_methods is None:
                collection_methods = ["Default"]

            # Build command
            output_path = output_dir or "/tmp/bloodhound"
            Path(output_path).mkdir(parents=True, exist_ok=True)

            cmd = [
                "bloodhound-python",
                "-c", ','.join(collection_methods),
                "-d", domain,
                "-u", username,
                "-p", password,
                "-ns", dc_ip,
                "--zip"
            ]

            # Execute
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=output_path
            )

            if result.returncode != 0:
                return {
                    "success": False,
                    "error": result.stderr
                }

            return {
                "success": True,
                "output_dir": output_path,
                "stdout": result.stdout
            }

        except FileNotFoundError:
            return {
                "success": False,
                "error": "bloodhound-python not found"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def parse_json_output(self, json_file: str) -> Dict[str, Any]:
        """Parse BloodHound JSON output file.

        Args:
            json_file: Path to JSON file

        Returns:
            Parsed JSON data
        """
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)

            return data

        except Exception as e:
            print(f"❌ JSON parsing error: {e}")
            return {}

    def find_path_to_da(
        self,
        start_user: str,
        api_url: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Find attack paths to Domain Admins group.

        Args:
            start_user: Starting user principal
            api_url: BloodHound API URL (if using Neo4j directly)

        Returns:
            List of attack paths
        """
        # This would require Neo4j connection
        # For now, return placeholder
        return self._query_bloodhound_api(
            query=f"MATCH p=shortestPath((u:User {{name:'{start_user}'}})-[*1..]->(g:Group {{name:'DOMAIN ADMINS@CORP.LOCAL'}})) RETURN p",
            api_url=api_url
        )

    def find_shortest_path(
        self,
        start: str,
        end: str,
        api_url: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Find shortest path between two nodes.

        Args:
            start: Starting node
            end: Ending node
            api_url: BloodHound API URL

        Returns:
            Path information
        """
        return self._query_bloodhound_api(
            query=f"MATCH p=shortestPath((a {{name:'{start}'}})-[*1..]->(b {{name:'{end}'}})) RETURN p",
            api_url=api_url
        )

    def _query_bloodhound_api(
        self,
        query: str,
        api_url: Optional[str] = None
    ) -> Any:
        """Execute a Cypher query against BloodHound/Neo4j.

        Args:
            query: Cypher query to execute
            api_url: Neo4j API URL

        Returns:
            Query results (would need Neo4j driver in production)
        """
        # Placeholder - would require neo4j driver
        # from neo4j import GraphDatabase
        # This is a mock implementation
        return []

    def find_unconstrained_delegation(
        self,
        json_file: str
    ) -> List[Dict[str, str]]:
        """Find computers with unconstrained delegation.

        Args:
            json_file: Path to computers JSON file

        Returns:
            List of computers with unconstrained delegation
        """
        try:
            data = self.parse_json_output(json_file)
            results = []

            computers = data.get("computers", [])
            for computer in computers:
                props = computer.get("properties", {})
                if props.get("unconstraineddelegation", False):
                    results.append({
                        "name": computer.get("name", "unknown"),
                        "properties": props
                    })

            return results

        except Exception as e:
            print(f"❌ Error finding unconstrained delegation: {e}")
            return []

    def find_kerberoastable_users(
        self,
        json_file: str
    ) -> List[Dict[str, str]]:
        """Find users with SPNs (Kerberoastable).

        Args:
            json_file: Path to users JSON file

        Returns:
            List of Kerberoastable users
        """
        try:
            data = self.parse_json_output(json_file)
            results = []

            users = data.get("users", [])
            for user in users:
                props = user.get("properties", {})
                if props.get("hasspn", False) and props.get("enabled", False):
                    results.append({
                        "name": user.get("name", "unknown"),
                        "spn": True
                    })

            return results

        except Exception as e:
            print(f"❌ Error finding Kerberoastable users: {e}")
            return []

    def find_asreproastable_users(
        self,
        json_file: str
    ) -> List[Dict[str, str]]:
        """Find users without Kerberos pre-authentication.

        Args:
            json_file: Path to users JSON file

        Returns:
            List of AS-REP roastable users
        """
        try:
            data = self.parse_json_output(json_file)
            results = []

            users = data.get("users", [])
            for user in users:
                props = user.get("properties", {})
                if props.get("dontreqpreauth", False) and props.get("enabled", False):
                    results.append({
                        "name": user.get("name", "unknown"),
                        "preauth_not_required": True
                    })

            return results

        except Exception as e:
            print(f"❌ Error finding AS-REP roastable users: {e}")
            return []

    def find_high_value_targets(
        self,
        json_file: str
    ) -> Dict[str, List[Dict[str, str]]]:
        """Find high value targets (marked by BloodHound).

        Args:
            json_file: Path to BloodHound JSON file

        Returns:
            Dictionary with high value users and computers
        """
        try:
            data = self.parse_json_output(json_file)
            results = {
                "users": [],
                "computers": []
            }

            # Check users
            users = data.get("users", [])
            for user in users:
                props = user.get("properties", {})
                if props.get("highvalue", False):
                    results["users"].append({
                        "name": user.get("name", "unknown")
                    })

            # Check computers
            computers = data.get("computers", [])
            for computer in computers:
                props = computer.get("properties", {})
                if props.get("highvalue", False):
                    results["computers"].append({
                        "name": computer.get("name", "unknown")
                    })

            return results

        except Exception as e:
            print(f"❌ Error finding high value targets: {e}")
            return {"users": [], "computers": []}

    def analyze_acls(
        self,
        json_file: str
    ) -> List[Dict[str, str]]:
        """Analyze ACLs for privilege escalation opportunities.

        Args:
            json_file: Path to ACLs JSON file

        Returns:
            List of interesting ACL entries
        """
        try:
            data = self.parse_json_output(json_file)
            results = []

            acls = data.get("acls", [])
            dangerous_rights = [
                "GenericAll",
                "WriteDacl",
                "WriteOwner",
                "GenericWrite",
                "ForceChangePassword"
            ]

            for acl in acls:
                right = acl.get("right", "")
                if right in dangerous_rights:
                    results.append({
                        "principal": acl.get("principal", "unknown"),
                        "right": right,
                        "target": acl.get("target", "unknown")
                    })

            return results

        except Exception as e:
            print(f"❌ Error analyzing ACLs: {e}")
            return []

    def run_cypher_query(
        self,
        query: str,
        api_url: Optional[str] = None
    ) -> Any:
        """Run a custom Cypher query.

        Args:
            query: Cypher query
            api_url: Neo4j API URL

        Returns:
            Query results
        """
        return self._query_bloodhound_api(query, api_url)

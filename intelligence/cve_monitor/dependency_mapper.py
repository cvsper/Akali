#!/usr/bin/env python3
"""
Dependency Mapper - Map packages to projects for CVE impact analysis
"""

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Set


class DependencyMapper:
    """Map dependencies across all family projects"""

    def __init__(self, projects_root: str = None):
        """
        Initialize dependency mapper

        Args:
            projects_root: Root directory containing projects (default: ~)
        """
        self.projects_root = projects_root or os.path.expanduser("~")
        self.inventory = {"projects": {}, "packages": {}, "last_scan": None}

    def scan_all_projects(self, project_paths: List[str] = None) -> Dict:
        """
        Scan all projects for dependencies

        Args:
            project_paths: List of project paths (default: known family projects)

        Returns:
            Dependency inventory
        """
        if not project_paths:
            # Default family projects
            project_paths = [
                "~/umuve-platform",
                "~/junkos-backend",
                "~/akali",
                "~/services/zim-memory",
                "~/services/hub",
            ]

        print("Scanning projects for dependencies...")

        for path in project_paths:
            expanded_path = os.path.expanduser(path)
            if os.path.exists(expanded_path):
                print(f"  Scanning: {path}")
                self._scan_project(expanded_path)
            else:
                print(f"  Skipping (not found): {path}")

        # Build reverse mapping (package -> projects)
        self._build_package_index()

        # Save inventory
        self._save_inventory()

        return self.inventory

    def _scan_project(self, project_path: str):
        """Scan single project for dependencies"""
        project_name = os.path.basename(project_path)

        # Initialize project entry
        if project_name not in self.inventory["projects"]:
            self.inventory["projects"][project_name] = {
                "path": project_path,
                "python": [],
                "nodejs": [],
                "ios": [],
            }

        # Scan Python dependencies
        python_deps = self._scan_python_deps(project_path)
        if python_deps:
            self.inventory["projects"][project_name]["python"] = python_deps

        # Scan Node.js dependencies
        nodejs_deps = self._scan_nodejs_deps(project_path)
        if nodejs_deps:
            self.inventory["projects"][project_name]["nodejs"] = nodejs_deps

        # Scan iOS dependencies
        ios_deps = self._scan_ios_deps(project_path)
        if ios_deps:
            self.inventory["projects"][project_name]["ios"] = ios_deps

    def _scan_python_deps(self, project_path: str) -> List[Dict]:
        """Scan Python dependencies (requirements.txt, Pipfile, pyproject.toml)"""
        deps = []

        # Check requirements.txt
        req_file = os.path.join(project_path, "requirements.txt")
        if os.path.exists(req_file):
            with open(req_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Parse: package==version or package>=version
                        match = re.match(r'^([a-zA-Z0-9\-_]+)([>=<~!]+)([\d.]+)', line)
                        if match:
                            package, operator, version = match.groups()
                            deps.append({
                                "name": package,
                                "version": version,
                                "operator": operator,
                                "source": "requirements.txt",
                            })

        # Check Pipfile
        pipfile = os.path.join(project_path, "Pipfile")
        if os.path.exists(pipfile):
            # Simple parsing of Pipfile [packages] section
            with open(pipfile, 'r') as f:
                in_packages = False
                for line in f:
                    if '[packages]' in line:
                        in_packages = True
                        continue
                    elif line.startswith('['):
                        in_packages = False

                    if in_packages:
                        match = re.match(r'^([a-zA-Z0-9\-_]+)\s*=\s*"([^"]+)"', line)
                        if match:
                            package, version_spec = match.groups()
                            deps.append({
                                "name": package,
                                "version": version_spec.strip('~>=<'),
                                "operator": "==",
                                "source": "Pipfile",
                            })

        # Check pyproject.toml (basic parsing)
        pyproject = os.path.join(project_path, "pyproject.toml")
        if os.path.exists(pyproject):
            with open(pyproject, 'r') as f:
                in_dependencies = False
                for line in f:
                    if 'dependencies' in line and '[' in line:
                        in_dependencies = True
                        continue
                    elif line.startswith('['):
                        in_dependencies = False

                    if in_dependencies:
                        match = re.match(r'^"([a-zA-Z0-9\-_]+)([>=<~!]+)([\d.]+)"', line.strip())
                        if match:
                            package, operator, version = match.groups()
                            deps.append({
                                "name": package,
                                "version": version,
                                "operator": operator,
                                "source": "pyproject.toml",
                            })

        return deps

    def _scan_nodejs_deps(self, project_path: str) -> List[Dict]:
        """Scan Node.js dependencies (package.json)"""
        deps = []

        package_json = os.path.join(project_path, "package.json")
        if os.path.exists(package_json):
            try:
                with open(package_json, 'r') as f:
                    data = json.load(f)

                # Scan dependencies
                for section in ["dependencies", "devDependencies"]:
                    if section in data:
                        for package, version in data[section].items():
                            # Clean version (remove ^, ~, etc.)
                            clean_version = version.lstrip('^~>=<')
                            deps.append({
                                "name": package,
                                "version": clean_version,
                                "operator": "==",
                                "source": f"package.json ({section})",
                            })
            except Exception as e:
                print(f"Error parsing package.json: {e}")

        return deps

    def _scan_ios_deps(self, project_path: str) -> List[Dict]:
        """Scan iOS dependencies (Podfile, Package.swift)"""
        deps = []

        # Check Podfile
        podfile = os.path.join(project_path, "Podfile")
        if os.path.exists(podfile):
            with open(podfile, 'r') as f:
                for line in f:
                    line = line.strip()
                    # Parse: pod 'PodName', '~> 1.2.3'
                    match = re.match(r"pod\s+'([^']+)'(?:,\s*'([^']+)')?", line)
                    if match:
                        package = match.group(1)
                        version = match.group(2) if match.group(2) else "latest"
                        deps.append({
                            "name": package,
                            "version": version.lstrip('~>'),
                            "operator": ">=",
                            "source": "Podfile",
                        })

        # Check Package.swift (basic parsing)
        package_swift = os.path.join(project_path, "Package.swift")
        if os.path.exists(package_swift):
            with open(package_swift, 'r') as f:
                content = f.read()
                # Parse: .package(url: "...", from: "1.2.3")
                matches = re.findall(r'\.package\(url:\s*"([^"]+)",\s*from:\s*"([\d.]+)"\)', content)
                for url, version in matches:
                    # Extract package name from URL
                    package = url.split('/')[-1].replace('.git', '')
                    deps.append({
                        "name": package,
                        "version": version,
                        "operator": ">=",
                        "source": "Package.swift",
                    })

        return deps

    def _build_package_index(self):
        """Build reverse index: package -> list of projects"""
        self.inventory["packages"] = {}

        for project_name, project_data in self.inventory["projects"].items():
            for ecosystem in ["python", "nodejs", "ios"]:
                for dep in project_data.get(ecosystem, []):
                    package = dep["name"]
                    if package not in self.inventory["packages"]:
                        self.inventory["packages"][package] = {
                            "projects": [],
                            "ecosystem": ecosystem,
                        }

                    self.inventory["packages"][package]["projects"].append({
                        "name": project_name,
                        "version": dep["version"],
                        "source": dep["source"],
                    })

    def get_projects_using_package(self, package_name: str) -> List[Dict]:
        """
        Get list of projects using a specific package

        Args:
            package_name: Package name

        Returns:
            List of project dictionaries
        """
        if package_name in self.inventory["packages"]:
            return self.inventory["packages"][package_name]["projects"]
        return []

    def analyze_cve_impact(self, package_name: str, affected_versions: List[str] = None) -> Dict:
        """
        Analyze CVE impact - which projects are affected

        Args:
            package_name: Package name
            affected_versions: List of affected versions (if known)

        Returns:
            Impact analysis dictionary
        """
        projects = self.get_projects_using_package(package_name)

        if not projects:
            return {
                "package": package_name,
                "affected_projects": [],
                "impact": "NONE",
                "recommendation": f"Package '{package_name}' not used in any tracked projects",
            }

        # Determine impact
        if affected_versions:
            # Check if any project uses affected version
            affected = []
            for proj in projects:
                if proj["version"] in affected_versions:
                    affected.append(proj)

            impact = "CRITICAL" if len(affected) >= 2 else "HIGH" if affected else "LOW"
        else:
            # Unknown affected versions - assume all projects affected
            affected = projects
            impact = "CRITICAL" if len(affected) >= 2 else "HIGH"

        return {
            "package": package_name,
            "affected_projects": affected,
            "total_projects": len(projects),
            "impact": impact,
            "recommendation": self._generate_recommendation(package_name, affected),
        }

    def _generate_recommendation(self, package_name: str, affected_projects: List[Dict]) -> str:
        """Generate remediation recommendation"""
        if not affected_projects:
            return f"No action needed - {package_name} not used in any projects"

        projects_str = ", ".join([p["name"] for p in affected_projects])
        return f"Update {package_name} in: {projects_str}"

    def _save_inventory(self):
        """Save inventory to disk"""
        from datetime import datetime

        self.inventory["last_scan"] = datetime.now().isoformat()

        output_file = os.path.expanduser("~/akali/intelligence/cve_monitor/dependency_inventory.json")
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        with open(output_file, 'w') as f:
            json.dump(self.inventory, f, indent=2)

        print(f"\nInventory saved to: {output_file}")

    def _load_inventory(self):
        """Load inventory from disk"""
        input_file = os.path.expanduser("~/akali/intelligence/cve_monitor/dependency_inventory.json")
        if os.path.exists(input_file):
            with open(input_file, 'r') as f:
                self.inventory = json.load(f)
            return True
        return False


def main():
    """CLI for dependency mapping"""
    import sys

    mapper = DependencyMapper()

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python dependency_mapper.py scan                    # Scan all projects")
        print("  python dependency_mapper.py search <package>        # Find which projects use a package")
        print("  python dependency_mapper.py impact <package>        # Analyze CVE impact")
        print("  python dependency_mapper.py list                    # List all tracked packages")
        sys.exit(1)

    command = sys.argv[1]

    if command == "scan":
        inventory = mapper.scan_all_projects()

        print(f"\n{'='*80}")
        print("Dependency Inventory")
        print(f"{'='*80}\n")

        total_deps = sum(
            len(proj.get("python", [])) + len(proj.get("nodejs", [])) + len(proj.get("ios", []))
            for proj in inventory["projects"].values()
        )

        print(f"Projects scanned: {len(inventory['projects'])}")
        print(f"Unique packages: {len(inventory['packages'])}")
        print(f"Total dependencies: {total_deps}")
        print()

        for project_name, project_data in inventory["projects"].items():
            py_count = len(project_data.get("python", []))
            node_count = len(project_data.get("nodejs", []))
            ios_count = len(project_data.get("ios", []))

            print(f"  {project_name}:")
            if py_count:
                print(f"    Python: {py_count} packages")
            if node_count:
                print(f"    Node.js: {node_count} packages")
            if ios_count:
                print(f"    iOS: {ios_count} packages")

    elif command == "search":
        if len(sys.argv) < 3:
            print("Error: Package name required")
            sys.exit(1)

        # Load existing inventory
        if not mapper._load_inventory():
            print("No inventory found. Run 'scan' first.")
            sys.exit(1)

        package = sys.argv[2]
        projects = mapper.get_projects_using_package(package)

        if projects:
            print(f"\n{'='*80}")
            print(f"Package: {package}")
            print(f"{'='*80}\n")
            print(f"Used in {len(projects)} project(s):\n")

            for proj in projects:
                print(f"  • {proj['name']}")
                print(f"    Version: {proj['version']}")
                print(f"    Source: {proj['source']}")
                print()
        else:
            print(f"Package '{package}' not found in any tracked projects")

    elif command == "impact":
        if len(sys.argv) < 3:
            print("Error: Package name required")
            sys.exit(1)

        # Load existing inventory
        if not mapper._load_inventory():
            print("No inventory found. Run 'scan' first.")
            sys.exit(1)

        package = sys.argv[2]
        analysis = mapper.analyze_cve_impact(package)

        print(f"\n{'='*80}")
        print(f"CVE Impact Analysis: {package}")
        print(f"{'='*80}\n")

        color = {
            "CRITICAL": "\033[91m",
            "HIGH": "\033[93m",
            "MEDIUM": "\033[94m",
            "LOW": "\033[92m",
            "NONE": "\033[90m",
        }.get(analysis["impact"], "")
        reset = "\033[0m"

        print(f"Impact: {color}{analysis['impact']}{reset}")
        print(f"Affected Projects: {len(analysis['affected_projects'])} / {analysis['total_projects']}")
        print(f"\nRecommendation: {analysis['recommendation']}")

        if analysis['affected_projects']:
            print("\nAffected:")
            for proj in analysis['affected_projects']:
                print(f"  • {proj['name']} (v{proj['version']})")

    elif command == "list":
        # Load existing inventory
        if not mapper._load_inventory():
            print("No inventory found. Run 'scan' first.")
            sys.exit(1)

        print(f"\n{'='*80}")
        print(f"Tracked Packages ({len(mapper.inventory['packages'])})")
        print(f"{'='*80}\n")

        # Group by ecosystem
        by_ecosystem = {"python": [], "nodejs": [], "ios": []}
        for package, data in mapper.inventory["packages"].items():
            ecosystem = data.get("ecosystem", "unknown")
            if ecosystem in by_ecosystem:
                by_ecosystem[ecosystem].append(package)

        for ecosystem, packages in by_ecosystem.items():
            if packages:
                print(f"\n{ecosystem.upper()} ({len(packages)} packages):")
                for package in sorted(packages):
                    project_count = len(mapper.inventory["packages"][package]["projects"])
                    print(f"  • {package} (used by {project_count} project(s))")

    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()

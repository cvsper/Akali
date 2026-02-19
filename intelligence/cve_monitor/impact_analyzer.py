#!/usr/bin/env python3
"""
Impact Analyzer - Calculate CVE blast radius across family projects
"""

import json
import os
from typing import Dict, List
from cve_tracker import CVETracker
from dependency_mapper import DependencyMapper


class ImpactAnalyzer:
    """Analyze CVE impact across family projects"""

    def __init__(self):
        """Initialize impact analyzer"""
        self.cve_tracker = CVETracker()
        self.dep_mapper = DependencyMapper()

        # Load dependency inventory
        if not self.dep_mapper._load_inventory():
            print("Warning: No dependency inventory found. Run 'akali intel scan-deps' first.")

    def analyze_recent_cves(self, hours: int = 24) -> List[Dict]:
        """
        Analyze recent CVEs for impact on family projects

        Args:
            hours: Hours to look back

        Returns:
            List of impact analyses
        """
        print(f"Analyzing CVEs from last {hours} hours...")

        # Get recent CVEs
        cves = self.cve_tracker.check_new_cves(since_hours=hours)

        analyses = []
        for cve in cves:
            # Try to extract affected package from description
            packages = self._extract_packages_from_cve(cve)

            for package in packages:
                impact = self.dep_mapper.analyze_cve_impact(package)
                if impact["affected_projects"]:
                    analyses.append({
                        "cve": cve,
                        "package": package,
                        "impact": impact,
                    })

        return analyses

    def analyze_cve(self, cve_id: str) -> Dict:
        """
        Analyze specific CVE for impact

        Args:
            cve_id: CVE identifier

        Returns:
            Impact analysis dictionary
        """
        # Lookup CVE
        cve = self.cve_tracker.lookup_cve(cve_id)
        if not cve:
            return {"error": f"CVE {cve_id} not found"}

        # Extract affected packages
        packages = self._extract_packages_from_cve(cve)

        if not packages:
            return {
                "cve": cve,
                "packages": [],
                "impact": "UNKNOWN",
                "message": "Could not determine affected packages from CVE description",
            }

        # Analyze impact for each package
        impacts = []
        for package in packages:
            impact = self.dep_mapper.analyze_cve_impact(package)
            if impact["affected_projects"]:
                impacts.append({
                    "package": package,
                    "impact": impact,
                })

        # Determine overall impact
        if not impacts:
            overall_impact = "NONE"
        elif any(i["impact"]["impact"] == "CRITICAL" for i in impacts):
            overall_impact = "CRITICAL"
        elif any(i["impact"]["impact"] == "HIGH" for i in impacts):
            overall_impact = "HIGH"
        else:
            overall_impact = "MEDIUM"

        return {
            "cve": cve,
            "packages": packages,
            "impacts": impacts,
            "overall_impact": overall_impact,
            "affected_project_count": sum(len(i["impact"]["affected_projects"]) for i in impacts),
        }

    def _extract_packages_from_cve(self, cve: Dict) -> List[str]:
        """
        Extract package names from CVE description

        This is a best-effort heuristic. For production, would integrate
        with CVE's CPE (Common Platform Enumeration) data.

        Args:
            cve: CVE dictionary

        Returns:
            List of package names
        """
        description = cve.get("description", "").lower()
        packages = []

        # Common package name patterns in CVE descriptions
        # Python packages
        python_packages = [
            "flask", "django", "requests", "urllib3", "cryptography",
            "pyjwt", "sqlalchemy", "pillow", "numpy", "pandas",
            "werkzeug", "jinja2", "click", "setuptools", "pip",
        ]

        for package in python_packages:
            if package in description:
                packages.append(package)

        # Node.js packages
        nodejs_packages = [
            "express", "react", "next", "axios", "lodash",
            "moment", "webpack", "babel", "eslint", "typescript",
            "socket.io", "dotenv", "bcrypt", "jsonwebtoken", "cors",
        ]

        for package in nodejs_packages:
            if package in description:
                packages.append(package)

        # iOS frameworks
        ios_packages = [
            "alamofire", "sdwebimage", "snapkit", "realm",
            "kingfisher", "rxswift", "swiftyjson",
        ]

        for package in ios_packages:
            if package in description:
                packages.append(package)

        # Remove duplicates
        return list(set(packages))

    def get_critical_alerts(self, hours: int = 24) -> List[Dict]:
        """
        Get critical CVE alerts that affect family projects

        Args:
            hours: Hours to look back

        Returns:
            List of critical alert dictionaries
        """
        analyses = self.analyze_recent_cves(hours)

        # Filter for Critical/High CVEs affecting projects
        critical = []
        for analysis in analyses:
            cve = analysis["cve"]
            impact = analysis["impact"]

            if cve["severity"] in ["CRITICAL", "HIGH"] and impact["affected_projects"]:
                critical.append({
                    "cve_id": cve["id"],
                    "severity": cve["severity"],
                    "cvss": cve.get("cvss_v3", cve.get("cvss_v2")),
                    "package": analysis["package"],
                    "affected_projects": [p["name"] for p in impact["affected_projects"]],
                    "description": cve["description"][:200] + "...",
                    "recommendation": impact["recommendation"],
                })

        return critical

    def generate_alert_message(self, cve_id: str) -> str:
        """
        Generate alert message for ZimMemory

        Args:
            cve_id: CVE identifier

        Returns:
            Formatted alert message
        """
        analysis = self.analyze_cve(cve_id)

        if "error" in analysis:
            return f"Error analyzing {cve_id}: {analysis['error']}"

        cve = analysis["cve"]
        impact = analysis["overall_impact"]

        # Build message
        message = f"""🚨 **SECURITY ALERT: {cve['id']}**

**Severity:** {cve['severity']} (CVSS: {cve.get('cvss_v3', 'N/A')})
**Impact:** {impact}
**Affected Projects:** {analysis['affected_project_count']}

**Description:**
{cve['description'][:300]}...

**Affected Packages:**
"""

        for pkg_impact in analysis.get("impacts", []):
            package = pkg_impact["package"]
            projects = pkg_impact["impact"]["affected_projects"]
            message += f"\n• **{package}** - used by {len(projects)} project(s):"
            for proj in projects:
                message += f"\n  - {proj['name']} (v{proj['version']})"

        message += f"\n\n**Recommendation:**\n"
        for pkg_impact in analysis.get("impacts", []):
            message += f"• {pkg_impact['impact']['recommendation']}\n"

        message += f"\n**References:**\n"
        for ref in cve.get("references", [])[:3]:  # First 3 refs
            message += f"• {ref}\n"

        return message


def main():
    """CLI for impact analysis"""
    import sys

    analyzer = ImpactAnalyzer()

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python impact_analyzer.py recent [hours]   # Analyze recent CVEs")
        print("  python impact_analyzer.py cve <CVE-ID>     # Analyze specific CVE")
        print("  python impact_analyzer.py critical         # Get critical alerts")
        sys.exit(1)

    command = sys.argv[1]

    if command == "recent":
        hours = int(sys.argv[2]) if len(sys.argv) > 2 else 24
        analyses = analyzer.analyze_recent_cves(hours)

        print(f"\n{'='*80}")
        print(f"CVE Impact Analysis (last {hours} hours)")
        print(f"{'='*80}\n")

        if not analyses:
            print("No CVEs affecting family projects found.")
        else:
            print(f"Found {len(analyses)} CVE(s) affecting family projects:\n")

            for analysis in analyses:
                cve = analysis["cve"]
                impact = analysis["impact"]

                color = {
                    "CRITICAL": "\033[91m",
                    "HIGH": "\033[93m",
                    "MEDIUM": "\033[94m",
                }.get(impact["impact"], "")
                reset = "\033[0m"

                print(f"{color}[{impact['impact']}]{reset} {cve['id']} - {analysis['package']}")
                print(f"  Affects: {', '.join([p['name'] for p in impact['affected_projects']])}")
                print(f"  {impact['recommendation']}")
                print()

    elif command == "cve":
        if len(sys.argv) < 3:
            print("Error: CVE ID required")
            sys.exit(1)

        cve_id = sys.argv[2]
        analysis = analyzer.analyze_cve(cve_id)

        if "error" in analysis:
            print(f"Error: {analysis['error']}")
            sys.exit(1)

        print(f"\n{'='*80}")
        print(f"CVE Impact Analysis: {cve_id}")
        print(f"{'='*80}\n")

        cve = analysis["cve"]
        print(f"Severity: {cve['severity']} (CVSS: {cve.get('cvss_v3', 'N/A')})")
        print(f"Overall Impact: {analysis['overall_impact']}")
        print(f"Affected Projects: {analysis['affected_project_count']}")
        print(f"\nDescription:\n{cve['description'][:300]}...\n")

        if analysis.get("impacts"):
            print("Package Impact:")
            for pkg_impact in analysis["impacts"]:
                package = pkg_impact["package"]
                impact = pkg_impact["impact"]
                print(f"\n  • {package}")
                print(f"    Impact: {impact['impact']}")
                print(f"    Projects:")
                for proj in impact["affected_projects"]:
                    print(f"      - {proj['name']} (v{proj['version']})")
                print(f"    Recommendation: {impact['recommendation']}")
        else:
            print("No family projects affected.")

    elif command == "critical":
        alerts = analyzer.get_critical_alerts()

        print(f"\n{'='*80}")
        print(f"CRITICAL SECURITY ALERTS")
        print(f"{'='*80}\n")

        if not alerts:
            print("✅ No critical alerts. All clear!")
        else:
            print(f"🚨 {len(alerts)} CRITICAL/HIGH CVE(s) affecting family projects:\n")

            for alert in alerts:
                color = "\033[91m" if alert["severity"] == "CRITICAL" else "\033[93m"
                reset = "\033[0m"

                print(f"{color}[{alert['severity']}]{reset} {alert['cve_id']} (CVSS: {alert['cvss']})")
                print(f"  Package: {alert['package']}")
                print(f"  Affects: {', '.join(alert['affected_projects'])}")
                print(f"  Action: {alert['recommendation']}")
                print()

    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()

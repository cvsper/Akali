#!/usr/bin/env python3
"""
CVE Tracker - Monitor NVD and GitHub Security Advisories for vulnerabilities
"""

import json
import os
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import requests

# Configuration
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_API_BASE = "https://api.github.com"
CACHE_FILE = os.path.expanduser("~/akali/intelligence/cve_monitor/cve_cache.json")
CACHE_DURATION_HOURS = 6  # Cache CVEs for 6 hours


class CVETracker:
    """Track CVEs from NVD and GitHub Security Advisories"""

    def __init__(self, nvd_api_key: Optional[str] = None, github_token: Optional[str] = None):
        """
        Initialize CVE tracker

        Args:
            nvd_api_key: Optional NVD API key for higher rate limits
            github_token: Optional GitHub token for higher rate limits
        """
        self.nvd_api_key = nvd_api_key
        self.github_token = github_token
        self.cache = self._load_cache()

    def _load_cache(self) -> Dict:
        """Load CVE cache from disk"""
        if os.path.exists(CACHE_FILE):
            try:
                with open(CACHE_FILE, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Warning: Failed to load cache: {e}")
        return {"cves": {}, "last_check": None}

    def _save_cache(self):
        """Save CVE cache to disk"""
        os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
        with open(CACHE_FILE, 'w') as f:
            json.dump(self.cache, f, indent=2)

    def _is_cache_valid(self) -> bool:
        """Check if cache is still valid"""
        if not self.cache.get("last_check"):
            return False

        last_check = datetime.fromisoformat(self.cache["last_check"])
        age = datetime.now() - last_check
        return age < timedelta(hours=CACHE_DURATION_HOURS)

    def check_new_cves(self, since_hours: int = 24) -> List[Dict]:
        """
        Check for new CVEs published in the last N hours

        Args:
            since_hours: Hours to look back (default: 24)

        Returns:
            List of new CVE dictionaries
        """
        # Check cache first
        if self._is_cache_valid():
            print("Using cached CVE data...")
            return self._filter_recent_cves(since_hours)

        print("Fetching new CVEs from NVD...")
        new_cves = self._fetch_nvd_cves(since_hours)

        # Update cache
        for cve in new_cves:
            self.cache["cves"][cve["id"]] = cve
        self.cache["last_check"] = datetime.now().isoformat()
        self._save_cache()

        return new_cves

    def _filter_recent_cves(self, since_hours: int) -> List[Dict]:
        """Filter cached CVEs by recency"""
        cutoff = datetime.now() - timedelta(hours=since_hours)
        recent = []

        for cve_id, cve in self.cache["cves"].items():
            published = datetime.fromisoformat(cve["published"])
            if published > cutoff:
                recent.append(cve)

        return recent

    def _fetch_nvd_cves(self, since_hours: int) -> List[Dict]:
        """
        Fetch CVEs from NVD API

        Args:
            since_hours: Hours to look back

        Returns:
            List of CVE dictionaries
        """
        # Calculate time range
        end_date = datetime.now()
        start_date = end_date - timedelta(hours=since_hours)

        # Format dates for NVD API (ISO 8601)
        pub_start = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        pub_end = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")

        # Build request
        params = {
            "pubStartDate": pub_start,
            "pubEndDate": pub_end,
        }

        headers = {}
        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key

        try:
            # NVD rate limits: 5 req/30s (no key) or 50 req/30s (with key)
            response = requests.get(NVD_API_BASE, params=params, headers=headers, timeout=30)
            response.raise_for_status()

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])

            cves = []
            for vuln in vulnerabilities:
                cve = vuln.get("cve", {})
                cves.append(self._parse_nvd_cve(cve))

            print(f"Fetched {len(cves)} CVEs from NVD")
            return cves

        except requests.exceptions.RequestException as e:
            print(f"Error fetching CVEs from NVD: {e}")
            return []

    def _parse_nvd_cve(self, cve: Dict) -> Dict:
        """
        Parse NVD CVE into standard format

        Args:
            cve: Raw CVE data from NVD

        Returns:
            Parsed CVE dictionary
        """
        cve_id = cve.get("id", "UNKNOWN")

        # Extract CVSS scores
        cvss_v3 = None
        cvss_v2 = None
        severity = "UNKNOWN"

        metrics = cve.get("metrics", {})
        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            cvss_v3 = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            severity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
        elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
            cvss_v3 = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
            severity = metrics["cvssMetricV30"][0]["cvssData"]["baseSeverity"]
        elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            cvss_v2 = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
            # Map V2 score to severity
            if cvss_v2 >= 7.0:
                severity = "HIGH"
            elif cvss_v2 >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"

        # Extract descriptions
        descriptions = cve.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # Extract references
        references = cve.get("references", [])
        refs = [ref.get("url", "") for ref in references]

        # Extract published date
        published = cve.get("published", datetime.now().isoformat())

        return {
            "id": cve_id,
            "description": description,
            "cvss_v3": cvss_v3,
            "cvss_v2": cvss_v2,
            "severity": severity,
            "published": published,
            "references": refs,
            "source": "NVD",
        }

    def lookup_cve(self, cve_id: str) -> Optional[Dict]:
        """
        Lookup specific CVE by ID

        Args:
            cve_id: CVE identifier (e.g., CVE-2024-1234)

        Returns:
            CVE dictionary or None if not found
        """
        # Check cache first
        if cve_id in self.cache["cves"]:
            return self.cache["cves"][cve_id]

        # Fetch from NVD
        print(f"Fetching {cve_id} from NVD...")
        url = f"{NVD_API_BASE}?cveId={cve_id}"

        headers = {}
        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key

        try:
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])

            if vulnerabilities:
                cve = vulnerabilities[0].get("cve", {})
                parsed = self._parse_nvd_cve(cve)

                # Update cache
                self.cache["cves"][cve_id] = parsed
                self._save_cache()

                return parsed
            else:
                print(f"CVE {cve_id} not found")
                return None

        except requests.exceptions.RequestException as e:
            print(f"Error fetching CVE {cve_id}: {e}")
            return None

    def filter_by_severity(self, cves: List[Dict], min_severity: str = "MEDIUM") -> List[Dict]:
        """
        Filter CVEs by minimum severity

        Args:
            cves: List of CVE dictionaries
            min_severity: Minimum severity (CRITICAL, HIGH, MEDIUM, LOW)

        Returns:
            Filtered list of CVEs
        """
        severity_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        min_level = severity_order.index(min_severity)

        filtered = []
        for cve in cves:
            severity = cve.get("severity", "UNKNOWN")
            if severity in severity_order:
                if severity_order.index(severity) >= min_level:
                    filtered.append(cve)

        return filtered

    def get_critical_high_cves(self, since_hours: int = 24) -> List[Dict]:
        """
        Get only Critical and High severity CVEs

        Args:
            since_hours: Hours to look back

        Returns:
            List of Critical/High CVEs
        """
        cves = self.check_new_cves(since_hours)
        return self.filter_by_severity(cves, min_severity="HIGH")


def main():
    """CLI for CVE tracking"""
    import sys

    tracker = CVETracker()

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python cve_tracker.py check [hours]    # Check for new CVEs")
        print("  python cve_tracker.py lookup <CVE-ID>  # Lookup specific CVE")
        print("  python cve_tracker.py critical         # Get Critical/High CVEs")
        sys.exit(1)

    command = sys.argv[1]

    if command == "check":
        hours = int(sys.argv[2]) if len(sys.argv) > 2 else 24
        cves = tracker.check_new_cves(since_hours=hours)

        print(f"\n{'='*80}")
        print(f"Found {len(cves)} CVEs published in last {hours} hours")
        print(f"{'='*80}\n")

        for cve in cves:
            severity_color = {
                "CRITICAL": "\033[91m",  # Red
                "HIGH": "\033[93m",      # Yellow
                "MEDIUM": "\033[94m",    # Blue
                "LOW": "\033[92m",       # Green
            }.get(cve["severity"], "")
            reset = "\033[0m"

            print(f"{severity_color}[{cve['severity']}]{reset} {cve['id']}")
            print(f"  CVSS v3: {cve.get('cvss_v3', 'N/A')}")
            print(f"  Published: {cve['published']}")
            print(f"  Description: {cve['description'][:200]}...")
            print()

    elif command == "lookup":
        if len(sys.argv) < 3:
            print("Error: CVE ID required")
            sys.exit(1)

        cve_id = sys.argv[2]
        cve = tracker.lookup_cve(cve_id)

        if cve:
            print(f"\n{'='*80}")
            print(f"{cve['id']}")
            print(f"{'='*80}\n")
            print(f"Severity: {cve['severity']}")
            print(f"CVSS v3: {cve.get('cvss_v3', 'N/A')}")
            print(f"CVSS v2: {cve.get('cvss_v2', 'N/A')}")
            print(f"Published: {cve['published']}")
            print(f"\nDescription:\n{cve['description']}")
            print(f"\nReferences:")
            for ref in cve['references']:
                print(f"  - {ref}")
        else:
            print(f"CVE {cve_id} not found")

    elif command == "critical":
        cves = tracker.get_critical_high_cves()

        print(f"\n{'='*80}")
        print(f"Found {len(cves)} CRITICAL/HIGH CVEs in last 24 hours")
        print(f"{'='*80}\n")

        for cve in cves:
            color = "\033[91m" if cve["severity"] == "CRITICAL" else "\033[93m"
            reset = "\033[0m"

            print(f"{color}[{cve['severity']}]{reset} {cve['id']} (CVSS: {cve.get('cvss_v3', 'N/A')})")
            print(f"  {cve['description'][:150]}...")
            print()

    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()

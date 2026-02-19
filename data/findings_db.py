"""Findings database - JSON-based storage for Phase 1."""

import json
from pathlib import Path
from typing import List, Optional, Dict, Any
from datetime import datetime


class FindingsDB:
    """Simple JSON-based findings database."""

    def __init__(self, db_path: str = "~/akali/data/findings.json"):
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_db_exists()

    def _ensure_db_exists(self):
        """Create empty database if it doesn't exist."""
        if not self.db_path.exists():
            self.db_path.write_text(json.dumps({"findings": []}, indent=2))

    def _load(self) -> Dict[str, Any]:
        """Load database from disk."""
        return json.loads(self.db_path.read_text())

    def _save(self, data: Dict[str, Any]):
        """Save database to disk."""
        self.db_path.write_text(json.dumps(data, indent=2))

    def add_finding(self, finding: Dict[str, Any]) -> str:
        """Add a finding to the database."""
        data = self._load()
        data["findings"].append(finding)
        self._save(data)
        return finding["id"]

    def add_findings(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Add multiple findings to the database."""
        data = self._load()
        data["findings"].extend(findings)
        self._save(data)
        return [f["id"] for f in findings]

    def get_finding(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """Get a finding by ID."""
        data = self._load()
        for finding in data["findings"]:
            if finding["id"] == finding_id:
                return finding
        return None

    def list_findings(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        scanner: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List findings with optional filters."""
        data = self._load()
        findings = data["findings"]

        if status:
            findings = [f for f in findings if f.get("status") == status]
        if severity:
            findings = [f for f in findings if f.get("severity") == severity]
        if scanner:
            findings = [f for f in findings if f.get("scanner") == scanner]

        return findings

    def update_finding(self, finding_id: str, updates: Dict[str, Any]) -> bool:
        """Update a finding."""
        data = self._load()
        for finding in data["findings"]:
            if finding["id"] == finding_id:
                finding.update(updates)
                self._save(data)
                return True
        return False

    def delete_finding(self, finding_id: str) -> bool:
        """Delete a finding."""
        data = self._load()
        original_count = len(data["findings"])
        data["findings"] = [f for f in data["findings"] if f["id"] != finding_id]
        self._save(data)
        return len(data["findings"]) < original_count

    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics."""
        data = self._load()
        findings = data["findings"]

        stats = {
            "total": len(findings),
            "by_status": {},
            "by_severity": {},
            "by_scanner": {}
        }

        for finding in findings:
            status = finding.get("status", "unknown")
            severity = finding.get("severity", "unknown")
            scanner = finding.get("scanner", "unknown")

            stats["by_status"][status] = stats["by_status"].get(status, 0) + 1
            stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1
            stats["by_scanner"][scanner] = stats["by_scanner"].get(scanner, 0) + 1

        return stats

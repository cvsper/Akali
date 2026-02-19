"""Tests for findings database."""

import sys
from pathlib import Path
import tempfile
import json

sys.path.append(str(Path.home() / "akali" / "data"))

from findings_db import FindingsDB


def test_findings_db_init():
    """Test database initialization."""
    db_path = tempfile.mktemp(suffix='.json')

    db = FindingsDB(db_path)
    assert Path(db_path).exists()
    print("✅ Database initialization works")

    # Cleanup
    Path(db_path).unlink()


def test_findings_crud():
    """Test CRUD operations."""
    db_path = tempfile.mktemp(suffix='.json')

    db = FindingsDB(db_path)

    # Create
    finding = {
        "id": "TEST-001",
        "severity": "high",
        "title": "Test finding",
        "status": "open"
    }
    db.add_finding(finding)

    # Read
    result = db.get_finding("TEST-001")
    assert result is not None
    assert result["title"] == "Test finding"
    print("✅ Create and read works")

    # Update
    db.update_finding("TEST-001", {"status": "closed"})
    result = db.get_finding("TEST-001")
    assert result["status"] == "closed"
    print("✅ Update works")

    # Delete
    db.delete_finding("TEST-001")
    result = db.get_finding("TEST-001")
    assert result is None
    print("✅ Delete works")

    # Cleanup
    Path(db_path).unlink()


def test_findings_stats():
    """Test statistics generation."""
    db_path = tempfile.mktemp(suffix='.json')

    db = FindingsDB(db_path)

    # Add test findings
    db.add_finding({"id": "T1", "severity": "critical", "status": "open", "scanner": "secrets"})
    db.add_finding({"id": "T2", "severity": "high", "status": "open", "scanner": "sast"})
    db.add_finding({"id": "T3", "severity": "medium", "status": "closed", "scanner": "secrets"})

    stats = db.get_stats()
    assert stats["total"] == 3
    assert stats["by_severity"]["critical"] == 1
    assert stats["by_status"]["open"] == 2
    print("✅ Statistics generation works")

    # Cleanup
    Path(db_path).unlink()


if __name__ == "__main__":
    print("Testing findings database...\n")
    test_findings_db_init()
    test_findings_crud()
    test_findings_stats()
    print("\n✅ All database tests passed")

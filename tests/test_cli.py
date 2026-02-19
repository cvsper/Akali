"""Tests for Akali CLI."""

import sys
from pathlib import Path
import tempfile

sys.path.append(str(Path.home() / "akali" / "core"))

from cli import AkaliCLI


def test_cli_init():
    """Test CLI initialization."""
    cli = AkaliCLI()
    assert cli.db is not None
    assert len(cli.scanners) == 3
    print("✅ CLI initialization works")


def test_cli_status():
    """Test status command."""
    cli = AkaliCLI()
    # Should not raise
    cli.status()
    print("✅ Status command works")


if __name__ == "__main__":
    print("Testing Akali CLI...\n")
    test_cli_init()
    test_cli_status()
    print("\n✅ All CLI tests passed")

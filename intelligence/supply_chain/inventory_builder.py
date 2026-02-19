#!/usr/bin/env python3
"""
Supply Chain Inventory Builder - Build complete package manifest
"""

import json
import os
from typing import Dict
import sys

# Add parent directory to path to import dependency_mapper
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cve_monitor.dependency_mapper import DependencyMapper


class InventoryBuilder:
    """Build supply chain inventory"""

    def __init__(self):
        """Initialize inventory builder"""
        self.mapper = DependencyMapper()
        self.inventory_file = os.path.expanduser("~/akali/intelligence/supply_chain/supply_chain_inventory.json")

    def build_inventory(self) -> Dict:
        """
        Build complete supply chain inventory

        Returns:
            Inventory dictionary
        """
        print("Building supply chain inventory...")

        # Scan all projects for dependencies
        inventory = self.mapper.scan_all_projects()

        # Add supply chain metadata
        inventory["supply_chain"] = {
            "total_packages": len(inventory["packages"]),
            "total_projects": len(inventory["projects"]),
            "ecosystems": self._count_ecosystems(inventory),
        }

        # Save inventory
        self._save_inventory(inventory)

        return inventory

    def _count_ecosystems(self, inventory: Dict) -> Dict:
        """Count packages by ecosystem"""
        ecosystems = {"python": 0, "nodejs": 0, "ios": 0}

        for package_data in inventory["packages"].values():
            ecosystem = package_data.get("ecosystem", "unknown")
            if ecosystem in ecosystems:
                ecosystems[ecosystem] += 1

        return ecosystems

    def _save_inventory(self, inventory: Dict):
        """Save inventory to disk"""
        os.makedirs(os.path.dirname(self.inventory_file), exist_ok=True)
        with open(self.inventory_file, 'w') as f:
            json.dump(inventory, f, indent=2)
        print(f"Inventory saved to: {self.inventory_file}")


if __name__ == "__main__":
    builder = InventoryBuilder()
    inventory = builder.build_inventory()

    print(f"\n{'='*80}")
    print("Supply Chain Inventory")
    print(f"{'='*80}\n")
    print(f"Total packages: {inventory['supply_chain']['total_packages']}")
    print(f"Total projects: {inventory['supply_chain']['total_projects']}")
    print(f"Python: {inventory['supply_chain']['ecosystems']['python']} packages")
    print(f"Node.js: {inventory['supply_chain']['ecosystems']['nodejs']} packages")
    print(f"iOS: {inventory['supply_chain']['ecosystems']['ios']} packages")

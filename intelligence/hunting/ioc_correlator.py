#!/usr/bin/env python3
"""
IoC Correlator - Correlate Indicators of Compromise across sources

Integrates with Phase 4 threat feeds to correlate IPs, domains, hashes, and other IoCs.
Maps relationships between indicators and identifies connected threats.
"""

import json
import os
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple
from pathlib import Path
from collections import defaultdict


class IoC:
    """Represents an Indicator of Compromise"""

    def __init__(self, ioc_type: str, value: str, source: str = "unknown",
                 confidence: float = 0.5, tags: Optional[List[str]] = None):
        self.type = ioc_type  # ip, domain, hash, email, url, etc.
        self.value = value
        self.source = source
        self.confidence = confidence  # 0.0 - 1.0
        self.tags = tags or []
        self.first_seen = datetime.now().isoformat()
        self.last_seen = datetime.now().isoformat()
        self.occurrences = 1
        self.related_iocs: Set[str] = set()
        self.metadata: Dict[str, Any] = {}

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary"""
        return {
            "type": self.type,
            "value": self.value,
            "source": self.source,
            "confidence": self.confidence,
            "tags": self.tags,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "occurrences": self.occurrences,
            "related_iocs": list(self.related_iocs),
            "metadata": self.metadata
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'IoC':
        """Deserialize from dictionary"""
        ioc = cls(
            ioc_type=data['type'],
            value=data['value'],
            source=data.get('source', 'unknown'),
            confidence=data.get('confidence', 0.5),
            tags=data.get('tags', [])
        )
        ioc.first_seen = data.get('first_seen', ioc.first_seen)
        ioc.last_seen = data.get('last_seen', ioc.last_seen)
        ioc.occurrences = data.get('occurrences', 1)
        ioc.related_iocs = set(data.get('related_iocs', []))
        ioc.metadata = data.get('metadata', {})
        return ioc


class IoCCorrelator:
    """
    Correlate IoCs across multiple sources and identify relationships

    Tracks:
    - IP addresses (malicious IPs, C2 servers)
    - Domain names (phishing, malware distribution)
    - File hashes (malware, exploits)
    - Email addresses (phishing, spam)
    - URLs (malicious links)
    """

    def __init__(self):
        self.db_file = Path.home() / "akali" / "intelligence" / "hunting" / "ioc_database.json"
        self.db_file.parent.mkdir(parents=True, exist_ok=True)

        self.iocs: Dict[str, IoC] = {}  # key: "type:value"
        self.relationships: Dict[str, Set[str]] = defaultdict(set)  # IoC -> related IoCs
        self._load_database()

    def _load_database(self):
        """Load IoC database from disk"""
        if self.db_file.exists():
            try:
                with open(self.db_file, 'r') as f:
                    data = json.load(f)

                for ioc_data in data.get('iocs', []):
                    ioc = IoC.from_dict(ioc_data)
                    key = self._make_key(ioc.type, ioc.value)
                    self.iocs[key] = ioc

                for rel_data in data.get('relationships', []):
                    self.relationships[rel_data['from']].update(rel_data['to'])

            except Exception as e:
                print(f"Warning: Failed to load IoC database: {e}")

    def _save_database(self):
        """Save IoC database to disk"""
        data = {
            "iocs": [ioc.to_dict() for ioc in self.iocs.values()],
            "relationships": [
                {"from": key, "to": list(related)}
                for key, related in self.relationships.items()
            ],
            "last_updated": datetime.now().isoformat()
        }

        with open(self.db_file, 'w') as f:
            json.dump(data, f, indent=2)

    def _make_key(self, ioc_type: str, value: str) -> str:
        """Create unique key for IoC"""
        return f"{ioc_type}:{value.lower()}"

    def add_ioc(self, ioc_type: str, value: str, source: str = "unknown",
                confidence: float = 0.5, tags: Optional[List[str]] = None) -> IoC:
        """
        Add or update an IoC

        Args:
            ioc_type: Type of IoC (ip, domain, hash, email, url)
            value: IoC value
            source: Source of the IoC
            confidence: Confidence score (0.0 - 1.0)
            tags: List of tags for categorization

        Returns:
            IoC object
        """
        key = self._make_key(ioc_type, value)

        if key in self.iocs:
            # Update existing IoC
            ioc = self.iocs[key]
            ioc.last_seen = datetime.now().isoformat()
            ioc.occurrences += 1

            # Update confidence (weighted average)
            ioc.confidence = (ioc.confidence * (ioc.occurrences - 1) + confidence) / ioc.occurrences

            # Merge tags
            if tags:
                ioc.tags = list(set(ioc.tags + tags))

        else:
            # Create new IoC
            ioc = IoC(ioc_type, value, source, confidence, tags)
            self.iocs[key] = ioc

        self._save_database()
        return ioc

    def search(self, value: str) -> List[IoC]:
        """
        Search for IoCs by value (partial match)

        Args:
            value: Search query

        Returns:
            List of matching IoCs
        """
        value_lower = value.lower()
        matches = []

        for ioc in self.iocs.values():
            if value_lower in ioc.value.lower():
                matches.append(ioc)

        return sorted(matches, key=lambda x: x.confidence, reverse=True)

    def get_ioc(self, ioc_type: str, value: str) -> Optional[IoC]:
        """Get specific IoC"""
        key = self._make_key(ioc_type, value)
        return self.iocs.get(key)

    def add_relationship(self, ioc1_type: str, ioc1_value: str,
                        ioc2_type: str, ioc2_value: str):
        """
        Add relationship between two IoCs

        Args:
            ioc1_type: Type of first IoC
            ioc1_value: Value of first IoC
            ioc2_type: Type of second IoC
            ioc2_value: Value of second IoC
        """
        key1 = self._make_key(ioc1_type, ioc1_value)
        key2 = self._make_key(ioc2_type, ioc2_value)

        # Bidirectional relationship
        self.relationships[key1].add(key2)
        self.relationships[key2].add(key1)

        # Update IoC objects
        if key1 in self.iocs:
            self.iocs[key1].related_iocs.add(key2)
        if key2 in self.iocs:
            self.iocs[key2].related_iocs.add(key1)

        self._save_database()

    def get_related(self, ioc_type: str, value: str, max_depth: int = 2) -> Dict[str, List[IoC]]:
        """
        Get related IoCs with relationship traversal

        Args:
            ioc_type: Type of IoC
            value: IoC value
            max_depth: Maximum depth to traverse (default: 2)

        Returns:
            Dictionary of depth -> list of related IoCs
        """
        key = self._make_key(ioc_type, value)

        if key not in self.iocs:
            return {}

        visited = {key}
        current_level = {key}
        related_by_depth = {}

        for depth in range(1, max_depth + 1):
            next_level = set()

            for current_key in current_level:
                for related_key in self.relationships.get(current_key, []):
                    if related_key not in visited:
                        next_level.add(related_key)
                        visited.add(related_key)

            if next_level:
                related_by_depth[f"depth_{depth}"] = [
                    self.iocs[k] for k in next_level if k in self.iocs
                ]
                current_level = next_level
            else:
                break

        return related_by_depth

    def correlate_logs(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Correlate log entries with known IoCs

        Args:
            logs: List of log entries to analyze

        Returns:
            List of correlations found
        """
        correlations = []

        for log in logs:
            log_correlations = []

            # Extract potential IoCs from log
            log_str = json.dumps(log)

            # Check for IPs
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            for ip in re.findall(ip_pattern, log_str):
                ioc = self.get_ioc("ip", ip)
                if ioc:
                    log_correlations.append({
                        "ioc_type": "ip",
                        "ioc_value": ip,
                        "confidence": ioc.confidence,
                        "tags": ioc.tags,
                        "source": ioc.source
                    })

            # Check for domains
            domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
            for domain in re.findall(domain_pattern, log_str.lower()):
                ioc = self.get_ioc("domain", domain)
                if ioc:
                    log_correlations.append({
                        "ioc_type": "domain",
                        "ioc_value": domain,
                        "confidence": ioc.confidence,
                        "tags": ioc.tags,
                        "source": ioc.source
                    })

            # Check for hashes (MD5, SHA1, SHA256)
            hash_patterns = {
                "md5": r'\b[a-f0-9]{32}\b',
                "sha1": r'\b[a-f0-9]{40}\b',
                "sha256": r'\b[a-f0-9]{64}\b'
            }

            for hash_type, pattern in hash_patterns.items():
                for hash_val in re.findall(pattern, log_str.lower()):
                    ioc = self.get_ioc("hash", hash_val)
                    if ioc:
                        log_correlations.append({
                            "ioc_type": "hash",
                            "ioc_value": hash_val,
                            "confidence": ioc.confidence,
                            "tags": ioc.tags,
                            "source": ioc.source
                        })

            if log_correlations:
                correlations.append({
                    "log": log,
                    "matches": log_correlations,
                    "match_count": len(log_correlations),
                    "max_confidence": max(c['confidence'] for c in log_correlations),
                    "severity": self._calculate_severity(log_correlations)
                })

        return correlations

    def _calculate_severity(self, matches: List[Dict[str, Any]]) -> str:
        """Calculate severity based on matched IoCs"""
        if not matches:
            return "info"

        max_confidence = max(m['confidence'] for m in matches)
        match_count = len(matches)

        if max_confidence >= 0.9 or match_count >= 5:
            return "critical"
        elif max_confidence >= 0.7 or match_count >= 3:
            return "high"
        elif max_confidence >= 0.5 or match_count >= 2:
            return "medium"
        else:
            return "low"

    def import_from_feed(self, feed_name: str, iocs: List[Dict[str, Any]]):
        """
        Import IoCs from threat feed

        Args:
            feed_name: Name of the feed source
            iocs: List of IoC dictionaries with type, value, confidence, tags
        """
        imported = 0

        for ioc_data in iocs:
            try:
                self.add_ioc(
                    ioc_type=ioc_data['type'],
                    value=ioc_data['value'],
                    source=feed_name,
                    confidence=ioc_data.get('confidence', 0.5),
                    tags=ioc_data.get('tags', [])
                )
                imported += 1
            except Exception as e:
                print(f"Warning: Failed to import IoC {ioc_data.get('value')}: {e}")

        print(f"Imported {imported} IoCs from {feed_name}")

    def get_statistics(self) -> Dict[str, Any]:
        """Get IoC database statistics"""
        by_type = defaultdict(int)
        by_source = defaultdict(int)
        by_confidence = {"high": 0, "medium": 0, "low": 0}

        for ioc in self.iocs.values():
            by_type[ioc.type] += 1
            by_source[ioc.source] += 1

            if ioc.confidence >= 0.7:
                by_confidence["high"] += 1
            elif ioc.confidence >= 0.4:
                by_confidence["medium"] += 1
            else:
                by_confidence["low"] += 1

        return {
            "total_iocs": len(self.iocs),
            "by_type": dict(by_type),
            "by_source": dict(by_source),
            "by_confidence": by_confidence,
            "total_relationships": sum(len(rels) for rels in self.relationships.values()) // 2,
            "last_updated": datetime.now().isoformat()
        }

    def cleanup_old_iocs(self, days: int = 90):
        """Remove IoCs not seen in X days"""
        cutoff = datetime.now() - timedelta(days=days)
        removed = []

        for key, ioc in list(self.iocs.items()):
            last_seen = datetime.fromisoformat(ioc.last_seen)

            if last_seen < cutoff:
                removed.append(key)
                del self.iocs[key]

                # Remove from relationships
                if key in self.relationships:
                    del self.relationships[key]

        self._save_database()
        print(f"Removed {len(removed)} old IoCs")

        return removed


if __name__ == "__main__":
    print("=== IoC Correlator Demo ===\n")

    correlator = IoCCorrelator()

    # Add sample IoCs
    print("Adding sample IoCs...")
    correlator.add_ioc("ip", "192.168.1.100", source="internal_logs", confidence=0.8, tags=["c2", "malware"])
    correlator.add_ioc("domain", "evil.example.com", source="threat_feed", confidence=0.9, tags=["phishing"])
    correlator.add_ioc("hash", "d41d8cd98f00b204e9800998ecf8427e", source="virustotal", confidence=0.95, tags=["malware", "trojan"])
    correlator.add_ioc("ip", "10.0.0.50", source="firewall_logs", confidence=0.6, tags=["suspicious"])

    # Add relationships
    print("Adding relationships...")
    correlator.add_relationship("ip", "192.168.1.100", "domain", "evil.example.com")
    correlator.add_relationship("domain", "evil.example.com", "hash", "d41d8cd98f00b204e9800998ecf8427e")

    # Get statistics
    print("\n=== Statistics ===")
    stats = correlator.get_statistics()
    print(f"Total IoCs: {stats['total_iocs']}")
    print(f"By Type: {stats['by_type']}")
    print(f"By Confidence: {stats['by_confidence']}")
    print(f"Relationships: {stats['total_relationships']}")

    # Search for IoC
    print("\n=== Search for '192.168' ===")
    results = correlator.search("192.168")
    for result in results:
        print(f"  [{result.type}] {result.value} (confidence: {result.confidence:.2f})")

    # Get related IoCs
    print("\n=== Related IoCs for 192.168.1.100 ===")
    related = correlator.get_related("ip", "192.168.1.100", max_depth=2)
    for depth, iocs in related.items():
        print(f"  {depth}:")
        for ioc in iocs:
            print(f"    [{ioc.type}] {ioc.value}")

    # Correlate logs
    print("\n=== Correlating Logs ===")
    sample_logs = [
        {"timestamp": "2026-02-19T10:30:00Z", "message": "Connection from 192.168.1.100 to evil.example.com"},
        {"timestamp": "2026-02-19T10:31:00Z", "message": "File hash: d41d8cd98f00b204e9800998ecf8427e"},
        {"timestamp": "2026-02-19T10:32:00Z", "message": "Normal traffic to google.com"}
    ]

    correlations = correlator.correlate_logs(sample_logs)
    print(f"\nFound {len(correlations)} correlated logs:")
    for corr in correlations:
        print(f"  [{corr['severity'].upper()}] {corr['match_count']} matches")
        for match in corr['matches']:
            print(f"    {match['ioc_type']}: {match['ioc_value']} ({match['confidence']:.2f})")

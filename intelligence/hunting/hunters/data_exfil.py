#!/usr/bin/env python3
"""
Data Exfiltration Hunter - Detect data exfiltration attempts

Identifies patterns indicative of data exfiltration:
- Large outbound data transfers
- Unusual file access patterns (bulk downloads)
- Data uploads to suspicious destinations
- DNS tunneling
- Steganography indicators
"""

from datetime import datetime
from typing import Dict, List, Any
from collections import defaultdict, Counter
import re


class DataExfilHunter:
    """Detect data exfiltration attempts"""

    def __init__(self):
        self.findings: List[Dict[str, Any]] = []
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']  # Free/suspicious TLDs
        self.suspicious_ports = [4444, 5555, 6666, 7777, 8888, 9999]  # Common backdoor ports

    def analyze(self, network_events: List[Dict[str, Any]],
                file_events: List[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Analyze network and file events for exfiltration

        Args:
            network_events: Network connection logs
            file_events: File access logs (optional)

        Returns:
            List of detected exfiltration attempts
        """
        self.findings = []

        # Analyze network patterns
        self._analyze_network_exfil(network_events)

        # Analyze file access patterns
        if file_events:
            self._analyze_file_exfil(file_events)

        # Analyze DNS patterns
        self._analyze_dns_exfil(network_events)

        return self.findings

    def _analyze_network_exfil(self, events: List[Dict[str, Any]]):
        """Analyze network traffic for exfiltration indicators"""

        # Group by source IP
        ip_traffic = defaultdict(lambda: {"bytes_sent": 0, "connections": []})

        for event in events:
            source_ip = event.get('source_ip', 'unknown')
            bytes_sent = event.get('bytes_sent', 0)

            ip_traffic[source_ip]["bytes_sent"] += bytes_sent
            ip_traffic[source_ip]["connections"].append(event)

        # Check for large uploads
        for source_ip, data in ip_traffic.items():
            total_mb = data["bytes_sent"] / (1024 * 1024)

            # Large outbound transfer
            if total_mb > 100:
                # Check destinations
                destinations = [c.get('dest_ip', '') for c in data["connections"]]
                dest_counter = Counter(destinations)

                # Single destination = more suspicious
                if len(dest_counter) == 1:
                    severity = "critical"
                elif len(dest_counter) <= 3:
                    severity = "high"
                else:
                    severity = "medium"

                self.findings.append({
                    "type": "large_data_exfil",
                    "severity": severity,
                    "source_ip": source_ip,
                    "total_mb": round(total_mb, 2),
                    "connection_count": len(data["connections"]),
                    "unique_destinations": len(dest_counter),
                    "top_destinations": dict(dest_counter.most_common(3)),
                    "description": f"Large outbound transfer: {total_mb:.1f} MB from {source_ip}"
                })

            # Check for suspicious ports
            suspicious_conns = [
                c for c in data["connections"]
                if c.get('port') in self.suspicious_ports
            ]

            if len(suspicious_conns) > 5:
                self.findings.append({
                    "type": "suspicious_port_exfil",
                    "severity": "high",
                    "source_ip": source_ip,
                    "connection_count": len(suspicious_conns),
                    "ports": list(set(c.get('port') for c in suspicious_conns)),
                    "description": f"Data transfer to suspicious ports from {source_ip}"
                })

            # Check for transfers to suspicious domains
            suspicious_domains = [
                c for c in data["connections"]
                if any(tld in c.get('dest_domain', '') for tld in self.suspicious_tlds)
            ]

            if suspicious_domains:
                self.findings.append({
                    "type": "suspicious_destination_exfil",
                    "severity": "high",
                    "source_ip": source_ip,
                    "connection_count": len(suspicious_domains),
                    "destinations": list(set(c.get('dest_domain', '') for c in suspicious_domains))[:5],
                    "description": f"Data transfer to suspicious domains from {source_ip}"
                })

    def _analyze_file_exfil(self, events: List[Dict[str, Any]]):
        """Analyze file access patterns for bulk exfiltration"""

        # Group by user
        user_files = defaultdict(list)

        for event in events:
            user = event.get('user', 'unknown')
            user_files[user].append(event)

        for user, files in user_files.items():
            # Bulk file reads
            read_events = [f for f in files if f.get('operation') == 'read']

            if len(read_events) > 100:
                # Check if sensitive files
                sensitive_patterns = ['password', 'secret', 'private', 'key', 'credential', 'token']
                sensitive_files = [
                    f for f in read_events
                    if any(pattern in f.get('file_path', '').lower() for pattern in sensitive_patterns)
                ]

                severity = "critical" if len(sensitive_files) > 10 else "high"

                self.findings.append({
                    "type": "bulk_file_exfil",
                    "severity": severity,
                    "user": user,
                    "files_accessed": len(read_events),
                    "sensitive_files": len(sensitive_files),
                    "sample_files": [f.get('file_path', '') for f in sensitive_files[:5]],
                    "description": f"Bulk file access by {user}: {len(read_events)} files ({len(sensitive_files)} sensitive)"
                })

            # Archive creation before exfil
            archive_patterns = ['.zip', '.tar', '.gz', '.7z', '.rar']
            archive_events = [
                f for f in files
                if any(ext in f.get('file_path', '').lower() for ext in archive_patterns)
                and f.get('operation') == 'write'
            ]

            if len(archive_events) > 5:
                self.findings.append({
                    "type": "suspicious_archive_creation",
                    "severity": "medium",
                    "user": user,
                    "archive_count": len(archive_events),
                    "archives": [f.get('file_path', '') for f in archive_events[:5]],
                    "description": f"Multiple archives created by {user} (potential data staging)"
                })

    def _analyze_dns_exfil(self, events: List[Dict[str, Any]]):
        """Analyze DNS patterns for DNS tunneling exfiltration"""

        # Group DNS queries by source
        dns_queries = defaultdict(list)

        for event in events:
            if event.get('protocol') == 'dns' or event.get('port') == 53:
                source_ip = event.get('source_ip', 'unknown')
                query = event.get('dns_query', '')

                if query:
                    dns_queries[source_ip].append(query)

        for source_ip, queries in dns_queries.items():
            # High query volume
            if len(queries) > 100:
                # Check for suspiciously long queries (DNS tunneling indicator)
                long_queries = [q for q in queries if len(q) > 50]

                if len(long_queries) > 10:
                    self.findings.append({
                        "type": "dns_tunneling_exfil",
                        "severity": "critical",
                        "source_ip": source_ip,
                        "total_queries": len(queries),
                        "suspicious_queries": len(long_queries),
                        "sample_queries": long_queries[:3],
                        "description": f"Possible DNS tunneling from {source_ip}: {len(long_queries)} suspiciously long queries"
                    })

            # Check for encoded data in subdomains (base64-like patterns)
            encoded_queries = [
                q for q in queries
                if self._looks_like_encoded(q)
            ]

            if len(encoded_queries) > 20:
                self.findings.append({
                    "type": "dns_encoded_exfil",
                    "severity": "high",
                    "source_ip": source_ip,
                    "encoded_query_count": len(encoded_queries),
                    "sample_queries": encoded_queries[:3],
                    "description": f"Encoded data in DNS queries from {source_ip}"
                })

    def _looks_like_encoded(self, query: str) -> bool:
        """Check if DNS query looks like it contains encoded data"""

        # Extract subdomain part
        parts = query.split('.')
        if len(parts) < 2:
            return False

        subdomain = parts[0]

        # Base64-like pattern: long, high entropy, alphanumeric with limited special chars
        if len(subdomain) > 20:
            # Count alphanumeric characters
            alnum_count = sum(c.isalnum() for c in subdomain)

            # High ratio of alphanumeric = possible encoding
            if alnum_count / len(subdomain) > 0.9:
                return True

        # Hex-like pattern
        if len(subdomain) > 20 and all(c in '0123456789abcdef' for c in subdomain.lower()):
            return True

        return False


if __name__ == "__main__":
    print("=== Data Exfiltration Hunter Demo ===\n")

    hunter = DataExfilHunter()

    # Simulate large data transfer
    network_events = []

    # Large upload to single destination
    for i in range(10):
        network_events.append({
            "timestamp": f"2026-02-19T10:{30 + i}:00Z",
            "source_ip": "10.0.0.100",
            "dest_ip": "93.184.216.34",
            "port": 443,
            "bytes_sent": 15 * 1024 * 1024,  # 15 MB each = 150 MB total
            "bytes_received": 1024
        })

    # DNS tunneling
    for i in range(50):
        network_events.append({
            "timestamp": f"2026-02-19T11:{i}:00Z",
            "source_ip": "10.0.0.50",
            "dest_ip": "8.8.8.8",
            "port": 53,
            "protocol": "dns",
            "dns_query": f"aBc123DeF456GhI789JkL012MnO345PqR678StU901.evil.example.com"
        })

    # File access
    file_events = []
    for i in range(150):
        file_events.append({
            "timestamp": f"2026-02-19T12:{i % 60}:00Z",
            "user": "alice",
            "file_path": f"/home/documents/file_{i}.pdf",
            "operation": "read"
        })

    findings = hunter.analyze(network_events, file_events)

    print(f"Detected {len(findings)} exfiltration attempts:\n")
    for finding in findings:
        print(f"[{finding['severity'].upper()}] {finding['type']}")
        print(f"  {finding['description']}")
        print()

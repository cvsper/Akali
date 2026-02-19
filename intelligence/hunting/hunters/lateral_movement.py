#!/usr/bin/env python3
"""
Lateral Movement Hunter - Detect lateral movement within network

Identifies patterns indicative of lateral movement:
- Pass-the-hash attacks
- RDP/SSH jumping between hosts
- Service account abuse
- SMB/WMI remote execution
- Unusual internal scanning
"""

from datetime import datetime, timedelta
from typing import Dict, List, Any, Set
from collections import defaultdict, Counter


class LateralMovementHunter:
    """Detect lateral movement attempts"""

    def __init__(self):
        self.findings: List[Dict[str, Any]] = []
        self.suspicious_ports = {
            22: "SSH",
            23: "Telnet",
            135: "RPC",
            139: "NetBIOS",
            445: "SMB",
            3389: "RDP",
            5985: "WinRM",
            5986: "WinRM-HTTPS"
        }

    def analyze(self, network_events: List[Dict[str, Any]],
                auth_events: List[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Analyze network and auth events for lateral movement

        Args:
            network_events: Internal network connections
            auth_events: Authentication events (optional)

        Returns:
            List of detected lateral movement attempts
        """
        self.findings = []

        # Analyze internal network scanning
        self._analyze_internal_scanning(network_events)

        # Analyze remote access patterns
        self._analyze_remote_access(network_events)

        # Analyze authentication patterns
        if auth_events:
            self._analyze_auth_patterns(auth_events)

        # Analyze connection chains
        self._analyze_connection_chains(network_events)

        return self.findings

    def _analyze_internal_scanning(self, events: List[Dict[str, Any]]):
        """Detect internal network scanning (precursor to lateral movement)"""

        # Group by source IP
        source_activity = defaultdict(lambda: {
            "destinations": set(),
            "ports": set(),
            "connections": []
        })

        for event in events:
            source_ip = event.get('source_ip', '')
            dest_ip = event.get('dest_ip', '')
            port = event.get('port', 0)

            source_activity[source_ip]["destinations"].add(dest_ip)
            source_activity[source_ip]["ports"].add(port)
            source_activity[source_ip]["connections"].append(event)

        # Detect port scanning
        for source_ip, data in source_activity.items():
            unique_dests = len(data["destinations"])
            unique_ports = len(data["ports"])

            # Scanning many hosts on same port (horizontal scan)
            if unique_dests > 20 and unique_ports <= 5:
                self.findings.append({
                    "type": "horizontal_port_scan",
                    "severity": "high",
                    "source_ip": source_ip,
                    "destinations_scanned": unique_dests,
                    "ports": list(data["ports"]),
                    "description": f"Horizontal port scanning from {source_ip}: {unique_dests} hosts scanned",
                    "indicator": "recon_before_lateral_movement"
                })

            # Scanning many ports on few hosts (vertical scan)
            if unique_ports > 20 and unique_dests <= 5:
                self.findings.append({
                    "type": "vertical_port_scan",
                    "severity": "medium",
                    "source_ip": source_ip,
                    "ports_scanned": unique_ports,
                    "targets": list(data["destinations"]),
                    "description": f"Vertical port scanning from {source_ip}: {unique_ports} ports scanned"
                })

    def _analyze_remote_access(self, events: List[Dict[str, Any]]):
        """Analyze remote access patterns (RDP, SSH, SMB)"""

        # Group by protocol/port
        remote_access = defaultdict(list)

        for event in events:
            port = event.get('port', 0)

            if port in self.suspicious_ports:
                protocol = self.suspicious_ports[port]
                remote_access[protocol].append(event)

        # Analyze each protocol
        for protocol, conns in remote_access.items():
            # Group by source IP
            source_chains = defaultdict(set)

            for conn in conns:
                source_ip = conn.get('source_ip', '')
                dest_ip = conn.get('dest_ip', '')
                source_chains[source_ip].add(dest_ip)

            # Detect jumping between hosts
            for source_ip, destinations in source_chains.items():
                if len(destinations) > 5:
                    self.findings.append({
                        "type": f"{protocol.lower()}_lateral_movement",
                        "severity": "critical",
                        "protocol": protocol,
                        "source_ip": source_ip,
                        "destinations": list(destinations),
                        "hop_count": len(destinations),
                        "description": f"Lateral movement via {protocol} from {source_ip} to {len(destinations)} hosts",
                        "indicator": "host_hopping"
                    })

    def _analyze_auth_patterns(self, events: List[Dict[str, Any]]):
        """Analyze authentication events for suspicious patterns"""

        # Group by user
        user_activity = defaultdict(lambda: {
            "sources": set(),
            "destinations": set(),
            "events": []
        })

        for event in events:
            user = event.get('user', '')
            source_ip = event.get('source_ip', '')
            dest_host = event.get('dest_host', '')

            user_activity[user]["sources"].add(source_ip)
            user_activity[user]["destinations"].add(dest_host)
            user_activity[user]["events"].append(event)

        for user, data in user_activity.items():
            # Single user accessing many hosts (service account abuse?)
            if len(data["destinations"]) > 10:
                self.findings.append({
                    "type": "multi_host_auth",
                    "severity": "high",
                    "user": user,
                    "source_count": len(data["sources"]),
                    "destination_count": len(data["destinations"]),
                    "description": f"User {user} authenticated to {len(data['destinations'])} hosts",
                    "indicator": "service_account_abuse"
                })

            # Single user from many sources (credential theft?)
            if len(data["sources"]) > 5:
                self.findings.append({
                    "type": "multi_source_auth",
                    "severity": "critical",
                    "user": user,
                    "sources": list(data["sources"]),
                    "description": f"User {user} authenticated from {len(data['sources'])} different sources",
                    "indicator": "stolen_credentials"
                })

            # Rapid authentication across hosts
            sorted_events = sorted(data["events"], key=lambda x: x.get('timestamp', ''))
            rapid_hops = self._detect_rapid_hops(sorted_events)

            if rapid_hops:
                self.findings.append({
                    "type": "rapid_lateral_movement",
                    "severity": "critical",
                    "user": user,
                    "hop_count": len(rapid_hops),
                    "hops": rapid_hops,
                    "description": f"Rapid lateral movement by {user}: {len(rapid_hops)} hops in short time",
                    "indicator": "automated_spreading"
                })

    def _detect_rapid_hops(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect rapid succession of authentication across hosts"""

        rapid_hops = []
        prev_host = None
        prev_time = None

        for event in events:
            current_host = event.get('dest_host', '')
            current_time_str = event.get('timestamp', '')

            if not current_time_str:
                continue

            try:
                current_time = datetime.fromisoformat(current_time_str.replace('Z', '+00:00'))
            except ValueError:
                continue

            # Check if different host within 5 minutes
            if prev_host and prev_time:
                if current_host != prev_host:
                    time_diff = (current_time - prev_time).total_seconds()

                    if time_diff < 300:  # Less than 5 minutes
                        rapid_hops.append({
                            "from_host": prev_host,
                            "to_host": current_host,
                            "time_diff_seconds": int(time_diff)
                        })

            prev_host = current_host
            prev_time = current_time

        return rapid_hops

    def _analyze_connection_chains(self, events: List[Dict[str, Any]]):
        """Analyze connection chains to detect movement paths"""

        # Build connection graph
        graph = defaultdict(set)

        for event in events:
            source = event.get('source_ip', '')
            dest = event.get('dest_ip', '')

            if source and dest:
                graph[source].add(dest)

        # Find hosts with both inbound and outbound connections (pivot points)
        all_sources = set(graph.keys())
        all_dests = set()
        for dests in graph.values():
            all_dests.update(dests)

        pivot_points = all_sources.intersection(all_dests)

        # Analyze pivot points
        for pivot in pivot_points:
            inbound = [src for src, dests in graph.items() if pivot in dests]
            outbound = list(graph[pivot])

            # High-degree pivot (many connections through this host)
            if len(inbound) > 3 and len(outbound) > 3:
                self.findings.append({
                    "type": "pivot_point_detected",
                    "severity": "critical",
                    "pivot_host": pivot,
                    "inbound_connections": len(inbound),
                    "outbound_connections": len(outbound),
                    "description": f"Host {pivot} is pivot point: {len(inbound)} inbound, {len(outbound)} outbound",
                    "indicator": "compromised_pivot"
                })


if __name__ == "__main__":
    print("=== Lateral Movement Hunter Demo ===\n")

    hunter = LateralMovementHunter()

    # Simulate lateral movement
    network_events = []

    # Internal port scanning
    for i in range(30):
        network_events.append({
            "timestamp": f"2026-02-19T10:{i}:00Z",
            "source_ip": "10.0.0.100",
            "dest_ip": f"10.0.0.{i + 1}",
            "port": 445,  # SMB
            "protocol": "tcp"
        })

    # RDP hopping
    rdp_chain = ["10.0.0.100", "10.0.0.50", "10.0.0.75", "10.0.0.25", "10.0.0.10", "10.0.0.5"]
    for i in range(len(rdp_chain) - 1):
        network_events.append({
            "timestamp": f"2026-02-19T11:{i * 2}:00Z",
            "source_ip": rdp_chain[i],
            "dest_ip": rdp_chain[i + 1],
            "port": 3389,  # RDP
            "protocol": "tcp"
        })

    # Authentication events
    auth_events = []
    for i in range(len(rdp_chain) - 1):
        auth_events.append({
            "timestamp": f"2026-02-19T11:{i * 2}:00Z",
            "user": "admin",
            "source_ip": rdp_chain[i],
            "dest_host": rdp_chain[i + 1],
            "success": True
        })

    findings = hunter.analyze(network_events, auth_events)

    print(f"Detected {len(findings)} lateral movement indicators:\n")
    for finding in findings:
        print(f"[{finding['severity'].upper()}] {finding['type']}")
        print(f"  {finding['description']}")
        print(f"  Indicator: {finding.get('indicator', 'N/A')}")
        print()

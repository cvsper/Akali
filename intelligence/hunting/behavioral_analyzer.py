#!/usr/bin/env python3
"""
Behavioral Analyzer - Detect anomalous behavior through statistical analysis

Establishes baselines of normal behavior and identifies deviations.
Uses statistical methods to detect anomalies without requiring labeled training data.
"""

import json
import os
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict, Counter
from pathlib import Path


class BehaviorBaseline:
    """Represents baseline behavior for a specific metric"""

    def __init__(self, metric_name: str):
        self.metric_name = metric_name
        self.samples: List[float] = []
        self.mean: Optional[float] = None
        self.stddev: Optional[float] = None
        self.min_val: Optional[float] = None
        self.max_val: Optional[float] = None
        self.percentile_95: Optional[float] = None
        self.last_updated: Optional[str] = None

    def add_sample(self, value: float):
        """Add a sample to the baseline"""
        self.samples.append(value)

    def calculate_statistics(self):
        """Calculate statistical measures from samples"""
        if not self.samples:
            return

        self.mean = statistics.mean(self.samples)
        self.min_val = min(self.samples)
        self.max_val = max(self.samples)

        if len(self.samples) >= 2:
            self.stddev = statistics.stdev(self.samples)

        # Calculate 95th percentile
        sorted_samples = sorted(self.samples)
        idx = int(len(sorted_samples) * 0.95)
        self.percentile_95 = sorted_samples[idx] if idx < len(sorted_samples) else sorted_samples[-1]

        self.last_updated = datetime.now().isoformat()

    def is_anomalous(self, value: float, sensitivity: float = 3.0) -> Tuple[bool, str]:
        """
        Check if a value is anomalous using standard deviation

        Args:
            value: Value to check
            sensitivity: Number of standard deviations (default: 3σ)

        Returns:
            (is_anomalous, reason)
        """
        if self.mean is None or self.stddev is None:
            return False, "Insufficient baseline data"

        # Z-score calculation
        z_score = abs((value - self.mean) / self.stddev) if self.stddev > 0 else 0

        if z_score > sensitivity:
            direction = "above" if value > self.mean else "below"
            return True, f"{z_score:.2f}σ {direction} mean ({self.mean:.2f})"

        return False, "Within normal range"

    def to_dict(self) -> Dict[str, Any]:
        """Serialize baseline to dictionary"""
        return {
            "metric_name": self.metric_name,
            "sample_count": len(self.samples),
            "mean": self.mean,
            "stddev": self.stddev,
            "min": self.min_val,
            "max": self.max_val,
            "percentile_95": self.percentile_95,
            "last_updated": self.last_updated
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BehaviorBaseline':
        """Deserialize baseline from dictionary"""
        baseline = cls(data['metric_name'])
        baseline.mean = data.get('mean')
        baseline.stddev = data.get('stddev')
        baseline.min_val = data.get('min')
        baseline.max_val = data.get('max')
        baseline.percentile_95 = data.get('percentile_95')
        baseline.last_updated = data.get('last_updated')
        return baseline


class BehavioralAnalyzer:
    """
    Analyze behavior patterns and detect anomalies

    Tracks:
    - Login patterns (time, frequency, failed attempts)
    - Network activity (connections, data volume)
    - API usage (rate, endpoints, errors)
    - File access (reads, writes, deletes)
    - User actions (commands, operations)
    """

    def __init__(self):
        self.baselines_file = Path.home() / "akali" / "intelligence" / "hunting" / "baselines.json"
        self.baselines_file.parent.mkdir(parents=True, exist_ok=True)

        self.baselines: Dict[str, BehaviorBaseline] = {}
        self.anomalies: List[Dict[str, Any]] = []
        self._load_baselines()

    def _load_baselines(self):
        """Load existing baselines from disk"""
        if self.baselines_file.exists():
            try:
                with open(self.baselines_file, 'r') as f:
                    data = json.load(f)

                for metric_name, baseline_data in data.items():
                    self.baselines[metric_name] = BehaviorBaseline.from_dict(baseline_data)

            except Exception as e:
                print(f"Warning: Failed to load baselines: {e}")

    def _save_baselines(self):
        """Save baselines to disk"""
        data = {name: baseline.to_dict() for name, baseline in self.baselines.items()}

        with open(self.baselines_file, 'w') as f:
            json.dump(data, f, indent=2)

    def create_baseline(self, metric_name: str, samples: List[float]) -> BehaviorBaseline:
        """
        Create a new behavioral baseline

        Args:
            metric_name: Name of the metric (e.g., "login_frequency_hourly")
            samples: Historical samples to establish baseline

        Returns:
            BehaviorBaseline object
        """
        baseline = BehaviorBaseline(metric_name)

        for sample in samples:
            baseline.add_sample(sample)

        baseline.calculate_statistics()
        self.baselines[metric_name] = baseline
        self._save_baselines()

        return baseline

    def analyze_login_pattern(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze login events for anomalies

        Expected event format:
        {
            "timestamp": "2026-02-19T10:30:00Z",
            "user": "alice@example.com",
            "ip": "192.168.1.100",
            "success": true,
            "user_agent": "Mozilla/5.0...",
            "location": "US"
        }
        """
        anomalies = []

        # Group by user
        user_events = defaultdict(list)
        for event in events:
            user_events[event['user']].append(event)

        for user, user_logins in user_events.items():
            # Analyze failed login attempts
            failed_attempts = [e for e in user_logins if not e.get('success', True)]
            failed_count = len(failed_attempts)

            if failed_count >= 5:
                anomalies.append({
                    "type": "excessive_failed_logins",
                    "severity": "high" if failed_count >= 10 else "medium",
                    "user": user,
                    "count": failed_count,
                    "description": f"User {user} has {failed_count} failed login attempts",
                    "events": failed_attempts[-5:]  # Last 5 attempts
                })

            # Analyze login times (detect odd-hours logins)
            for event in user_logins:
                if event.get('success'):
                    timestamp = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
                    hour = timestamp.hour

                    # Flag logins between 1 AM - 5 AM
                    if 1 <= hour <= 5:
                        anomalies.append({
                            "type": "odd_hours_login",
                            "severity": "low",
                            "user": user,
                            "timestamp": event['timestamp'],
                            "hour": hour,
                            "description": f"Login at unusual hour: {hour}:00"
                        })

            # Analyze location changes
            locations = [e.get('location') for e in user_logins if e.get('success') and e.get('location')]
            if len(set(locations)) > 1:
                # Check for rapid location changes
                sorted_events = sorted(user_logins, key=lambda x: x['timestamp'])
                for i in range(len(sorted_events) - 1):
                    if (sorted_events[i].get('location') != sorted_events[i+1].get('location') and
                        sorted_events[i].get('success') and sorted_events[i+1].get('success')):

                        time1 = datetime.fromisoformat(sorted_events[i]['timestamp'].replace('Z', '+00:00'))
                        time2 = datetime.fromisoformat(sorted_events[i+1]['timestamp'].replace('Z', '+00:00'))
                        time_diff = (time2 - time1).total_seconds() / 3600  # hours

                        if time_diff < 1:  # Less than 1 hour apart
                            anomalies.append({
                                "type": "impossible_travel",
                                "severity": "critical",
                                "user": user,
                                "location1": sorted_events[i]['location'],
                                "location2": sorted_events[i+1]['location'],
                                "time_diff_hours": round(time_diff, 2),
                                "description": f"User logged in from {sorted_events[i]['location']} and {sorted_events[i+1]['location']} {time_diff:.1f} hours apart"
                            })

        self.anomalies.extend(anomalies)
        return anomalies

    def analyze_network_traffic(self, connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze network connections for anomalies

        Expected connection format:
        {
            "timestamp": "2026-02-19T10:30:00Z",
            "source_ip": "10.0.0.100",
            "dest_ip": "93.184.216.34",
            "port": 443,
            "protocol": "tcp",
            "bytes_sent": 1024,
            "bytes_received": 4096
        }
        """
        anomalies = []

        # Group by source IP
        ip_connections = defaultdict(list)
        for conn in connections:
            ip_connections[conn['source_ip']].append(conn)

        for source_ip, conns in ip_connections.items():
            # Analyze connection volume
            conn_count = len(conns)
            total_bytes = sum(c.get('bytes_sent', 0) + c.get('bytes_received', 0) for c in conns)

            # Check baseline for connection count
            metric_name = f"connections_per_hour_{source_ip}"
            if metric_name in self.baselines:
                is_anomalous, reason = self.baselines[metric_name].is_anomalous(conn_count)
                if is_anomalous:
                    anomalies.append({
                        "type": "abnormal_connection_volume",
                        "severity": "medium",
                        "source_ip": source_ip,
                        "connection_count": conn_count,
                        "description": f"Abnormal connection volume: {reason}"
                    })

            # Check for data exfiltration (large outbound transfers)
            if total_bytes > 100 * 1024 * 1024:  # > 100 MB
                anomalies.append({
                    "type": "large_data_transfer",
                    "severity": "high",
                    "source_ip": source_ip,
                    "total_bytes": total_bytes,
                    "total_mb": round(total_bytes / (1024 * 1024), 2),
                    "description": f"Large data transfer detected: {total_bytes / (1024 * 1024):.2f} MB"
                })

            # Check for unusual ports
            uncommon_ports = [c for c in conns if c.get('port', 0) not in [80, 443, 22, 3306, 5432, 6379, 27017]]
            if len(uncommon_ports) > 10:
                port_counts = Counter(c['port'] for c in uncommon_ports)
                anomalies.append({
                    "type": "unusual_port_activity",
                    "severity": "medium",
                    "source_ip": source_ip,
                    "uncommon_port_count": len(uncommon_ports),
                    "top_ports": dict(port_counts.most_common(5)),
                    "description": f"Connections to {len(uncommon_ports)} uncommon ports"
                })

        self.anomalies.extend(anomalies)
        return anomalies

    def analyze_api_usage(self, requests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze API requests for anomalies

        Expected request format:
        {
            "timestamp": "2026-02-19T10:30:00Z",
            "user": "alice@example.com",
            "endpoint": "/api/users",
            "method": "GET",
            "status_code": 200,
            "response_time_ms": 150
        }
        """
        anomalies = []

        # Group by user
        user_requests = defaultdict(list)
        for req in requests:
            user_requests[req['user']].append(req)

        for user, reqs in user_requests.items():
            # Analyze request rate
            request_count = len(reqs)

            metric_name = f"api_requests_per_hour_{user}"
            if metric_name in self.baselines:
                is_anomalous, reason = self.baselines[metric_name].is_anomalous(request_count)
                if is_anomalous:
                    anomalies.append({
                        "type": "abnormal_api_rate",
                        "severity": "medium",
                        "user": user,
                        "request_count": request_count,
                        "description": f"Abnormal API request rate: {reason}"
                    })

            # Analyze error rate
            error_requests = [r for r in reqs if r.get('status_code', 200) >= 400]
            error_rate = len(error_requests) / len(reqs) if reqs else 0

            if error_rate > 0.2:  # > 20% error rate
                anomalies.append({
                    "type": "high_api_error_rate",
                    "severity": "high",
                    "user": user,
                    "error_count": len(error_requests),
                    "total_requests": len(reqs),
                    "error_rate": round(error_rate * 100, 2),
                    "description": f"High API error rate: {error_rate * 100:.1f}%"
                })

            # Detect potential scraping (sequential resource access)
            endpoints = [r['endpoint'] for r in reqs]
            if len(set(endpoints)) > 50 and request_count > 100:
                anomalies.append({
                    "type": "potential_scraping",
                    "severity": "medium",
                    "user": user,
                    "unique_endpoints": len(set(endpoints)),
                    "total_requests": request_count,
                    "description": f"Potential scraping activity: {request_count} requests to {len(set(endpoints))} endpoints"
                })

        self.anomalies.extend(anomalies)
        return anomalies

    def analyze_file_access(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze file access patterns for anomalies

        Expected event format:
        {
            "timestamp": "2026-02-19T10:30:00Z",
            "user": "alice",
            "file_path": "/home/alice/document.pdf",
            "operation": "read",
            "success": true
        }
        """
        anomalies = []

        # Group by user
        user_events = defaultdict(list)
        for event in events:
            user_events[event['user']].append(event)

        for user, user_files in user_events.items():
            # Analyze bulk file operations
            file_count = len(user_files)

            if file_count > 100:
                anomalies.append({
                    "type": "bulk_file_access",
                    "severity": "medium",
                    "user": user,
                    "file_count": file_count,
                    "description": f"Bulk file access: {file_count} files accessed"
                })

            # Analyze sensitive file access
            sensitive_patterns = ['/etc/', '.ssh/', '.aws/', 'password', 'secret', 'private_key']
            sensitive_files = [
                e for e in user_files
                if any(pattern in e['file_path'].lower() for pattern in sensitive_patterns)
            ]

            if len(sensitive_files) > 5:
                anomalies.append({
                    "type": "sensitive_file_access",
                    "severity": "high",
                    "user": user,
                    "sensitive_file_count": len(sensitive_files),
                    "sample_files": [e['file_path'] for e in sensitive_files[:5]],
                    "description": f"Multiple sensitive file accesses: {len(sensitive_files)} files"
                })

        self.anomalies.extend(anomalies)
        return anomalies

    def get_anomalies(self, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get detected anomalies, optionally filtered by severity"""
        if severity:
            return [a for a in self.anomalies if a.get('severity') == severity]
        return self.anomalies

    def clear_anomalies(self):
        """Clear all detected anomalies"""
        self.anomalies = []

    def export_baselines(self, output_file: str):
        """Export baselines to a file"""
        data = {name: baseline.to_dict() for name, baseline in self.baselines.items()}

        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"Exported {len(self.baselines)} baselines to {output_file}")


if __name__ == "__main__":
    # Demo usage
    analyzer = BehavioralAnalyzer()

    # Create sample baseline for API requests
    samples = [50, 55, 48, 52, 49, 51, 53, 50, 52, 48]  # Normal: ~50 requests/hour
    analyzer.create_baseline("api_requests_per_hour_alice@example.com", samples)

    # Test with sample data
    login_events = [
        {"timestamp": "2026-02-19T03:30:00Z", "user": "alice@example.com", "ip": "192.168.1.100", "success": True, "location": "US"},
        {"timestamp": "2026-02-19T10:30:00Z", "user": "bob@example.com", "ip": "10.0.0.50", "success": False},
        {"timestamp": "2026-02-19T10:31:00Z", "user": "bob@example.com", "ip": "10.0.0.50", "success": False},
        {"timestamp": "2026-02-19T10:32:00Z", "user": "bob@example.com", "ip": "10.0.0.50", "success": False},
        {"timestamp": "2026-02-19T10:33:00Z", "user": "bob@example.com", "ip": "10.0.0.50", "success": False},
        {"timestamp": "2026-02-19T10:34:00Z", "user": "bob@example.com", "ip": "10.0.0.50", "success": False},
    ]

    print("\n=== Analyzing Login Patterns ===")
    login_anomalies = analyzer.analyze_login_pattern(login_events)
    for anomaly in login_anomalies:
        print(f"[{anomaly['severity'].upper()}] {anomaly['type']}: {anomaly['description']}")

    print(f"\nTotal anomalies detected: {len(analyzer.get_anomalies())}")

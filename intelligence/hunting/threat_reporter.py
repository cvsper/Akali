#!/usr/bin/env python3
"""
Threat Reporter - Generate comprehensive threat hunting reports

Generates reports in multiple formats:
- Markdown (human-readable)
- JSON (machine-parseable)
- HTML (web-viewable)
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path


class ThreatReporter:
    """Generate threat hunting reports"""

    def __init__(self):
        self.reports_dir = Path.home() / "akali" / "intelligence" / "hunting" / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(self, title: str, findings: List[Dict[str, Any]],
                       metadata: Optional[Dict[str, Any]] = None,
                       format: str = "markdown") -> str:
        """
        Generate threat hunting report

        Args:
            title: Report title
            findings: List of threat findings
            metadata: Optional metadata (scan details, timeframe, etc.)
            format: Output format (markdown, json, html)

        Returns:
            Path to generated report
        """
        report_data = {
            "title": title,
            "generated_at": datetime.now().isoformat(),
            "metadata": metadata or {},
            "findings": findings,
            "statistics": self._calculate_statistics(findings)
        }

        if format == "json":
            return self._generate_json_report(report_data)
        elif format == "html":
            return self._generate_html_report(report_data)
        else:
            return self._generate_markdown_report(report_data)

    def _calculate_statistics(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate statistics from findings"""

        if not findings:
            return {
                "total_findings": 0,
                "by_severity": {},
                "by_type": {},
                "critical_count": 0,
                "high_count": 0
            }

        from collections import Counter

        severity_counts = Counter(f.get('severity', 'unknown') for f in findings)
        type_counts = Counter(f.get('type', 'unknown') for f in findings)

        return {
            "total_findings": len(findings),
            "by_severity": dict(severity_counts),
            "by_type": dict(type_counts),
            "critical_count": severity_counts.get('critical', 0),
            "high_count": severity_counts.get('high', 0),
            "medium_count": severity_counts.get('medium', 0),
            "low_count": severity_counts.get('low', 0)
        }

    def _generate_markdown_report(self, data: Dict[str, Any]) -> str:
        """Generate Markdown report"""

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"threat_report_{timestamp}.md"
        filepath = self.reports_dir / filename

        stats = data['statistics']

        # Build markdown content
        lines = [
            f"# {data['title']}",
            "",
            f"**Generated:** {data['generated_at']}",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
            f"- **Total Threats Detected:** {stats['total_findings']}",
            f"- **Critical:** {stats['critical_count']}",
            f"- **High:** {stats['high_count']}",
            f"- **Medium:** {stats['medium_count']}",
            f"- **Low:** {stats['low_count']}",
            "",
        ]

        # Metadata
        if data['metadata']:
            lines.extend([
                "## Scan Details",
                "",
            ])

            for key, value in data['metadata'].items():
                lines.append(f"- **{key.replace('_', ' ').title()}:** {value}")

            lines.append("")

        # Severity breakdown
        lines.extend([
            "## Findings by Severity",
            "",
        ])

        for severity, count in sorted(stats['by_severity'].items(),
                                     key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}.get(x[0], 4)):
            lines.append(f"- **{severity.upper()}:** {count}")

        lines.append("")

        # Type breakdown
        lines.extend([
            "## Findings by Type",
            "",
        ])

        for threat_type, count in sorted(stats['by_type'].items(), key=lambda x: x[1], reverse=True):
            lines.append(f"- **{threat_type}:** {count}")

        lines.append("")

        # Detailed findings
        lines.extend([
            "---",
            "",
            "## Detailed Findings",
            "",
        ])

        # Group by severity
        by_severity = {}
        for finding in data['findings']:
            severity = finding.get('severity', 'unknown')
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(finding)

        # Output in severity order
        for severity in ['critical', 'high', 'medium', 'low', 'unknown']:
            if severity not in by_severity:
                continue

            lines.extend([
                f"### {severity.upper()} Severity",
                "",
            ])

            for idx, finding in enumerate(by_severity[severity], 1):
                lines.extend([
                    f"#### {idx}. {finding.get('type', 'Unknown').replace('_', ' ').title()}",
                    "",
                    f"**Description:** {finding.get('description', 'No description')}",
                    "",
                ])

                # Add finding-specific details
                details_to_show = ['source_ip', 'user', 'target', 'count', 'file_count',
                                  'connection_count', 'destinations', 'total_mb']

                for key in details_to_show:
                    if key in finding:
                        value = finding[key]
                        if isinstance(value, list) and len(value) > 10:
                            value = f"{len(value)} items (showing first 5: {value[:5]})"
                        lines.append(f"- **{key.replace('_', ' ').title()}:** {value}")

                # Indicators
                if 'indicators' in finding:
                    lines.append(f"- **Indicators:** {finding['indicators']}")

                lines.append("")

        # Recommendations
        lines.extend([
            "---",
            "",
            "## Recommendations",
            "",
        ])

        recommendations = self._generate_recommendations(data['findings'], stats)
        for rec in recommendations:
            lines.append(f"- {rec}")

        lines.extend([
            "",
            "---",
            "",
            f"*Report generated by Akali Threat Hunting System*",
            f"*{data['generated_at']}*"
        ])

        # Write file
        with open(filepath, 'w') as f:
            f.write('\n'.join(lines))

        print(f"Markdown report generated: {filepath}")
        return str(filepath)

    def _generate_json_report(self, data: Dict[str, Any]) -> str:
        """Generate JSON report"""

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"threat_report_{timestamp}.json"
        filepath = self.reports_dir / filename

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"JSON report generated: {filepath}")
        return str(filepath)

    def _generate_html_report(self, data: Dict[str, Any]) -> str:
        """Generate HTML report"""

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"threat_report_{timestamp}.html"
        filepath = self.reports_dir / filename

        stats = data['statistics']

        # Build HTML
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>{data['title']}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .header {{
            background: #1a1a1a;
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 20px;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }}
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .stat-value {{
            font-size: 32px;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        .stat-label {{
            color: #666;
            font-size: 14px;
        }}
        .critical {{ color: #d32f2f; }}
        .high {{ color: #f57c00; }}
        .medium {{ color: #fbc02d; }}
        .low {{ color: #388e3c; }}
        .finding {{
            background: white;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-left: 4px solid;
        }}
        .finding.critical {{ border-left-color: #d32f2f; }}
        .finding.high {{ border-left-color: #f57c00; }}
        .finding.medium {{ border-left-color: #fbc02d; }}
        .finding.low {{ border-left-color: #388e3c; }}
        .finding-header {{
            font-size: 18px;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        .finding-description {{
            color: #555;
            margin-bottom: 10px;
        }}
        .finding-details {{
            font-size: 14px;
            color: #777;
        }}
        .severity-badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
            color: white;
        }}
        .severity-badge.critical {{ background: #d32f2f; }}
        .severity-badge.high {{ background: #f57c00; }}
        .severity-badge.medium {{ background: #fbc02d; color: #333; }}
        .severity-badge.low {{ background: #388e3c; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{data['title']}</h1>
        <p>Generated: {data['generated_at']}</p>
    </div>

    <div class="stats">
        <div class="stat-card">
            <div class="stat-value">{stats['total_findings']}</div>
            <div class="stat-label">Total Threats</div>
        </div>
        <div class="stat-card">
            <div class="stat-value critical">{stats['critical_count']}</div>
            <div class="stat-label">Critical</div>
        </div>
        <div class="stat-card">
            <div class="stat-value high">{stats['high_count']}</div>
            <div class="stat-label">High</div>
        </div>
        <div class="stat-card">
            <div class="stat-value medium">{stats['medium_count']}</div>
            <div class="stat-label">Medium</div>
        </div>
        <div class="stat-card">
            <div class="stat-value low">{stats['low_count']}</div>
            <div class="stat-label">Low</div>
        </div>
    </div>

    <h2>Detailed Findings</h2>
"""

        # Add findings
        for finding in data['findings']:
            severity = finding.get('severity', 'unknown')
            html += f"""
    <div class="finding {severity}">
        <div class="finding-header">
            <span class="severity-badge {severity}">{severity.upper()}</span>
            {finding.get('type', 'Unknown').replace('_', ' ').title()}
        </div>
        <div class="finding-description">
            {finding.get('description', 'No description')}
        </div>
        <div class="finding-details">
"""

            # Add finding details
            for key, value in finding.items():
                if key not in ['type', 'severity', 'description']:
                    if isinstance(value, list) and len(value) > 10:
                        value = f"{len(value)} items"
                    html += f"            <strong>{key.replace('_', ' ').title()}:</strong> {value}<br>\n"

            html += """        </div>
    </div>
"""

        html += """
</body>
</html>
"""

        # Write file
        with open(filepath, 'w') as f:
            f.write(html)

        print(f"HTML report generated: {filepath}")
        return str(filepath)

    def _generate_recommendations(self, findings: List[Dict[str, Any]],
                                 stats: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on findings"""

        recommendations = []

        # Based on severity
        if stats['critical_count'] > 0:
            recommendations.append(
                f"**URGENT:** Address {stats['critical_count']} critical findings immediately. "
                "These represent active or imminent threats."
            )

        if stats['high_count'] > 5:
            recommendations.append(
                f"High priority: {stats['high_count']} high-severity findings detected. "
                "Review and remediate within 24 hours."
            )

        # Based on finding types
        finding_types = set(f.get('type', '') for f in findings)

        if 'credential_stuffing' in finding_types:
            recommendations.append(
                "Implement rate limiting and account lockout policies to prevent credential stuffing attacks."
            )

        if 'large_data_exfil' in finding_types or 'dns_tunneling_exfil' in finding_types:
            recommendations.append(
                "Review data loss prevention policies and monitor outbound traffic more closely."
            )

        if 'lateral_movement' in finding_types or 'pivot_point_detected' in finding_types:
            recommendations.append(
                "Implement network segmentation and restrict lateral movement capabilities. "
                "Review service account permissions."
            )

        if 'impossible_travel' in finding_types:
            recommendations.append(
                "Implement multi-factor authentication and location-based access controls."
            )

        # Generic recommendations
        recommendations.extend([
            "Review all findings and update incident response procedures as needed.",
            "Document false positives to improve future threat hunting accuracy.",
            "Consider integrating findings with SIEM for automated alerting."
        ])

        return recommendations


if __name__ == "__main__":
    print("=== Threat Reporter Demo ===\n")

    reporter = ThreatReporter()

    # Sample findings
    findings = [
        {
            "type": "credential_stuffing",
            "severity": "critical",
            "source_ip": "203.0.113.10",
            "failed_attempts": 150,
            "unique_users_targeted": 45,
            "description": "Credential stuffing attack detected from 203.0.113.10"
        },
        {
            "type": "large_data_exfil",
            "severity": "high",
            "source_ip": "10.0.0.100",
            "total_mb": 250.5,
            "description": "Large data transfer detected: 250.5 MB uploaded"
        },
        {
            "type": "lateral_movement",
            "severity": "critical",
            "user": "admin",
            "hop_count": 7,
            "description": "Lateral movement detected: admin account accessed 7 hosts"
        }
    ]

    metadata = {
        "scan_start": "2026-02-19T10:00:00Z",
        "scan_end": "2026-02-19T12:00:00Z",
        "events_analyzed": 50000,
        "sources": ["firewall_logs", "auth_logs", "network_flow"]
    }

    # Generate reports in all formats
    print("Generating Markdown report...")
    md_path = reporter.generate_report("Threat Hunting Report", findings, metadata, format="markdown")

    print("\nGenerating JSON report...")
    json_path = reporter.generate_report("Threat Hunting Report", findings, metadata, format="json")

    print("\nGenerating HTML report...")
    html_path = reporter.generate_report("Threat Hunting Report", findings, metadata, format="html")

    print("\nAll reports generated successfully!")

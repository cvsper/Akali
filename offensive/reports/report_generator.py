"""Report generator for offensive security scan results."""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
import sys

sys.path.append(str(Path(__file__).parent.parent.parent))
from defensive.scanners.scanner_base import Finding


class ReportGenerator:
    """Generate security scan reports in various formats."""

    def __init__(self, report_dir: str = None):
        if report_dir:
            self.report_dir = Path(report_dir)
        else:
            self.report_dir = Path.home() / "akali" / "offensive" / "reports" / "scan_reports"

        self.report_dir.mkdir(parents=True, exist_ok=True)

    def generate_html(self, findings: List[Finding], target: str, scan_type: str) -> str:
        """Generate HTML report.

        Args:
            findings: List of findings
            target: Scan target
            scan_type: Type of scan performed

        Returns:
            Path to generated HTML report
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"akali_report_{timestamp}.html"
        filepath = self.report_dir / filename

        # Organize findings by severity
        by_severity = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": []
        }

        for finding in findings:
            severity = finding.severity.lower()
            if severity in by_severity:
                by_severity[severity].append(finding)

        # Generate HTML
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Akali Security Report - {target}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 8px 8px 0 0;
        }}
        .header h1 {{
            margin-bottom: 10px;
            font-size: 32px;
        }}
        .header .meta {{
            opacity: 0.9;
            font-size: 14px;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px 40px;
            border-bottom: 1px solid #e0e0e0;
        }}
        .summary-card {{
            text-align: center;
            padding: 20px;
            border-radius: 8px;
            background: #f8f9fa;
        }}
        .summary-card .number {{
            font-size: 36px;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        .summary-card .label {{
            font-size: 12px;
            text-transform: uppercase;
            color: #666;
            letter-spacing: 0.5px;
        }}
        .critical {{ color: #d32f2f; background: #ffebee; }}
        .high {{ color: #f57c00; background: #fff3e0; }}
        .medium {{ color: #fbc02d; background: #fffde7; }}
        .low {{ color: #1976d2; background: #e3f2fd; }}
        .info {{ color: #616161; background: #f5f5f5; }}
        .content {{
            padding: 40px;
        }}
        .severity-section {{
            margin-bottom: 40px;
        }}
        .severity-section h2 {{
            font-size: 24px;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e0e0e0;
        }}
        .finding {{
            background: #f8f9fa;
            border-left: 4px solid #ccc;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 4px;
        }}
        .finding.critical {{ border-left-color: #d32f2f; }}
        .finding.high {{ border-left-color: #f57c00; }}
        .finding.medium {{ border-left-color: #fbc02d; }}
        .finding.low {{ border-left-color: #1976d2; }}
        .finding.info {{ border-left-color: #616161; }}
        .finding h3 {{
            font-size: 18px;
            margin-bottom: 10px;
            color: #333;
        }}
        .finding .meta {{
            font-size: 12px;
            color: #666;
            margin-bottom: 15px;
        }}
        .finding .meta span {{
            display: inline-block;
            margin-right: 15px;
        }}
        .finding .description {{
            margin-bottom: 15px;
            color: #555;
        }}
        .finding .fix {{
            background: #fff;
            padding: 15px;
            border-radius: 4px;
            border-left: 3px solid #4caf50;
            margin-top: 15px;
        }}
        .finding .fix strong {{
            color: #4caf50;
            display: block;
            margin-bottom: 5px;
        }}
        .footer {{
            text-align: center;
            padding: 30px;
            color: #666;
            font-size: 14px;
            border-top: 1px solid #e0e0e0;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
            text-transform: uppercase;
            margin-right: 5px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🥷 Akali Security Report</h1>
            <div class="meta">
                <div><strong>Target:</strong> {target}</div>
                <div><strong>Scan Type:</strong> {scan_type}</div>
                <div><strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>
            </div>
        </div>

        <div class="summary">
            <div class="summary-card critical">
                <div class="number">{len(by_severity['critical'])}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card high">
                <div class="number">{len(by_severity['high'])}</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card medium">
                <div class="number">{len(by_severity['medium'])}</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card low">
                <div class="number">{len(by_severity['low'])}</div>
                <div class="label">Low</div>
            </div>
            <div class="summary-card info">
                <div class="number">{len(by_severity['info'])}</div>
                <div class="label">Info</div>
            </div>
        </div>

        <div class="content">
"""

        # Generate findings sections
        for severity in ["critical", "high", "medium", "low", "info"]:
            findings_list = by_severity[severity]
            if not findings_list:
                continue

            html += f"""
            <div class="severity-section">
                <h2 class="{severity}">{severity.upper()} Severity ({len(findings_list)})</h2>
"""

            for finding in findings_list:
                finding_dict = finding.to_dict()

                html += f"""
                <div class="finding {severity}">
                    <h3>{finding_dict['title']}</h3>
                    <div class="meta">
                        <span><strong>ID:</strong> {finding_dict['id']}</span>
                        <span><strong>Type:</strong> {finding_dict['type']}</span>
"""

                if finding_dict.get('cvss'):
                    html += f"""                        <span><strong>CVSS:</strong> {finding_dict['cvss']}</span>
"""
                if finding_dict.get('cwe'):
                    html += f"""                        <span><strong>CWE:</strong> {finding_dict['cwe']}</span>
"""
                if finding_dict.get('owasp'):
                    html += f"""                        <span><strong>OWASP:</strong> {finding_dict['owasp']}</span>
"""
                if finding_dict.get('file'):
                    location = finding_dict['file']
                    if finding_dict.get('line'):
                        location += f":{finding_dict['line']}"
                    html += f"""                        <span><strong>Location:</strong> {location}</span>
"""

                html += """                    </div>
"""

                html += f"""                    <div class="description">{finding_dict['description']}</div>
"""

                if finding_dict.get('fix'):
                    html += f"""                    <div class="fix">
                        <strong>🔧 Recommended Fix:</strong>
                        {finding_dict['fix']}
                    </div>
"""

                html += """                </div>
"""

            html += """            </div>
"""

        html += f"""
        </div>

        <div class="footer">
            Generated by <strong>Akali - The Security Sentinel</strong><br>
            Total Findings: {len(findings)} | Scan Type: {scan_type}
        </div>
    </div>
</body>
</html>
"""

        # Write to file
        with open(filepath, 'w') as f:
            f.write(html)

        return str(filepath)

    def generate_markdown(self, findings: List[Finding], target: str, scan_type: str) -> str:
        """Generate Markdown report.

        Args:
            findings: List of findings
            target: Scan target
            scan_type: Type of scan performed

        Returns:
            Path to generated Markdown report
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"akali_report_{timestamp}.md"
        filepath = self.report_dir / filename

        # Organize findings by severity
        by_severity = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": []
        }

        for finding in findings:
            severity = finding.severity.lower()
            if severity in by_severity:
                by_severity[severity].append(finding)

        # Generate Markdown
        md = f"""# 🥷 Akali Security Report

**Target:** {target}
**Scan Type:** {scan_type}
**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

---

## Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | {len(by_severity['critical'])} |
| 🟠 High | {len(by_severity['high'])} |
| 🟡 Medium | {len(by_severity['medium'])} |
| 🔵 Low | {len(by_severity['low'])} |
| ⚪ Info | {len(by_severity['info'])} |
| **Total** | **{len(findings)}** |

---

"""

        # Generate findings sections
        for severity in ["critical", "high", "medium", "low", "info"]:
            findings_list = by_severity[severity]
            if not findings_list:
                continue

            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}

            md += f"""## {emoji[severity]} {severity.upper()} Severity ({len(findings_list)})\n\n"""

            for i, finding in enumerate(findings_list, 1):
                finding_dict = finding.to_dict()

                md += f"""### {i}. {finding_dict['title']}

**ID:** {finding_dict['id']}
**Type:** {finding_dict['type']}
**Severity:** {finding_dict['severity'].upper()}
"""

                if finding_dict.get('cvss'):
                    md += f"""**CVSS:** {finding_dict['cvss']}  \n"""
                if finding_dict.get('cwe'):
                    md += f"""**CWE:** {finding_dict['cwe']}  \n"""
                if finding_dict.get('owasp'):
                    md += f"""**OWASP:** {finding_dict['owasp']}  \n"""
                if finding_dict.get('file'):
                    location = finding_dict['file']
                    if finding_dict.get('line'):
                        location += f":{finding_dict['line']}"
                    md += f"""**Location:** `{location}`  \n"""

                md += f"""
**Description:**
{finding_dict['description']}

"""

                if finding_dict.get('fix'):
                    md += f"""**🔧 Recommended Fix:**
{finding_dict['fix']}

"""

                md += "---\n\n"

        md += f"""
## Report Information

- **Generated by:** Akali - The Security Sentinel
- **Total Findings:** {len(findings)}
- **Scan Type:** {scan_type}
- **Report Path:** {filepath}

"""

        # Write to file
        with open(filepath, 'w') as f:
            f.write(md)

        return str(filepath)

    def generate_json(self, findings: List[Finding], target: str, scan_type: str) -> str:
        """Generate JSON report.

        Args:
            findings: List of findings
            target: Scan target
            scan_type: Type of scan performed

        Returns:
            Path to generated JSON report
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"akali_report_{timestamp}.json"
        filepath = self.report_dir / filename

        report = {
            "metadata": {
                "target": target,
                "scan_type": scan_type,
                "generated": datetime.now().isoformat(),
                "tool": "Akali - The Security Sentinel",
                "version": "2.0"
            },
            "summary": {
                "total_findings": len(findings),
                "by_severity": {}
            },
            "findings": []
        }

        # Count by severity
        for finding in findings:
            severity = finding.severity.lower()
            report["summary"]["by_severity"][severity] = report["summary"]["by_severity"].get(severity, 0) + 1
            report["findings"].append(finding.to_dict())

        # Write to file
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)

        return str(filepath)


def main():
    """CLI for report generator."""
    import sys

    if len(sys.argv) < 3:
        print("Usage: python report_generator.py <format> <findings_json_path>")
        print("Formats: html, markdown, json")
        sys.exit(1)

    format_type = sys.argv[1].lower()
    findings_json = sys.argv[2]

    if format_type not in ["html", "markdown", "md", "json"]:
        print(f"❌ Invalid format: {format_type}")
        print("Valid formats: html, markdown, json")
        sys.exit(1)

    # Load findings from JSON
    try:
        with open(findings_json, 'r') as f:
            data = json.load(f)

        findings = [Finding(**f) for f in data.get("findings", [])]
        target = data.get("metadata", {}).get("target", "Unknown")
        scan_type = data.get("metadata", {}).get("scan_type", "Unknown")

    except Exception as e:
        print(f"❌ Error loading findings: {e}")
        sys.exit(1)

    # Generate report
    generator = ReportGenerator()

    try:
        if format_type == "html":
            output = generator.generate_html(findings, target, scan_type)
        elif format_type in ["markdown", "md"]:
            output = generator.generate_markdown(findings, target, scan_type)
        else:  # json
            output = generator.generate_json(findings, target, scan_type)

        print(f"✅ Report generated: {output}")

    except Exception as e:
        print(f"❌ Error generating report: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

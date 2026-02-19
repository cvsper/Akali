#!/usr/bin/env python3
"""
Threat Hunting CLI - Command-line interface for threat hunting operations

Commands:
- akali hunt analyze <logs> - Analyze logs for behavioral anomalies
- akali hunt ml-train <data> - Train ML anomaly detection model
- akali hunt ml-detect <data> - Detect anomalies using ML
- akali hunt ioc <indicator> - Check IoC against database
- akali hunt ioc-import <feed> - Import IoCs from threat feed
- akali hunt report - Generate threat hunting report
- akali hunt stats - Show hunting statistics
"""

import sys
import json
from pathlib import Path

# Add hunting modules to path
sys.path.insert(0, str(Path.home() / "akali" / "intelligence" / "hunting"))

from behavioral_analyzer import BehavioralAnalyzer
from ioc_correlator import IoCCorrelator
from threat_reporter import ThreatReporter

# Hunt modules
from hunters.credential_stuffing import CredentialStuffingHunter
from hunters.data_exfil import DataExfilHunter
from hunters.lateral_movement import LateralMovementHunter

# ML detector (optional - requires scikit-learn)
try:
    from ml_anomaly_detector import MLAnomalyDetector, NetworkTrafficDetector, APIUsageDetector
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False


class HuntCLI:
    """Threat hunting command-line interface"""

    def __init__(self):
        self.behavioral_analyzer = BehavioralAnalyzer()
        self.ioc_correlator = IoCCorrelator()
        self.threat_reporter = ThreatReporter()

        # Specialized hunters
        self.credential_hunter = CredentialStuffingHunter()
        self.exfil_hunter = DataExfilHunter()
        self.lateral_hunter = LateralMovementHunter()

    def analyze_logs(self, log_file: str, analysis_type: str = "auto"):
        """
        Analyze logs for threats

        Args:
            log_file: Path to log file (JSON format)
            analysis_type: Type of analysis (auto, login, network, api, file)
        """
        print(f"Analyzing logs from {log_file}...")

        # Load logs
        try:
            with open(log_file, 'r') as f:
                logs = json.load(f)

            if not isinstance(logs, list):
                logs = [logs]

        except Exception as e:
            print(f"Error loading logs: {e}")
            return

        all_findings = []

        # Auto-detect log type or use specified type
        if analysis_type == "auto":
            analysis_type = self._detect_log_type(logs)
            print(f"Detected log type: {analysis_type}")

        # Run appropriate analysis
        if analysis_type == "login":
            print("\n=== Login Pattern Analysis ===")
            findings = self.behavioral_analyzer.analyze_login_pattern(logs)
            all_findings.extend(findings)

            # Also run credential stuffing hunter
            cred_findings = self.credential_hunter.analyze(logs)
            all_findings.extend(cred_findings)

        elif analysis_type == "network":
            print("\n=== Network Traffic Analysis ===")
            findings = self.behavioral_analyzer.analyze_network_traffic(logs)
            all_findings.extend(findings)

            # Also run data exfil hunter
            exfil_findings = self.exfil_hunter.analyze(logs)
            all_findings.extend(exfil_findings)

            # Also run lateral movement hunter
            lateral_findings = self.lateral_hunter.analyze(logs)
            all_findings.extend(lateral_findings)

        elif analysis_type == "api":
            print("\n=== API Usage Analysis ===")
            findings = self.behavioral_analyzer.analyze_api_usage(logs)
            all_findings.extend(findings)

        elif analysis_type == "file":
            print("\n=== File Access Analysis ===")
            findings = self.behavioral_analyzer.analyze_file_access(logs)
            all_findings.extend(findings)

            # Also run data exfil hunter
            exfil_findings = self.exfil_hunter.analyze([], logs)
            all_findings.extend(exfil_findings)

        # Correlate with known IoCs
        print("\n=== IoC Correlation ===")
        correlations = self.ioc_correlator.correlate_logs(logs)

        if correlations:
            print(f"Found {len(correlations)} log entries matching known IoCs")
            for corr in correlations[:5]:  # Show first 5
                print(f"  [{corr['severity'].upper()}] {corr['match_count']} IoC matches")

        # Display findings
        print(f"\n=== Analysis Complete ===")
        print(f"Total findings: {len(all_findings)}")

        if all_findings:
            # Group by severity
            by_severity = {}
            for finding in all_findings:
                severity = finding.get('severity', 'unknown')
                by_severity[severity] = by_severity.get(severity, 0) + 1

            print("\nBy severity:")
            for severity in ['critical', 'high', 'medium', 'low']:
                if severity in by_severity:
                    print(f"  {severity.upper()}: {by_severity[severity]}")

            # Show critical findings
            critical = [f for f in all_findings if f.get('severity') == 'critical']
            if critical:
                print(f"\nCritical findings:")
                for finding in critical[:3]:
                    print(f"  - {finding.get('description', 'No description')}")

        return all_findings

    def _detect_log_type(self, logs: list) -> str:
        """Auto-detect log type from structure"""

        if not logs:
            return "unknown"

        sample = logs[0]

        # Check for login logs
        if 'user' in sample and ('success' in sample or 'failed' in sample):
            return "login"

        # Check for network logs
        if 'source_ip' in sample and 'dest_ip' in sample:
            return "network"

        # Check for API logs
        if 'endpoint' in sample or ('method' in sample and 'status_code' in sample):
            return "api"

        # Check for file logs
        if 'file_path' in sample and 'operation' in sample:
            return "file"

        return "unknown"

    def check_ioc(self, indicator: str):
        """Check if indicator is a known IoC"""

        print(f"Checking IoC: {indicator}")

        # Search in database
        results = self.ioc_correlator.search(indicator)

        if results:
            print(f"\nFound {len(results)} matching IoCs:\n")

            for ioc in results:
                print(f"Type: {ioc.type}")
                print(f"Value: {ioc.value}")
                print(f"Confidence: {ioc.confidence:.2f}")
                print(f"Source: {ioc.source}")
                print(f"Tags: {', '.join(ioc.tags)}")
                print(f"First seen: {ioc.first_seen}")
                print(f"Last seen: {ioc.last_seen}")
                print(f"Occurrences: {ioc.occurrences}")

                # Show related IoCs
                if ioc.related_iocs:
                    print(f"Related IoCs: {len(ioc.related_iocs)}")

                print()
        else:
            print("No matching IoCs found in database")

    def import_iocs(self, feed_file: str, feed_name: str = "custom"):
        """Import IoCs from JSON file"""

        print(f"Importing IoCs from {feed_file}...")

        try:
            with open(feed_file, 'r') as f:
                iocs = json.load(f)

            if not isinstance(iocs, list):
                iocs = [iocs]

            self.ioc_correlator.import_from_feed(feed_name, iocs)

            print(f"Import complete!")

        except Exception as e:
            print(f"Error importing IoCs: {e}")

    def generate_report(self, findings: list, output_format: str = "markdown"):
        """Generate threat hunting report"""

        if not findings:
            print("No findings to report")
            return

        print(f"Generating {output_format} report...")

        metadata = {
            "total_findings": len(findings),
            "generated_by": "Akali Threat Hunting System"
        }

        report_path = self.threat_reporter.generate_report(
            title="Threat Hunting Report",
            findings=findings,
            metadata=metadata,
            format=output_format
        )

        print(f"Report generated: {report_path}")

    def show_stats(self):
        """Show threat hunting statistics"""

        print("=== Threat Hunting Statistics ===\n")

        # Behavioral analysis stats
        print("Behavioral Analysis:")
        print(f"  Baselines: {len(self.behavioral_analyzer.baselines)}")
        print(f"  Anomalies detected: {len(self.behavioral_analyzer.anomalies)}")

        # IoC database stats
        ioc_stats = self.ioc_correlator.get_statistics()
        print(f"\nIoC Database:")
        print(f"  Total IoCs: {ioc_stats['total_iocs']}")
        print(f"  By confidence:")
        for level, count in ioc_stats['by_confidence'].items():
            print(f"    {level}: {count}")
        print(f"  By type:")
        for ioc_type, count in ioc_stats['by_type'].items():
            print(f"    {ioc_type}: {count}")

        # ML stats (if available)
        if ML_AVAILABLE:
            models_dir = Path.home() / "akali" / "intelligence" / "hunting" / "models"
            if models_dir.exists():
                models = list(models_dir.glob("*.pkl"))
                print(f"\nML Models:")
                print(f"  Trained models: {len(models)}")
                for model in models:
                    print(f"    - {model.stem}")


def main():
    """Main CLI entry point"""

    cli = HuntCLI()

    if len(sys.argv) < 2:
        print("Usage: akali hunt <command> [args]")
        print("\nCommands:")
        print("  analyze <log_file> [type] - Analyze logs for threats")
        print("  ioc <indicator>           - Check IoC against database")
        print("  ioc-import <file> [name]  - Import IoCs from file")
        print("  report <findings_file>    - Generate threat report")
        print("  stats                     - Show hunting statistics")
        return

    command = sys.argv[1]

    if command == "analyze":
        if len(sys.argv) < 3:
            print("Usage: akali hunt analyze <log_file> [type]")
            return

        log_file = sys.argv[2]
        analysis_type = sys.argv[3] if len(sys.argv) > 3 else "auto"

        findings = cli.analyze_logs(log_file, analysis_type)

        # Optionally save findings
        if findings:
            findings_file = "hunt_findings.json"
            with open(findings_file, 'w') as f:
                json.dump(findings, f, indent=2)
            print(f"\nFindings saved to {findings_file}")

    elif command == "ioc":
        if len(sys.argv) < 3:
            print("Usage: akali hunt ioc <indicator>")
            return

        indicator = sys.argv[2]
        cli.check_ioc(indicator)

    elif command == "ioc-import":
        if len(sys.argv) < 3:
            print("Usage: akali hunt ioc-import <file> [feed_name]")
            return

        feed_file = sys.argv[2]
        feed_name = sys.argv[3] if len(sys.argv) > 3 else "custom"
        cli.import_iocs(feed_file, feed_name)

    elif command == "report":
        if len(sys.argv) < 3:
            print("Usage: akali hunt report <findings_file> [format]")
            return

        findings_file = sys.argv[2]
        output_format = sys.argv[3] if len(sys.argv) > 3 else "markdown"

        try:
            with open(findings_file, 'r') as f:
                findings = json.load(f)

            cli.generate_report(findings, output_format)

        except Exception as e:
            print(f"Error: {e}")

    elif command == "stats":
        cli.show_stats()

    else:
        print(f"Unknown command: {command}")


if __name__ == "__main__":
    main()

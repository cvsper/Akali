#!/usr/bin/env python3
"""
Akali Phishing Report Generator

Generate detailed reports and metrics for phishing simulation campaigns.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
import sys

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from education.phishing.campaign_manager import CampaignManager


class ReportGenerator:
    """Generate phishing campaign reports"""

    def __init__(self):
        self.manager = CampaignManager()

    def generate_campaign_report(self, campaign_id: str) -> Dict[str, Any]:
        """
        Generate comprehensive campaign report

        Returns:
            Report dict with all metrics and analysis
        """
        campaign = self.manager.get_campaign(campaign_id)
        if not campaign:
            return {'error': 'Campaign not found'}

        results = self.manager.get_campaign_results(campaign_id)
        targets = self.manager.get_campaign_targets(campaign_id)
        template = self.manager.get_template(campaign.template_id)

        # Calculate additional metrics
        analysis = self._analyze_campaign(campaign, results, targets)

        report = {
            'campaign': {
                'id': campaign.id,
                'name': campaign.name,
                'template': template['name'] if template else campaign.template_id,
                'template_difficulty': template['difficulty'] if template else 'unknown',
                'status': campaign.status,
                'created_at': campaign.created_at,
                'started_at': campaign.started_at,
                'completed_at': campaign.completed_at
            },
            'metrics': {
                'total_targets': results['total_targets'],
                'emails_sent': results['emails_sent'],
                'links_clicked': results['links_clicked'],
                'reported': results['reported'],
                'click_rate': round(results['click_rate'], 2),
                'report_rate': round(results['report_rate'], 2),
                'avg_time_to_click_minutes': results.get('avg_time_to_click')
            },
            'status_breakdown': results['status_breakdown'],
            'analysis': analysis,
            'targets': [
                {
                    'email': t['recipient_email'],
                    'name': t['recipient_name'],
                    'status': t['status'],
                    'sent_at': t['sent_at'],
                    'clicked_at': t['clicked_at'],
                    'reported_at': t['reported_at']
                }
                for t in targets
            ],
            'generated_at': datetime.now().isoformat()
        }

        return report

    def _analyze_campaign(
        self,
        campaign,
        results: Dict[str, Any],
        targets: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Analyze campaign performance"""

        click_rate = results['click_rate']
        report_rate = results['report_rate']

        # Determine risk level
        if click_rate >= 30:
            risk_level = 'high'
            risk_description = 'High click rate indicates significant phishing susceptibility'
        elif click_rate >= 15:
            risk_level = 'medium'
            risk_description = 'Moderate click rate - targeted training recommended'
        elif click_rate >= 5:
            risk_level = 'low'
            risk_description = 'Low click rate - users show good awareness'
        else:
            risk_level = 'very_low'
            risk_description = 'Excellent performance - minimal phishing risk'

        # Determine awareness level based on report rate
        if report_rate >= 20:
            awareness = 'excellent'
        elif report_rate >= 10:
            awareness = 'good'
        elif report_rate >= 5:
            awareness = 'fair'
        else:
            awareness = 'poor'

        # Identify vulnerable users (clicked but didn't report)
        vulnerable_users = [
            t['recipient_email']
            for t in targets
            if t['clicked_at'] and not t['reported_at']
        ]

        # Identify aware users (reported without clicking, or reported after clicking)
        aware_users = [
            t['recipient_email']
            for t in targets
            if t['reported_at']
        ]

        return {
            'risk_level': risk_level,
            'risk_description': risk_description,
            'awareness_level': awareness,
            'vulnerable_user_count': len(vulnerable_users),
            'aware_user_count': len(aware_users),
            'vulnerable_users': vulnerable_users[:10],  # Top 10
            'aware_users': aware_users[:10],  # Top 10
            'recommendations': self._generate_recommendations(click_rate, report_rate, results)
        }

    def _generate_recommendations(
        self,
        click_rate: float,
        report_rate: float,
        results: Dict[str, Any]
    ) -> List[str]:
        """Generate actionable recommendations"""

        recommendations = []

        # Click rate recommendations
        if click_rate >= 30:
            recommendations.append("URGENT: Implement mandatory security awareness training for all users")
            recommendations.append("Consider deploying email gateway with advanced phishing filters")
        elif click_rate >= 15:
            recommendations.append("Schedule targeted phishing awareness training")
            recommendations.append("Deploy browser extension for real-time phishing warnings")
        elif click_rate >= 5:
            recommendations.append("Continue regular phishing simulations to maintain awareness")

        # Report rate recommendations
        if report_rate < 5:
            recommendations.append("Promote and incentivize phishing reporting mechanisms")
            recommendations.append("Create easy-to-use 'Report Phish' button in email client")
        elif report_rate < 10:
            recommendations.append("Reward users who report phishing attempts")
            recommendations.append("Share success stories of caught phishing attempts")

        # Time to click
        avg_time = results.get('avg_time_to_click')
        if avg_time and avg_time < 5:
            recommendations.append("Users click very quickly - emphasize 'Stop and Think' training")

        # General recommendations
        if not recommendations:
            recommendations.append("Maintain current security awareness program")
            recommendations.append("Run quarterly phishing simulations to track trends")

        return recommendations

    def print_campaign_report(self, campaign_id: str):
        """Print formatted campaign report to console"""

        report = self.generate_campaign_report(campaign_id)

        if 'error' in report:
            print(f"❌ {report['error']}")
            return

        campaign = report['campaign']
        metrics = report['metrics']
        analysis = report['analysis']

        # Header
        print("\n" + "="*70)
        print(f"🥷 AKALI PHISHING SIMULATION REPORT")
        print("="*70 + "\n")

        # Campaign info
        print(f"Campaign: {campaign['name']}")
        print(f"ID: {campaign['id']}")
        print(f"Template: {campaign['template']} ({campaign['template_difficulty']} difficulty)")
        print(f"Status: {campaign['status']}")
        print(f"Created: {campaign['created_at']}")

        if campaign['started_at']:
            print(f"Started: {campaign['started_at']}")
        if campaign['completed_at']:
            print(f"Completed: {campaign['completed_at']}")

        # Metrics
        print("\n" + "-"*70)
        print("📊 METRICS")
        print("-"*70 + "\n")

        print(f"Total Targets: {metrics['total_targets']}")
        print(f"Emails Sent: {metrics['emails_sent']}")
        print(f"Links Clicked: {metrics['links_clicked']}")
        print(f"Reported: {metrics['reported']}")
        print()

        # Click rate with visual indicator
        click_rate = metrics['click_rate']
        click_bar = '█' * int(click_rate / 2) + '░' * (50 - int(click_rate / 2))
        print(f"Click Rate: {click_rate}% [{click_bar}]")

        # Report rate
        report_rate = metrics['report_rate']
        report_bar = '█' * int(report_rate / 2) + '░' * (50 - int(report_rate / 2))
        print(f"Report Rate: {report_rate}% [{report_bar}]")

        if metrics.get('avg_time_to_click_minutes'):
            print(f"\nAverage Time to Click: {metrics['avg_time_to_click_minutes']:.1f} minutes")

        # Status breakdown
        print("\n" + "-"*70)
        print("📋 STATUS BREAKDOWN")
        print("-"*70 + "\n")

        status_emoji = {
            'pending': '⏳',
            'sent': '📧',
            'clicked': '🔴',
            'reported': '✅'
        }

        for status, count in report['status_breakdown'].items():
            emoji = status_emoji.get(status, '•')
            print(f"{emoji} {status.title()}: {count}")

        # Analysis
        print("\n" + "-"*70)
        print("🔍 ANALYSIS")
        print("-"*70 + "\n")

        risk_emoji = {
            'very_low': '🟢',
            'low': '🟡',
            'medium': '🟠',
            'high': '🔴'
        }

        awareness_emoji = {
            'excellent': '🏆',
            'good': '✅',
            'fair': '⚠️',
            'poor': '❌'
        }

        print(f"{risk_emoji.get(analysis['risk_level'], '•')} Risk Level: {analysis['risk_level'].upper()}")
        print(f"   {analysis['risk_description']}")
        print()
        print(f"{awareness_emoji.get(analysis['awareness_level'], '•')} Awareness Level: {analysis['awareness_level'].upper()}")
        print()
        print(f"Vulnerable Users: {analysis['vulnerable_user_count']}")
        print(f"Aware Users: {analysis['aware_user_count']}")

        # Recommendations
        print("\n" + "-"*70)
        print("💡 RECOMMENDATIONS")
        print("-"*70 + "\n")

        for i, rec in enumerate(analysis['recommendations'], 1):
            print(f"{i}. {rec}")

        # Vulnerable users (if any)
        if analysis['vulnerable_users']:
            print("\n" + "-"*70)
            print("⚠️  HIGH-RISK USERS (Clicked but did not report)")
            print("-"*70 + "\n")

            for email in analysis['vulnerable_users']:
                print(f"  • {email}")

            if analysis['vulnerable_user_count'] > 10:
                print(f"\n  ... and {analysis['vulnerable_user_count'] - 10} more")

        # Aware users (if any)
        if analysis['aware_users']:
            print("\n" + "-"*70)
            print("🏆 TOP PERFORMERS (Reported phishing)")
            print("-"*70 + "\n")

            for email in analysis['aware_users']:
                print(f"  • {email}")

            if analysis['aware_user_count'] > 10:
                print(f"\n  ... and {analysis['aware_user_count'] - 10} more")

        print("\n" + "="*70 + "\n")

    def export_json_report(self, campaign_id: str, output_path: Optional[str] = None) -> str:
        """Export campaign report as JSON"""

        report = self.generate_campaign_report(campaign_id)

        if 'error' in report:
            raise ValueError(report['error'])

        if not output_path:
            output_dir = Path.home() / ".akali" / "reports"
            output_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = output_dir / f"phishing_report_{campaign_id}_{timestamp}.json"

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)

        return str(output_path)

    def compare_campaigns(self, campaign_ids: List[str]) -> Dict[str, Any]:
        """Compare metrics across multiple campaigns"""

        comparison = {
            'campaigns': [],
            'summary': {
                'avg_click_rate': 0,
                'avg_report_rate': 0,
                'trend': 'unknown'
            }
        }

        click_rates = []
        report_rates = []

        for campaign_id in campaign_ids:
            report = self.generate_campaign_report(campaign_id)
            if 'error' not in report:
                comparison['campaigns'].append({
                    'id': campaign_id,
                    'name': report['campaign']['name'],
                    'template': report['campaign']['template'],
                    'click_rate': report['metrics']['click_rate'],
                    'report_rate': report['metrics']['report_rate'],
                    'risk_level': report['analysis']['risk_level']
                })
                click_rates.append(report['metrics']['click_rate'])
                report_rates.append(report['metrics']['report_rate'])

        if click_rates:
            comparison['summary']['avg_click_rate'] = round(sum(click_rates) / len(click_rates), 2)
            comparison['summary']['avg_report_rate'] = round(sum(report_rates) / len(report_rates), 2)

            # Determine trend (if click rate is decreasing over time, that's good)
            if len(click_rates) >= 2:
                if click_rates[-1] < click_rates[0]:
                    comparison['summary']['trend'] = 'improving'
                elif click_rates[-1] > click_rates[0]:
                    comparison['summary']['trend'] = 'worsening'
                else:
                    comparison['summary']['trend'] = 'stable'

        return comparison


def main():
    """CLI testing"""
    import sys

    print("\n📊 Akali Phishing Report Generator\n")

    manager = CampaignManager()
    campaigns = manager.list_campaigns()

    if not campaigns:
        print("No campaigns found. Create a campaign first.")
        return

    print("Available campaigns:")
    for i, campaign in enumerate(campaigns, 1):
        print(f"{i}. {campaign.id} - {campaign.name} ({campaign.status})")

    if len(sys.argv) > 1:
        campaign_id = sys.argv[1]
    else:
        try:
            choice = int(input("\nSelect campaign number: "))
            campaign_id = campaigns[choice - 1].id
        except (ValueError, IndexError, KeyboardInterrupt):
            print("\nExiting.")
            return

    # Generate report
    generator = ReportGenerator()
    generator.print_campaign_report(campaign_id)


if __name__ == '__main__':
    main()

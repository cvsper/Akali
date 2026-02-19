#!/usr/bin/env python3
"""
Akali Post-Mortem Generator
Generate comprehensive incident post-mortem reports
"""

import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Dict, Optional, List, Any

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from incident.incidents.incident_db import IncidentDB


class PostMortemGenerator:
    """Generate post-mortem reports from incident data"""

    def __init__(self, db_path: Optional[str] = None):
        """Initialize post-mortem generator"""
        self.db = IncidentDB(db_path)

    def generate_report(self, incident_id: str, output_path: Optional[str] = None) -> str:
        """
        Generate post-mortem report for an incident

        Args:
            incident_id: Incident ID
            output_path: Optional path to save report (default: ~/.akali/reports/)

        Returns:
            Path to generated report
        """
        # Get incident data
        incident = self.db.get_incident(incident_id)
        if not incident:
            raise ValueError(f"Incident not found: {incident_id}")

        timeline = self.db.get_timeline(incident_id)
        evidence = self.db.get_evidence(incident_id)
        actions = self.db.get_actions(incident_id)

        # Generate report content
        report_md = self._generate_markdown(incident, timeline, evidence, actions)

        # Save report
        if output_path is None:
            reports_dir = Path.home() / '.akali' / 'reports'
            reports_dir.mkdir(parents=True, exist_ok=True)
            output_path = str(reports_dir / f'{incident_id}_post_mortem.md')

        with open(output_path, 'w') as f:
            f.write(report_md)

        return output_path

    def _generate_markdown(self,
                          incident: Dict[str, Any],
                          timeline: List[Dict[str, Any]],
                          evidence: List[Dict[str, Any]],
                          actions: List[Dict[str, Any]]) -> str:
        """Generate markdown post-mortem report"""
        lines = []

        # Header
        lines.append(f"# Post-Mortem Report: {incident['title']}")
        lines.append(f"**Incident ID:** {incident['id']}")
        lines.append(f"**Date:** {datetime.now(UTC).strftime('%Y-%m-%d')}")
        lines.append("")

        # Executive Summary
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(self._generate_executive_summary(incident, timeline, actions))
        lines.append("")

        # Incident Details
        lines.append("## Incident Details")
        lines.append("")
        lines.append(f"**Severity:** {incident['severity'].upper()}")
        lines.append(f"**Type:** {(incident['incident_type'] or 'Unknown').replace('_', ' ').title()}")
        lines.append(f"**Status:** {incident['status'].title()}")
        lines.append(f"**Created:** {self._format_timestamp(incident['created_at'])}")
        if incident['closed_at']:
            lines.append(f"**Closed:** {self._format_timestamp(incident['closed_at'])}")
            lines.append(f"**Duration:** {self._calculate_duration(incident['created_at'], incident['closed_at'])}")
        lines.append("")

        if incident['affected_systems']:
            lines.append(f"**Affected Systems:**")
            for system in incident['affected_systems']:
                lines.append(f"- {system}")
            lines.append("")

        if incident['assigned_to']:
            lines.append(f"**Response Team:**")
            for person in incident['assigned_to']:
                lines.append(f"- {person}")
            lines.append("")

        # Description
        if incident['description']:
            lines.append("## Incident Description")
            lines.append("")
            lines.append(incident['description'])
            lines.append("")

        # Timeline
        lines.append("## Timeline of Events")
        lines.append("")
        lines.append(self._generate_timeline(timeline))
        lines.append("")

        # Root Cause Analysis
        lines.append("## Root Cause Analysis")
        lines.append("")
        lines.append(self._generate_root_cause(incident, timeline))
        lines.append("")

        # Response Actions
        lines.append("## Response Actions Taken")
        lines.append("")
        lines.append(self._generate_actions_summary(actions))
        lines.append("")

        # Evidence
        if evidence:
            lines.append("## Evidence Collected")
            lines.append("")
            lines.append(self._generate_evidence_summary(evidence))
            lines.append("")

        # Impact Assessment
        lines.append("## Impact Assessment")
        lines.append("")
        lines.append(self._generate_impact_assessment(incident, timeline))
        lines.append("")

        # Lessons Learned
        lines.append("## Lessons Learned")
        lines.append("")
        lines.append(self._generate_lessons_learned(incident))
        lines.append("")

        # Action Items
        lines.append("## Action Items and Preventive Measures")
        lines.append("")
        lines.append(self._generate_action_items(incident))
        lines.append("")

        # Conclusion
        lines.append("## Conclusion")
        lines.append("")
        lines.append(self._generate_conclusion(incident))
        lines.append("")

        # Footer
        lines.append("---")
        lines.append("")
        lines.append(f"*Generated by Akali Incident Response System on {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}*")

        return '\n'.join(lines)

    def _generate_executive_summary(self,
                                   incident: Dict[str, Any],
                                   timeline: List[Dict[str, Any]],
                                   actions: List[Dict[str, Any]]) -> str:
        """Generate executive summary section"""
        severity = incident['severity'].upper()
        incident_type = (incident['incident_type'] or 'security incident').replace('_', ' ')
        systems = ', '.join(incident['affected_systems']) if incident['affected_systems'] else 'multiple systems'

        duration = 'ongoing'
        if incident['closed_at']:
            duration = self._calculate_duration(incident['created_at'], incident['closed_at'])

        completed_actions = sum(1 for a in actions if a['status'] == 'completed')
        total_actions = len(actions)

        summary = f"""On {self._format_date(incident['created_at'])}, we identified a {severity} severity {incident_type} affecting {systems}. The incident was detected and contained within {duration}. Our incident response team executed {completed_actions} out of {total_actions} planned response actions. """

        if incident['status'] == 'closed':
            summary += "The incident has been fully resolved, all affected systems have been restored, and preventive measures have been implemented. "
        else:
            summary += "The incident response is still in progress. "

        summary += "This report details the timeline, root cause, response actions, and lessons learned."

        return summary

    def _generate_timeline(self, timeline: List[Dict[str, Any]]) -> str:
        """Generate timeline section"""
        lines = []

        for event in timeline:
            timestamp = self._format_timestamp(event['timestamp'])
            event_type = event['event_type'].replace('_', ' ').title()
            actor = event['actor'] or 'system'

            lines.append(f"**{timestamp}** | {event_type} | {actor}")
            lines.append(f"- {event['event']}")
            lines.append("")

        return '\n'.join(lines) if lines else "*No timeline events recorded*"

    def _generate_root_cause(self,
                            incident: Dict[str, Any],
                            timeline: List[Dict[str, Any]]) -> str:
        """Generate root cause analysis section"""
        # Look for investigation events in timeline
        investigation_events = [
            e for e in timeline
            if 'root cause' in e['event'].lower() or 'vulnerability' in e['event'].lower()
        ]

        if investigation_events:
            return investigation_events[-1]['event']

        # Default RCA template
        return f"""**Initial Vector:**
TBD - Requires further investigation

**Contributing Factors:**
- Factor 1: TBD
- Factor 2: TBD

**Root Cause:**
The root cause analysis determined that {(incident['incident_type'] or 'this incident').replace('_', ' ')} occurred due to [detailed explanation needed].

*Note: This section should be completed with specific technical details from the investigation.*"""

    def _generate_actions_summary(self, actions: List[Dict[str, Any]]) -> str:
        """Generate actions summary section"""
        if not actions:
            return "*No actions recorded*"

        lines = []

        # Group actions by type
        action_types = {}
        for action in actions:
            action_type = action['action_type']
            if action_type not in action_types:
                action_types[action_type] = []
            action_types[action_type].append(action)

        for action_type, type_actions in action_types.items():
            lines.append(f"### {action_type.replace('_', ' ').title()}")
            lines.append("")

            for action in type_actions:
                status_emoji = {
                    'completed': '✅',
                    'failed': '❌',
                    'in_progress': '🔄',
                    'pending': '⏳'
                }.get(action['status'], '•')

                lines.append(f"{status_emoji} **{action['action']}**")
                lines.append(f"   - Status: {action['status']}")

                if action['result']:
                    lines.append(f"   - Result: {action['result']}")

                if action['completed_at']:
                    duration = self._calculate_duration(
                        action['started_at'],
                        action['completed_at']
                    )
                    lines.append(f"   - Duration: {duration}")

                lines.append("")

        return '\n'.join(lines)

    def _generate_evidence_summary(self, evidence: List[Dict[str, Any]]) -> str:
        """Generate evidence summary section"""
        lines = []

        for ev in evidence:
            lines.append(f"**{ev['evidence_type'].replace('_', ' ').title()}**")
            lines.append(f"- Description: {ev['description'] or 'N/A'}")
            if ev['file_path']:
                lines.append(f"- Location: `{ev['file_path']}`")
            if ev['file_hash']:
                lines.append(f"- SHA256: `{ev['file_hash']}`")
            lines.append(f"- Collected: {self._format_timestamp(ev['collected_at'])} by {ev['collected_by']}")
            lines.append("")

        return '\n'.join(lines)

    def _generate_impact_assessment(self,
                                   incident: Dict[str, Any],
                                   timeline: List[Dict[str, Any]]) -> str:
        """Generate impact assessment section"""
        systems_affected = len(incident['affected_systems']) if incident['affected_systems'] else 0

        downtime = "None"
        if incident['closed_at']:
            downtime = self._calculate_duration(incident['created_at'], incident['closed_at'])

        return f"""**Systems Affected:** {systems_affected}

**Service Downtime:** {downtime}

**Data Impact:** TBD - Requires assessment

**Business Impact:** TBD - Requires quantification

**Financial Impact:** TBD - Requires calculation

*Note: Complete this section with specific impact metrics from the incident.*"""

    def _generate_lessons_learned(self, incident: Dict[str, Any]) -> str:
        """Generate lessons learned section"""
        return f"""### What Went Well
- Incident was detected promptly
- Response team was activated quickly
- Evidence was preserved
- [Add more positives]

### What Could Be Improved
- [Add specific improvements]
- [Add specific improvements]

### Key Takeaways
1. [Key learning 1]
2. [Key learning 2]
3. [Key learning 3]

*Note: Complete this section with specific lessons from the incident response.*"""

    def _generate_action_items(self, incident: Dict[str, Any]) -> str:
        """Generate action items section"""
        return f"""### Immediate Actions (0-7 days)
- [ ] Complete all pending remediation tasks
- [ ] Verify all systems are fully operational
- [ ] Update security monitoring rules

### Short-term Actions (1-4 weeks)
- [ ] Implement additional security controls
- [ ] Update incident response procedures
- [ ] Conduct team training on lessons learned

### Long-term Actions (1-3 months)
- [ ] Review and update security architecture
- [ ] Implement strategic security improvements
- [ ] Conduct security audit

*Note: Customize these action items based on the specific incident.*"""

    def _generate_conclusion(self, incident: Dict[str, Any]) -> str:
        """Generate conclusion section"""
        if incident['status'] == 'closed':
            return f"""The incident has been successfully resolved. All affected systems have been restored and are operating normally. Preventive measures have been implemented to reduce the likelihood of similar incidents. The response team demonstrated effective coordination and execution of the incident response plan. Continued monitoring is in place to ensure no residual issues remain."""
        else:
            return f"""The incident response is ongoing. The response team continues to work toward full resolution. This report will be updated as new information becomes available."""

    def _format_timestamp(self, timestamp: str) -> str:
        """Format timestamp for display"""
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d %H:%M:%S UTC')

    def _format_date(self, timestamp: str) -> str:
        """Format date for display"""
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        return dt.strftime('%B %d, %Y')

    def _calculate_duration(self, start: str, end: str) -> str:
        """Calculate duration between timestamps"""
        # Parse timestamps and ensure both are timezone-aware
        start_dt = datetime.fromisoformat(start.replace('Z', '+00:00'))
        end_dt = datetime.fromisoformat(end.replace('Z', '+00:00'))

        # Ensure both are timezone-aware
        if start_dt.tzinfo is None:
            start_dt = start_dt.replace(tzinfo=UTC)
        if end_dt.tzinfo is None:
            end_dt = end_dt.replace(tzinfo=UTC)

        delta = end_dt - start_dt

        days = delta.days
        hours = delta.seconds // 3600
        minutes = (delta.seconds % 3600) // 60

        parts = []
        if days > 0:
            parts.append(f"{days}d")
        if hours > 0:
            parts.append(f"{hours}h")
        if minutes > 0 or not parts:
            parts.append(f"{minutes}m")

        return ' '.join(parts)

    def close(self):
        """Close database connection"""
        self.db.close()


def main():
    """Test post-mortem generator"""
    # Use existing test incident if available
    generator = PostMortemGenerator()

    # Get the first available incident
    incidents = generator.db.list_incidents(limit=1)

    if not incidents:
        print("No incidents found. Creating test incident...")
        from incident.incidents.incident_tracker import IncidentTracker

        tracker = IncidentTracker()
        incident = tracker.create_incident(
            title='Test Incident for Post-Mortem',
            severity='high',
            description='This is a test incident for post-mortem report generation',
            incident_type='test',
            affected_systems=['test-system-1', 'test-system-2']
        )

        # Add some actions
        tracker.log_action(
            incident_id=incident['id'],
            action_type='containment',
            action='Isolated affected systems',
            status='completed',
            actor='akali'
        )

        tracker.log_action(
            incident_id=incident['id'],
            action_type='investigation',
            action='Analyzed logs for root cause',
            status='completed',
            actor='akali'
        )

        # Close incident
        tracker.close_incident(
            incident_id=incident['id'],
            resolution='Test incident resolved successfully',
            actor='akali'
        )

        tracker.close()
        incident_id = incident['id']
    else:
        incident_id = incidents[0]['id']

    print(f"Generating post-mortem report for {incident_id}...")

    # Generate report
    report_path = generator.generate_report(incident_id)

    print(f"\n✅ Post-mortem report generated: {report_path}")
    print("\nPreview:")
    print("-" * 80)

    with open(report_path, 'r') as f:
        lines = f.readlines()
        # Print first 30 lines
        for line in lines[:30]:
            print(line.rstrip())

    print("-" * 80)
    print(f"\nFull report available at: {report_path}")

    generator.close()


if __name__ == '__main__':
    main()

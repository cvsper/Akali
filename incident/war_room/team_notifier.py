#!/usr/bin/env python3
"""
Akali Team Notifier
Broadcasts incident alerts to all agents via ZimMemory
"""

import requests
import json
from datetime import datetime, UTC
from typing import Dict, Optional, List, Any


class TeamNotifier:
    """Notify team members via ZimMemory messaging"""

    def __init__(self, zim_url: str = "http://10.0.0.209:5001"):
        """Initialize team notifier"""
        self.zim_url = zim_url
        self.from_agent = "akali"

    def send_broadcast(self,
                      subject: str,
                      body: str,
                      priority: str = 'high',
                      metadata: Optional[Dict[str, Any]] = None) -> bool:
        """
        Send broadcast message to all agents

        Args:
            subject: Message subject
            body: Message body
            priority: Message priority (low, medium, high, critical)
            metadata: Additional metadata

        Returns:
            True if sent successfully
        """
        try:
            # Format message with subject and body
            full_message = f"{subject}\n\n{body}"

            # Add metadata as JSON footer if provided
            if metadata:
                full_message += f"\n\n---\nMetadata: {json.dumps(metadata)}"

            message = {
                'from_agent': self.from_agent,
                'to_agent': 'broadcast',
                'message': full_message,
                'priority': priority
            }

            response = requests.post(
                f'{self.zim_url}/messages/send',
                json=message,
                timeout=5
            )

            return response.status_code == 200

        except Exception as e:
            print(f"Failed to send broadcast: {e}")
            return False

    def send_war_room_activation(self,
                                 incident_id: str,
                                 title: str,
                                 severity: str,
                                 incident_type: Optional[str] = None,
                                 affected_systems: Optional[List[str]] = None,
                                 playbook: Optional[str] = None) -> bool:
        """Send war room activation alert"""
        severity_emoji = {
            'low': '🟢',
            'medium': '🟡',
            'high': '🟠',
            'critical': '🔴'
        }.get(severity, '⚪')

        subject = f"🚨 WAR ROOM ACTIVATED: {title}"

        body_lines = [
            f"War room activated for {incident_id}",
            "",
            f"{severity_emoji} Severity: {severity.upper()}",
        ]

        if incident_type:
            body_lines.append(f"Type: {incident_type.replace('_', ' ').title()}")

        if affected_systems:
            body_lines.append(f"Affected: {', '.join(affected_systems)}")

        body_lines.extend([
            "",
            "⚡ All agents please join coordination channel.",
        ])

        if playbook:
            body_lines.append(f"📋 Playbook: {playbook}")

        body_lines.extend([
            "",
            f"Status: http://localhost:8765/incidents/{incident_id}"
        ])

        metadata = {
            'incident_id': incident_id,
            'war_room_active': True,
            'severity': severity,
            'incident_type': incident_type,
            'playbook': playbook
        }

        return self.send_broadcast(
            subject=subject,
            body='\n'.join(body_lines),
            priority='critical' if severity == 'critical' else 'high',
            metadata=metadata
        )

    def send_status_update(self,
                          incident_id: str,
                          status: str,
                          message: str,
                          severity: str = 'high') -> bool:
        """Send incident status update"""
        status_emoji = {
            'new': '🆕',
            'active': '⚡',
            'contained': '🛡️',
            'resolved': '✅',
            'closed': '🔒'
        }.get(status, '📢')

        subject = f"{status_emoji} {incident_id} Update: {status.title()}"

        body = f"{message}\n\nStatus: http://localhost:8765/incidents/{incident_id}"

        metadata = {
            'incident_id': incident_id,
            'status': status
        }

        return self.send_broadcast(
            subject=subject,
            body=body,
            priority='high',
            metadata=metadata
        )

    def send_war_room_deactivation(self,
                                   incident_id: str,
                                   title: str,
                                   resolution: Optional[str] = None) -> bool:
        """Send war room deactivation notice"""
        subject = f"✅ WAR ROOM CLOSED: {title}"

        body_lines = [
            f"War room closed for {incident_id}",
            "",
            "Incident resolved and closed.",
        ]

        if resolution:
            body_lines.extend([
                "",
                f"Resolution: {resolution}"
            ])

        body_lines.extend([
            "",
            f"Full report: http://localhost:8765/incidents/{incident_id}"
        ])

        metadata = {
            'incident_id': incident_id,
            'war_room_active': False,
            'resolution': resolution
        }

        return self.send_broadcast(
            subject=subject,
            body='\n'.join(body_lines),
            priority='medium',
            metadata=metadata
        )

    def send_playbook_started(self,
                             incident_id: str,
                             playbook_name: str,
                             total_steps: int) -> bool:
        """Notify that playbook execution started"""
        subject = f"📋 Playbook Started: {playbook_name}"

        body = f"Playbook '{playbook_name}' started for {incident_id}\n\nTotal steps: {total_steps}"

        metadata = {
            'incident_id': incident_id,
            'playbook': playbook_name,
            'event': 'playbook_started'
        }

        return self.send_broadcast(
            subject=subject,
            body=body,
            priority='medium',
            metadata=metadata
        )

    def send_playbook_step(self,
                          incident_id: str,
                          playbook_name: str,
                          step_name: str,
                          step_number: int,
                          total_steps: int) -> bool:
        """Notify about playbook step progress"""
        subject = f"📋 Playbook Progress: {step_name}"

        body = (
            f"Playbook '{playbook_name}' for {incident_id}\n"
            f"\n"
            f"Step {step_number}/{total_steps}: {step_name}"
        )

        metadata = {
            'incident_id': incident_id,
            'playbook': playbook_name,
            'step': step_name,
            'step_number': step_number,
            'total_steps': total_steps,
            'event': 'playbook_step'
        }

        return self.send_broadcast(
            subject=subject,
            body=body,
            priority='low',
            metadata=metadata
        )

    def send_playbook_completed(self,
                               incident_id: str,
                               playbook_name: str,
                               completed_steps: int) -> bool:
        """Notify that playbook execution completed"""
        subject = f"✅ Playbook Completed: {playbook_name}"

        body = (
            f"Playbook '{playbook_name}' completed for {incident_id}\n"
            f"\n"
            f"Completed steps: {completed_steps}"
        )

        metadata = {
            'incident_id': incident_id,
            'playbook': playbook_name,
            'completed_steps': completed_steps,
            'event': 'playbook_completed'
        }

        return self.send_broadcast(
            subject=subject,
            body=body,
            priority='medium',
            metadata=metadata
        )

    def send_evidence_collected(self,
                               incident_id: str,
                               evidence_type: str,
                               description: str) -> bool:
        """Notify about evidence collection"""
        subject = f"🔍 Evidence Collected: {evidence_type}"

        body = (
            f"Evidence collected for {incident_id}\n"
            f"\n"
            f"Type: {evidence_type}\n"
            f"Description: {description}"
        )

        metadata = {
            'incident_id': incident_id,
            'evidence_type': evidence_type,
            'event': 'evidence_collected'
        }

        return self.send_broadcast(
            subject=subject,
            body=body,
            priority='low',
            metadata=metadata
        )

    def send_action_completed(self,
                             incident_id: str,
                             action: str,
                             result: str) -> bool:
        """Notify about completed action"""
        subject = f"✅ Action Completed: {action}"

        body = (
            f"Action completed for {incident_id}\n"
            f"\n"
            f"Action: {action}\n"
            f"Result: {result}"
        )

        metadata = {
            'incident_id': incident_id,
            'action': action,
            'event': 'action_completed'
        }

        return self.send_broadcast(
            subject=subject,
            body=body,
            priority='medium',
            metadata=metadata
        )

    def send_custom_alert(self,
                         incident_id: str,
                         alert_title: str,
                         alert_body: str,
                         priority: str = 'medium') -> bool:
        """Send custom alert"""
        subject = f"🔔 {incident_id}: {alert_title}"

        metadata = {
            'incident_id': incident_id,
            'event': 'custom_alert'
        }

        return self.send_broadcast(
            subject=subject,
            body=alert_body,
            priority=priority,
            metadata=metadata
        )

    def test_connection(self) -> bool:
        """Test connection to ZimMemory"""
        try:
            response = requests.get(f'{self.zim_url}/health', timeout=5)
            return response.status_code == 200
        except Exception:
            return False


def main():
    """Test team notifier"""
    notifier = TeamNotifier()

    # Test connection
    print("Testing connection to ZimMemory...")
    if notifier.test_connection():
        print("✅ Connected to ZimMemory")
    else:
        print("❌ Failed to connect to ZimMemory")
        print("   Make sure ZimMemory is running at http://10.0.0.209:5001")
        return

    # Test war room activation
    print("\nSending war room activation...")
    success = notifier.send_war_room_activation(
        incident_id='INCIDENT-TEST-001',
        title='Test SQL Injection',
        severity='critical',
        incident_type='sql_injection',
        affected_systems=['booking-api', 'user-api'],
        playbook='sql-injection-response'
    )
    print(f"{'✅' if success else '❌'} War room activation sent")

    # Test status update
    print("\nSending status update...")
    success = notifier.send_status_update(
        incident_id='INCIDENT-TEST-001',
        status='contained',
        message='Booking API successfully isolated. Investigating vulnerability.'
    )
    print(f"{'✅' if success else '❌'} Status update sent")

    # Test war room deactivation
    print("\nSending war room deactivation...")
    success = notifier.send_war_room_deactivation(
        incident_id='INCIDENT-TEST-001',
        title='Test SQL Injection',
        resolution='Vulnerability patched with parameterized queries'
    )
    print(f"{'✅' if success else '❌'} War room deactivation sent")

    print("\nTest completed!")
    print("\nCheck ZimMemory inbox to verify messages were received:")
    print("  http://10.0.0.209:5001/agent-messaging/messages?to_agent=broadcast")


if __name__ == '__main__':
    main()

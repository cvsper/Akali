#!/usr/bin/env python3
"""
Akali War Room Commander
Activate and coordinate incident response war room
"""

import json
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Dict, Optional, Any

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from incident.incidents.incident_db import IncidentDB
from incident.incidents.incident_tracker import IncidentTracker
from incident.war_room.team_notifier import TeamNotifier


class WarRoomCommander:
    """War room activation and coordination"""

    def __init__(self, db_path: Optional[str] = None):
        """Initialize war room commander"""
        self.tracker = IncidentTracker(db_path)
        self.notifier = TeamNotifier()
        self.state_file = Path.home() / '.akali' / 'war_room_state.json'
        self.state_file.parent.mkdir(exist_ok=True)

    def activate_war_room(self,
                         incident_id: str,
                         notify_team: bool = True,
                         isolate_services: bool = False) -> Dict[str, Any]:
        """
        Activate war room for an incident

        Args:
            incident_id: Incident ID to activate war room for
            notify_team: Send team notification (default: True)
            isolate_services: Lock down affected services (default: False)

        Returns:
            War room state dict
        """
        # Get incident
        incident = self.tracker.get_incident(incident_id)
        if not incident:
            raise ValueError(f"Incident not found: {incident_id}")

        # Check if already active
        if incident['war_room_active']:
            return self._load_state()

        # Activate incident if not already active
        if incident['status'] == 'new':
            incident = self.tracker.update_status(
                incident_id,
                'active',
                actor='war-room-commander',
                note='War room activated'
            )

        # Update incident to mark war room as active
        incident = self.tracker.db.update_incident(
            incident_id,
            war_room_active=True
        )

        # Log activation to timeline
        self.tracker.db.add_timeline_event(
            incident_id=incident_id,
            event_type='war_room',
            event='War room activated',
            actor='war-room-commander',
            metadata={'notify_team': notify_team, 'isolate_services': isolate_services}
        )

        # Send team notification
        if notify_team:
            self.notifier.send_war_room_activation(
                incident_id=incident_id,
                title=incident['title'],
                severity=incident['severity'],
                incident_type=incident['incident_type'],
                affected_systems=incident['affected_systems'],
                playbook=incident['playbook_id']
            )

        # Optional: Isolate services
        if isolate_services and incident['affected_systems']:
            for system in incident['affected_systems']:
                self.tracker.log_action(
                    incident_id=incident_id,
                    action_type='containment',
                    action=f'Isolate system: {system}',
                    status='pending',
                    actor='war-room-commander'
                )

        # Create war room state
        state = {
            'incident_id': incident_id,
            'activated_at': datetime.now(UTC).isoformat(),
            'activated_by': 'war-room-commander',
            'status': 'active',
            'team_notified': notify_team,
            'services_isolated': isolate_services
        }

        self._save_state(state)

        return state

    def deactivate_war_room(self,
                           resolution: Optional[str] = None,
                           notify_team: bool = True) -> bool:
        """
        Deactivate war room

        Args:
            resolution: Optional resolution summary
            notify_team: Send team notification (default: True)

        Returns:
            True if deactivated successfully
        """
        # Load current state
        state = self._load_state()
        if not state:
            return False

        incident_id = state['incident_id']

        # Get incident
        incident = self.tracker.get_incident(incident_id)
        if not incident:
            return False

        # Update incident to mark war room as inactive
        self.tracker.db.update_incident(
            incident_id,
            war_room_active=False
        )

        # Log deactivation to timeline
        self.tracker.db.add_timeline_event(
            incident_id=incident_id,
            event_type='war_room',
            event='War room deactivated',
            actor='war-room-commander',
            metadata={'resolution': resolution}
        )

        # Send team notification
        if notify_team:
            self.notifier.send_war_room_deactivation(
                incident_id=incident_id,
                title=incident['title'],
                resolution=resolution
            )

        # Update state
        state['status'] = 'inactive'
        state['deactivated_at'] = datetime.now(UTC).isoformat()
        self._save_state(state)

        return True

    def get_status(self) -> Optional[Dict[str, Any]]:
        """Get current war room status"""
        state = self._load_state()
        if not state or state['status'] != 'active':
            return None

        # Get incident details
        incident = self.tracker.get_incident(state['incident_id'])
        if not incident:
            return None

        # Get timeline
        timeline = self.tracker.db.get_timeline(state['incident_id'])

        # Get actions
        actions = self.tracker.db.get_actions(state['incident_id'])

        return {
            'state': state,
            'incident': incident,
            'timeline': timeline,
            'actions': actions,
            'duration': self._calculate_duration(state['activated_at'])
        }

    def get_timeline(self, limit: int = 50) -> list:
        """Get war room timeline"""
        state = self._load_state()
        if not state:
            return []

        timeline = self.tracker.db.get_timeline(state['incident_id'])
        return timeline[-limit:] if len(timeline) > limit else timeline

    def broadcast_message(self, message: str, priority: str = 'high') -> bool:
        """Broadcast message to team"""
        state = self._load_state()
        if not state or state['status'] != 'active':
            return False

        incident_id = state['incident_id']
        incident = self.tracker.get_incident(incident_id)

        if not incident:
            return False

        # Send notification
        return self.notifier.send_custom_alert(
            incident_id=incident_id,
            alert_title='War Room Update',
            alert_body=message,
            priority=priority
        )

    def escalate_severity(self, new_severity: str, reason: str) -> bool:
        """Escalate incident severity"""
        state = self._load_state()
        if not state or state['status'] != 'active':
            return False

        incident = self.tracker.escalate_severity(
            incident_id=state['incident_id'],
            new_severity=new_severity,
            reason=reason,
            actor='war-room-commander'
        )

        if incident:
            # Notify team of escalation
            self.notifier.send_status_update(
                incident_id=state['incident_id'],
                status='escalated',
                message=f"Severity escalated to {new_severity.upper()}\n\nReason: {reason}",
                severity='critical' if new_severity == 'critical' else 'high'
            )

        return incident is not None

    def _save_state(self, state: Dict[str, Any]):
        """Save war room state to disk"""
        with open(self.state_file, 'w') as f:
            json.dump(state, f, indent=2)

    def _load_state(self) -> Optional[Dict[str, Any]]:
        """Load war room state from disk"""
        if not self.state_file.exists():
            return None

        with open(self.state_file, 'r') as f:
            return json.load(f)

    def _calculate_duration(self, start_time: str) -> str:
        """Calculate duration since war room activation"""
        start = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
        now = datetime.now(UTC)
        delta = now - start

        hours = delta.seconds // 3600
        minutes = (delta.seconds % 3600) // 60

        if delta.days > 0:
            return f"{delta.days}d {hours}h {minutes}m"
        elif hours > 0:
            return f"{hours}h {minutes}m"
        else:
            return f"{minutes}m"

    def close(self):
        """Close database connections"""
        self.tracker.close()


def main():
    """Test war room commander"""
    commander = WarRoomCommander()

    # Clean up test state
    state_file = Path.home() / '.akali' / 'war_room_state.json'
    if state_file.exists():
        state_file.unlink()

    # Create test incident
    print("Creating test incident...")
    incident = commander.tracker.create_incident(
        title='Test War Room Incident',
        severity='critical',
        description='Testing war room activation',
        incident_type='test',
        affected_systems=['test-api']
    )
    incident_id = incident['id']
    print(f"Created: {incident_id}")

    # Activate war room
    print("\nActivating war room...")
    state = commander.activate_war_room(
        incident_id=incident_id,
        notify_team=True,
        isolate_services=False
    )
    print(f"War room activated: {state['status']}")

    # Get status
    print("\nWar room status:")
    status = commander.get_status()
    if status:
        print(f"  Incident: {status['incident']['title']}")
        print(f"  Status: {status['incident']['status']}")
        print(f"  Severity: {status['incident']['severity']}")
        print(f"  Duration: {status['duration']}")
        print(f"  Timeline events: {len(status['timeline'])}")

    # Broadcast message
    print("\nBroadcasting message...")
    commander.broadcast_message("Test war room message", priority='high')
    print("Message sent")

    # Escalate severity
    print("\nEscalating severity (test)...")
    # Skip escalation since already critical

    # Deactivate war room
    print("\nDeactivating war room...")
    commander.deactivate_war_room(
        resolution='Test completed successfully',
        notify_team=True
    )
    print("War room deactivated")

    # Verify deactivation
    status = commander.get_status()
    print(f"War room active: {status is not None}")

    commander.close()
    print("\nTest completed!")


if __name__ == '__main__':
    main()

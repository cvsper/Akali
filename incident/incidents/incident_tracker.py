#!/usr/bin/env python3
"""
Akali Incident Tracker
High-level incident lifecycle management and coordination
"""

import json
import hashlib
from datetime import datetime, UTC
from pathlib import Path
from typing import Dict, List, Optional, Any

from incident.incidents.incident_db import IncidentDB


class IncidentTracker:
    """High-level incident lifecycle manager"""

    # Status flow: new → active → contained → resolved → closed
    VALID_STATUSES = ['new', 'active', 'contained', 'resolved', 'closed']
    STATUS_TRANSITIONS = {
        'new': ['active', 'closed'],
        'active': ['contained', 'resolved', 'closed'],
        'contained': ['resolved', 'closed'],
        'resolved': ['closed', 'active'],  # Can reopen
        'closed': []  # Terminal state
    }

    SEVERITY_LEVELS = ['low', 'medium', 'high', 'critical']

    def __init__(self, db_path: Optional[str] = None):
        """Initialize incident tracker"""
        self.db = IncidentDB(db_path)

    def create_incident(self,
                       title: str,
                       severity: str,
                       description: Optional[str] = None,
                       incident_type: Optional[str] = None,
                       affected_systems: Optional[List[str]] = None,
                       assigned_to: Optional[List[str]] = None,
                       auto_activate: bool = False) -> Dict[str, Any]:
        """
        Create a new incident

        Args:
            title: Incident title
            severity: Severity level (low, medium, high, critical)
            description: Detailed description
            incident_type: Type of incident (sql_injection, data_breach, etc.)
            affected_systems: List of affected systems
            assigned_to: List of assigned team members
            auto_activate: If True, immediately activate the incident

        Returns:
            Created incident dict
        """
        # Validate severity
        if severity not in self.SEVERITY_LEVELS:
            raise ValueError(f"Invalid severity: {severity}. Must be one of: {self.SEVERITY_LEVELS}")

        # Generate incident ID
        incident_id = self._generate_incident_id(title)

        # Create incident
        incident = self.db.create_incident(
            incident_id=incident_id,
            title=title,
            severity=severity,
            description=description,
            incident_type=incident_type,
            affected_systems=affected_systems,
            assigned_to=assigned_to
        )

        # Auto-activate if requested (for critical incidents)
        if auto_activate or severity == 'critical':
            incident = self.update_status(incident_id, 'active', actor='akali-auto')

        return incident

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Get incident by ID"""
        return self.db.get_incident(incident_id)

    def list_incidents(self,
                      status: Optional[str] = None,
                      severity: Optional[str] = None,
                      limit: int = 50) -> List[Dict[str, Any]]:
        """List incidents with filtering"""
        return self.db.list_incidents(status=status, severity=severity, limit=limit)

    def get_active_incidents(self) -> List[Dict[str, Any]]:
        """Get all active incidents"""
        return [
            inc for inc in self.db.list_incidents(limit=1000)
            if inc['status'] in ['new', 'active', 'contained']
        ]

    def update_status(self,
                     incident_id: str,
                     new_status: str,
                     actor: Optional[str] = None,
                     note: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Update incident status with validation

        Args:
            incident_id: Incident ID
            new_status: New status
            actor: Who/what is making the change
            note: Optional note about the status change

        Returns:
            Updated incident or None if validation fails
        """
        # Validate status
        if new_status not in self.VALID_STATUSES:
            raise ValueError(f"Invalid status: {new_status}. Must be one of: {self.VALID_STATUSES}")

        # Get current incident
        incident = self.db.get_incident(incident_id)
        if not incident:
            return None

        current_status = incident['status']

        # Validate transition
        if new_status not in self.STATUS_TRANSITIONS.get(current_status, []):
            raise ValueError(
                f"Invalid status transition from {current_status} to {new_status}. "
                f"Valid transitions: {self.STATUS_TRANSITIONS.get(current_status, [])}"
            )

        # Update status
        incident = self.db.update_incident(incident_id, status=new_status)

        # Add timeline event with note
        event_text = f'Status changed from {current_status} to {new_status}'
        if note:
            event_text += f': {note}'

        self.db.add_timeline_event(
            incident_id=incident_id,
            event_type='status_change',
            event=event_text,
            actor=actor or 'unknown'
        )

        return incident

    def assign_team_member(self,
                          incident_id: str,
                          team_member: str,
                          actor: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Assign team member to incident"""
        incident = self.db.get_incident(incident_id)
        if not incident:
            return None

        assigned = incident['assigned_to']
        if team_member not in assigned:
            assigned.append(team_member)
            incident = self.db.update_incident(incident_id, assigned_to=assigned)

            self.db.add_timeline_event(
                incident_id=incident_id,
                event_type='assignment',
                event=f'Team member assigned: {team_member}',
                actor=actor or 'unknown'
            )

        return incident

    def unassign_team_member(self,
                            incident_id: str,
                            team_member: str,
                            actor: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Remove team member from incident"""
        incident = self.db.get_incident(incident_id)
        if not incident:
            return None

        assigned = incident['assigned_to']
        if team_member in assigned:
            assigned.remove(team_member)
            incident = self.db.update_incident(incident_id, assigned_to=assigned)

            self.db.add_timeline_event(
                incident_id=incident_id,
                event_type='assignment',
                event=f'Team member unassigned: {team_member}',
                actor=actor or 'unknown'
            )

        return incident

    def add_affected_system(self,
                           incident_id: str,
                           system: str,
                           actor: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Add affected system to incident"""
        incident = self.db.get_incident(incident_id)
        if not incident:
            return None

        systems = incident['affected_systems']
        if system not in systems:
            systems.append(system)
            incident = self.db.update_incident(incident_id, affected_systems=systems)

            self.db.add_timeline_event(
                incident_id=incident_id,
                event_type='scope_change',
                event=f'Affected system added: {system}',
                actor=actor or 'unknown'
            )

        return incident

    def escalate_severity(self,
                         incident_id: str,
                         new_severity: str,
                         reason: str,
                         actor: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Escalate incident severity"""
        if new_severity not in self.SEVERITY_LEVELS:
            raise ValueError(f"Invalid severity: {new_severity}")

        incident = self.db.get_incident(incident_id)
        if not incident:
            return None

        old_severity = incident['severity']
        incident = self.db.update_incident(incident_id, severity=new_severity)

        self.db.add_timeline_event(
            incident_id=incident_id,
            event_type='escalation',
            event=f'Severity escalated from {old_severity} to {new_severity}: {reason}',
            actor=actor or 'unknown'
        )

        return incident

    def attach_playbook(self,
                       incident_id: str,
                       playbook_id: str,
                       actor: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Attach playbook to incident"""
        incident = self.db.update_incident(incident_id, playbook_id=playbook_id)

        if incident:
            self.db.add_timeline_event(
                incident_id=incident_id,
                event_type='playbook',
                event=f'Playbook attached: {playbook_id}',
                actor=actor or 'unknown'
            )

        return incident

    def add_note(self,
                incident_id: str,
                note: str,
                actor: Optional[str] = None) -> bool:
        """Add note to incident timeline"""
        self.db.add_timeline_event(
            incident_id=incident_id,
            event_type='note',
            event=note,
            actor=actor or 'unknown'
        )
        return True

    def log_action(self,
                  incident_id: str,
                  action_type: str,
                  action: str,
                  status: str = 'pending',
                  actor: Optional[str] = None) -> int:
        """Log an action taken for the incident"""
        return self.db.add_action(
            incident_id=incident_id,
            action_type=action_type,
            action=action,
            status=status,
            performed_by=actor or 'unknown'
        )

    def complete_action(self,
                       action_id: int,
                       result: Optional[str] = None) -> bool:
        """Mark action as completed"""
        return self.db.update_action(action_id, status='completed', result=result)

    def fail_action(self,
                   action_id: int,
                   result: Optional[str] = None) -> bool:
        """Mark action as failed"""
        return self.db.update_action(action_id, status='failed', result=result)

    def collect_evidence(self,
                        incident_id: str,
                        evidence_type: str,
                        file_path: Optional[str] = None,
                        description: Optional[str] = None,
                        actor: Optional[str] = None) -> int:
        """Collect and store evidence"""
        # Calculate file hash if file exists
        file_hash = None
        if file_path and Path(file_path).exists():
            file_hash = self._hash_file(file_path)

        return self.db.add_evidence(
            incident_id=incident_id,
            evidence_type=evidence_type,
            file_path=file_path,
            file_hash=file_hash,
            description=description,
            collected_by=actor or 'unknown'
        )

    def get_full_incident_report(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Get complete incident data including timeline, evidence, and actions"""
        incident = self.db.get_incident(incident_id)
        if not incident:
            return None

        return {
            'incident': incident,
            'timeline': self.db.get_timeline(incident_id),
            'evidence': self.db.get_evidence(incident_id),
            'actions': self.db.get_actions(incident_id)
        }

    def close_incident(self,
                      incident_id: str,
                      resolution: str,
                      actor: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Close incident with resolution note"""
        incident = self.update_status(
            incident_id=incident_id,
            new_status='closed',
            actor=actor,
            note=f'Resolution: {resolution}'
        )

        return incident

    def reopen_incident(self,
                       incident_id: str,
                       reason: str,
                       actor: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Reopen a resolved incident"""
        incident = self.db.get_incident(incident_id)
        if not incident:
            return None

        if incident['status'] != 'resolved':
            raise ValueError("Can only reopen incidents in 'resolved' status")

        return self.update_status(
            incident_id=incident_id,
            new_status='active',
            actor=actor,
            note=f'Reopened: {reason}'
        )

    def _generate_incident_id(self, title: str) -> str:
        """Generate unique incident ID"""
        # Simple counter-based ID (INCIDENT-001, INCIDENT-002, etc.)
        incidents = self.db.list_incidents(limit=1)
        if incidents:
            # Get highest ID number
            existing_ids = [inc['id'] for inc in self.db.list_incidents(limit=10000)]
            numbers = [int(id.split('-')[1]) for id in existing_ids if id.startswith('INCIDENT-')]
            if numbers:
                next_num = max(numbers) + 1
            else:
                next_num = 1
        else:
            next_num = 1

        return f'INCIDENT-{next_num:03d}'

    def _hash_file(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

    def close(self):
        """Close database connection"""
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def main():
    """Test incident tracker"""
    tracker = IncidentTracker()

    # Clean up test database
    import os
    db_path = os.path.expanduser('~/.akali/incidents.db')
    if os.path.exists(db_path):
        os.remove(db_path)
        tracker = IncidentTracker()

    # Create incident
    print("Creating incident...")
    incident = tracker.create_incident(
        title='SQL Injection in Booking API',
        severity='critical',
        description='Suspected SQL injection vulnerability detected',
        incident_type='sql_injection',
        affected_systems=['booking-api'],
        assigned_to=['dommo']
    )
    print(f"Created: {incident['id']} - Status: {incident['status']}")

    # Check status (auto-activated because critical)
    print(f"\nIncident auto-activated due to severity: {incident['status']}")

    # Add team member
    print("\nAssigning team member...")
    incident = tracker.assign_team_member(incident['id'], 'zim', actor='dommo')
    print(f"Assigned: {incident['assigned_to']}")

    # Add affected system
    print("\nAdding affected system...")
    incident = tracker.add_affected_system(incident['id'], 'user-api', actor='dommo')
    print(f"Affected systems: {incident['affected_systems']}")

    # Log action
    print("\nLogging action...")
    action_id = tracker.log_action(
        incident_id=incident['id'],
        action_type='containment',
        action='Isolate booking API',
        status='in_progress',
        actor='akali'
    )
    print(f"Action logged: {action_id}")

    # Collect evidence
    print("\nCollecting evidence...")
    evidence_id = tracker.collect_evidence(
        incident_id=incident['id'],
        evidence_type='log',
        description='API access logs',
        actor='akali'
    )
    print(f"Evidence collected: {evidence_id}")

    # Contain incident
    print("\nContaining incident...")
    incident = tracker.update_status(incident['id'], 'contained', actor='dommo', note='API isolated successfully')
    print(f"Status: {incident['status']}")

    # Complete action
    print("\nCompleting action...")
    tracker.complete_action(action_id, result='API successfully isolated')
    print("Action completed")

    # Resolve incident
    print("\nResolving incident...")
    incident = tracker.update_status(incident['id'], 'resolved', actor='dommo', note='Vulnerability patched')
    print(f"Status: {incident['status']}")

    # Get full report
    print("\nFull incident report:")
    report = tracker.get_full_incident_report(incident['id'])
    print(f"Timeline events: {len(report['timeline'])}")
    print(f"Evidence items: {len(report['evidence'])}")
    print(f"Actions: {len(report['actions'])}")

    # Close incident
    print("\nClosing incident...")
    incident = tracker.close_incident(
        incident_id=incident['id'],
        resolution='SQL injection fixed by implementing parameterized queries',
        actor='dommo'
    )
    print(f"Status: {incident['status']}")

    tracker.close()
    print("\nTest completed successfully!")


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
Akali Incident Database
SQLite-based incident tracking database with timeline, evidence, and action tracking
"""

import sqlite3
import json
import os
from datetime import datetime, UTC
from pathlib import Path
from typing import Dict, List, Optional, Any


class IncidentDB:
    """Incident database manager"""

    def __init__(self, db_path: Optional[str] = None):
        """Initialize incident database"""
        if db_path is None:
            # Default to ~/.akali/incidents.db
            akali_dir = Path.home() / '.akali'
            akali_dir.mkdir(exist_ok=True)
            db_path = str(akali_dir / 'incidents.db')

        self.db_path = db_path
        self.conn = None
        self._init_db()

    def _init_db(self):
        """Initialize database schema"""
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row  # Enable dict-like access

        cursor = self.conn.cursor()

        # Incidents table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT NOT NULL,  -- low, medium, high, critical
                status TEXT NOT NULL,     -- new, active, contained, resolved, closed
                incident_type TEXT,       -- sql_injection, data_breach, ransomware, etc.
                affected_systems TEXT,    -- JSON array of affected systems
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                closed_at TEXT,
                assigned_to TEXT,         -- JSON array of team members
                playbook_id TEXT,         -- Associated playbook
                war_room_active BOOLEAN DEFAULT 0,
                metadata TEXT             -- JSON for extensibility
            )
        ''')

        # Incident timeline table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS incident_timeline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,  -- status_change, action, note, alert
                event TEXT NOT NULL,       -- Event description
                actor TEXT,                -- Who/what caused the event
                metadata TEXT,             -- JSON for additional data
                FOREIGN KEY (incident_id) REFERENCES incidents(id)
            )
        ''')

        # Incident evidence table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS incident_evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                evidence_type TEXT NOT NULL,  -- log, screenshot, file, network_capture
                file_path TEXT,               -- Path to evidence file
                file_hash TEXT,               -- SHA256 hash for integrity
                description TEXT,
                collected_at TEXT NOT NULL,
                collected_by TEXT,            -- Agent/person who collected
                chain_of_custody TEXT,        -- JSON tracking evidence handling
                metadata TEXT,                -- JSON for additional data
                FOREIGN KEY (incident_id) REFERENCES incidents(id)
            )
        ''')

        # Incident actions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS incident_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                action_type TEXT NOT NULL,  -- containment, investigation, remediation, notification
                action TEXT NOT NULL,       -- Action description
                status TEXT NOT NULL,       -- pending, in_progress, completed, failed
                result TEXT,                -- Action result/output
                started_at TEXT,
                completed_at TEXT,
                performed_by TEXT,          -- Agent/person who performed action
                metadata TEXT,              -- JSON for additional data
                FOREIGN KEY (incident_id) REFERENCES incidents(id)
            )
        ''')

        # Create indexes for performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents(created_at)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timeline_incident ON incident_timeline(incident_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_evidence_incident ON incident_evidence(incident_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_actions_incident ON incident_actions(incident_id)')

        self.conn.commit()

    def create_incident(self,
                       incident_id: str,
                       title: str,
                       severity: str,
                       description: Optional[str] = None,
                       incident_type: Optional[str] = None,
                       affected_systems: Optional[List[str]] = None,
                       assigned_to: Optional[List[str]] = None,
                       metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Create a new incident"""
        now = datetime.now(UTC).isoformat()

        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO incidents (
                id, title, description, severity, status, incident_type,
                affected_systems, created_at, updated_at, assigned_to, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            incident_id,
            title,
            description,
            severity,
            'new',
            incident_type,
            json.dumps(affected_systems or []),
            now,
            now,
            json.dumps(assigned_to or []),
            json.dumps(metadata or {})
        ))

        self.conn.commit()

        # Log creation to timeline
        self.add_timeline_event(
            incident_id=incident_id,
            event_type='status_change',
            event=f'Incident created: {title}',
            actor='akali'
        )

        return self.get_incident(incident_id)

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Get incident by ID"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT * FROM incidents WHERE id = ?', (incident_id,))
        row = cursor.fetchone()

        if not row:
            return None

        incident = dict(row)
        # Parse JSON fields
        incident['affected_systems'] = json.loads(incident['affected_systems'])
        incident['assigned_to'] = json.loads(incident['assigned_to'])
        incident['metadata'] = json.loads(incident['metadata'])

        return incident

    def update_incident(self, incident_id: str, **updates) -> Optional[Dict[str, Any]]:
        """Update incident fields"""
        allowed_fields = [
            'title', 'description', 'severity', 'status', 'incident_type',
            'affected_systems', 'assigned_to', 'playbook_id', 'war_room_active', 'metadata'
        ]

        # Filter to only allowed fields
        updates = {k: v for k, v in updates.items() if k in allowed_fields}

        if not updates:
            return self.get_incident(incident_id)

        # Convert list/dict fields to JSON
        for field in ['affected_systems', 'assigned_to', 'metadata']:
            if field in updates and isinstance(updates[field], (list, dict)):
                updates[field] = json.dumps(updates[field])

        # Always update updated_at
        updates['updated_at'] = datetime.utcnow().isoformat()

        # If closing, set closed_at
        if updates.get('status') == 'closed' and 'closed_at' not in updates:
            updates['closed_at'] = updates['updated_at']

        # Build SQL
        set_clause = ', '.join([f'{k} = ?' for k in updates.keys()])
        values = list(updates.values()) + [incident_id]

        cursor = self.conn.cursor()
        cursor.execute(f'UPDATE incidents SET {set_clause} WHERE id = ?', values)
        self.conn.commit()

        # Log status change to timeline
        if 'status' in updates:
            self.add_timeline_event(
                incident_id=incident_id,
                event_type='status_change',
                event=f'Status changed to: {updates["status"]}',
                actor='akali'
            )

        return self.get_incident(incident_id)

    def list_incidents(self,
                      status: Optional[str] = None,
                      severity: Optional[str] = None,
                      limit: int = 50,
                      offset: int = 0) -> List[Dict[str, Any]]:
        """List incidents with optional filtering"""
        query = 'SELECT * FROM incidents WHERE 1=1'
        params = []

        if status:
            query += ' AND status = ?'
            params.append(status)

        if severity:
            query += ' AND severity = ?'
            params.append(severity)

        query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?'
        params.extend([limit, offset])

        cursor = self.conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()

        incidents = []
        for row in rows:
            incident = dict(row)
            incident['affected_systems'] = json.loads(incident['affected_systems'])
            incident['assigned_to'] = json.loads(incident['assigned_to'])
            incident['metadata'] = json.loads(incident['metadata'])
            incidents.append(incident)

        return incidents

    def search_incidents(self, search_term: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Search incidents by title or description"""
        query = '''
            SELECT * FROM incidents
            WHERE title LIKE ? OR description LIKE ?
            ORDER BY created_at DESC LIMIT ?
        '''
        search_pattern = f'%{search_term}%'

        cursor = self.conn.cursor()
        cursor.execute(query, (search_pattern, search_pattern, limit))
        rows = cursor.fetchall()

        incidents = []
        for row in rows:
            incident = dict(row)
            incident['affected_systems'] = json.loads(incident['affected_systems'])
            incident['assigned_to'] = json.loads(incident['assigned_to'])
            incident['metadata'] = json.loads(incident['metadata'])
            incidents.append(incident)

        return incidents

    def add_timeline_event(self,
                          incident_id: str,
                          event_type: str,
                          event: str,
                          actor: Optional[str] = None,
                          metadata: Optional[Dict[str, Any]] = None) -> int:
        """Add event to incident timeline"""
        now = datetime.now(UTC).isoformat()

        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO incident_timeline (
                incident_id, timestamp, event_type, event, actor, metadata
            ) VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            incident_id,
            now,
            event_type,
            event,
            actor,
            json.dumps(metadata or {})
        ))

        self.conn.commit()
        return cursor.lastrowid

    def get_timeline(self, incident_id: str) -> List[Dict[str, Any]]:
        """Get incident timeline"""
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT * FROM incident_timeline
            WHERE incident_id = ?
            ORDER BY timestamp ASC
        ''', (incident_id,))
        rows = cursor.fetchall()

        timeline = []
        for row in rows:
            event = dict(row)
            event['metadata'] = json.loads(event['metadata'])
            timeline.append(event)

        return timeline

    def add_evidence(self,
                    incident_id: str,
                    evidence_type: str,
                    file_path: Optional[str] = None,
                    file_hash: Optional[str] = None,
                    description: Optional[str] = None,
                    collected_by: Optional[str] = None,
                    metadata: Optional[Dict[str, Any]] = None) -> int:
        """Add evidence to incident"""
        now = datetime.now(UTC).isoformat()

        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO incident_evidence (
                incident_id, evidence_type, file_path, file_hash,
                description, collected_at, collected_by,
                chain_of_custody, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            incident_id,
            evidence_type,
            file_path,
            file_hash,
            description,
            now,
            collected_by,
            json.dumps([{
                'timestamp': now,
                'action': 'collected',
                'by': collected_by
            }]),
            json.dumps(metadata or {})
        ))

        self.conn.commit()

        # Log to timeline
        self.add_timeline_event(
            incident_id=incident_id,
            event_type='evidence',
            event=f'Evidence collected: {evidence_type}',
            actor=collected_by
        )

        return cursor.lastrowid

    def get_evidence(self, incident_id: str) -> List[Dict[str, Any]]:
        """Get all evidence for incident"""
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT * FROM incident_evidence
            WHERE incident_id = ?
            ORDER BY collected_at DESC
        ''', (incident_id,))
        rows = cursor.fetchall()

        evidence_list = []
        for row in rows:
            evidence = dict(row)
            evidence['chain_of_custody'] = json.loads(evidence['chain_of_custody'])
            evidence['metadata'] = json.loads(evidence['metadata'])
            evidence_list.append(evidence)

        return evidence_list

    def add_action(self,
                  incident_id: str,
                  action_type: str,
                  action: str,
                  status: str = 'pending',
                  performed_by: Optional[str] = None,
                  metadata: Optional[Dict[str, Any]] = None) -> int:
        """Add action to incident"""
        now = datetime.now(UTC).isoformat()

        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO incident_actions (
                incident_id, action_type, action, status,
                started_at, performed_by, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            incident_id,
            action_type,
            action,
            status,
            now if status != 'pending' else None,
            performed_by,
            json.dumps(metadata or {})
        ))

        self.conn.commit()

        # Log to timeline
        self.add_timeline_event(
            incident_id=incident_id,
            event_type='action',
            event=f'Action started: {action}',
            actor=performed_by
        )

        return cursor.lastrowid

    def update_action(self, action_id: int,
                     status: Optional[str] = None,
                     result: Optional[str] = None) -> bool:
        """Update action status/result"""
        updates = {}

        if status:
            updates['status'] = status
            if status == 'in_progress' and not updates.get('started_at'):
                updates['started_at'] = datetime.utcnow().isoformat()
            elif status in ('completed', 'failed'):
                updates['completed_at'] = datetime.utcnow().isoformat()

        if result:
            updates['result'] = result

        if not updates:
            return False

        set_clause = ', '.join([f'{k} = ?' for k in updates.keys()])
        values = list(updates.values()) + [action_id]

        cursor = self.conn.cursor()
        cursor.execute(f'UPDATE incident_actions SET {set_clause} WHERE id = ?', values)
        self.conn.commit()

        return cursor.rowcount > 0

    def get_actions(self, incident_id: str) -> List[Dict[str, Any]]:
        """Get all actions for incident"""
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT * FROM incident_actions
            WHERE incident_id = ?
            ORDER BY started_at DESC
        ''', (incident_id,))
        rows = cursor.fetchall()

        actions = []
        for row in rows:
            action = dict(row)
            action['metadata'] = json.loads(action['metadata'])
            actions.append(action)

        return actions

    def get_stats(self) -> Dict[str, Any]:
        """Get incident statistics"""
        cursor = self.conn.cursor()

        # Total incidents
        cursor.execute('SELECT COUNT(*) as count FROM incidents')
        total = cursor.fetchone()['count']

        # By status
        cursor.execute('SELECT status, COUNT(*) as count FROM incidents GROUP BY status')
        by_status = {row['status']: row['count'] for row in cursor.fetchall()}

        # By severity
        cursor.execute('SELECT severity, COUNT(*) as count FROM incidents GROUP BY severity')
        by_severity = {row['severity']: row['count'] for row in cursor.fetchall()}

        # Active war rooms
        cursor.execute('SELECT COUNT(*) as count FROM incidents WHERE war_room_active = 1')
        active_war_rooms = cursor.fetchone()['count']

        return {
            'total_incidents': total,
            'by_status': by_status,
            'by_severity': by_severity,
            'active_war_rooms': active_war_rooms
        }

    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def main():
    """Test incident database"""
    db = IncidentDB()

    # Test creating an incident
    incident = db.create_incident(
        incident_id='INCIDENT-001',
        title='Test SQL Injection',
        severity='critical',
        description='Suspected SQL injection in booking API',
        incident_type='sql_injection',
        affected_systems=['booking-api'],
        assigned_to=['dommo']
    )

    print(f"Created incident: {incident['id']}")
    print(f"Status: {incident['status']}")

    # Test adding timeline event
    db.add_timeline_event(
        incident_id='INCIDENT-001',
        event_type='alert',
        event='Suspicious SQL query detected',
        actor='scanner'
    )

    # Test adding evidence
    db.add_evidence(
        incident_id='INCIDENT-001',
        evidence_type='log',
        file_path='/var/log/api.log',
        description='API access logs',
        collected_by='akali'
    )

    # Test adding action
    db.add_action(
        incident_id='INCIDENT-001',
        action_type='containment',
        action='Isolate booking API',
        status='in_progress',
        performed_by='akali'
    )

    # Get stats
    stats = db.get_stats()
    print(f"\nStats: {json.dumps(stats, indent=2)}")

    db.close()
    print("\nTest completed successfully!")


if __name__ == '__main__':
    main()

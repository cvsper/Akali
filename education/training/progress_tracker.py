#!/usr/bin/env python3
"""
Akali Progress Tracker - Track user training progress

Stores training session results in SQLite database:
- Module completion status
- Quiz scores
- Certificates earned
- Progress over time
"""

import sqlite3
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import json


class ProgressTracker:
    """Track and persist user training progress"""

    def __init__(self, db_path: str = None):
        if db_path is None:
            # Default to ~/.akali/training.db
            akali_dir = Path.home() / ".akali"
            akali_dir.mkdir(exist_ok=True)
            db_path = str(akali_dir / "training.db")

        self.db_path = db_path
        self._init_database()

    def _init_database(self):
        """Initialize database schema"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS training_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    module_id TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    passed BOOLEAN,
                    score INTEGER,
                    total_questions INTEGER,
                    percentage REAL,
                    certificate_issued BOOLEAN DEFAULT 0,
                    metadata TEXT
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS module_progress (
                    agent_id TEXT,
                    module_id TEXT,
                    attempts INTEGER DEFAULT 0,
                    best_score INTEGER DEFAULT 0,
                    best_percentage REAL DEFAULT 0,
                    first_attempt TEXT,
                    last_attempt TEXT,
                    completed BOOLEAN DEFAULT 0,
                    PRIMARY KEY (agent_id, module_id)
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS certificates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    module_id TEXT NOT NULL,
                    issued_at TEXT NOT NULL,
                    certificate_path TEXT,
                    UNIQUE(agent_id, module_id)
                )
            """)

            # Indexes for performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_agent ON training_sessions(agent_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_module ON training_sessions(module_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_progress_agent ON module_progress(agent_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_certificates_agent ON certificates(agent_id)")

            conn.commit()

    def record_session(self, session_data: Dict[str, Any]) -> int:
        """Record a training session"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                INSERT INTO training_sessions (
                    agent_id, module_id, started_at, completed_at,
                    passed, score, total_questions, percentage, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                session_data.get('agent_id', 'unknown'),
                session_data['module_id'],
                datetime.now().isoformat(),
                session_data.get('timestamp', datetime.now().isoformat()),
                session_data.get('passed', False),
                session_data.get('score', 0),
                session_data.get('total_questions', 0),
                session_data.get('percentage', 0.0),
                json.dumps(session_data.get('answers', []))
            ))
            session_id = cursor.lastrowid

            # Update module progress
            self._update_module_progress(
                conn,
                session_data.get('agent_id', 'unknown'),
                session_data['module_id'],
                session_data.get('passed', False),
                session_data.get('score', 0),
                session_data.get('percentage', 0.0)
            )

            conn.commit()
            return session_id

    def _update_module_progress(self, conn, agent_id: str, module_id: str,
                                 passed: bool, score: int, percentage: float):
        """Update aggregated module progress"""
        # Get current progress
        cursor = conn.execute("""
            SELECT attempts, best_score, best_percentage, first_attempt
            FROM module_progress
            WHERE agent_id = ? AND module_id = ?
        """, (agent_id, module_id))

        row = cursor.fetchone()

        if row:
            attempts, best_score, best_percentage, first_attempt = row
            attempts += 1
            best_score = max(best_score, score)
            best_percentage = max(best_percentage, percentage)

            conn.execute("""
                UPDATE module_progress
                SET attempts = ?, best_score = ?, best_percentage = ?,
                    last_attempt = ?, completed = ?
                WHERE agent_id = ? AND module_id = ?
            """, (
                attempts, best_score, best_percentage,
                datetime.now().isoformat(), passed,
                agent_id, module_id
            ))
        else:
            # First attempt
            conn.execute("""
                INSERT INTO module_progress (
                    agent_id, module_id, attempts, best_score, best_percentage,
                    first_attempt, last_attempt, completed
                ) VALUES (?, ?, 1, ?, ?, ?, ?, ?)
            """, (
                agent_id, module_id, score, percentage,
                datetime.now().isoformat(), datetime.now().isoformat(), passed
            ))

    def get_agent_progress(self, agent_id: str) -> Dict[str, Any]:
        """Get complete progress for an agent"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row

            # Get module progress
            cursor = conn.execute("""
                SELECT * FROM module_progress
                WHERE agent_id = ?
                ORDER BY last_attempt DESC
            """, (agent_id,))

            modules = [dict(row) for row in cursor.fetchall()]

            # Get certificates
            cursor = conn.execute("""
                SELECT * FROM certificates
                WHERE agent_id = ?
            """, (agent_id,))

            certificates = [dict(row) for row in cursor.fetchall()]

            # Get recent sessions
            cursor = conn.execute("""
                SELECT * FROM training_sessions
                WHERE agent_id = ?
                ORDER BY started_at DESC
                LIMIT 10
            """, (agent_id,))

            recent_sessions = [dict(row) for row in cursor.fetchall()]

            # Calculate statistics
            total_modules = len(modules)
            completed_modules = sum(1 for m in modules if m['completed'])
            total_attempts = sum(m['attempts'] for m in modules)
            avg_score = sum(m['best_percentage'] for m in modules) / total_modules if total_modules > 0 else 0

            return {
                'agent_id': agent_id,
                'modules': modules,
                'certificates': certificates,
                'recent_sessions': recent_sessions,
                'stats': {
                    'total_modules': total_modules,
                    'completed_modules': completed_modules,
                    'completion_rate': (completed_modules / total_modules * 100) if total_modules > 0 else 0,
                    'total_attempts': total_attempts,
                    'average_score': avg_score,
                    'certificates_earned': len(certificates)
                }
            }

    def get_module_progress(self, agent_id: str, module_id: str) -> Optional[Dict[str, Any]]:
        """Get progress for a specific module"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row

            cursor = conn.execute("""
                SELECT * FROM module_progress
                WHERE agent_id = ? AND module_id = ?
            """, (agent_id, module_id))

            row = cursor.fetchone()
            if not row:
                return None

            return dict(row)

    def mark_certificate_issued(self, agent_id: str, module_id: str, certificate_path: str):
        """Mark that a certificate was issued"""
        with sqlite3.connect(self.db_path) as conn:
            # Insert or replace certificate
            conn.execute("""
                INSERT OR REPLACE INTO certificates (agent_id, module_id, issued_at, certificate_path)
                VALUES (?, ?, ?, ?)
            """, (agent_id, module_id, datetime.now().isoformat(), certificate_path))

            # Update session
            conn.execute("""
                UPDATE training_sessions
                SET certificate_issued = 1
                WHERE agent_id = ? AND module_id = ?
                  AND id = (
                      SELECT id FROM training_sessions
                      WHERE agent_id = ? AND module_id = ?
                      ORDER BY completed_at DESC
                      LIMIT 1
                  )
            """, (agent_id, module_id, agent_id, module_id))

            conn.commit()

    def get_certificates(self, agent_id: str) -> List[Dict[str, Any]]:
        """Get all certificates for an agent"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row

            cursor = conn.execute("""
                SELECT * FROM certificates
                WHERE agent_id = ?
                ORDER BY issued_at DESC
            """, (agent_id,))

            return [dict(row) for row in cursor.fetchall()]

    def get_leaderboard(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top performers across all agents"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT
                    agent_id,
                    COUNT(*) as modules_completed,
                    AVG(best_percentage) as avg_score,
                    SUM(attempts) as total_attempts
                FROM module_progress
                WHERE completed = 1
                GROUP BY agent_id
                ORDER BY modules_completed DESC, avg_score DESC
                LIMIT ?
            """, (limit,))

            return [
                {
                    'agent_id': row[0],
                    'modules_completed': row[1],
                    'avg_score': row[2],
                    'total_attempts': row[3]
                }
                for row in cursor.fetchall()
            ]


def main():
    """CLI for testing progress tracker"""
    tracker = ProgressTracker()

    # Test data
    test_session = {
        'agent_id': 'dommo',
        'module_id': 'owasp_01_injection',
        'passed': True,
        'score': 4,
        'total_questions': 5,
        'percentage': 80.0,
        'timestamp': datetime.now().isoformat()
    }

    session_id = tracker.record_session(test_session)
    print(f"✅ Recorded session #{session_id}")

    progress = tracker.get_agent_progress('dommo')
    print(f"\n📊 Progress for dommo:")
    print(f"  Modules: {progress['stats']['total_modules']}")
    print(f"  Completed: {progress['stats']['completed_modules']}")
    print(f"  Average Score: {progress['stats']['average_score']:.1f}%")


if __name__ == '__main__':
    main()

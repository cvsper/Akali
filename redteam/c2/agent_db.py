import sqlite3
import time
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class Agent:
    id: str
    hostname: str
    platform: str
    mode: str
    last_seen: float
    status: str = "active"

class AgentDB:
    """SQLite database for agent tracking"""

    def __init__(self, db_path: str = "/tmp/akali/c2.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def init_db(self):
        """Initialize database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS agents (
                id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                platform TEXT NOT NULL,
                mode TEXT NOT NULL,
                last_seen REAL NOT NULL,
                status TEXT DEFAULT 'active'
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                command TEXT NOT NULL,
                args TEXT,
                status TEXT DEFAULT 'pending',
                created_at REAL NOT NULL,
                completed_at REAL,
                FOREIGN KEY (agent_id) REFERENCES agents(id)
            )
        """)

        conn.commit()
        conn.close()

    def add_agent(self, agent: Agent):
        """Register new agent"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO agents (id, hostname, platform, mode, last_seen, status)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (agent.id, agent.hostname, agent.platform, agent.mode, agent.last_seen, agent.status))

        conn.commit()
        conn.close()

    def list_agents(self) -> List[Agent]:
        """List all agents"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT id, hostname, platform, mode, last_seen, status FROM agents")
        rows = cursor.fetchall()

        conn.close()

        return [Agent(*row) for row in rows]

    def add_task(self, task_id: str, agent_id: str, command: str, args: str, status: str):
        """Add task to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO tasks (id, agent_id, command, args, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (task_id, agent_id, command, args, status, time.time()))

        conn.commit()
        conn.close()

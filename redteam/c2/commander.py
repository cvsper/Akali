import time
import requests
from typing import List
from redteam.c2.agent_db import AgentDB, Agent

ZIM_MEMORY_API = "http://10.0.0.209:5001"

class C2Commander:
    """C2 command and control center"""

    def __init__(self, db_path: str = "/tmp/akali/c2.db"):
        self.db = AgentDB(db_path)

    def register_agent(self, hostname: str, platform: str, mode: str) -> str:
        """Register a new agent"""
        agent_id = f"agent-{int(time.time())}"

        agent = Agent(
            id=agent_id,
            hostname=hostname,
            platform=platform,
            mode=mode,
            last_seen=time.time()
        )

        self.db.add_agent(agent)
        return agent_id

    def list_agents(self) -> List[Agent]:
        """List all registered agents"""
        return self.db.list_agents()

    def send_task(self, agent_id: str, command: str, args: str = "") -> str:
        """Send task to agent via ZimMemory"""
        task_id = f"task-{int(time.time())}"

        message = {
            "from_agent": "akali",
            "to_agent": agent_id,
            "subject": task_id,
            "body": command,
            "priority": "normal",
            "metadata": {"args": args}
        }

        try:
            response = requests.post(
                f"{ZIM_MEMORY_API}/messages/send",
                json=message,
                timeout=5
            )

            if response.status_code == 200:
                # Store task in database
                self.db.add_task(task_id, agent_id, command, args, "pending")
                return task_id
            else:
                raise Exception(f"Failed to send task: {response.status_code}")
        except requests.exceptions.RequestException as e:
            # If ZimMemory unavailable, still store in DB
            self.db.add_task(task_id, agent_id, command, args, "pending")
            return task_id

import sqlite3
import time
import yaml
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

@dataclass
class Campaign:
    id: str
    name: str
    target: str
    mode: str
    template: str
    status: str
    created_at: float
    current_stage: Optional[str] = None

class CampaignOrchestrator:
    """Campaign orchestration for red/purple team operations"""

    def __init__(self, db_path: str = "/tmp/akali/campaigns.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def init_db(self):
        """Initialize database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS campaigns (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                target TEXT NOT NULL,
                mode TEXT NOT NULL,
                template TEXT NOT NULL,
                status TEXT DEFAULT 'created',
                created_at REAL NOT NULL,
                current_stage TEXT
            )
        """)

        conn.commit()
        conn.close()

    def create_campaign(self, name: str, target: str, mode: str, template: str = "mobile-test") -> str:
        """Create a new campaign"""
        campaign_id = f"campaign-{int(time.time())}"

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO campaigns (id, name, target, mode, template, status, created_at)
            VALUES (?, ?, ?, ?, ?, 'created', ?)
        """, (campaign_id, name, target, mode, template, time.time()))

        conn.commit()
        conn.close()

        return campaign_id

    def get_campaign(self, campaign_id: str) -> Campaign:
        """Get campaign by ID"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, name, target, mode, template, status, created_at, current_stage
            FROM campaigns WHERE id = ?
        """, (campaign_id,))

        row = cursor.fetchone()
        conn.close()

        if not row:
            raise ValueError(f"Campaign {campaign_id} not found")

        return Campaign(*row)

    def update_campaign_status(self, campaign_id: str, status: str):
        """Update campaign status"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE campaigns SET status = ? WHERE id = ?
        """, (status, campaign_id))

        conn.commit()
        conn.close()

    def update_campaign_stage(self, campaign_id: str, stage: str):
        """Update current campaign stage"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE campaigns SET current_stage = ? WHERE id = ?
        """, (stage, campaign_id))

        conn.commit()
        conn.close()

    def run_campaign(self, campaign_id: str):
        """Execute campaign"""
        campaign = self.get_campaign(campaign_id)
        template_path = Path(__file__).parent / "templates" / f"{campaign.template}.yaml"

        if not template_path.exists():
            print(f"[!] Template {campaign.template}.yaml not found")
            return

        with open(template_path) as f:
            template = yaml.safe_load(f)

        print(f"\n[*] Starting campaign: {campaign.name}")
        print(f"[*] Target: {campaign.target}")
        print(f"[*] Mode: {campaign.mode}")

        for stage in template['stages']:
            print(f"\n[*] Stage: {stage['name']}")
            print(f"    {stage['description']}")

            # Check if checkpoint required (red team mode)
            if campaign.mode == 'red' and stage.get('checkpoint'):
                approval = input(f"[?] Proceed with {stage['name']}? (yes/no): ")
                if approval.lower() != 'yes':
                    print("[!] Campaign halted by user")
                    self.update_campaign_status(campaign_id, "halted")
                    return

            # Execute stage tasks
            for task in stage['tasks']:
                self.execute_task(campaign_id, task)

            self.update_campaign_stage(campaign_id, stage['name'])

        print("\n[+] Campaign complete!")
        self.update_campaign_status(campaign_id, "complete")

    def execute_task(self, campaign_id: str, task: dict):
        """Execute a single campaign task"""
        action = task['action']
        params = task.get('params', {})

        print(f"    [→] {action}")
        # TODO: Implement actual task execution
        # For now, just simulate
        time.sleep(0.1)

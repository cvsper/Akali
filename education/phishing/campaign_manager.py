#!/usr/bin/env python3
"""
Akali Phishing Campaign Manager

Manages phishing simulation campaigns - creation, scheduling, targeting, and tracking.
"""

import sqlite3
import json
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
import uuid


class PhishingCampaign:
    """Represents a single phishing campaign"""

    def __init__(self, campaign_data: Dict[str, Any]):
        self.id = campaign_data['id']
        self.name = campaign_data['name']
        self.template_id = campaign_data['template_id']
        self.status = campaign_data['status']
        self.created_at = campaign_data['created_at']
        self.started_at = campaign_data.get('started_at')
        self.completed_at = campaign_data.get('completed_at')
        self.config = json.loads(campaign_data.get('config', '{}'))


class CampaignManager:
    """Manages phishing simulation campaigns"""

    def __init__(self, db_path: str = "~/.akali/phishing.db"):
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.templates_dir = Path.home() / "akali" / "education" / "phishing" / "templates"
        self._init_database()

    def _init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Campaigns table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS campaigns (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                template_id TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                config TEXT
            )
        ''')

        # Campaign targets table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS campaign_targets (
                id TEXT PRIMARY KEY,
                campaign_id TEXT NOT NULL,
                recipient_email TEXT NOT NULL,
                recipient_name TEXT,
                sent_at TEXT,
                clicked_at TEXT,
                reported_at TEXT,
                status TEXT NOT NULL,
                tracking_token TEXT UNIQUE NOT NULL,
                FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
            )
        ''')

        # Campaign clicks table (detailed click tracking)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS campaign_clicks (
                id TEXT PRIMARY KEY,
                target_id TEXT NOT NULL,
                campaign_id TEXT NOT NULL,
                clicked_at TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                referer TEXT,
                FOREIGN KEY (target_id) REFERENCES campaign_targets(id),
                FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
            )
        ''')

        # Campaign results (aggregate metrics)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS campaign_results (
                campaign_id TEXT PRIMARY KEY,
                total_targets INTEGER NOT NULL,
                emails_sent INTEGER NOT NULL DEFAULT 0,
                emails_opened INTEGER NOT NULL DEFAULT 0,
                links_clicked INTEGER NOT NULL DEFAULT 0,
                credentials_submitted INTEGER NOT NULL DEFAULT 0,
                reported INTEGER NOT NULL DEFAULT 0,
                click_rate REAL NOT NULL DEFAULT 0,
                report_rate REAL NOT NULL DEFAULT 0,
                avg_time_to_click REAL,
                FOREIGN KEY (campaign_id) REFERENCES campaigns(id)
            )
        ''')

        conn.commit()
        conn.close()

    def list_templates(self) -> List[Dict[str, Any]]:
        """List all available phishing templates"""
        templates = []

        if not self.templates_dir.exists():
            return templates

        for template_file in self.templates_dir.glob("*.yaml"):
            try:
                with open(template_file, 'r') as f:
                    template = yaml.safe_load(f)
                    templates.append({
                        'id': template['id'],
                        'name': template['name'],
                        'category': template['category'],
                        'difficulty': template['difficulty'],
                        'description': template['description']
                    })
            except Exception as e:
                print(f"Warning: Failed to load template {template_file.name}: {e}")

        return templates

    def get_template(self, template_id: str) -> Optional[Dict[str, Any]]:
        """Load a specific template"""
        template_path = self.templates_dir / f"{template_id}.yaml"

        if not template_path.exists():
            return None

        with open(template_path, 'r') as f:
            return yaml.safe_load(f)

    def create_campaign(
        self,
        name: str,
        template_id: str,
        targets: List[Dict[str, str]],
        description: str = None,
        config: Dict[str, Any] = None
    ) -> str:
        """
        Create a new phishing campaign

        Args:
            name: Campaign name
            template_id: Email template to use
            targets: List of target recipients [{'email': '...', 'name': '...'}]
            description: Optional campaign description
            config: Campaign configuration (tracking_domain, sender_name, etc.)

        Returns:
            Campaign ID
        """
        # Verify template exists
        template = self.get_template(template_id)
        if not template:
            raise ValueError(f"Template not found: {template_id}")

        # Generate campaign ID
        campaign_id = f"CAMP-{uuid.uuid4().hex[:8].upper()}"

        # Default config
        if config is None:
            config = {}
        config.setdefault('tracking_domain', 'phish-test.akali.local')
        config.setdefault('company_name', 'Acme Corporation')
        config.setdefault('similar_domain', 'acme-corp.com')

        # Create campaign
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO campaigns (id, name, description, template_id, status, created_at, config)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            campaign_id,
            name,
            description,
            template_id,
            'draft',
            datetime.now().isoformat(),
            json.dumps(config)
        ))

        # Add targets
        for target in targets:
            target_id = f"TGT-{uuid.uuid4().hex[:8].upper()}"
            tracking_token = uuid.uuid4().hex

            cursor.execute('''
                INSERT INTO campaign_targets (
                    id, campaign_id, recipient_email, recipient_name,
                    status, tracking_token
                )
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                target_id,
                campaign_id,
                target['email'],
                target.get('name', target['email'].split('@')[0]),
                'pending',
                tracking_token
            ))

        # Initialize results
        cursor.execute('''
            INSERT INTO campaign_results (campaign_id, total_targets)
            VALUES (?, ?)
        ''', (campaign_id, len(targets)))

        conn.commit()
        conn.close()

        return campaign_id

    def list_campaigns(
        self,
        status: Optional[str] = None
    ) -> List[PhishingCampaign]:
        """List campaigns with optional status filter"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = 'SELECT * FROM campaigns'
        params = []

        if status:
            query += ' WHERE status = ?'
            params.append(status)

        query += ' ORDER BY created_at DESC'

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        return [PhishingCampaign(dict(row)) for row in rows]

    def get_campaign(self, campaign_id: str) -> Optional[PhishingCampaign]:
        """Get campaign details"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM campaigns WHERE id = ?', (campaign_id,))
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        return PhishingCampaign(dict(row))

    def update_campaign_status(self, campaign_id: str, status: str) -> bool:
        """Update campaign status"""
        valid_statuses = ['draft', 'scheduled', 'active', 'paused', 'completed', 'cancelled']
        if status not in valid_statuses:
            raise ValueError(f"Invalid status. Must be one of: {valid_statuses}")

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        updates = {'status': status}

        if status == 'active':
            updates['started_at'] = datetime.now().isoformat()
        elif status in ['completed', 'cancelled']:
            updates['completed_at'] = datetime.now().isoformat()

        set_clause = ', '.join([f'{k} = ?' for k in updates.keys()])
        cursor.execute(
            f'UPDATE campaigns SET {set_clause} WHERE id = ?',
            list(updates.values()) + [campaign_id]
        )

        conn.commit()
        affected = cursor.rowcount
        conn.close()

        return affected > 0

    def get_campaign_targets(self, campaign_id: str) -> List[Dict[str, Any]]:
        """Get all targets for a campaign"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM campaign_targets
            WHERE campaign_id = ?
            ORDER BY recipient_email
        ''', (campaign_id,))

        rows = cursor.fetchall()
        conn.close()

        return [dict(row) for row in rows]

    def record_email_sent(self, target_id: str) -> bool:
        """Record that an email was sent to a target"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            UPDATE campaign_targets
            SET sent_at = ?, status = 'sent'
            WHERE id = ?
        ''', (datetime.now().isoformat(), target_id))

        # Update campaign results
        cursor.execute('''
            UPDATE campaign_results
            SET emails_sent = emails_sent + 1
            WHERE campaign_id = (
                SELECT campaign_id FROM campaign_targets WHERE id = ?
            )
        ''', (target_id,))

        conn.commit()
        affected = cursor.rowcount
        conn.close()

        return affected > 0

    def record_click(
        self,
        tracking_token: str,
        ip_address: str = None,
        user_agent: str = None,
        referer: str = None
    ) -> Optional[str]:
        """
        Record a phishing link click

        Returns:
            Target ID if successful, None otherwise
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Find target by tracking token
        cursor.execute('''
            SELECT id, campaign_id, clicked_at FROM campaign_targets
            WHERE tracking_token = ?
        ''', (tracking_token,))

        result = cursor.fetchone()
        if not result:
            conn.close()
            return None

        target_id, campaign_id, previous_click = result

        # Record click
        click_id = f"CLK-{uuid.uuid4().hex[:8].upper()}"
        cursor.execute('''
            INSERT INTO campaign_clicks (
                id, target_id, campaign_id, clicked_at, ip_address, user_agent, referer
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            click_id,
            target_id,
            campaign_id,
            datetime.now().isoformat(),
            ip_address,
            user_agent,
            referer
        ))

        # Update target (only first click)
        if not previous_click:
            cursor.execute('''
                UPDATE campaign_targets
                SET clicked_at = ?, status = 'clicked'
                WHERE id = ?
            ''', (datetime.now().isoformat(), target_id))

            # Update campaign results
            cursor.execute('''
                UPDATE campaign_results
                SET links_clicked = links_clicked + 1
                WHERE campaign_id = ?
            ''', (campaign_id,))

            # Update click rate
            cursor.execute('''
                UPDATE campaign_results
                SET click_rate = CAST(links_clicked AS REAL) / CAST(emails_sent AS REAL) * 100
                WHERE campaign_id = ? AND emails_sent > 0
            ''', (campaign_id,))

        conn.commit()
        conn.close()

        return target_id

    def record_report(self, tracking_token: str) -> bool:
        """Record that a target reported the phishing email"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Find target
        cursor.execute('''
            SELECT id, campaign_id FROM campaign_targets
            WHERE tracking_token = ?
        ''', (tracking_token,))

        result = cursor.fetchone()
        if not result:
            conn.close()
            return False

        target_id, campaign_id = result

        # Update target
        cursor.execute('''
            UPDATE campaign_targets
            SET reported_at = ?, status = 'reported'
            WHERE id = ?
        ''', (datetime.now().isoformat(), target_id))

        # Update campaign results
        cursor.execute('''
            UPDATE campaign_results
            SET reported = reported + 1
            WHERE campaign_id = ?
        ''', (campaign_id,))

        # Update report rate
        cursor.execute('''
            UPDATE campaign_results
            SET report_rate = CAST(reported AS REAL) / CAST(emails_sent AS REAL) * 100
            WHERE campaign_id = ? AND emails_sent > 0
        ''', (campaign_id,))

        conn.commit()
        conn.close()

        return True

    def get_campaign_results(self, campaign_id: str) -> Dict[str, Any]:
        """Get campaign metrics and results"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Get aggregate results
        cursor.execute('''
            SELECT * FROM campaign_results WHERE campaign_id = ?
        ''', (campaign_id,))

        results = dict(cursor.fetchone())

        # Get status breakdown
        cursor.execute('''
            SELECT status, COUNT(*) as count
            FROM campaign_targets
            WHERE campaign_id = ?
            GROUP BY status
        ''', (campaign_id,))

        results['status_breakdown'] = {
            row['status']: row['count']
            for row in cursor.fetchall()
        }

        # Calculate average time to click
        cursor.execute('''
            SELECT AVG(
                (julianday(clicked_at) - julianday(sent_at)) * 24 * 60
            ) as avg_minutes
            FROM campaign_targets
            WHERE campaign_id = ? AND clicked_at IS NOT NULL AND sent_at IS NOT NULL
        ''', (campaign_id,))

        avg_time = cursor.fetchone()['avg_minutes']
        if avg_time:
            results['avg_time_to_click'] = round(avg_time, 2)

        conn.close()

        return results

    def delete_campaign(self, campaign_id: str) -> bool:
        """Delete a campaign and all associated data"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Delete in order (foreign key constraints)
        cursor.execute('DELETE FROM campaign_clicks WHERE campaign_id = ?', (campaign_id,))
        cursor.execute('DELETE FROM campaign_targets WHERE campaign_id = ?', (campaign_id,))
        cursor.execute('DELETE FROM campaign_results WHERE campaign_id = ?', (campaign_id,))
        cursor.execute('DELETE FROM campaigns WHERE id = ?', (campaign_id,))

        conn.commit()
        affected = cursor.rowcount
        conn.close()

        return affected > 0


def main():
    """CLI testing"""
    manager = CampaignManager()

    # List templates
    print("\n📧 Available Phishing Templates:\n")
    templates = manager.list_templates()

    for template in templates:
        difficulty_emoji = {'low': '🟢', 'medium': '🟡', 'high': '🔴'}.get(template['difficulty'], '⚪')
        print(f"{difficulty_emoji} {template['id']}")
        print(f"   {template['name']}")
        print(f"   Category: {template['category']} | Difficulty: {template['difficulty']}")
        print()

    print(f"Total templates: {len(templates)}")


if __name__ == '__main__':
    main()

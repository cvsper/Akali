"""Alert Manager - Severity-based routing, deduplication, and escalation."""

import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict


@dataclass
class Alert:
    """Alert data structure."""
    id: str
    finding_id: str
    severity: str
    title: str
    description: str
    scanner: str
    target: str
    created_at: str
    status: str = "pending"  # pending, sent, acknowledged, escalated
    sent_at: Optional[str] = None
    acknowledged_at: Optional[str] = None
    escalated_at: Optional[str] = None
    agent_id: Optional[str] = None
    retry_count: int = 0


class AlertManager:
    """Manages alert routing, deduplication, rate limiting, and escalation."""

    def __init__(
        self,
        queue_path: str = "~/akali/autonomous/alerts/alert_queue.json",
        findings_db=None
    ):
        self.queue_path = Path(queue_path).expanduser()
        self.queue_path.parent.mkdir(parents=True, exist_ok=True)
        self.findings_db = findings_db
        self.logger = logging.getLogger("akali.alert_manager")

        # Configuration
        self.max_alerts_per_hour = 10
        self.escalation_threshold_hours = 24
        self.dedup_window_hours = 24

        self._ensure_queue_exists()

    def _ensure_queue_exists(self):
        """Create empty queue if it doesn't exist."""
        if not self.queue_path.exists():
            self.queue_path.write_text(json.dumps({
                "alerts": [],
                "history": [],
                "stats": {
                    "total_sent": 0,
                    "total_acknowledged": 0,
                    "total_escalated": 0
                }
            }, indent=2))

    def _load_queue(self) -> Dict[str, Any]:
        """Load alert queue from disk."""
        return json.loads(self.queue_path.read_text())

    def _save_queue(self, data: Dict[str, Any]):
        """Save alert queue to disk."""
        self.queue_path.write_text(json.dumps(data, indent=2))

    def _generate_alert_id(self) -> str:
        """Generate unique alert ID."""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        import random
        suffix = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=6))
        return f"alert-{timestamp}-{suffix}"

    def _is_duplicate(self, finding_id: str) -> bool:
        """Check if alert for this finding was sent recently."""
        data = self._load_queue()
        cutoff = datetime.now() - timedelta(hours=self.dedup_window_hours)

        for alert in data["history"]:
            if alert["finding_id"] == finding_id:
                created = datetime.fromisoformat(alert["created_at"])
                if created > cutoff:
                    self.logger.info(f"Duplicate alert for finding {finding_id} - skipping")
                    return True
        return False

    def _check_rate_limit(self) -> bool:
        """Check if we've hit the rate limit for alerts."""
        data = self._load_queue()
        cutoff = datetime.now() - timedelta(hours=1)

        recent_alerts = [
            a for a in data["history"]
            if datetime.fromisoformat(a["created_at"]) > cutoff
        ]

        if len(recent_alerts) >= self.max_alerts_per_hour:
            self.logger.warning(
                f"Rate limit reached: {len(recent_alerts)} alerts in last hour"
            )
            return False
        return True

    def _determine_routing(self, finding: Dict[str, Any]) -> str:
        """Determine which agent should receive the alert."""
        scanner = finding.get("scanner", "").lower()
        severity = finding.get("severity", "").lower()
        target = finding.get("target", "").lower()
        description = finding.get("description", "").lower()

        # Backend/API issues
        if any(x in scanner for x in ["api", "nuclei"]) or "backend" in target:
            return "dommo"

        # QA/test issues
        if "test" in target or "qa" in description:
            return "banksy"

        # Platform/frontend issues
        if any(x in scanner for x in ["nikto", "zap"]) or "platform" in target:
            return "dommo"

        # Security-specific findings (track in Akali)
        if severity in ["critical", "high"]:
            return "akali"

        # Default to sevs for unknown
        return "sevs"

    def send_alert(
        self,
        finding_id: str,
        agent_id: Optional[str] = None,
        force: bool = False
    ) -> Dict[str, Any]:
        """
        Send an alert for a finding.

        Args:
            finding_id: ID of the finding to alert on
            agent_id: Optional agent to route to (auto-determined if not provided)
            force: Skip deduplication and rate limiting checks

        Returns:
            Alert details or error
        """
        # Get finding from database
        if not self.findings_db:
            return {"error": "Findings database not configured"}

        finding = self.findings_db.get_finding(finding_id)
        if not finding:
            return {"error": f"Finding {finding_id} not found"}

        # Check for duplicate
        if not force and self._is_duplicate(finding_id):
            return {
                "error": "Duplicate alert",
                "finding_id": finding_id,
                "status": "skipped"
            }

        # Check rate limit
        if not force and not self._check_rate_limit():
            return {
                "error": "Rate limit exceeded",
                "finding_id": finding_id,
                "status": "queued"
            }

        # Determine agent routing
        if not agent_id:
            agent_id = self._determine_routing(finding)

        # Create alert
        alert = Alert(
            id=self._generate_alert_id(),
            finding_id=finding_id,
            severity=finding.get("severity", "unknown"),
            title=finding.get("title", "Security Finding"),
            description=finding.get("description", ""),
            scanner=finding.get("scanner", "unknown"),
            target=finding.get("target", "unknown"),
            created_at=datetime.now().isoformat(),
            agent_id=agent_id
        )

        # Add to queue
        data = self._load_queue()
        data["alerts"].append(asdict(alert))
        self._save_queue(data)

        self.logger.info(
            f"Alert {alert.id} created for finding {finding_id} -> agent {agent_id}"
        )

        return {
            "alert_id": alert.id,
            "finding_id": finding_id,
            "agent_id": agent_id,
            "severity": alert.severity,
            "status": "pending"
        }

    def ack_alert(self, alert_id: str) -> bool:
        """Acknowledge an alert."""
        data = self._load_queue()

        for alert in data["alerts"]:
            if alert["id"] == alert_id:
                alert["status"] = "acknowledged"
                alert["acknowledged_at"] = datetime.now().isoformat()
                self._save_queue(data)

                # Update stats
                data["stats"]["total_acknowledged"] += 1
                self._save_queue(data)

                self.logger.info(f"Alert {alert_id} acknowledged")
                return True

        return False

    def list_alerts(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        agent_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        List alerts with optional filters.

        Args:
            status: Filter by status (pending, sent, acknowledged, escalated)
            severity: Filter by severity (critical, high, medium, low)
            agent_id: Filter by agent ID

        Returns:
            List of matching alerts
        """
        data = self._load_queue()
        alerts = data["alerts"]

        if status:
            alerts = [a for a in alerts if a["status"] == status]
        if severity:
            alerts = [a for a in alerts if a["severity"] == severity]
        if agent_id:
            alerts = [a for a in alerts if a["agent_id"] == agent_id]

        return alerts

    def mark_sent(self, alert_id: str, success: bool = True) -> bool:
        """Mark an alert as sent and move to history."""
        data = self._load_queue()

        for i, alert in enumerate(data["alerts"]):
            if alert["id"] == alert_id:
                if success:
                    alert["status"] = "sent"
                    alert["sent_at"] = datetime.now().isoformat()

                    # Move to history
                    data["history"].append(alert)
                    data["alerts"].pop(i)

                    # Update stats
                    data["stats"]["total_sent"] += 1

                    self.logger.info(f"Alert {alert_id} marked as sent")
                else:
                    # Increment retry count
                    alert["retry_count"] += 1
                    self.logger.warning(
                        f"Alert {alert_id} failed to send (retry {alert['retry_count']})"
                    )

                self._save_queue(data)
                return True

        return False

    def check_escalations(self) -> List[Dict[str, Any]]:
        """Check for alerts that need escalation."""
        data = self._load_queue()
        escalations = []
        cutoff = datetime.now() - timedelta(hours=self.escalation_threshold_hours)

        for alert in data["alerts"]:
            # Skip if already escalated
            if alert["status"] == "escalated":
                continue

            # Check if alert is old enough to escalate
            created = datetime.fromisoformat(alert["created_at"])
            if created < cutoff and alert["status"] != "acknowledged":
                alert["status"] = "escalated"
                alert["escalated_at"] = datetime.now().isoformat()
                escalations.append(alert)

        if escalations:
            data["stats"]["total_escalated"] += len(escalations)
            self._save_queue(data)
            self.logger.warning(f"Escalated {len(escalations)} unacknowledged alerts")

        return escalations

    def get_stats(self) -> Dict[str, Any]:
        """Get alert statistics."""
        data = self._load_queue()

        stats = data.get("stats", {
            "total_sent": 0,
            "total_acknowledged": 0,
            "total_escalated": 0
        })

        stats.update({
            "pending_alerts": len([a for a in data["alerts"] if a["status"] == "pending"]),
            "sent_alerts": len([a for a in data["alerts"] if a["status"] == "sent"]),
            "acknowledged_alerts": len([
                a for a in data["alerts"] if a["status"] == "acknowledged"
            ]),
            "escalated_alerts": len([
                a for a in data["alerts"] if a["status"] == "escalated"
            ]),
            "history_count": len(data["history"])
        })

        return stats

    def get_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Get alert details by ID."""
        data = self._load_queue()

        # Check active alerts
        for alert in data["alerts"]:
            if alert["id"] == alert_id:
                return alert

        # Check history
        for alert in data["history"]:
            if alert["id"] == alert_id:
                return alert

        return None

    def cleanup_old_history(self, days: int = 30) -> int:
        """Remove alert history older than specified days."""
        data = self._load_queue()
        cutoff = datetime.now() - timedelta(days=days)

        original_count = len(data["history"])
        data["history"] = [
            a for a in data["history"]
            if datetime.fromisoformat(a["created_at"]) > cutoff
        ]

        removed = original_count - len(data["history"])
        if removed > 0:
            self._save_queue(data)
            self.logger.info(f"Cleaned up {removed} old alerts from history")

        return removed

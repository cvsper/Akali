"""ZimMemory Alerter - Send alerts to ZimMemory agent messaging system."""

import json
import logging
import time
from typing import Dict, Any, Optional
from datetime import datetime
import urllib.request
import urllib.error


class ZimAlerter:
    """Send security alerts to agents via ZimMemory messaging."""

    def __init__(
        self,
        zim_url: str = "http://10.0.0.209:5001",
        sender_id: str = "akali",
        timeout: int = 10
    ):
        self.zim_url = zim_url.rstrip('/')
        self.sender_id = sender_id
        self.timeout = timeout
        self.logger = logging.getLogger("akali.zim_alerter")

    def _map_priority(self, severity: str) -> str:
        """Map Akali severity to ZimMemory priority."""
        severity = severity.lower()

        if severity in ["critical", "high"]:
            return "critical"
        elif severity == "medium":
            return "high"
        elif severity == "low":
            return "normal"
        else:
            return "normal"

    def _route_agent(self, finding: Dict[str, Any], override_agent: Optional[str] = None) -> str:
        """Determine which agent should receive the alert."""
        if override_agent:
            return override_agent

        scanner = finding.get("scanner", "").lower()
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
        if finding.get("severity", "").lower() in ["critical", "high"]:
            return "akali"

        # Default to sevs
        return "sevs"

    def _format_message(self, finding: Dict[str, Any], alert: Dict[str, Any]) -> str:
        """Format alert message with finding details."""
        severity = finding.get("severity", "unknown").upper()
        title = finding.get("title", "Security Finding")
        scanner = finding.get("scanner", "unknown")
        target = finding.get("target", "unknown")
        description = finding.get("description", "")
        finding_id = finding.get("id", "unknown")

        # Severity emoji
        emoji_map = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "info": "🔵"
        }
        emoji = emoji_map.get(severity.lower(), "⚠️")

        # Build message
        message = f"{emoji} **{severity}** Security Alert\n\n"
        message += f"**Title:** {title}\n"
        message += f"**Scanner:** {scanner}\n"
        message += f"**Target:** {target}\n"
        message += f"**Finding ID:** {finding_id}\n\n"
        message += f"**Description:**\n{description}\n\n"

        # Add remediation if available
        if "remediation" in finding:
            message += f"**Remediation:**\n{finding['remediation']}\n\n"

        # Add links if available
        if "file_path" in finding:
            message += f"**File:** `{finding['file_path']}`\n"
        if "line_number" in finding:
            message += f"**Line:** {finding['line_number']}\n"

        # Add acknowledgment instruction
        message += f"\n---\n"
        message += f"*Acknowledge with:* `akali alert ack {alert.get('id', 'N/A')}`"

        return message

    def _send_http_request(
        self,
        endpoint: str,
        data: Dict[str, Any],
        method: str = "POST"
    ) -> Dict[str, Any]:
        """Send HTTP request to ZimMemory."""
        url = f"{self.zim_url}{endpoint}"

        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(data).encode('utf-8'),
                headers={
                    'Content-Type': 'application/json',
                    'User-Agent': f'Akali-Alerter/1.0'
                },
                method=method
            )

            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                response_data = response.read().decode('utf-8')
                return json.loads(response_data) if response_data else {}

        except urllib.error.HTTPError as e:
            error_body = e.read().decode('utf-8')
            self.logger.error(f"HTTP {e.code} from ZimMemory: {error_body}")
            raise Exception(f"ZimMemory HTTP error: {e.code} - {error_body}")

        except urllib.error.URLError as e:
            self.logger.error(f"Network error connecting to ZimMemory: {e.reason}")
            raise Exception(f"ZimMemory connection error: {e.reason}")

        except Exception as e:
            self.logger.error(f"Unexpected error sending to ZimMemory: {str(e)}")
            raise

    def send_to_zim(
        self,
        finding: Dict[str, Any],
        alert: Dict[str, Any],
        recipient_id: Optional[str] = None,
        max_retries: int = 3
    ) -> Dict[str, Any]:
        """
        Send alert to ZimMemory with retry logic.

        Args:
            finding: Finding data from findings database
            alert: Alert data from alert manager
            recipient_id: Optional agent ID override
            max_retries: Maximum retry attempts

        Returns:
            Response from ZimMemory or error details
        """
        # Determine recipient
        agent_id = recipient_id or self._route_agent(finding, alert.get("agent_id"))

        # Map priority
        priority = self._map_priority(finding.get("severity", "medium"))

        # Format message
        message = self._format_message(finding, alert)

        # Build ZimMemory message payload
        payload = {
            "recipient_id": agent_id,
            "sender_id": self.sender_id,
            "message": message,
            "priority": priority,
            "metadata": {
                "alert_id": alert.get("id"),
                "finding_id": finding.get("id"),
                "severity": finding.get("severity"),
                "scanner": finding.get("scanner"),
                "target": finding.get("target"),
                "timestamp": datetime.now().isoformat()
            }
        }

        # Retry logic with exponential backoff
        last_error = None
        for attempt in range(max_retries):
            try:
                self.logger.info(
                    f"Sending alert to {agent_id} via ZimMemory (attempt {attempt + 1})"
                )

                response = self._send_http_request(
                    "/messages/send",
                    payload
                )

                self.logger.info(
                    f"Successfully sent alert {alert.get('id')} to {agent_id}"
                )

                return {
                    "success": True,
                    "message_id": response.get("message_id"),
                    "recipient_id": agent_id,
                    "attempt": attempt + 1,
                    "response": response
                }

            except Exception as e:
                last_error = str(e)
                self.logger.warning(
                    f"Attempt {attempt + 1} failed: {last_error}"
                )

                # Exponential backoff
                if attempt < max_retries - 1:
                    backoff = 2 ** attempt
                    self.logger.info(f"Retrying in {backoff} seconds...")
                    time.sleep(backoff)

        # All retries failed
        self.logger.error(
            f"Failed to send alert to {agent_id} after {max_retries} attempts"
        )

        return {
            "success": False,
            "error": last_error,
            "recipient_id": agent_id,
            "attempts": max_retries
        }

    def send_escalation(
        self,
        alert: Dict[str, Any],
        finding: Dict[str, Any],
        reason: str = "Unacknowledged for 24 hours"
    ) -> Dict[str, Any]:
        """
        Send escalation alert to sevs.

        Args:
            alert: Alert data
            finding: Finding data
            reason: Escalation reason

        Returns:
            Response from ZimMemory
        """
        severity = finding.get("severity", "unknown").upper()
        title = finding.get("title", "Security Finding")
        original_agent = alert.get("agent_id", "unknown")

        message = f"🚨 **ESCALATION** 🚨\n\n"
        message += f"**Reason:** {reason}\n"
        message += f"**Original Recipient:** {original_agent}\n"
        message += f"**Severity:** {severity}\n"
        message += f"**Title:** {title}\n"
        message += f"**Alert ID:** {alert.get('id')}\n"
        message += f"**Finding ID:** {finding.get('id')}\n\n"
        message += f"**Original Message:**\n"
        message += self._format_message(finding, alert)

        payload = {
            "recipient_id": "sevs",
            "sender_id": self.sender_id,
            "message": message,
            "priority": "critical",
            "metadata": {
                "type": "escalation",
                "alert_id": alert.get("id"),
                "finding_id": finding.get("id"),
                "original_agent": original_agent,
                "escalation_reason": reason,
                "timestamp": datetime.now().isoformat()
            }
        }

        try:
            response = self._send_http_request("/messages/send", payload)
            self.logger.info(f"Escalation sent to sevs for alert {alert.get('id')}")

            return {
                "success": True,
                "message_id": response.get("message_id"),
                "response": response
            }

        except Exception as e:
            self.logger.error(f"Failed to send escalation: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }

    def send_digest(
        self,
        alerts: list,
        findings: list,
        digest_type: str = "daily"
    ) -> Dict[str, Any]:
        """
        Send digest of multiple alerts to agents.

        Args:
            alerts: List of alert objects
            findings: List of corresponding findings
            digest_type: Type of digest (daily, weekly, hourly)

        Returns:
            Summary of sent digests
        """
        # Group alerts by agent
        agent_alerts = {}
        for alert, finding in zip(alerts, findings):
            agent_id = alert.get("agent_id", "sevs")
            if agent_id not in agent_alerts:
                agent_alerts[agent_id] = []
            agent_alerts[agent_id].append((alert, finding))

        results = []

        # Send digest to each agent
        for agent_id, alert_list in agent_alerts.items():
            message = f"📊 **{digest_type.title()} Security Digest**\n\n"
            message += f"**Total Alerts:** {len(alert_list)}\n\n"

            # Group by severity
            severity_counts = {}
            for alert, finding in alert_list:
                sev = finding.get("severity", "unknown")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            message += "**By Severity:**\n"
            for severity, count in sorted(severity_counts.items()):
                message += f"- {severity.title()}: {count}\n"

            message += "\n**Findings:**\n\n"

            # List each finding
            for i, (alert, finding) in enumerate(alert_list, 1):
                title = finding.get("title", "Unknown")
                severity = finding.get("severity", "unknown")
                scanner = finding.get("scanner", "unknown")
                message += f"{i}. [{severity.upper()}] {title} (via {scanner})\n"

            message += f"\n---\n*View all findings with:* `akali findings list`"

            payload = {
                "recipient_id": agent_id,
                "sender_id": self.sender_id,
                "message": message,
                "priority": "normal",
                "metadata": {
                    "type": "digest",
                    "digest_type": digest_type,
                    "alert_count": len(alert_list),
                    "timestamp": datetime.now().isoformat()
                }
            }

            try:
                response = self._send_http_request("/messages/send", payload)
                results.append({
                    "agent_id": agent_id,
                    "success": True,
                    "alert_count": len(alert_list),
                    "message_id": response.get("message_id")
                })
                self.logger.info(
                    f"Sent {digest_type} digest to {agent_id} ({len(alert_list)} alerts)"
                )

            except Exception as e:
                results.append({
                    "agent_id": agent_id,
                    "success": False,
                    "error": str(e)
                })
                self.logger.error(
                    f"Failed to send digest to {agent_id}: {str(e)}"
                )

        return {
            "digest_type": digest_type,
            "total_agents": len(agent_alerts),
            "total_alerts": len(alerts),
            "results": results
        }

    def test_connection(self) -> Dict[str, Any]:
        """Test connection to ZimMemory."""
        try:
            # Try to reach the health endpoint (if available) or messages endpoint
            response = self._send_http_request(
                "/messages/send",
                {
                    "recipient_id": "akali",
                    "sender_id": "akali",
                    "message": "Connection test from Akali alert system",
                    "priority": "normal"
                }
            )

            return {
                "success": True,
                "zim_url": self.zim_url,
                "response": response
            }

        except Exception as e:
            return {
                "success": False,
                "zim_url": self.zim_url,
                "error": str(e)
            }

"""ZimMemory integration for Akali."""

import json
import requests
from typing import List, Dict, Any, Optional
from datetime import datetime


class ZimMemory:
    """Client for ZimMemory API."""

    def __init__(self, base_url: str = "http://10.0.0.209:5001"):
        self.base_url = base_url
        self.agent_id = "akali"

    def send_message(
        self,
        to_agent: str,
        subject: str,
        body: str,
        priority: str = "medium",
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """Send message to another agent via ZimMemory."""
        url = f"{self.base_url}/messages/send"

        payload = {
            "from_agent": self.agent_id,
            "to_agent": to_agent,
            "subject": subject,
            "body": body,
            "priority": priority,
            "metadata": metadata or {}
        }

        try:
            response = requests.post(url, json=payload, timeout=5)
            response.raise_for_status()
            result = response.json()
            return result.get("thread_id", "")
        except requests.RequestException as e:
            print(f"⚠️  Failed to send message to ZimMemory: {e}")
            return ""

    def get_inbox(
        self,
        status: str = "unread",
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Get inbox messages from ZimMemory."""
        url = f"{self.base_url}/messages/inbox"
        params = {
            "agent_id": self.agent_id,
            "status": status,
            "limit": limit
        }

        try:
            response = requests.get(url, params=params, timeout=5)
            response.raise_for_status()
            return response.json().get("messages", [])
        except requests.RequestException as e:
            print(f"⚠️  Failed to get inbox from ZimMemory: {e}")
            return []

    def add_memory(
        self,
        content: str,
        category: str = "security",
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """Add memory to ZimMemory."""
        url = f"{self.base_url}/memory/add"

        payload = {
            "content": content,
            "metadata": {
                "agent": self.agent_id,
                "category": category,
                "timestamp": datetime.now().isoformat(),
                **(metadata or {})
            }
        }

        try:
            response = requests.post(url, json=payload, timeout=5)
            response.raise_for_status()
            result = response.json()
            return result.get("id", "")
        except requests.RequestException as e:
            print(f"⚠️  Failed to add memory to ZimMemory: {e}")
            return ""

    def format_security_alert(
        self,
        finding: Dict[str, Any],
        target_agent: str = "dommo"
    ) -> str:
        """Format finding as security alert message."""
        severity_emoji = {
            "critical": "🚨",
            "high": "🔴",
            "medium": "🟡",
            "low": "🔵"
        }.get(finding.get("severity", "medium"), "⚪")

        severity = finding.get("severity", "unknown").upper()
        title = finding.get("title", "Security issue")
        location = finding.get("file", "Unknown")
        if finding.get("line"):
            location += f":{finding['line']}"

        body = f"""{severity_emoji} **{severity}**: {title}

**Location:** `{location}`

**Description:**
{finding.get('description', 'No description')}

"""

        if finding.get("cvss"):
            body += f"**CVSS:** {finding['cvss']}\n"
        if finding.get("cwe"):
            body += f"**CWE:** {finding['cwe']}\n"
        if finding.get("owasp"):
            body += f"**OWASP:** {finding['owasp']}\n"

        if finding.get("fix"):
            body += f"\n**Recommended Fix:**\n{finding['fix']}\n"

        body += f"\n**Finding ID:** {finding['id']}"
        body += f"\n**Scanner:** {finding.get('scanner', 'unknown')}"
        body += "\n\nNeed help? Message me in ZimMemory. 🥷"

        return body

    def alert_finding(
        self,
        finding: Dict[str, Any],
        target_agent: str = "dommo"
    ) -> str:
        """Send finding as alert to agent."""
        severity = finding.get("severity", "medium")
        priority = "critical" if severity == "critical" else "high" if severity == "high" else "medium"

        subject = f"{severity.upper()}: {finding.get('title', 'Security issue')}"
        body = self.format_security_alert(finding, target_agent)

        return self.send_message(
            to_agent=target_agent,
            subject=subject,
            body=body,
            priority=priority,
            metadata={
                "finding_id": finding["id"],
                "severity": severity,
                "scanner": finding.get("scanner")
            }
        )

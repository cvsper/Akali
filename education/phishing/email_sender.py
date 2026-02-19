#!/usr/bin/env python3
"""
Akali Phishing Email Sender

SMTP email sending for phishing simulation campaigns.
"""

import smtplib
import yaml
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
import time


class EmailSender:
    """Sends phishing simulation emails via SMTP"""

    def __init__(
        self,
        smtp_host: str = "localhost",
        smtp_port: int = 1025,
        smtp_user: Optional[str] = None,
        smtp_password: Optional[str] = None,
        use_tls: bool = False
    ):
        """
        Initialize email sender

        For testing, use a local SMTP server like mailhog or smtp4dev:
        - mailhog: docker run -p 1025:1025 -p 8025:8025 mailhog/mailhog
        - smtp4dev: docker run -p 3000:80 -p 2525:25 rnwood/smtp4dev
        """
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self.smtp_password = smtp_password
        self.use_tls = use_tls
        self.templates_dir = Path.home() / "akali" / "education" / "phishing" / "templates"

    def _load_template(self, template_id: str) -> Dict[str, Any]:
        """Load email template"""
        template_path = self.templates_dir / f"{template_id}.yaml"

        if not template_path.exists():
            raise ValueError(f"Template not found: {template_id}")

        with open(template_path, 'r') as f:
            return yaml.safe_load(f)

    def _render_email(
        self,
        template: Dict[str, Any],
        recipient_email: str,
        recipient_name: str,
        tracking_token: str,
        config: Dict[str, Any]
    ) -> tuple[str, str]:
        """
        Render email subject and body with variables

        Returns:
            (subject, body)
        """
        # Build variable context
        context = {
            'recipient_email': recipient_email,
            'recipient_name': recipient_name,
            'recipient_id': tracking_token[:8],
            'tracking_domain': config.get('tracking_domain', 'phish-test.akali.local'),
            'company_name': config.get('company_name', 'Acme Corporation'),
            'similar_domain': config.get('similar_domain', 'acme-corp.com'),
            'company_domain': config.get('company_domain', 'acme.com'),
            'ceo_name': config.get('ceo_name', 'John Smith'),
            'sender_name': config.get('sender_name', 'IT Department'),
            'vendor_name': config.get('vendor_name', 'Acme Supplies'),
            'vendor_domain': config.get('vendor_domain', 'acmesupplies.com'),
            'contact_name': config.get('contact_name', 'Jessica Martinez'),
            'current_time': datetime.now().strftime('%I:%M %p'),
            'current_date': datetime.now().strftime('%B %d, %Y'),
            'deadline_date': config.get('deadline_date', 'Friday'),
            'campaign_id': config.get('campaign_id', 'TEST'),
        }

        # Render tracking URL if template has one
        if template.get('tracking_url'):
            tracking_url = template['tracking_url'].format(**context, recipient_id=tracking_token)
        else:
            tracking_url = f"https://{context['tracking_domain']}/track/{tracking_token}"

        context['tracking_url'] = tracking_url

        # Render subject and body
        subject = template['subject'].format(**context)
        body = template['body'].format(**context)

        return subject, body

    def send_email(
        self,
        template_id: str,
        recipient_email: str,
        recipient_name: str,
        tracking_token: str,
        config: Dict[str, Any],
        from_email: Optional[str] = None,
        from_name: Optional[str] = None
    ) -> bool:
        """
        Send a single phishing simulation email

        Args:
            template_id: Template to use
            recipient_email: Target email address
            recipient_name: Target name
            tracking_token: Unique tracking token
            config: Campaign configuration
            from_email: Override sender email
            from_name: Override sender name

        Returns:
            True if sent successfully
        """
        try:
            # Load template
            template = self._load_template(template_id)

            # Render email
            subject, body = self._render_email(
                template,
                recipient_email,
                recipient_name,
                tracking_token,
                config
            )

            # Determine sender
            if not from_email:
                from_email_pattern = template.get('from_email_pattern', 'noreply@{similar_domain}')
                from_email = from_email_pattern.format(
                    similar_domain=config.get('similar_domain', 'acme-corp.com'),
                    company_domain=config.get('company_domain', 'acme.com'),
                    ceo_name=config.get('ceo_name', 'john.smith').lower().replace(' ', '.')
                )

            if not from_name:
                from_name = template.get('from_name', config.get('sender_name', 'IT Department'))

            # Create email message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f"{from_name} <{from_email}>"
            msg['To'] = f"{recipient_name} <{recipient_email}>"
            msg['Date'] = datetime.now().strftime('%a, %d %b %Y %H:%M:%S %z')

            # Add text body
            text_part = MIMEText(body, 'plain')
            msg.attach(text_part)

            # Add HTML version (basic HTML wrapping)
            html_body = f"""
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6;">
            <pre style="white-space: pre-wrap; font-family: Arial, sans-serif;">
{body}
            </pre>
            </body>
            </html>
            """
            html_part = MIMEText(html_body, 'html')
            msg.attach(html_part)

            # Send email
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls()
                if self.smtp_user and self.smtp_password:
                    server.login(self.smtp_user, self.smtp_password)

                server.send_message(msg)

            return True

        except Exception as e:
            print(f"Failed to send email to {recipient_email}: {e}")
            return False

    def send_campaign_emails(
        self,
        campaign_id: str,
        targets: List[Dict[str, Any]],
        template_id: str,
        config: Dict[str, Any],
        delay_seconds: float = 0.5,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """
        Send emails for an entire campaign

        Args:
            campaign_id: Campaign ID
            targets: List of target dicts with email, name, tracking_token
            template_id: Template to use
            config: Campaign configuration
            delay_seconds: Delay between emails (rate limiting)
            dry_run: If True, don't actually send emails

        Returns:
            Results dict with sent/failed counts
        """
        results = {
            'total': len(targets),
            'sent': 0,
            'failed': 0,
            'failures': []
        }

        config['campaign_id'] = campaign_id

        for target in targets:
            if dry_run:
                print(f"[DRY RUN] Would send to: {target['recipient_email']}")
                results['sent'] += 1
                time.sleep(0.1)  # Minimal delay for dry run
                continue

            success = self.send_email(
                template_id=template_id,
                recipient_email=target['recipient_email'],
                recipient_name=target['recipient_name'],
                tracking_token=target['tracking_token'],
                config=config
            )

            if success:
                results['sent'] += 1
                print(f"✅ Sent to: {target['recipient_email']}")
            else:
                results['failed'] += 1
                results['failures'].append(target['recipient_email'])
                print(f"❌ Failed: {target['recipient_email']}")

            # Rate limiting delay
            if delay_seconds > 0:
                time.sleep(delay_seconds)

        return results

    def test_connection(self) -> bool:
        """Test SMTP connection"""
        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=5) as server:
                if self.use_tls:
                    server.starttls()
                if self.smtp_user and self.smtp_password:
                    server.login(self.smtp_user, self.smtp_password)
                return True
        except Exception as e:
            print(f"SMTP connection failed: {e}")
            return False


def main():
    """CLI testing"""
    import sys

    print("\n📧 Akali Email Sender Test\n")

    # Test SMTP connection
    sender = EmailSender()

    print("Testing SMTP connection (localhost:1025)...")
    if sender.test_connection():
        print("✅ SMTP connection successful")
    else:
        print("❌ SMTP connection failed")
        print("\nTo test, run a local SMTP server:")
        print("  docker run -p 1025:1025 -p 8025:8025 mailhog/mailhog")
        print("\nThen view emails at: http://localhost:8025")
        sys.exit(1)

    # Send test email
    print("\nSending test phishing email...")

    test_config = {
        'tracking_domain': 'phish-test.akali.local',
        'company_name': 'OpenClaw Family',
        'similar_domain': 'openclaw-team.com',
        'ceo_name': 'Shamar Donaldson'
    }

    success = sender.send_email(
        template_id='password_reset',
        recipient_email='test@example.com',
        recipient_name='Test User',
        tracking_token='test123456',
        config=test_config
    )

    if success:
        print("✅ Test email sent!")
        print("\nView at: http://localhost:8025")
    else:
        print("❌ Test email failed")


if __name__ == '__main__':
    main()

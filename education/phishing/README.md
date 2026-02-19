# Akali Phishing Simulation System

Realistic phishing simulation platform for security awareness training.

## Components

### 1. Campaign Manager (`campaign_manager.py`)
SQLite-based campaign management:
- Campaign CRUD operations
- Target tracking
- Click and report recording
- Aggregate metrics

Database: `~/.akali/phishing.db`

### 2. Email Sender (`email_sender.py`)
SMTP email delivery:
- Template rendering with variable substitution
- Rate-limited sending
- Test mode (dry run)
- Requires SMTP server (mailhog/smtp4dev for testing)

### 3. Click Tracker (`click_tracker.py`)
Flask-based tracking server:
- Click recording with metadata (IP, user agent)
- Educational landing pages
- Report acknowledgment
- Runs on port 5555

### 4. Report Generator (`report_generator.py`)
Campaign analytics and reporting:
- Detailed metrics (click rate, report rate, time to click)
- Risk analysis and recommendations
- Vulnerable user identification
- JSON export

### 5. Email Templates (`templates/`)
20 realistic phishing templates:
- CEO fraud / BEC
- Credential harvesting (password resets, O365, banking)
- Malware delivery (invoices, software updates, voicemail)
- Social engineering (LinkedIn, Zoom, prize scams)

Each template includes:
- Realistic email subject and body
- Red flag indicators
- Educational points
- Difficulty rating

## Quick Start

### 1. Start Local SMTP Server (for testing)

```bash
# Using mailhog (recommended)
docker run -p 1025:1025 -p 8025:8025 mailhog/mailhog

# View emails at: http://localhost:8025
```

### 2. Create a Campaign

```python
from education.phishing.campaign_manager import CampaignManager

manager = CampaignManager()

# Define targets
targets = [
    {'email': 'alice@example.com', 'name': 'Alice'},
    {'email': 'bob@example.com', 'name': 'Bob'}
]

# Create campaign
campaign_id = manager.create_campaign(
    name="Q1 Security Awareness Test",
    template_id="password_reset",
    targets=targets,
    description="Quarterly phishing simulation",
    config={
        'tracking_domain': 'phish-test.akali.local',
        'company_name': 'Acme Corp',
        'similar_domain': 'acme-security.com'
    }
)

print(f"Campaign created: {campaign_id}")
```

### 3. Start Click Tracker

```bash
python3 education/phishing/click_tracker.py

# Runs on http://127.0.0.1:5555
```

### 4. Send Campaign Emails

```python
from education.phishing.email_sender import EmailSender
from education.phishing.campaign_manager import CampaignManager

manager = CampaignManager()
sender = EmailSender(smtp_host='localhost', smtp_port=1025)

campaign_id = "CAMP-12345678"
campaign = manager.get_campaign(campaign_id)
targets = manager.get_campaign_targets(campaign_id)

# Send emails
results = sender.send_campaign_emails(
    campaign_id=campaign_id,
    targets=targets,
    template_id=campaign.template_id,
    config=campaign.config,
    delay_seconds=0.5
)

print(f"Sent: {results['sent']}, Failed: {results['failed']}")

# Mark campaign as active
manager.update_campaign_status(campaign_id, 'active')
```

### 5. Track Results

```python
from education.phishing.report_generator import ReportGenerator

generator = ReportGenerator()

# Print console report
generator.print_campaign_report(campaign_id)

# Export JSON report
report_path = generator.export_json_report(campaign_id)
print(f"Report saved: {report_path}")
```

## CLI Usage

```bash
# List templates
akali phish list-templates

# Create campaign
akali phish create-campaign \
  --name "Q1 Awareness Test" \
  --template password_reset \
  --targets targets.json

# List campaigns
akali phish list-campaigns

# Send campaign emails
akali phish send CAMP-12345678

# View campaign report
akali phish report CAMP-12345678

# Export report to JSON
akali phish export CAMP-12345678 --output report.json

# Start tracking server
akali phish start-tracker
```

## Email Templates

### Available Templates (20 total)

1. **ceo_fraud** - CEO impersonation / BEC (high difficulty)
2. **password_reset** - Fake password reset (medium)
3. **payroll_update** - Fake HR/payroll update (medium)
4. **shipping_notification** - Fake package delivery (low)
5. **security_alert** - Fake security alert (medium)
6. **invoice_scam** - Fake vendor invoice (medium)
7. **office365_quota** - Fake O365 storage warning (low)
8. **tax_refund** - Fake IRS refund (medium)
9. **linkedin_connection** - Fake LinkedIn request (low)
10. **zoom_meeting** - Fake Zoom invite (medium)
11. **bank_fraud_alert** - Fake bank fraud alert (high)
12. **docusign_fake** - Fake DocuSign document (medium)
13. **apple_id_locked** - Fake Apple ID locked (low)
14. **voicemail_notification** - Fake voicemail with malware (low)
15. **benefits_enrollment** - Fake benefits enrollment (medium)
16. **google_drive_share** - Fake Google Drive share (low)
17. **it_policy_update** - Fake IT policy update (medium)
18. **prize_winner** - Fake lottery/prize scam (low)
19. **software_update** - Fake Windows update (medium)
20. **vendor_payment** - Vendor payment change fraud (high)

### Template Categories
- **credential_theft** - Harvest login credentials
- **malware** - Deliver malware payload
- **impersonation** - Impersonate executives/trusted parties
- **data_theft** - Harvest personal/financial data
- **financial_fraud** - Direct financial fraud (wire transfers)

## Campaign Configuration

```python
config = {
    # Required
    'tracking_domain': 'phish-test.akali.local',  # Domain for tracking links

    # Optional (defaults provided)
    'company_name': 'Acme Corporation',
    'similar_domain': 'acme-corp.com',  # Typosquatted domain
    'company_domain': 'acme.com',
    'ceo_name': 'John Smith',
    'sender_name': 'IT Department',
    'vendor_name': 'Acme Supplies',
    'vendor_domain': 'acmesupplies.com',
    'contact_name': 'Jessica Martinez'
}
```

## Metrics Tracked

### Per Campaign
- **Total Targets** - Number of recipients
- **Emails Sent** - Successfully delivered
- **Links Clicked** - Unique clicks
- **Click Rate** - Percentage of recipients who clicked
- **Reported** - Users who reported the email
- **Report Rate** - Percentage who reported
- **Avg Time to Click** - Average minutes from send to click

### Per Target
- **Status** - pending, sent, clicked, reported
- **Sent At** - Email delivery timestamp
- **Clicked At** - First click timestamp
- **Reported At** - Report timestamp
- **IP Address** - Click source IP
- **User Agent** - Browser/device info

### Risk Analysis
- **Risk Level** - very_low, low, medium, high
- **Awareness Level** - poor, fair, good, excellent
- **Vulnerable Users** - Clicked but didn't report
- **Aware Users** - Reported the phishing attempt
- **Recommendations** - Actionable next steps

## Best Practices

### Campaign Design
1. **Start Easy** - Begin with low-difficulty templates to establish baseline
2. **Educate First** - Send awareness training before first simulation
3. **Gradual Difficulty** - Increase sophistication over time
4. **Mix Templates** - Vary attack types to test different scenarios
5. **Repeat Quarterly** - Regular simulations maintain awareness

### Targeting
1. **Start Small** - Pilot with 10-20 users before company-wide
2. **Segment by Role** - Finance users get invoice scams, execs get BEC
3. **Track Repeat Offenders** - Users who click multiple times need training
4. **Reward Reporters** - Acknowledge users who report phishing

### Timing
1. **Avoid Busy Periods** - Don't send during year-end, holidays
2. **Vary Send Times** - Morning, afternoon, evening to test vigilance
3. **Test New Employees** - Send within 30 days of onboarding
4. **Post-Incident** - Test awareness after real phishing incidents

### Follow-Up
1. **Immediate Education** - Show landing page immediately after click
2. **Targeted Training** - Require training for clickers
3. **Executive Reporting** - Share metrics with leadership
4. **Trend Analysis** - Track improvement over multiple campaigns

## Integration

### ZimMemory Integration
Send alerts to agent shared memory:

```python
import requests

# Alert on high-risk campaign results
if click_rate > 30:
    requests.post('http://10.0.0.209:5001/messages/send', json={
        'from_agent': 'akali',
        'to_agent': 'dommo',
        'subject': f'🚨 High Phishing Click Rate: {click_rate}%',
        'body': f'Campaign {campaign_id} had {click_rate}% click rate. Training needed.',
        'priority': 'high'
    })
```

### Scheduled Campaigns
Use cron or Akali's scheduler:

```python
from autonomous.scheduler.cron_manager import CronManager

manager = CronManager()
manager.add_job(
    job_id='quarterly_phishing',
    name='Quarterly Phishing Simulation',
    schedule='0 9 1 */3 *',  # 9 AM on 1st of every 3rd month
    command='akali phish send-scheduled'
)
```

## Security Considerations

### Legal & Ethical
1. **Get Approval** - Require management/legal approval before running
2. **Internal Only** - Never send to external addresses
3. **No Real Harm** - Don't actually steal credentials or deploy malware
4. **Clear Purpose** - Users should know company runs simulations (not specific timing)
5. **Safe Harbor** - Don't punish clickers, focus on education

### Technical Safety
1. **Isolated Tracking** - Keep tracking server isolated from production
2. **No Real Credentials** - Never store or transmit real passwords
3. **Local SMTP** - Use local SMTP for testing, authenticated SMTP for production
4. **Rate Limiting** - Don't overwhelm mail servers
5. **Opt-Out** - Allow executives/sensitive roles to opt out

### Data Protection
1. **Anonymize Reports** - Protect individual user privacy in reports
2. **Retention Policy** - Delete campaign data after 90 days
3. **Access Control** - Restrict access to campaign data
4. **Encryption** - Store sensitive data encrypted

## Troubleshooting

### Emails Not Sending
```bash
# Test SMTP connection
python3 education/phishing/email_sender.py

# Check SMTP server logs
docker logs [mailhog-container-id]
```

### Clicks Not Tracking
```bash
# Verify tracker is running
curl http://127.0.0.1:5555/health

# Check campaign_clicks table
sqlite3 ~/.akali/phishing.db "SELECT * FROM campaign_clicks LIMIT 5"
```

### Invalid Template
```bash
# List available templates
python3 education/phishing/campaign_manager.py

# Validate template YAML
python3 -c "import yaml; yaml.safe_load(open('templates/password_reset.yaml'))"
```

## Testing

```bash
# Test campaign manager
python3 education/phishing/campaign_manager.py

# Test email sender (requires SMTP server)
python3 education/phishing/email_sender.py

# Test click tracker
python3 education/phishing/click_tracker.py

# Test report generator
python3 education/phishing/report_generator.py
```

## Requirements

```bash
# Core dependencies (included)
- yaml
- sqlite3
- flask
- smtplib

# For testing
docker run -p 1025:1025 -p 8025:8025 mailhog/mailhog
```

## Future Enhancements

- PDF report generation with charts
- Email attachment simulation (safe test files)
- SMS/text message phishing templates
- Real-time dashboard for active campaigns
- Machine learning to identify high-risk users
- Integration with email security gateways
- Automated training assignment for clickers
- Template builder UI
- Multi-language support
- Voice phishing (vishing) simulation

---

🥷 **Akali Phishing Simulation** - Protecting the family through awareness training

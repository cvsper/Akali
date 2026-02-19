#!/usr/bin/env python3
"""
Akali Phishing Click Tracker

Flask-based click tracking server with educational landing pages.
"""

from flask import Flask, request, render_template_string, redirect, url_for
from pathlib import Path
from typing import Optional
import sys

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from education.phishing.campaign_manager import CampaignManager


app = Flask(__name__)
app.config['SECRET_KEY'] = 'akali-phishing-tracker-dev-key'


# Landing page templates

EDUCATION_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Security Awareness Alert - Akali</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            max-width: 600px;
            width: 100%;
            padding: 40px;
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
        }
        .emoji {
            font-size: 64px;
            margin-bottom: 15px;
        }
        h1 {
            color: #e74c3c;
            font-size: 28px;
            margin-bottom: 10px;
        }
        .subtitle {
            color: #7f8c8d;
            font-size: 16px;
        }
        .alert-box {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 20px;
            margin: 25px 0;
            border-radius: 4px;
        }
        .alert-box h2 {
            color: #856404;
            font-size: 18px;
            margin-bottom: 10px;
        }
        .alert-box p {
            color: #856404;
            line-height: 1.6;
        }
        .indicators {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }
        .indicators h3 {
            color: #2c3e50;
            font-size: 16px;
            margin-bottom: 15px;
        }
        .indicators ul {
            list-style: none;
        }
        .indicators li {
            padding: 8px 0;
            color: #34495e;
            line-height: 1.5;
        }
        .indicators li:before {
            content: "🚩 ";
            margin-right: 8px;
        }
        .education {
            background: #e8f5e9;
            border-left: 4px solid #4caf50;
            padding: 20px;
            border-radius: 4px;
            margin: 20px 0;
        }
        .education h3 {
            color: #2e7d32;
            font-size: 16px;
            margin-bottom: 10px;
        }
        .education ul {
            color: #2e7d32;
            padding-left: 20px;
        }
        .education li {
            margin: 8px 0;
            line-height: 1.5;
        }
        .footer {
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #ecf0f1;
            color: #7f8c8d;
            font-size: 14px;
        }
        .footer a {
            color: #3498db;
            text-decoration: none;
        }
        .footer a:hover {
            text-decoration: underline;
        }
        .report-btn {
            display: inline-block;
            background: #27ae60;
            color: white;
            padding: 12px 30px;
            border-radius: 6px;
            text-decoration: none;
            margin-top: 20px;
            font-weight: 600;
            transition: background 0.3s;
        }
        .report-btn:hover {
            background: #229954;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="emoji">🥷</div>
            <h1>This Was a Phishing Simulation</h1>
            <p class="subtitle">You clicked on a simulated phishing link</p>
        </div>

        <div class="alert-box">
            <h2>Don't Panic - This Was a Test!</h2>
            <p>
                This was a <strong>security awareness training exercise</strong> by Akali.
                No real harm was done, but in a real attack, your click could have led to:
            </p>
            <ul style="margin-top: 10px; padding-left: 20px;">
                <li>Credential theft (stolen passwords)</li>
                <li>Malware installation</li>
                <li>Data breach</li>
                <li>Financial fraud</li>
            </ul>
        </div>

        <div class="indicators">
            <h3>Red Flags You Missed:</h3>
            <ul>
                {% for indicator in indicators %}
                <li>{{ indicator }}</li>
                {% endfor %}
            </ul>
        </div>

        <div class="education">
            <h3>How to Protect Yourself:</h3>
            <ul>
                {% for point in education_points %}
                <li>{{ point }}</li>
                {% endfor %}
            </ul>
        </div>

        <div style="text-align: center;">
            <a href="{{ url_for('report_phish', token=tracking_token) }}" class="report-btn">
                ✅ I Understand - Mark as Reported
            </a>
        </div>

        <div class="footer">
            <p>This simulation helps improve security awareness across our organization.</p>
            <p style="margin-top: 10px;">
                Questions? Contact the Akali security team.
            </p>
        </div>
    </div>
</body>
</html>
"""

REPORTED_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Great Job! - Akali</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            max-width: 600px;
            width: 100%;
            padding: 40px;
            text-align: center;
        }
        .emoji {
            font-size: 80px;
            margin-bottom: 20px;
        }
        h1 {
            color: #27ae60;
            font-size: 32px;
            margin-bottom: 15px;
        }
        p {
            color: #7f8c8d;
            font-size: 16px;
            line-height: 1.6;
            margin: 15px 0;
        }
        .highlight {
            background: #e8f5e9;
            padding: 20px;
            border-radius: 8px;
            margin: 25px 0;
        }
        .highlight strong {
            color: #2e7d32;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="emoji">🎉</div>
        <h1>Excellent Work!</h1>
        <p>
            Thank you for completing this security awareness exercise.
            You've learned how to identify phishing attempts.
        </p>
        <div class="highlight">
            <p>
                <strong>Remember:</strong> When in doubt, report suspicious emails to your
                security team. It's always better to be safe than sorry!
            </p>
        </div>
        <p style="margin-top: 30px; color: #95a5a6; font-size: 14px;">
            This window can now be closed.
        </p>
    </div>
</body>
</html>
"""

ERROR_PAGE_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Invalid Link - Akali</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            background: #f5f5f5;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            max-width: 500px;
            width: 100%;
            padding: 40px;
            text-align: center;
        }
        .emoji {
            font-size: 64px;
            margin-bottom: 20px;
        }
        h1 {
            color: #e74c3c;
            font-size: 24px;
            margin-bottom: 15px;
        }
        p {
            color: #7f8c8d;
            line-height: 1.6;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="emoji">❌</div>
        <h1>Invalid Tracking Link</h1>
        <p>
            This tracking link is invalid or has expired.
            If you believe this is an error, please contact support.
        </p>
    </div>
</body>
</html>
"""


# Routes

@app.route('/')
def index():
    """Root endpoint"""
    return "Akali Phishing Simulation Tracker - Active"


@app.route('/track/<token>')
@app.route('/reset/<campaign_id>/<token>')
@app.route('/hr-portal/<campaign_id>/<token>')
@app.route('/o365/<campaign_id>/<token>')
@app.route('/secure/<campaign_id>/<token>')
@app.route('/confirm/<campaign_id>/<token>')
@app.route('/invoice/<campaign_id>/<token>')
@app.route('/irs/<campaign_id>/<token>')
@app.route('/linkedin/<campaign_id>/<token>')
@app.route('/zoom/<campaign_id>/<token>')
@app.route('/bank/<campaign_id>/<token>')
@app.route('/docusign/<campaign_id>/<token>')
@app.route('/appleid/<campaign_id>/<token>')
@app.route('/voicemail/<campaign_id>/<token>')
@app.route('/benefits/<campaign_id>/<token>')
@app.route('/gdrive/<campaign_id>/<token>')
@app.route('/policy/<campaign_id>/<token>')
@app.route('/prize/<campaign_id>/<token>')
@app.route('/update/<campaign_id>/<token>')
def track_click(token: str, campaign_id: Optional[str] = None):
    """Track phishing link click and show education page"""

    # Get request metadata
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
    user_agent = request.headers.get('User-Agent', '')
    referer = request.headers.get('Referer', '')

    # Record click in database
    manager = CampaignManager()
    target_id = manager.record_click(
        tracking_token=token,
        ip_address=ip_address,
        user_agent=user_agent,
        referer=referer
    )

    if not target_id:
        # Invalid token
        return render_template_string(ERROR_PAGE_TEMPLATE), 404

    # Get campaign and target info to show relevant education
    campaign_targets = manager.get_campaign_targets(campaign_id) if campaign_id else []
    target = next((t for t in campaign_targets if t['tracking_token'] == token), None)

    # Get template to show relevant indicators
    if target:
        campaign = manager.get_campaign(target['campaign_id'])
        template = manager.get_template(campaign.template_id)

        indicators = template.get('indicators', [
            "Suspicious sender email domain",
            "Urgency and time pressure",
            "Request to click on external link",
            "Generic greeting or impersonal message"
        ])

        education_points = template.get('education_points', [
            "Always verify unexpected emails through official channels",
            "Hover over links to see real destination",
            "Check sender email address carefully",
            "When in doubt, contact your IT/security team"
        ])
    else:
        # Default education
        indicators = [
            "Suspicious sender email domain",
            "Urgency and time pressure",
            "Request to click on external link"
        ]
        education_points = [
            "Always verify unexpected emails",
            "Hover over links before clicking",
            "Report suspicious emails to security"
        ]

    return render_template_string(
        EDUCATION_PAGE_TEMPLATE,
        indicators=indicators,
        education_points=education_points,
        tracking_token=token
    )


@app.route('/report/<token>')
def report_phish(token: str):
    """Mark phishing email as reported (positive acknowledgment)"""

    manager = CampaignManager()
    success = manager.record_report(token)

    if success:
        return render_template_string(REPORTED_PAGE_TEMPLATE)
    else:
        return render_template_string(ERROR_PAGE_TEMPLATE), 404


@app.route('/health')
def health():
    """Health check endpoint"""
    return {'status': 'healthy', 'service': 'akali-phishing-tracker'}


def start_server(host: str = '127.0.0.1', port: int = 5555, debug: bool = True):
    """Start the Flask tracking server"""
    print(f"\n🥷 Akali Phishing Tracker Starting...")
    print(f"   Listening on: http://{host}:{port}")
    print(f"   Click any phishing link to see education page\n")

    app.run(host=host, port=port, debug=debug)


if __name__ == '__main__':
    start_server()

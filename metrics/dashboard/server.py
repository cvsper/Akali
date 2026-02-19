#!/usr/bin/env python3
"""
Dashboard Server - Simple Flask dashboard for Akali metrics
"""

import json
import os
import sys
from flask import Flask, render_template, jsonify

# Add parent directories to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from metrics.scorecard.score_calculator import ScoreCalculator
from metrics.observatory.mttd_mttr_tracker import MTTDMTTRTracker

app = Flask(__name__)

# Initialize components
score_calc = ScoreCalculator()
metrics_tracker = MTTDMTTRTracker()


@app.route("/")
def index():
    """Dashboard homepage"""
    return render_template("index.html")


@app.route("/api/score")
def api_score():
    """Get current security score"""
    try:
        score_data = score_calc.calculate_score()
        return jsonify(score_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/metrics")
def api_metrics():
    """Get MTTD/MTTR metrics"""
    try:
        metrics_data = metrics_tracker.calculate_metrics()
        return jsonify(metrics_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/findings")
def api_findings():
    """Get all findings"""
    try:
        findings_file = os.path.expanduser("~/akali/data/findings.json")
        if os.path.exists(findings_file):
            with open(findings_file, 'r') as f:
                findings = json.load(f)
            return jsonify(findings)
        else:
            return jsonify([])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def start_dashboard(host="127.0.0.1", port=8765):
    """Start dashboard server"""
    print(f"\n{'='*80}")
    print("AKALI SECURITY DASHBOARD")
    print(f"{'='*80}\n")
    print(f"Dashboard running at: http://{host}:{port}")
    print("Press Ctrl+C to stop\n")

    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    start_dashboard()

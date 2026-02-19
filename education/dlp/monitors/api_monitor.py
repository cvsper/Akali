"""API Monitor for Akali DLP System.

Flask middleware for monitoring API requests/responses for PII violations.
Can be integrated into Flask applications or used as proxy.
"""

import sys
from typing import Optional, Dict, Any, Callable
from pathlib import Path
from flask import Flask, request, Response, jsonify
import json

sys.path.insert(0, str(Path.home() / "akali"))

from education.dlp.content_inspector import ContentInspector, Violation
from education.dlp.policy_engine import PolicyEngine, PolicyAction


class DLPMiddleware:
    """Flask middleware for DLP monitoring."""

    def __init__(
        self,
        app: Flask,
        inspector: Optional[ContentInspector] = None,
        policy_engine: Optional[PolicyEngine] = None,
        on_violation: Optional[Callable[[Violation], None]] = None
    ):
        """Initialize DLP middleware.

        Args:
            app: Flask application
            inspector: Content inspector instance
            policy_engine: Policy engine instance
            on_violation: Callback for violations
        """
        self.app = app
        self.inspector = inspector or ContentInspector()
        self.policy_engine = policy_engine or PolicyEngine()
        self.on_violation = on_violation
        self.violations: list = []

        # Register middleware
        self.app.before_request(self.before_request)
        self.app.after_request(self.after_request)

    def before_request(self):
        """Inspect request payload for PII."""
        # Skip non-JSON requests
        if not request.is_json:
            return None

        try:
            payload = request.get_json()

            # Inspect payload
            violation = self.inspector.inspect_api_request(request.path, payload)

            if violation:
                print(f"⚠️  DLP violation in request to {request.path}")

                # Apply policy
                action = self.policy_engine.enforce(violation)
                violation.action_taken = action.value

                # Store violation
                self.violations.append(violation)

                # Call callback
                if self.on_violation:
                    self.on_violation(violation)

                # Take action
                if action == PolicyAction.BLOCK:
                    return jsonify({
                        'error': 'Request blocked by DLP policy',
                        'violation_id': violation.violation_id,
                        'message': 'Request contains sensitive PII data'
                    }), 403

                elif action == PolicyAction.REDACT:
                    # Redact PII from request (in production)
                    pass

                # Send alert
                self._send_alert(violation, 'request')

        except Exception as e:
            print(f"⚠️  DLP middleware error: {e}")

        return None

    def after_request(self, response: Response) -> Response:
        """Inspect response payload for PII."""
        # Only inspect JSON responses
        if response.content_type != 'application/json':
            return response

        try:
            # Get response data
            response_data = response.get_json()

            if not response_data:
                return response

            # Inspect response
            violation = self.inspector.inspect_api_response(request.path, response_data)

            if violation:
                print(f"⚠️  DLP violation in response from {request.path}")

                # Apply policy
                action = self.policy_engine.enforce(violation)
                violation.action_taken = action.value

                # Store violation
                self.violations.append(violation)

                # Call callback
                if self.on_violation:
                    self.on_violation(violation)

                # Take action
                if action == PolicyAction.BLOCK:
                    return jsonify({
                        'error': 'Response blocked by DLP policy',
                        'violation_id': violation.violation_id,
                        'message': 'Response contains sensitive PII data'
                    }), 403

                elif action == PolicyAction.REDACT:
                    # Redact PII from response (in production)
                    pass

                # Send alert
                self._send_alert(violation, 'response')

        except Exception as e:
            print(f"⚠️  DLP middleware error: {e}")

        return response

    def _send_alert(self, violation: Violation, direction: str):
        """Send alert to ZimMemory."""
        try:
            import requests

            recipient = 'dommo' if violation.severity in ['critical', 'high'] else 'zim'

            message = f"""🚨 API DLP Violation Detected

Endpoint: {violation.source_path}
Direction: {direction.upper()}
Severity: {violation.severity.upper()}
PII Types: {', '.join([m['pii_type'] for m in violation.pii_matches])}
Total Matches: {len(violation.pii_matches)}

Action: {violation.action_taken or 'WARN'}

Review violation: {violation.violation_id}
"""

            requests.post(
                'http://10.0.0.209:5001/messages/send',
                json={
                    'from_agent': 'akali',
                    'to_agent': recipient,
                    'subject': f'🚨 API DLP: {violation.severity.upper()}',
                    'body': message,
                    'priority': violation.severity,
                    'metadata': {
                        'violation_id': violation.violation_id,
                        'source': 'api',
                        'direction': direction
                    }
                },
                timeout=5
            )

        except Exception as e:
            print(f"⚠️  Failed to send alert: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Get monitoring statistics."""
        return {
            'total_violations': len(self.violations),
            'violations_by_severity': self._count_by_severity(),
            'violations_by_endpoint': self._count_by_endpoint()
        }

    def _count_by_severity(self) -> Dict[str, int]:
        """Count violations by severity."""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for violation in self.violations:
            counts[violation.severity] = counts.get(violation.severity, 0) + 1
        return counts

    def _count_by_endpoint(self) -> Dict[str, int]:
        """Count violations by endpoint."""
        counts = {}
        for violation in self.violations:
            endpoint = violation.source_path
            counts[endpoint] = counts.get(endpoint, 0) + 1
        return counts


class APIMonitor:
    """Standalone API monitor for testing."""

    def __init__(
        self,
        inspector: Optional[ContentInspector] = None,
        policy_engine: Optional[PolicyEngine] = None
    ):
        """Initialize API monitor.

        Args:
            inspector: Content inspector instance
            policy_engine: Policy engine instance
        """
        self.inspector = inspector or ContentInspector()
        self.policy_engine = policy_engine or PolicyEngine()

    def inspect_request(self, endpoint: str, payload: Dict[str, Any]) -> Optional[Violation]:
        """Inspect API request for PII.

        Args:
            endpoint: API endpoint
            payload: Request payload

        Returns:
            Violation if found, None otherwise
        """
        violation = self.inspector.inspect_api_request(endpoint, payload)

        if violation:
            action = self.policy_engine.enforce(violation)
            violation.action_taken = action.value

            print(f"⚠️  DLP violation in request to {endpoint}")
            print(f"Severity: {violation.severity}")
            print(f"Action: {action.value}")

            if action == PolicyAction.BLOCK:
                print("🚫 Request would be BLOCKED")

        return violation

    def inspect_response(self, endpoint: str, response: Dict[str, Any]) -> Optional[Violation]:
        """Inspect API response for PII.

        Args:
            endpoint: API endpoint
            response: Response payload

        Returns:
            Violation if found, None otherwise
        """
        violation = self.inspector.inspect_api_response(endpoint, response)

        if violation:
            action = self.policy_engine.enforce(violation)
            violation.action_taken = action.value

            print(f"⚠️  DLP violation in response from {endpoint}")
            print(f"Severity: {violation.severity}")
            print(f"Action: {action.value}")

            if action == PolicyAction.BLOCK:
                print("🚫 Response would be BLOCKED")

        return violation


def create_demo_app() -> Flask:
    """Create demo Flask app with DLP middleware."""
    app = Flask(__name__)

    # Add DLP middleware
    dlp = DLPMiddleware(app)

    @app.route('/api/users', methods=['POST'])
    def create_user():
        """Demo endpoint that accepts user data."""
        user = request.get_json()
        return jsonify({
            'id': 123,
            'name': user.get('name'),
            'email': user.get('email'),
            'message': 'User created successfully'
        })

    @app.route('/api/users/<int:user_id>', methods=['GET'])
    def get_user(user_id):
        """Demo endpoint that returns user data (with PII)."""
        return jsonify({
            'id': user_id,
            'name': 'John Doe',
            'email': 'john@example.com',
            'ssn': '123-45-6789',  # PII - should trigger violation
            'phone': '(555) 123-4567'
        })

    @app.route('/api/stats', methods=['GET'])
    def get_stats():
        """Get DLP monitoring stats."""
        return jsonify(dlp.get_stats())

    return app


def main():
    """Run API monitor in demo mode."""
    import argparse

    parser = argparse.ArgumentParser(description='Akali DLP API Monitor')
    parser.add_argument(
        '--demo',
        action='store_true',
        help='Run demo Flask app with DLP'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=5050,
        help='Port for demo app (default: 5050)'
    )

    args = parser.parse_args()

    if args.demo:
        print("🔍 Starting DLP-enabled demo API server")
        print(f"Listening on http://localhost:{args.port}")
        print("\nDemo endpoints:")
        print("  POST /api/users - Create user (test PII in request)")
        print("  GET /api/users/<id> - Get user (test PII in response)")
        print("  GET /api/stats - View DLP stats")
        print("\nPress Ctrl+C to stop\n")

        app = create_demo_app()
        app.run(host='0.0.0.0', port=args.port, debug=True)
    else:
        # Standalone testing
        monitor = APIMonitor()

        print("🔍 Testing API Monitor\n")
        print("=" * 70)

        # Test request with PII
        print("\nTest 1: Request with PII")
        test_request = {
            'name': 'John Doe',
            'email': 'john@example.com',
            'ssn': '123-45-6789',
            'phone': '(555) 123-4567'
        }
        monitor.inspect_request('/api/users', test_request)

        # Test response with PII
        print("\n\nTest 2: Response with PII")
        test_response = {
            'user': {
                'id': 123,
                'name': 'Jane Smith',
                'email': 'jane@example.com',
                'credit_card': '4532-1234-5678-9010'
            }
        }
        monitor.inspect_response('/api/users/123', test_response)

        print("\n" + "=" * 70)


if __name__ == '__main__':
    main()

"""MQTT protocol analyzer and security tester."""

import socket
from typing import List, Dict, Literal


SecurityLevel = Literal["good", "moderate", "weak", "critical"]


class MQTTAnalyzer:
    """MQTT broker analyzer and security tester"""

    # Common MQTT topics to probe
    COMMON_TOPICS = [
        "$SYS/#",
        "#",
        "test",
        "home/#",
        "sensor/#",
        "device/#",
        "iot/#"
    ]

    def probe_broker(
        self,
        broker: str,
        port: int = 1883,
        timeout: int = 5
    ) -> Dict:
        """Probe MQTT broker for accessibility"""
        try:
            # Try to connect to MQTT port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((broker, port))
            sock.close()

            accessible = (result == 0)

            # If accessible, test anonymous access
            anonymous_allowed = False
            if accessible:
                anonymous_allowed = self.test_anonymous_access(broker, port, timeout)

            return {
                'accessible': accessible,
                'anonymous_allowed': anonymous_allowed,
                'port': port,
                'broker': broker
            }

        except (socket.timeout, socket.error, Exception):
            return {
                'accessible': False,
                'anonymous_allowed': False,
                'port': port,
                'broker': broker
            }

    def test_anonymous_access(
        self,
        broker: str,
        port: int = 1883,
        timeout: int = 5
    ) -> bool:
        """Test if broker allows anonymous connections"""
        try:
            # Try importing paho.mqtt.client
            import paho.mqtt.client as mqtt

            # Create client without credentials
            client = mqtt.Client()
            client.connect(broker, port, keepalive=timeout)
            client.disconnect()

            # If connection succeeded, anonymous is allowed
            return True

        except ImportError:
            # paho-mqtt not installed, can't test
            return False
        except Exception:
            # Connection failed, anonymous not allowed
            return False

    def enumerate_topics(
        self,
        broker: str,
        port: int = 1883,
        timeout: int = 5
    ) -> List[str]:
        """Enumerate MQTT topics by trying common patterns"""
        discovered_topics = []

        try:
            import paho.mqtt.client as mqtt

            def on_message(client, userdata, message):
                topic = message.topic
                if topic not in discovered_topics:
                    discovered_topics.append(topic)

            client = mqtt.Client()
            client.on_message = on_message

            # Try to connect
            client.connect(broker, port, keepalive=timeout)

            # Subscribe to common topics
            for topic in self.COMMON_TOPICS:
                try:
                    client.subscribe(topic)
                except:
                    pass

            # Wait briefly for messages
            client.loop_start()
            import time
            time.sleep(min(timeout, 3))
            client.loop_stop()
            client.disconnect()

            return discovered_topics

        except ImportError:
            # paho-mqtt not installed
            return []
        except Exception:
            return []

    def assess_security(
        self,
        anonymous_allowed: bool,
        encryption: bool,
        authentication: bool
    ) -> Dict:
        """Assess MQTT broker security configuration"""
        risks = []

        # Check anonymous access
        if anonymous_allowed:
            risks.append("Anonymous access allowed")

        # Check encryption
        if not encryption:
            risks.append("Unencrypted connection (no TLS)")

        # Check authentication
        if not authentication:
            risks.append("No authentication required")

        # Determine security level
        if anonymous_allowed and not encryption and not authentication:
            level: SecurityLevel = "critical"
        elif anonymous_allowed or not encryption:
            level = "weak"
        elif not authentication:
            level = "moderate"
        else:
            level = "good"

        return {
            'level': level,
            'risks': risks,
            'anonymous_allowed': anonymous_allowed,
            'encryption': encryption,
            'authentication': authentication
        }

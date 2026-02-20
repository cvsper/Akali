"""Tests for MQTT analyzer."""

import pytest
from iot.protocol.mqtt_analyzer import MQTTAnalyzer


def test_probe_broker():
    """Test MQTT broker probing"""
    analyzer = MQTTAnalyzer()

    # Test with invalid broker
    result = analyzer.probe_broker("127.0.0.1", port=1883, timeout=2)

    assert isinstance(result, dict)
    assert 'accessible' in result
    assert 'anonymous_allowed' in result
    assert isinstance(result['accessible'], bool)


def test_enumerate_topics():
    """Test MQTT topic enumeration"""
    analyzer = MQTTAnalyzer()

    # Test with common topic patterns
    topics = analyzer.enumerate_topics(
        broker="127.0.0.1",
        port=1883,
        timeout=2
    )

    assert isinstance(topics, list)
    # Empty list is OK if broker not accessible


def test_test_anonymous_access():
    """Test anonymous access detection"""
    analyzer = MQTTAnalyzer()

    # Test connection attempt
    has_anonymous = analyzer.test_anonymous_access(
        broker="127.0.0.1",
        port=1883,
        timeout=2
    )

    assert isinstance(has_anonymous, bool)


def test_assess_security():
    """Test MQTT security assessment"""
    analyzer = MQTTAnalyzer()

    # Test with insecure config
    assessment = analyzer.assess_security(
        anonymous_allowed=True,
        encryption=False,
        authentication=False
    )

    assert isinstance(assessment, dict)
    assert 'level' in assessment
    assert 'risks' in assessment
    assert assessment['level'] == "critical"
    assert len(assessment['risks']) > 0

    # Test with secure config
    assessment = analyzer.assess_security(
        anonymous_allowed=False,
        encryption=True,
        authentication=True
    )

    assert assessment['level'] == "good"
    assert len(assessment['risks']) == 0

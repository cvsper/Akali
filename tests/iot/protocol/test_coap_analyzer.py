"""Tests for CoAP analyzer."""

import pytest
from iot.protocol.coap_analyzer import CoAPAnalyzer


def test_probe_server():
    """Test CoAP server probing"""
    analyzer = CoAPAnalyzer()

    # Test with invalid server
    result = analyzer.probe_server("127.0.0.1", port=5683, timeout=2)

    assert isinstance(result, dict)
    assert 'accessible' in result
    assert 'protocol' in result
    assert isinstance(result['accessible'], bool)


def test_discover_resources():
    """Test CoAP resource discovery"""
    analyzer = CoAPAnalyzer()

    # Test with invalid server
    resources = analyzer.discover_resources(
        server="127.0.0.1",
        port=5683,
        timeout=2
    )

    assert isinstance(resources, list)
    # Empty list is OK if server not accessible


def test_test_anonymous_access():
    """Test anonymous access detection"""
    analyzer = CoAPAnalyzer()

    # Test GET request
    has_anonymous = analyzer.test_anonymous_access(
        server="127.0.0.1",
        port=5683,
        timeout=2
    )

    assert isinstance(has_anonymous, bool)


def test_assess_security():
    """Test CoAP security assessment"""
    analyzer = CoAPAnalyzer()

    # Test with insecure config
    assessment = analyzer.assess_security(
        anonymous_allowed=True,
        encryption=False,
        dtls_enabled=False
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
        dtls_enabled=True
    )

    assert assessment['level'] == "good"

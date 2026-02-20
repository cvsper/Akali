"""Tests for MetricsCollector class."""

import pytest
from datetime import datetime, timedelta

from purple.validation.metrics_collector import MetricsCollector


class TestMetricsCollector:
    """Test MetricsCollector functionality."""

    @pytest.fixture
    def collector(self):
        """Create MetricsCollector instance."""
        return MetricsCollector()

    def test_initialization(self, collector):
        """Test MetricsCollector initializes correctly."""
        assert collector is not None

    def test_calculate_mttd(self, collector):
        """Test MTTD calculation."""
        attack_start = datetime(2026, 2, 20, 10, 0, 0)
        detection_time = datetime(2026, 2, 20, 10, 0, 5)

        mttd = collector.calculate_mttd(attack_start, detection_time)

        assert mttd is not None
        assert isinstance(mttd, float)
        assert mttd == 5.0  # 5 seconds

    def test_calculate_mttd_minutes(self, collector):
        """Test MTTD calculation in minutes."""
        attack_start = datetime(2026, 2, 20, 10, 0, 0)
        detection_time = datetime(2026, 2, 20, 10, 2, 30)

        mttd = collector.calculate_mttd(attack_start, detection_time)

        assert mttd == 150.0  # 2 minutes 30 seconds

    def test_calculate_mttr(self, collector):
        """Test MTTR calculation."""
        detection_time = datetime(2026, 2, 20, 10, 0, 5)
        response_time = datetime(2026, 2, 20, 10, 5, 0)

        mttr = collector.calculate_mttr(detection_time, response_time)

        assert mttr is not None
        assert isinstance(mttr, float)
        assert mttr == 295.0  # 4 minutes 55 seconds

    def test_calculate_detection_rate(self, collector):
        """Test detection rate calculation."""
        total_attacks = 100
        detected_attacks = 85

        rate = collector.calculate_detection_rate(total_attacks, detected_attacks)

        assert rate is not None
        assert isinstance(rate, float)
        assert rate == 85.0  # 85%

    def test_calculate_detection_rate_perfect(self, collector):
        """Test 100% detection rate."""
        rate = collector.calculate_detection_rate(50, 50)

        assert rate == 100.0

    def test_calculate_detection_rate_zero(self, collector):
        """Test 0% detection rate."""
        rate = collector.calculate_detection_rate(50, 0)

        assert rate == 0.0

    def test_calculate_false_positive_rate(self, collector):
        """Test false positive rate calculation."""
        total_alerts = 120
        false_positives = 20

        rate = collector.calculate_false_positive_rate(total_alerts, false_positives)

        assert rate is not None
        assert isinstance(rate, float)
        assert rate == pytest.approx(16.67, rel=0.01)  # ~16.67%

    def test_calculate_false_positive_rate_zero(self, collector):
        """Test zero false positive rate."""
        rate = collector.calculate_false_positive_rate(100, 0)

        assert rate == 0.0

    def test_calculate_coverage(self, collector):
        """Test attack coverage calculation."""
        attack_types = ['sqli', 'xss', 'port_scan', 'brute_force', 'kerberoast']
        detected_types = ['sqli', 'xss', 'port_scan']

        coverage = collector.calculate_coverage(attack_types, detected_types)

        assert coverage is not None
        assert isinstance(coverage, float)
        assert coverage == 60.0  # 3/5 = 60%

    def test_calculate_coverage_perfect(self, collector):
        """Test 100% coverage."""
        attack_types = ['sqli', 'xss', 'port_scan']
        detected_types = ['sqli', 'xss', 'port_scan']

        coverage = collector.calculate_coverage(attack_types, detected_types)

        assert coverage == 100.0

    def test_calculate_coverage_zero(self, collector):
        """Test 0% coverage."""
        attack_types = ['sqli', 'xss', 'port_scan']
        detected_types = []

        coverage = collector.calculate_coverage(attack_types, detected_types)

        assert coverage == 0.0

    def test_calculate_average_mttd(self, collector):
        """Test average MTTD calculation."""
        mttd_values = [5.0, 10.0, 15.0, 20.0]

        avg_mttd = collector.calculate_average_mttd(mttd_values)

        assert avg_mttd is not None
        assert avg_mttd == 12.5

    def test_calculate_average_mttr(self, collector):
        """Test average MTTR calculation."""
        mttr_values = [60.0, 120.0, 180.0]

        avg_mttr = collector.calculate_average_mttr(mttr_values)

        assert avg_mttr is not None
        assert avg_mttr == 120.0

    def test_calculate_percentile_mttd(self, collector):
        """Test MTTD percentile calculation."""
        # Use 20 values to ensure distinct percentiles
        mttd_values = [float(i) for i in range(1, 21)]

        p50 = collector.calculate_percentile_mttd(mttd_values, 50)
        p90 = collector.calculate_percentile_mttd(mttd_values, 90)
        p95 = collector.calculate_percentile_mttd(mttd_values, 95)

        assert p50 is not None
        assert p90 is not None
        assert p95 is not None
        assert p50 < p90 < p95

    def test_calculate_metrics_summary(self, collector):
        """Test calculating comprehensive metrics summary."""
        data = {
            'total_attacks': 100,
            'detected_attacks': 85,
            'total_alerts': 120,
            'false_positives': 20,
            'attack_types': ['sqli', 'xss', 'port_scan'],
            'detected_types': ['sqli', 'xss'],
            'mttd_values': [5.0, 10.0, 15.0],
            'mttr_values': [60.0, 120.0, 180.0]
        }

        summary = collector.calculate_metrics_summary(data)

        assert summary is not None
        assert 'detection_rate' in summary
        assert 'false_positive_rate' in summary
        assert 'coverage' in summary
        assert 'avg_mttd' in summary
        assert 'avg_mttr' in summary
        assert summary['detection_rate'] == 85.0
        assert summary['coverage'] == pytest.approx(66.67, rel=0.01)

    def test_format_duration(self, collector):
        """Test duration formatting."""
        # Seconds
        assert collector.format_duration(5.0) == "5.0s"

        # Minutes
        assert collector.format_duration(125.0) == "2m 5s"

        # Hours
        assert collector.format_duration(3665.0) == "1h 1m 5s"

    def test_export_metrics_json(self, collector, tmp_path):
        """Test exporting metrics to JSON."""
        metrics = {
            'detection_rate': 85.0,
            'false_positive_rate': 16.67,
            'coverage': 60.0
        }

        output_file = tmp_path / "metrics.json"
        collector.export_metrics(metrics, str(output_file), format='json')

        assert output_file.exists()
        import json
        loaded = json.loads(output_file.read_text())
        assert loaded['detection_rate'] == 85.0

    def test_export_metrics_csv(self, collector, tmp_path):
        """Test exporting metrics to CSV."""
        metrics = {
            'detection_rate': 85.0,
            'false_positive_rate': 16.67,
            'coverage': 60.0
        }

        output_file = tmp_path / "metrics.csv"
        collector.export_metrics(metrics, str(output_file), format='csv')

        assert output_file.exists()
        content = output_file.read_text()
        assert 'detection_rate' in content
        assert '85.0' in content

    def test_compare_metrics(self, collector):
        """Test comparing two metric sets."""
        baseline = {
            'detection_rate': 80.0,
            'false_positive_rate': 20.0,
            'avg_mttd': 10.0
        }

        current = {
            'detection_rate': 85.0,
            'false_positive_rate': 16.67,
            'avg_mttd': 8.0
        }

        comparison = collector.compare_metrics(baseline, current)

        assert comparison is not None
        assert comparison['detection_rate']['improvement'] is True
        assert comparison['detection_rate']['delta'] == 5.0
        assert comparison['false_positive_rate']['improvement'] is True
        assert comparison['avg_mttd']['improvement'] is True

    def test_calculate_trend(self, collector):
        """Test calculating metric trends over time."""
        historical_data = [
            {'timestamp': '2026-02-01', 'detection_rate': 75.0},
            {'timestamp': '2026-02-08', 'detection_rate': 78.0},
            {'timestamp': '2026-02-15', 'detection_rate': 82.0},
            {'timestamp': '2026-02-20', 'detection_rate': 85.0}
        ]

        trend = collector.calculate_trend(historical_data, 'detection_rate')

        assert trend is not None
        assert trend['direction'] == 'improving'
        assert trend['slope'] > 0

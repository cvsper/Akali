"""Tests for ReportGenerator class."""

import pytest
from pathlib import Path
import json

from purple.validation.report_generator import ReportGenerator


class TestReportGenerator:
    """Test ReportGenerator functionality."""

    @pytest.fixture
    def generator(self):
        """Create ReportGenerator instance."""
        return ReportGenerator()

    @pytest.fixture
    def simulation_data(self):
        """Create sample simulation data."""
        return {
            'simulation_id': 'sim-001',
            'timestamp': '2026-02-20T10:00:00Z',
            'duration': 300,
            'attack_type': 'sqli',
            'target': 'http://localhost:8080',
            'attacks': [
                {
                    'attack_id': 'attack-001',
                    'type': 'sqli',
                    'start_time': '2026-02-20T10:00:00Z',
                    'end_time': '2026-02-20T10:00:05Z',
                    'success': True
                }
            ],
            'detections': [
                {
                    'detection_id': 'det-001',
                    'timestamp': '2026-02-20T10:00:05Z',
                    'source': 'WAF',
                    'severity': 'high'
                }
            ],
            'metrics': {
                'mttd': 5.0,
                'mttr': 295.0,
                'detection_rate': 100.0,
                'false_positive_rate': 0.0,
                'coverage': 100.0
            }
        }

    def test_initialization(self, generator):
        """Test ReportGenerator initializes correctly."""
        assert generator is not None

    def test_generate_pdf_report(self, generator, simulation_data, tmp_path):
        """Test PDF report generation."""
        output_path = tmp_path / "report.pdf"

        result = generator.generate_pdf_report(simulation_data, str(output_path))

        assert result is not None
        assert result == str(output_path)
        assert output_path.exists()

    def test_generate_html_report(self, generator, simulation_data, tmp_path):
        """Test HTML report generation."""
        output_path = tmp_path / "report.html"

        result = generator.generate_html_report(simulation_data, str(output_path))

        assert result is not None
        assert result == str(output_path)
        assert output_path.exists()

        # Verify HTML content
        content = output_path.read_text()
        assert '<html>' in content
        assert 'sim-001' in content
        assert 'MTTD' in content

    def test_generate_json_report(self, generator, simulation_data, tmp_path):
        """Test JSON report generation."""
        output_path = tmp_path / "report.json"

        result = generator.generate_json_report(simulation_data, str(output_path))

        assert result is not None
        assert result == str(output_path)
        assert output_path.exists()

        # Verify JSON content
        content = json.loads(output_path.read_text())
        assert content['simulation_id'] == 'sim-001'
        assert 'metrics' in content

    def test_generate_executive_summary(self, generator, simulation_data):
        """Test executive summary generation."""
        summary = generator.generate_executive_summary(simulation_data)

        assert summary is not None
        assert isinstance(summary, str)
        assert 'sim-001' in summary
        assert '100.0%' in summary  # Detection rate

    def test_generate_attack_timeline(self, generator, simulation_data):
        """Test attack timeline generation."""
        timeline = generator.generate_attack_timeline(simulation_data)

        assert timeline is not None
        assert isinstance(timeline, list)
        assert len(timeline) > 0
        assert timeline[0]['event'] == 'attack_started'

    def test_generate_detection_timeline(self, generator, simulation_data):
        """Test detection timeline generation."""
        timeline = generator.generate_detection_timeline(simulation_data)

        assert timeline is not None
        assert isinstance(timeline, list)
        assert len(timeline) > 0
        assert timeline[0]['source'] == 'WAF'

    def test_generate_metrics_table(self, generator, simulation_data):
        """Test metrics table generation."""
        table = generator.generate_metrics_table(simulation_data['metrics'])

        assert table is not None
        assert isinstance(table, str)
        assert 'MTTD' in table
        assert 'MTTR' in table
        assert '5.0' in table

    def test_generate_coverage_matrix(self, generator):
        """Test coverage matrix generation."""
        attack_types = ['sqli', 'xss', 'port_scan', 'brute_force']
        detected_types = ['sqli', 'xss']

        matrix = generator.generate_coverage_matrix(attack_types, detected_types)

        assert matrix is not None
        assert isinstance(matrix, dict)
        assert matrix['sqli'] is True
        assert matrix['xss'] is True
        assert matrix['port_scan'] is False

    def test_generate_recommendations(self, generator, simulation_data):
        """Test recommendations generation."""
        recommendations = generator.generate_recommendations(simulation_data)

        assert recommendations is not None
        assert isinstance(recommendations, list)
        assert len(recommendations) >= 0

    def test_generate_recommendations_low_detection_rate(self, generator):
        """Test recommendations for low detection rate."""
        data = {
            'metrics': {
                'detection_rate': 50.0,
                'false_positive_rate': 25.0,
                'mttd': 300.0
            }
        }

        recommendations = generator.generate_recommendations(data)

        assert recommendations is not None
        assert len(recommendations) > 0
        assert any('detection' in r.lower() for r in recommendations)

    def test_generate_chart_timeline(self, generator, simulation_data, tmp_path):
        """Test timeline chart generation."""
        chart_path = tmp_path / "timeline.png"

        result = generator.generate_chart_timeline(simulation_data, str(chart_path))

        assert result is not None
        assert Path(chart_path).exists()

    def test_generate_chart_metrics(self, generator, simulation_data, tmp_path):
        """Test metrics chart generation."""
        chart_path = tmp_path / "metrics.png"

        result = generator.generate_chart_metrics(simulation_data['metrics'], str(chart_path))

        assert result is not None
        assert Path(chart_path).exists()

    def test_generate_chart_coverage(self, generator, tmp_path):
        """Test coverage chart generation."""
        coverage_data = {
            'sqli': True,
            'xss': True,
            'port_scan': False,
            'brute_force': False
        }

        chart_path = tmp_path / "coverage.png"

        result = generator.generate_chart_coverage(coverage_data, str(chart_path))

        assert result is not None
        assert Path(chart_path).exists()

    def test_format_html_template(self, generator, simulation_data):
        """Test HTML template formatting."""
        html = generator.format_html_template(simulation_data)

        assert html is not None
        assert '<html>' in html
        assert '<head>' in html
        assert '<body>' in html
        assert 'sim-001' in html

    def test_format_pdf_template(self, generator, simulation_data):
        """Test PDF template formatting."""
        pdf_content = generator.format_pdf_template(simulation_data)

        assert pdf_content is not None

    def test_add_watermark(self, generator, tmp_path):
        """Test adding watermark to report."""
        report_path = tmp_path / "report.pdf"
        report_path.write_text("dummy content")

        result = generator.add_watermark(str(report_path), "CONFIDENTIAL")

        assert result is True

    def test_generate_multiple_format_reports(self, generator, simulation_data, tmp_path):
        """Test generating reports in multiple formats."""
        formats = ['pdf', 'html', 'json']
        results = []

        for fmt in formats:
            output_path = tmp_path / f"report.{fmt}"
            if fmt == 'pdf':
                result = generator.generate_pdf_report(simulation_data, str(output_path))
            elif fmt == 'html':
                result = generator.generate_html_report(simulation_data, str(output_path))
            elif fmt == 'json':
                result = generator.generate_json_report(simulation_data, str(output_path))

            results.append(result)
            assert output_path.exists()

        assert len(results) == 3

    def test_report_with_empty_detections(self, generator, tmp_path):
        """Test report generation with no detections."""
        data = {
            'simulation_id': 'sim-002',
            'attacks': [{'attack_id': 'attack-001', 'success': True}],
            'detections': [],
            'metrics': {
                'mttd': None,
                'detection_rate': 0.0
            }
        }

        output_path = tmp_path / "report.html"
        result = generator.generate_html_report(data, str(output_path))

        assert result is not None
        assert output_path.exists()

        content = output_path.read_text()
        assert '0.0%' in content  # Detection rate

    def test_report_with_multiple_attacks(self, generator, tmp_path):
        """Test report with multiple attack types."""
        data = {
            'simulation_id': 'sim-003',
            'attacks': [
                {'attack_id': 'attack-001', 'type': 'sqli', 'success': True},
                {'attack_id': 'attack-002', 'type': 'xss', 'success': True},
                {'attack_id': 'attack-003', 'type': 'port_scan', 'success': True}
            ],
            'detections': [
                {'detection_id': 'det-001', 'attack_id': 'attack-001'},
                {'detection_id': 'det-002', 'attack_id': 'attack-002'}
            ],
            'metrics': {
                'detection_rate': 66.67
            }
        }

        output_path = tmp_path / "report.html"
        result = generator.generate_html_report(data, str(output_path))

        assert result is not None
        assert output_path.exists()

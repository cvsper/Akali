"""Tests for DefenseTester class."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
from pathlib import Path
import tempfile
import json

from purple.validation.defense_tester import DefenseTester


class TestDefenseTester:
    """Test DefenseTester functionality."""

    @pytest.fixture
    def tester(self):
        """Create DefenseTester instance."""
        return DefenseTester()

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for test files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_initialization(self, tester):
        """Test DefenseTester initializes correctly."""
        assert tester is not None
        assert hasattr(tester, 'attack_simulator')
        assert hasattr(tester, 'detection_monitor')
        assert hasattr(tester, 'metrics_collector')
        assert hasattr(tester, 'report_generator')

    @patch('purple.validation.defense_tester.AttackSimulator')
    @patch('purple.validation.defense_tester.DetectionMonitor')
    def test_run_attack_simulation(self, mock_monitor, mock_simulator, tester):
        """Test running an attack simulation."""
        # Mock attack execution
        mock_simulator.return_value.execute_attack.return_value = {
            'success': True,
            'attack_id': 'attack-001',
            'start_time': datetime.now().isoformat(),
            'end_time': (datetime.now() + timedelta(seconds=10)).isoformat()
        }

        # Mock detection monitoring
        mock_monitor.return_value.monitor.return_value = [
            {
                'detection_id': 'det-001',
                'timestamp': datetime.now().isoformat(),
                'source': 'WAF',
                'severity': 'high'
            }
        ]

        result = tester.run_attack_simulation('sqli', 'http://localhost:8080', duration=300)

        assert result is not None
        assert 'attack_id' in result
        assert 'detections' in result
        assert 'mttd' in result
        assert result['success'] is True

    def test_measure_mttd(self, tester, temp_dir):
        """Test MTTD calculation."""
        # Create mock attack log
        attack_log = temp_dir / "attack.log"
        attack_log.write_text(f"2026-02-20 10:00:00 - Attack started\n")

        # Create mock detection log
        detection_log = temp_dir / "detection.log"
        detection_log.write_text(
            f"2026-02-20 10:00:05 - Alert: SQL injection detected\n"
        )

        mttd = tester.measure_mttd(str(attack_log), str(detection_log))

        assert mttd is not None
        assert isinstance(mttd, float)
        assert mttd >= 0
        assert mttd == 5.0  # 5 second difference

    def test_measure_mttd_no_detection(self, tester, temp_dir):
        """Test MTTD when no detection occurred."""
        attack_log = temp_dir / "attack.log"
        attack_log.write_text(f"2026-02-20 10:00:00 - Attack started\n")

        detection_log = temp_dir / "detection.log"
        detection_log.write_text("")  # Empty log

        mttd = tester.measure_mttd(str(attack_log), str(detection_log))

        assert mttd is None or mttd == -1  # No detection

    def test_measure_mttr(self, tester, temp_dir):
        """Test MTTR calculation."""
        incident_log = temp_dir / "incident.log"
        incident_log.write_text(
            "2026-02-20 10:00:05 - Incident detected\n"
            "2026-02-20 10:02:30 - Incident contained\n"
            "2026-02-20 10:05:00 - Incident resolved\n"
        )

        mttr = tester.measure_mttr(str(incident_log))

        assert mttr is not None
        assert isinstance(mttr, float)
        assert mttr > 0
        assert mttr == 145.0  # 2 minutes 25 seconds (detected to contained)

    @patch('purple.validation.defense_tester.AttackSimulator')
    def test_run_attack_chain(self, mock_simulator, tester):
        """Test running multi-step attack chain."""
        chain = [
            {
                'step': 1,
                'attack': 'port_scan',
                'target': '10.0.0.5',
                'wait_for_detection': False
            },
            {
                'step': 2,
                'attack': 'sqli',
                'target': 'http://10.0.0.5/login',
                'wait_for_detection': True
            }
        ]

        mock_simulator.return_value.execute_attack.return_value = {
            'success': True,
            'attack_id': 'attack-001'
        }

        result = tester.run_attack_chain(chain)

        assert result is not None
        assert 'chain_id' in result
        assert 'steps' in result
        assert len(result['steps']) == 2
        assert result['success'] is True

    def test_run_attack_chain_with_failure(self, tester):
        """Test attack chain stops on failure."""
        chain = [
            {
                'step': 1,
                'attack': 'port_scan',
                'target': '10.0.0.5',
                'wait_for_detection': False
            },
            {
                'step': 2,
                'attack': 'invalid_attack',
                'target': 'http://10.0.0.5',
                'wait_for_detection': True
            }
        ]

        result = tester.run_attack_chain(chain)

        assert result is not None
        assert result['success'] is False
        assert 'error' in result

    def test_monitor_detection(self, tester):
        """Test monitoring for detection events."""
        # Mock the detection monitor's method directly on the tester instance
        mock_detections = [
            {
                'detection_id': 'det-001',
                'timestamp': datetime.now().isoformat(),
                'source': 'IDS',
                'attack_type': 'port_scan'
            }
        ]
        tester.detection_monitor.monitor_log_file = Mock(return_value=mock_detections)

        detections = tester.monitor_detection('10.0.0.5', 'port_scan', timeout=60)

        assert detections is not None
        assert isinstance(detections, list)
        assert len(detections) > 0
        assert detections[0]['source'] == 'IDS'

    def test_monitor_detection_timeout(self, tester):
        """Test monitoring times out with no detection."""
        detections = tester.monitor_detection('10.0.0.5', 'port_scan', timeout=1)

        assert detections is not None
        assert isinstance(detections, list)
        assert len(detections) == 0

    @patch('purple.validation.defense_tester.ReportGenerator')
    def test_generate_report_pdf(self, mock_generator, tester, temp_dir):
        """Test PDF report generation."""
        output_path = temp_dir / "report.pdf"

        # Add simulation to tester
        tester.simulations['sim-001'] = {
            'attack_id': 'attack-001',
            'attack_type': 'sqli',
            'target': 'http://localhost',
            'success': True,
            'detections': []
        }

        mock_generator.return_value.generate_pdf_report.return_value = str(output_path)

        result = tester.generate_report('sim-001', str(output_path), format='pdf')

        assert result is not None
        assert result == str(output_path)

    @patch('purple.validation.defense_tester.ReportGenerator')
    def test_generate_report_html(self, mock_generator, tester, temp_dir):
        """Test HTML report generation."""
        output_path = temp_dir / "report.html"

        # Add simulation to tester
        tester.simulations['sim-001'] = {
            'attack_id': 'attack-001',
            'attack_type': 'sqli',
            'target': 'http://localhost',
            'success': True,
            'detections': []
        }

        mock_generator.return_value.generate_html_report.return_value = str(output_path)

        result = tester.generate_report('sim-001', str(output_path), format='html')

        assert result is not None
        assert result == str(output_path)

    @patch('purple.validation.defense_tester.ReportGenerator')
    def test_generate_report_json(self, mock_generator, tester, temp_dir):
        """Test JSON report generation."""
        output_path = temp_dir / "report.json"

        # Add simulation to tester
        tester.simulations['sim-001'] = {
            'attack_id': 'attack-001',
            'attack_type': 'sqli',
            'target': 'http://localhost',
            'success': True,
            'detections': []
        }

        mock_generator.return_value.generate_json_report.return_value = str(output_path)

        result = tester.generate_report('sim-001', str(output_path), format='json')

        assert result is not None
        assert result == str(output_path)

    def test_invalid_attack_type(self, tester):
        """Test handling of invalid attack type."""
        with pytest.raises(ValueError):
            tester.run_attack_simulation('invalid_attack', 'http://localhost')

    def test_invalid_target(self, tester):
        """Test handling of invalid target."""
        with pytest.raises(ValueError):
            tester.run_attack_simulation('sqli', '')

    def test_load_attack_chain_from_file(self, tester, temp_dir):
        """Test loading attack chain from JSON file."""
        chain_file = temp_dir / "chain.json"
        chain_data = {
            'chain_id': 'test_chain',
            'steps': [
                {
                    'step': 1,
                    'attack': 'port_scan',
                    'target': '10.0.0.5',
                    'wait_for_detection': False
                }
            ]
        }
        chain_file.write_text(json.dumps(chain_data))

        chain = tester.load_attack_chain(str(chain_file))

        assert chain is not None
        assert chain['chain_id'] == 'test_chain'
        assert len(chain['steps']) == 1

    def test_save_simulation_state(self, tester, temp_dir):
        """Test saving simulation state for resumability."""
        state = {
            'simulation_id': 'sim-001',
            'status': 'in_progress',
            'current_step': 2,
            'results': []
        }

        state_file = temp_dir / "state.json"
        tester.save_simulation_state(state, str(state_file))

        assert state_file.exists()
        loaded_state = json.loads(state_file.read_text())
        assert loaded_state['simulation_id'] == 'sim-001'

    def test_resume_simulation(self, tester, temp_dir):
        """Test resuming a saved simulation."""
        state_file = temp_dir / "state.json"
        state = {
            'simulation_id': 'sim-001',
            'status': 'in_progress',
            'current_step': 2,
            'results': [{'step': 1, 'success': True}]
        }
        state_file.write_text(json.dumps(state))

        resumed = tester.resume_simulation(str(state_file))

        assert resumed is not None
        assert resumed['simulation_id'] == 'sim-001'
        assert resumed['current_step'] == 2

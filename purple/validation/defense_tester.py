"""Main defense tester for purple team validation."""

from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path
import json
import uuid
import re

from purple.validation.attack_simulator import AttackSimulator
from purple.validation.detection_monitor import DetectionMonitor
from purple.validation.metrics_collector import MetricsCollector
from purple.validation.report_generator import ReportGenerator


class DefenseTester:
    """Automated defense validation and testing."""

    def __init__(self):
        """Initialize defense tester."""
        self.attack_simulator = AttackSimulator()
        self.detection_monitor = DetectionMonitor()
        self.metrics_collector = MetricsCollector()
        self.report_generator = ReportGenerator()
        self.simulations = {}

    def run_attack_simulation(
        self,
        attack_type: str,
        target: str,
        duration: int = 300
    ) -> Dict:
        """
        Execute attack and monitor for detection.

        Args:
            attack_type: Type of attack to simulate
            target: Target for the attack
            duration: Maximum duration in seconds

        Returns:
            Simulation results dictionary

        Raises:
            ValueError: If attack type or target is invalid
        """
        if not attack_type:
            raise ValueError("Attack type is required")
        if not target:
            raise ValueError("Target is required")

        available_attacks = self.attack_simulator.list_available_attacks()
        if attack_type not in available_attacks:
            raise ValueError(f"Invalid attack type: {attack_type}")

        simulation_id = str(uuid.uuid4())
        start_time = datetime.now()

        # Execute attack
        attack_result = self.attack_simulator.execute_attack(attack_type, target)

        # Monitor for detections
        detections = self.detection_monitor.monitor_log_file(
            '/var/log/syslog',
            attack_type,
            timeout=duration
        )

        end_time = datetime.now()

        # Calculate MTTD if detections occurred
        mttd = None
        if detections and attack_result.get('success'):
            first_detection_time = datetime.fromisoformat(detections[0]['timestamp']) if 'timestamp' in detections[0] else end_time
            attack_start_time = datetime.fromisoformat(attack_result['start_time'])
            mttd = self.metrics_collector.calculate_mttd(attack_start_time, first_detection_time)

        result = {
            'simulation_id': simulation_id,
            'attack_type': attack_type,
            'target': target,
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'success': attack_result.get('success', False),
            'attack_id': attack_result.get('attack_id'),
            'detections': detections,
            'mttd': mttd,
            'duration': (end_time - start_time).total_seconds()
        }

        self.simulations[simulation_id] = result

        return result

    def measure_mttd(self, attack_log_path: str, detection_log_path: str) -> Optional[float]:
        """
        Calculate Mean Time To Detect (MTTD) from log files.

        Args:
            attack_log_path: Path to attack log file
            detection_log_path: Path to detection log file

        Returns:
            MTTD in seconds, or None if no detection
        """
        attack_log = Path(attack_log_path)
        detection_log = Path(detection_log_path)

        if not attack_log.exists():
            raise FileNotFoundError(f"Attack log not found: {attack_log_path}")

        # Extract attack start time
        attack_start_time = None
        with open(attack_log, 'r') as f:
            for line in f:
                if 'Attack started' in line or 'started' in line.lower():
                    # Extract timestamp from line
                    timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
                    if timestamp_match:
                        attack_start_time = datetime.strptime(timestamp_match.group(1), '%Y-%m-%d %H:%M:%S')
                        break

        if not attack_start_time:
            return None

        # Extract detection time
        if not detection_log.exists() or detection_log.stat().st_size == 0:
            return -1  # No detection

        detection_time = None
        with open(detection_log, 'r') as f:
            for line in f:
                if any(keyword in line.lower() for keyword in ['alert', 'detected', 'blocked', 'injection']):
                    # Extract timestamp
                    timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
                    if timestamp_match:
                        detection_time = datetime.strptime(timestamp_match.group(1), '%Y-%m-%d %H:%M:%S')
                        break

        if not detection_time:
            return -1  # No detection

        return self.metrics_collector.calculate_mttd(attack_start_time, detection_time)

    def measure_mttr(self, incident_log_path: str) -> Optional[float]:
        """
        Calculate Mean Time To Respond (MTTR) from incident log.

        Args:
            incident_log_path: Path to incident log file

        Returns:
            MTTR in seconds
        """
        incident_log = Path(incident_log_path)

        if not incident_log.exists():
            raise FileNotFoundError(f"Incident log not found: {incident_log_path}")

        # Extract detection and resolution times
        detection_time = None
        resolution_time = None

        with open(incident_log, 'r') as f:
            for line in f:
                timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
                if not timestamp_match:
                    continue

                timestamp = datetime.strptime(timestamp_match.group(1), '%Y-%m-%d %H:%M:%S')

                if 'detected' in line.lower() and not detection_time:
                    detection_time = timestamp
                elif any(keyword in line.lower() for keyword in ['resolved', 'contained']) and not resolution_time:
                    resolution_time = timestamp

        if detection_time and resolution_time:
            return self.metrics_collector.calculate_mttr(detection_time, resolution_time)

        return None

    def run_attack_chain(self, chain: List[Dict]) -> Dict:
        """
        Run multi-step attack chain.

        Args:
            chain: List of attack step dictionaries

        Returns:
            Chain execution results

        Raises:
            ValueError: If chain is invalid
        """
        if not chain:
            raise ValueError("Attack chain cannot be empty")

        chain_id = str(uuid.uuid4())
        results = {
            'chain_id': chain_id,
            'steps': [],
            'success': True,
            'start_time': datetime.now().isoformat()
        }

        for step in chain:
            attack_type = step.get('attack')
            target = step.get('target')
            wait_for_detection = step.get('wait_for_detection', False)

            if not attack_type or not target:
                results['success'] = False
                results['error'] = f"Invalid step: missing attack type or target"
                break

            try:
                # Execute attack
                attack_result = self.attack_simulator.execute_attack(attack_type, target)

                step_result = {
                    'step': step.get('step'),
                    'attack_type': attack_type,
                    'target': target,
                    'success': attack_result.get('success'),
                    'attack_id': attack_result.get('attack_id')
                }

                # Wait for detection if requested
                if wait_for_detection:
                    detections = self.detection_monitor.monitor_log_file(
                        '/var/log/syslog',
                        attack_type,
                        timeout=60
                    )
                    step_result['detections'] = detections

                results['steps'].append(step_result)

                # Stop on failure
                if not attack_result.get('success'):
                    results['success'] = False
                    break

            except Exception as e:
                results['success'] = False
                results['error'] = str(e)
                break

        results['end_time'] = datetime.now().isoformat()

        return results

    def monitor_detection(self, target: str, attack_type: str, timeout: int = 600) -> List[Dict]:
        """
        Monitor target for detection events.

        Args:
            target: Target to monitor
            attack_type: Type of attack to monitor for
            timeout: Timeout in seconds

        Returns:
            List of detection events
        """
        return self.detection_monitor.monitor_log_file(
            '/var/log/syslog',
            attack_type,
            timeout=timeout
        )

    def generate_report(
        self,
        simulation_id: str,
        output_path: str,
        format: str = "pdf"
    ) -> str:
        """
        Generate purple team validation report.

        Args:
            simulation_id: Simulation ID
            output_path: Output file path
            format: Report format (pdf, html, json)

        Returns:
            Path to generated report

        Raises:
            ValueError: If simulation not found or format invalid
        """
        if simulation_id not in self.simulations:
            raise ValueError(f"Simulation not found: {simulation_id}")

        simulation_data = self.simulations[simulation_id]

        if format == 'pdf':
            return self.report_generator.generate_pdf_report(simulation_data, output_path)
        elif format == 'html':
            return self.report_generator.generate_html_report(simulation_data, output_path)
        elif format == 'json':
            return self.report_generator.generate_json_report(simulation_data, output_path)
        else:
            raise ValueError(f"Invalid format: {format}")

    def load_attack_chain(self, chain_file_path: str) -> Dict:
        """
        Load attack chain from JSON file.

        Args:
            chain_file_path: Path to chain JSON file

        Returns:
            Attack chain dictionary
        """
        chain_file = Path(chain_file_path)

        if not chain_file.exists():
            raise FileNotFoundError(f"Chain file not found: {chain_file_path}")

        with open(chain_file, 'r') as f:
            return json.load(f)

    def save_simulation_state(self, state: Dict, state_file_path: str):
        """
        Save simulation state for resumability.

        Args:
            state: Simulation state dictionary
            state_file_path: Path to save state file
        """
        with open(state_file_path, 'w') as f:
            json.dump(state, f, indent=2)

    def resume_simulation(self, state_file_path: str) -> Dict:
        """
        Resume a saved simulation.

        Args:
            state_file_path: Path to state file

        Returns:
            Resumed simulation state
        """
        state_file = Path(state_file_path)

        if not state_file.exists():
            raise FileNotFoundError(f"State file not found: {state_file_path}")

        with open(state_file, 'r') as f:
            return json.load(f)

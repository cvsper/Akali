#!/usr/bin/env python3
"""
Akali Playbook Engine
Execute YAML-based incident response playbooks
"""

import yaml
import json
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Dict, List, Optional, Any

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from incident.incidents.incident_tracker import IncidentTracker
from incident.war_room.team_notifier import TeamNotifier


class PlaybookEngine:
    """YAML playbook execution engine"""

    def __init__(self, playbooks_dir: Optional[Path] = None):
        """Initialize playbook engine"""
        if playbooks_dir is None:
            playbooks_dir = Path(__file__).parent
        self.playbooks_dir = Path(playbooks_dir)
        self.state_dir = Path.home() / '.akali' / 'playbook_runs'
        self.state_dir.mkdir(parents=True, exist_ok=True)

        self.tracker = IncidentTracker()
        self.notifier = TeamNotifier()

    def list_playbooks(self) -> List[Dict[str, Any]]:
        """List available playbooks"""
        playbooks = []

        for yaml_file in self.playbooks_dir.glob('*.yaml'):
            try:
                with open(yaml_file, 'r') as f:
                    data = yaml.safe_load(f)

                if 'playbook' in data:
                    pb = data['playbook']
                    playbooks.append({
                        'id': pb.get('id', yaml_file.stem),
                        'name': pb.get('name', yaml_file.stem),
                        'description': pb.get('description', ''),
                        'severity': pb.get('severity', 'unknown'),
                        'version': pb.get('version', '1.0'),
                        'file': str(yaml_file)
                    })
            except Exception as e:
                print(f"Error loading playbook {yaml_file}: {e}")

        return playbooks

    def load_playbook(self, playbook_id: str) -> Optional[Dict[str, Any]]:
        """Load playbook by ID"""
        # Try exact filename match
        yaml_file = self.playbooks_dir / f'{playbook_id}.yaml'

        if not yaml_file.exists():
            # Try searching by ID in playbook metadata
            for pf in self.playbooks_dir.glob('*.yaml'):
                try:
                    with open(pf, 'r') as f:
                        data = yaml.safe_load(f)
                    if data.get('playbook', {}).get('id') == playbook_id:
                        yaml_file = pf
                        break
                except Exception:
                    continue

        if not yaml_file.exists():
            return None

        try:
            with open(yaml_file, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading playbook: {e}")
            return None

    def start_playbook(self,
                      playbook_id: str,
                      incident_id: str,
                      auto_execute: bool = False) -> Optional[str]:
        """
        Start playbook execution

        Args:
            playbook_id: Playbook ID to execute
            incident_id: Incident ID to attach playbook to
            auto_execute: Auto-execute automated steps without confirmation

        Returns:
            Playbook run ID
        """
        # Load playbook
        playbook_data = self.load_playbook(playbook_id)
        if not playbook_data:
            raise ValueError(f"Playbook not found: {playbook_id}")

        playbook = playbook_data['playbook']
        steps = playbook_data.get('steps', [])

        # Get incident
        incident = self.tracker.get_incident(incident_id)
        if not incident:
            raise ValueError(f"Incident not found: {incident_id}")

        # Attach playbook to incident
        self.tracker.attach_playbook(
            incident_id=incident_id,
            playbook_id=playbook['id'],
            actor='playbook-engine'
        )

        # Create playbook run
        run_id = f"run-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}"
        run_state = {
            'run_id': run_id,
            'playbook_id': playbook['id'],
            'playbook_name': playbook['name'],
            'incident_id': incident_id,
            'started_at': datetime.now(UTC).isoformat(),
            'status': 'running',
            'auto_execute': auto_execute,
            'current_step': 0,
            'total_steps': len(steps),
            'steps': [
                {
                    'id': step['id'],
                    'name': step['name'],
                    'status': 'pending',
                    'started_at': None,
                    'completed_at': None,
                    'result': None
                }
                for step in steps
            ]
        }

        self._save_run_state(run_id, run_state)

        # Notify team
        self.notifier.send_playbook_started(
            incident_id=incident_id,
            playbook_name=playbook['name'],
            total_steps=len(steps)
        )

        # Log to incident timeline
        self.tracker.add_note(
            incident_id=incident_id,
            note=f"Playbook started: {playbook['name']} ({len(steps)} steps)",
            actor='playbook-engine'
        )

        return run_id

    def execute_step(self,
                    run_id: str,
                    step_id: str,
                    result: Optional[str] = None) -> bool:
        """
        Execute or mark a playbook step as completed

        Args:
            run_id: Playbook run ID
            step_id: Step ID to execute
            result: Optional result/output from step execution

        Returns:
            True if step completed successfully
        """
        run_state = self._load_run_state(run_id)
        if not run_state:
            return False

        # Find step in run state
        step_idx = None
        for i, step in enumerate(run_state['steps']):
            if step['id'] == step_id:
                step_idx = i
                break

        if step_idx is None:
            return False

        # Update step status
        run_state['steps'][step_idx]['status'] = 'completed'
        run_state['steps'][step_idx]['completed_at'] = datetime.now(UTC).isoformat()
        run_state['steps'][step_idx]['result'] = result

        # Update current step
        run_state['current_step'] = step_idx + 1

        # Check if all steps completed
        all_completed = all(s['status'] == 'completed' for s in run_state['steps'])
        if all_completed:
            run_state['status'] = 'completed'
            run_state['completed_at'] = datetime.now(UTC).isoformat()

            # Notify team
            self.notifier.send_playbook_completed(
                incident_id=run_state['incident_id'],
                playbook_name=run_state['playbook_name'],
                completed_steps=len(run_state['steps'])
            )

            # Log to incident
            self.tracker.add_note(
                incident_id=run_state['incident_id'],
                note=f"Playbook completed: {run_state['playbook_name']}",
                actor='playbook-engine'
            )
        else:
            # Notify about step progress
            self.notifier.send_playbook_step(
                incident_id=run_state['incident_id'],
                playbook_name=run_state['playbook_name'],
                step_name=run_state['steps'][step_idx]['name'],
                step_number=step_idx + 1,
                total_steps=len(run_state['steps'])
            )

        self._save_run_state(run_id, run_state)

        return True

    def get_run_status(self, run_id: str) -> Optional[Dict[str, Any]]:
        """Get playbook run status"""
        return self._load_run_state(run_id)

    def get_current_step(self, run_id: str) -> Optional[Dict[str, Any]]:
        """Get current step in playbook execution"""
        run_state = self._load_run_state(run_id)
        if not run_state:
            return None

        current_idx = run_state['current_step']
        if current_idx >= len(run_state['steps']):
            return None  # All steps completed

        # Load full playbook to get step details
        playbook_data = self.load_playbook(run_state['playbook_id'])
        if not playbook_data:
            return None

        steps = playbook_data.get('steps', [])
        if current_idx >= len(steps):
            return None

        # Combine run state and playbook definition
        step = steps[current_idx].copy()
        step['run_status'] = run_state['steps'][current_idx]

        return step

    def abort_playbook(self, run_id: str, reason: str) -> bool:
        """Abort playbook execution"""
        run_state = self._load_run_state(run_id)
        if not run_state:
            return False

        run_state['status'] = 'aborted'
        run_state['aborted_at'] = datetime.now(UTC).isoformat()
        run_state['abort_reason'] = reason

        self._save_run_state(run_id, run_state)

        # Notify team
        self.notifier.send_status_update(
            incident_id=run_state['incident_id'],
            status='playbook_aborted',
            message=f"Playbook '{run_state['playbook_name']}' aborted: {reason}"
        )

        # Log to incident
        self.tracker.add_note(
            incident_id=run_state['incident_id'],
            note=f"Playbook aborted: {run_state['playbook_name']} - {reason}",
            actor='playbook-engine'
        )

        return True

    def list_active_runs(self) -> List[Dict[str, Any]]:
        """List active playbook runs"""
        active_runs = []

        for state_file in self.state_dir.glob('run-*.json'):
            try:
                with open(state_file, 'r') as f:
                    run_state = json.load(f)

                if run_state.get('status') == 'running':
                    active_runs.append(run_state)
            except Exception:
                continue

        return active_runs

    def _save_run_state(self, run_id: str, state: Dict[str, Any]):
        """Save playbook run state"""
        state_file = self.state_dir / f'{run_id}.json'
        with open(state_file, 'w') as f:
            json.dump(state, f, indent=2)

    def _load_run_state(self, run_id: str) -> Optional[Dict[str, Any]]:
        """Load playbook run state"""
        state_file = self.state_dir / f'{run_id}.json'
        if not state_file.exists():
            return None

        try:
            with open(state_file, 'r') as f:
                return json.load(f)
        except Exception:
            return None

    def close(self):
        """Close database connections"""
        self.tracker.close()


def main():
    """Test playbook engine"""
    # Create test playbook
    playbooks_dir = Path(__file__).parent
    test_playbook_file = playbooks_dir / 'test-playbook.yaml'

    test_playbook = {
        'playbook': {
            'id': 'test-playbook',
            'name': 'Test Playbook',
            'description': 'Test playbook for engine validation',
            'severity': 'medium',
            'version': '1.0'
        },
        'steps': [
            {
                'id': 'step1',
                'name': 'First Step',
                'description': 'Test step 1',
                'type': 'manual'
            },
            {
                'id': 'step2',
                'name': 'Second Step',
                'description': 'Test step 2',
                'type': 'automated'
            },
            {
                'id': 'step3',
                'name': 'Third Step',
                'description': 'Test step 3',
                'type': 'manual'
            }
        ]
    }

    with open(test_playbook_file, 'w') as f:
        yaml.dump(test_playbook, f)

    engine = PlaybookEngine()

    # List playbooks
    print("Available playbooks:")
    playbooks = engine.list_playbooks()
    for pb in playbooks:
        print(f"  - {pb['id']}: {pb['name']}")

    # Create test incident
    print("\nCreating test incident...")
    incident = engine.tracker.create_incident(
        title='Test Playbook Execution',
        severity='medium',
        description='Testing playbook engine'
    )
    incident_id = incident['id']
    print(f"Created: {incident_id}")

    # Start playbook
    print("\nStarting playbook...")
    run_id = engine.start_playbook(
        playbook_id='test-playbook',
        incident_id=incident_id,
        auto_execute=False
    )
    print(f"Run ID: {run_id}")

    # Get current step
    print("\nCurrent step:")
    step = engine.get_current_step(run_id)
    if step:
        print(f"  {step['name']}: {step['description']}")

    # Execute steps
    print("\nExecuting steps...")
    for i, step_id in enumerate(['step1', 'step2', 'step3'], 1):
        print(f"  Step {i}: {step_id}")
        engine.execute_step(run_id, step_id, result=f'Step {i} completed successfully')

    # Get final status
    print("\nFinal status:")
    status = engine.get_run_status(run_id)
    if status:
        print(f"  Status: {status['status']}")
        print(f"  Completed: {status['current_step']}/{status['total_steps']}")

    # Clean up test playbook
    test_playbook_file.unlink()

    engine.close()
    print("\nTest completed!")


if __name__ == '__main__':
    main()

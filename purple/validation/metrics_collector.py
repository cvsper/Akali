"""Metrics collection for purple team validation."""

from datetime import datetime
from typing import List, Dict, Optional
import json
import csv
import statistics


class MetricsCollector:
    """Collect and calculate security metrics."""

    def __init__(self):
        """Initialize metrics collector."""
        pass

    def calculate_mttd(self, attack_start: datetime, detection_time: datetime) -> float:
        """
        Calculate Mean Time To Detect (MTTD).

        Args:
            attack_start: Attack start timestamp
            detection_time: Detection timestamp

        Returns:
            MTTD in seconds
        """
        delta = detection_time - attack_start
        return delta.total_seconds()

    def calculate_mttr(self, detection_time: datetime, response_time: datetime) -> float:
        """
        Calculate Mean Time To Respond (MTTR).

        Args:
            detection_time: Detection timestamp
            response_time: Response/resolution timestamp

        Returns:
            MTTR in seconds
        """
        delta = response_time - detection_time
        return delta.total_seconds()

    def calculate_detection_rate(self, total_attacks: int, detected_attacks: int) -> float:
        """
        Calculate detection rate as percentage.

        Args:
            total_attacks: Total number of attacks
            detected_attacks: Number of detected attacks

        Returns:
            Detection rate percentage
        """
        if total_attacks == 0:
            return 0.0
        return (detected_attacks / total_attacks) * 100.0

    def calculate_false_positive_rate(self, total_alerts: int, false_positives: int) -> float:
        """
        Calculate false positive rate.

        Args:
            total_alerts: Total number of alerts
            false_positives: Number of false positive alerts

        Returns:
            False positive rate percentage
        """
        if total_alerts == 0:
            return 0.0
        return (false_positives / total_alerts) * 100.0

    def calculate_coverage(self, attack_types: List[str], detected_types: List[str]) -> float:
        """
        Calculate attack coverage percentage.

        Args:
            attack_types: All attack types tested
            detected_types: Attack types that were detected

        Returns:
            Coverage percentage
        """
        if len(attack_types) == 0:
            return 0.0
        detected_count = len([at for at in attack_types if at in detected_types])
        return (detected_count / len(attack_types)) * 100.0

    def calculate_average_mttd(self, mttd_values: List[float]) -> float:
        """
        Calculate average MTTD.

        Args:
            mttd_values: List of MTTD values

        Returns:
            Average MTTD
        """
        if not mttd_values:
            return 0.0
        return statistics.mean(mttd_values)

    def calculate_average_mttr(self, mttr_values: List[float]) -> float:
        """
        Calculate average MTTR.

        Args:
            mttr_values: List of MTTR values

        Returns:
            Average MTTR
        """
        if not mttr_values:
            return 0.0
        return statistics.mean(mttr_values)

    def calculate_percentile_mttd(self, mttd_values: List[float], percentile: int) -> float:
        """
        Calculate MTTD percentile.

        Args:
            mttd_values: List of MTTD values
            percentile: Percentile to calculate (0-100)

        Returns:
            MTTD at given percentile
        """
        if not mttd_values:
            return 0.0
        sorted_values = sorted(mttd_values)
        index = int((percentile / 100.0) * len(sorted_values))
        index = min(index, len(sorted_values) - 1)
        return sorted_values[index]

    def calculate_metrics_summary(self, data: Dict) -> Dict:
        """
        Calculate comprehensive metrics summary.

        Args:
            data: Dictionary with metrics data

        Returns:
            Summary dictionary with all metrics
        """
        summary = {}

        # Detection rate
        if 'total_attacks' in data and 'detected_attacks' in data:
            summary['detection_rate'] = self.calculate_detection_rate(
                data['total_attacks'],
                data['detected_attacks']
            )

        # False positive rate
        if 'total_alerts' in data and 'false_positives' in data:
            summary['false_positive_rate'] = self.calculate_false_positive_rate(
                data['total_alerts'],
                data['false_positives']
            )

        # Coverage
        if 'attack_types' in data and 'detected_types' in data:
            summary['coverage'] = self.calculate_coverage(
                data['attack_types'],
                data['detected_types']
            )

        # Average MTTD
        if 'mttd_values' in data and data['mttd_values']:
            summary['avg_mttd'] = self.calculate_average_mttd(data['mttd_values'])

        # Average MTTR
        if 'mttr_values' in data and data['mttr_values']:
            summary['avg_mttr'] = self.calculate_average_mttr(data['mttr_values'])

        return summary

    def format_duration(self, seconds: float) -> str:
        """
        Format duration in human-readable format.

        Args:
            seconds: Duration in seconds

        Returns:
            Formatted string (e.g., "2m 5s", "1h 1m 5s")
        """
        if seconds < 60:
            return f"{seconds}s"

        minutes = int(seconds // 60)
        remaining_seconds = int(seconds % 60)

        if minutes < 60:
            return f"{minutes}m {remaining_seconds}s"

        hours = minutes // 60
        remaining_minutes = minutes % 60
        return f"{hours}h {remaining_minutes}m {remaining_seconds}s"

    def export_metrics(self, metrics: Dict, output_path: str, format: str = 'json'):
        """
        Export metrics to file.

        Args:
            metrics: Metrics dictionary
            output_path: Output file path
            format: Export format ('json' or 'csv')
        """
        if format == 'json':
            with open(output_path, 'w') as f:
                json.dump(metrics, f, indent=2)
        elif format == 'csv':
            with open(output_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Metric', 'Value'])
                for key, value in metrics.items():
                    writer.writerow([key, value])

    def compare_metrics(self, baseline: Dict, current: Dict) -> Dict:
        """
        Compare current metrics against baseline.

        Args:
            baseline: Baseline metrics
            current: Current metrics

        Returns:
            Comparison results with improvement indicators
        """
        comparison = {}

        for metric in baseline.keys():
            if metric in current:
                baseline_value = baseline[metric]
                current_value = current[metric]
                delta = current_value - baseline_value

                # Determine if improvement (depends on metric type)
                improvement = False
                if metric in ['detection_rate', 'coverage']:
                    improvement = delta > 0  # Higher is better
                elif metric in ['false_positive_rate', 'avg_mttd', 'avg_mttr']:
                    improvement = delta < 0  # Lower is better

                comparison[metric] = {
                    'baseline': baseline_value,
                    'current': current_value,
                    'delta': delta,
                    'improvement': improvement
                }

        return comparison

    def calculate_trend(self, historical_data: List[Dict], metric_name: str) -> Dict:
        """
        Calculate trend for a metric over time.

        Args:
            historical_data: List of historical metric data points
            metric_name: Name of metric to analyze

        Returns:
            Trend analysis (direction, slope)
        """
        if len(historical_data) < 2:
            return {'direction': 'insufficient_data', 'slope': 0}

        values = [d[metric_name] for d in historical_data]

        # Simple linear trend
        n = len(values)
        x_sum = sum(range(n))
        y_sum = sum(values)
        xy_sum = sum(i * v for i, v in enumerate(values))
        x2_sum = sum(i * i for i in range(n))

        slope = (n * xy_sum - x_sum * y_sum) / (n * x2_sum - x_sum * x_sum)

        # Determine direction
        if slope > 0.5:
            direction = 'improving' if metric_name in ['detection_rate', 'coverage'] else 'degrading'
        elif slope < -0.5:
            direction = 'degrading' if metric_name in ['detection_rate', 'coverage'] else 'improving'
        else:
            direction = 'stable'

        return {
            'direction': direction,
            'slope': slope
        }

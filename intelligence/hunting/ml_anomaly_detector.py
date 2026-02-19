#!/usr/bin/env python3
"""
ML Anomaly Detector - Machine learning-based anomaly detection

Uses Isolation Forest algorithm for unsupervised anomaly detection.
Detects outliers in multi-dimensional feature space without requiring labeled data.
"""

import json
import os
import pickle
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path

try:
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    print("Warning: scikit-learn not available. Install with: pip install scikit-learn pandas numpy")


class MLAnomalyDetector:
    """
    Machine learning-based anomaly detection using Isolation Forest

    Isolation Forest works by:
    1. Randomly selecting a feature
    2. Randomly selecting a split value between min/max of that feature
    3. Recursively partitioning data
    4. Anomalies are isolated quickly (fewer splits needed)
    """

    def __init__(self, contamination: float = 0.1):
        """
        Initialize ML anomaly detector

        Args:
            contamination: Expected proportion of outliers (default: 0.1 = 10%)
        """
        if not SKLEARN_AVAILABLE:
            raise ImportError("scikit-learn required. Install with: pip install scikit-learn pandas numpy")

        self.models_dir = Path.home() / "akali" / "intelligence" / "hunting" / "models"
        self.models_dir.mkdir(parents=True, exist_ok=True)

        self.contamination = contamination
        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self.feature_names: List[str] = []
        self.is_trained = False

    def train(self, data: pd.DataFrame, feature_columns: List[str], model_name: str = "default"):
        """
        Train isolation forest model on historical data

        Args:
            data: DataFrame with historical data
            feature_columns: List of column names to use as features
            model_name: Name for saving the model

        Returns:
            Training statistics
        """
        if data.empty:
            raise ValueError("Cannot train on empty dataset")

        # Extract features
        X = data[feature_columns].values

        # Handle missing values
        X = np.nan_to_num(X, nan=0.0)

        # Normalize features
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        # Train Isolation Forest
        self.model = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_estimators=100,
            max_samples='auto',
            max_features=1.0,
            bootstrap=False,
            n_jobs=-1  # Use all CPU cores
        )

        self.model.fit(X_scaled)
        self.feature_names = feature_columns
        self.is_trained = True

        # Get training statistics
        predictions = self.model.predict(X_scaled)
        scores = self.model.score_samples(X_scaled)

        num_anomalies = np.sum(predictions == -1)
        anomaly_rate = num_anomalies / len(predictions)

        stats = {
            "model_name": model_name,
            "training_samples": len(data),
            "feature_count": len(feature_columns),
            "features": feature_columns,
            "contamination": self.contamination,
            "detected_anomalies": int(num_anomalies),
            "anomaly_rate": round(anomaly_rate * 100, 2),
            "avg_score": float(np.mean(scores)),
            "min_score": float(np.min(scores)),
            "max_score": float(np.max(scores)),
            "trained_at": datetime.now().isoformat()
        }

        # Save model
        self.save_model(model_name)

        return stats

    def predict(self, data: pd.DataFrame) -> List[Dict[str, Any]]:
        """
        Predict anomalies in new data

        Args:
            data: DataFrame with new data (must have same features as training)

        Returns:
            List of anomalies with details
        """
        if not self.is_trained:
            raise ValueError("Model not trained. Call train() first.")

        if data.empty:
            return []

        # Extract features
        X = data[self.feature_names].values
        X = np.nan_to_num(X, nan=0.0)

        # Scale features
        X_scaled = self.scaler.transform(X)

        # Predict
        predictions = self.model.predict(X_scaled)
        scores = self.model.score_samples(X_scaled)

        # Extract anomalies
        anomalies = []
        for idx, (pred, score) in enumerate(zip(predictions, scores)):
            if pred == -1:  # Anomaly
                anomaly = {
                    "index": int(idx),
                    "anomaly_score": float(score),
                    "severity": self._score_to_severity(score),
                    "features": {},
                    "timestamp": datetime.now().isoformat()
                }

                # Add feature values
                for feature_idx, feature_name in enumerate(self.feature_names):
                    anomaly["features"][feature_name] = float(X[idx][feature_idx])

                # Add original data if available
                if idx < len(data):
                    row_data = data.iloc[idx].to_dict()
                    anomaly["data"] = {k: (v if not isinstance(v, (np.integer, np.floating)) else float(v))
                                      for k, v in row_data.items() if k not in self.feature_names}

                anomalies.append(anomaly)

        return anomalies

    def _score_to_severity(self, score: float) -> str:
        """Convert anomaly score to severity level"""
        # More negative score = more anomalous
        if score < -0.5:
            return "critical"
        elif score < -0.3:
            return "high"
        elif score < -0.1:
            return "medium"
        else:
            return "low"

    def save_model(self, model_name: str):
        """Save trained model to disk"""
        if not self.is_trained:
            raise ValueError("No trained model to save")

        model_path = self.models_dir / f"{model_name}.pkl"

        model_data = {
            "model": self.model,
            "scaler": self.scaler,
            "feature_names": self.feature_names,
            "contamination": self.contamination,
            "trained_at": datetime.now().isoformat()
        }

        with open(model_path, 'wb') as f:
            pickle.dump(model_data, f)

        print(f"Model saved to {model_path}")

    def load_model(self, model_name: str):
        """Load trained model from disk"""
        model_path = self.models_dir / f"{model_name}.pkl"

        if not model_path.exists():
            raise FileNotFoundError(f"Model not found: {model_path}")

        with open(model_path, 'rb') as f:
            model_data = pickle.load(f)

        self.model = model_data["model"]
        self.scaler = model_data["scaler"]
        self.feature_names = model_data["feature_names"]
        self.contamination = model_data["contamination"]
        self.is_trained = True

        print(f"Model loaded from {model_path}")
        print(f"Features: {', '.join(self.feature_names)}")
        print(f"Trained at: {model_data['trained_at']}")

    def evaluate(self, data: pd.DataFrame, labels: Optional[List[int]] = None) -> Dict[str, Any]:
        """
        Evaluate model performance (if labels are available)

        Args:
            data: DataFrame with test data
            labels: Optional list of true labels (1 = normal, -1 = anomaly)

        Returns:
            Evaluation metrics
        """
        if not self.is_trained:
            raise ValueError("Model not trained. Call train() first.")

        X = data[self.feature_names].values
        X = np.nan_to_num(X, nan=0.0)
        X_scaled = self.scaler.transform(X)

        predictions = self.model.predict(X_scaled)
        scores = self.model.score_samples(X_scaled)

        metrics = {
            "total_samples": len(data),
            "predicted_anomalies": int(np.sum(predictions == -1)),
            "predicted_normal": int(np.sum(predictions == 1)),
            "avg_score": float(np.mean(scores)),
            "score_std": float(np.std(scores))
        }

        # If labels provided, calculate accuracy metrics
        if labels is not None:
            labels = np.array(labels)
            true_positives = np.sum((predictions == -1) & (labels == -1))
            false_positives = np.sum((predictions == -1) & (labels == 1))
            true_negatives = np.sum((predictions == 1) & (labels == 1))
            false_negatives = np.sum((predictions == 1) & (labels == -1))

            precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
            recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
            f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

            metrics.update({
                "true_positives": int(true_positives),
                "false_positives": int(false_positives),
                "true_negatives": int(true_negatives),
                "false_negatives": int(false_negatives),
                "precision": round(precision, 3),
                "recall": round(recall, 3),
                "f1_score": round(f1, 3),
                "accuracy": round((true_positives + true_negatives) / len(labels), 3)
            })

        return metrics


class NetworkTrafficDetector(MLAnomalyDetector):
    """Specialized detector for network traffic anomalies"""

    def prepare_features(self, connections: List[Dict[str, Any]]) -> pd.DataFrame:
        """
        Prepare network connection data for ML

        Features:
        - Connection count per source IP
        - Total bytes sent/received
        - Unique destinations
        - Port diversity
        - Protocol distribution
        """
        records = []

        # Group by source IP and time window
        from collections import defaultdict
        ip_groups = defaultdict(list)

        for conn in connections:
            ip_groups[conn['source_ip']].append(conn)

        for source_ip, conns in ip_groups.items():
            record = {
                "source_ip": source_ip,
                "connection_count": len(conns),
                "unique_destinations": len(set(c.get('dest_ip', '') for c in conns)),
                "total_bytes_sent": sum(c.get('bytes_sent', 0) for c in conns),
                "total_bytes_received": sum(c.get('bytes_received', 0) for c in conns),
                "unique_ports": len(set(c.get('port', 0) for c in conns)),
                "avg_bytes_per_connection": sum(c.get('bytes_sent', 0) + c.get('bytes_received', 0) for c in conns) / len(conns) if conns else 0,
            }

            records.append(record)

        return pd.DataFrame(records)


class APIUsageDetector(MLAnomalyDetector):
    """Specialized detector for API usage anomalies"""

    def prepare_features(self, requests: List[Dict[str, Any]]) -> pd.DataFrame:
        """
        Prepare API request data for ML

        Features:
        - Request rate
        - Error rate
        - Unique endpoints accessed
        - Average response time
        - Method distribution
        """
        records = []

        from collections import defaultdict
        user_groups = defaultdict(list)

        for req in requests:
            user_groups[req['user']].append(req)

        for user, reqs in user_groups.items():
            error_count = sum(1 for r in reqs if r.get('status_code', 200) >= 400)

            record = {
                "user": user,
                "request_count": len(reqs),
                "unique_endpoints": len(set(r.get('endpoint', '') for r in reqs)),
                "error_rate": error_count / len(reqs) if reqs else 0,
                "avg_response_time": sum(r.get('response_time_ms', 0) for r in reqs) / len(reqs) if reqs else 0,
                "max_response_time": max((r.get('response_time_ms', 0) for r in reqs), default=0),
            }

            records.append(record)

        return pd.DataFrame(records)


if __name__ == "__main__":
    if not SKLEARN_AVAILABLE:
        print("scikit-learn not installed. Demo skipped.")
        exit(1)

    print("=== ML Anomaly Detector Demo ===\n")

    # Create sample network traffic data
    np.random.seed(42)

    # Normal traffic
    normal_data = []
    for i in range(100):
        normal_data.append({
            "source_ip": f"10.0.0.{i % 50}",
            "connection_count": np.random.normal(50, 10),
            "unique_destinations": np.random.normal(10, 2),
            "total_bytes_sent": np.random.normal(10000, 2000),
            "total_bytes_received": np.random.normal(50000, 10000),
            "unique_ports": np.random.normal(5, 1),
            "avg_bytes_per_connection": np.random.normal(1000, 200)
        })

    # Anomalous traffic (data exfiltration)
    for i in range(10):
        normal_data.append({
            "source_ip": f"10.0.0.{i}",
            "connection_count": np.random.normal(200, 20),  # Much higher
            "unique_destinations": np.random.normal(50, 10),  # Much higher
            "total_bytes_sent": np.random.normal(100000, 20000),  # Much higher
            "total_bytes_received": np.random.normal(50000, 10000),
            "unique_ports": np.random.normal(20, 5),  # Much higher
            "avg_bytes_per_connection": np.random.normal(1000, 200)
        })

    df = pd.DataFrame(normal_data)

    # Train model
    detector = NetworkTrafficDetector(contamination=0.1)
    features = ["connection_count", "unique_destinations", "total_bytes_sent",
                "total_bytes_received", "unique_ports", "avg_bytes_per_connection"]

    print("Training model...")
    stats = detector.train(df, features, model_name="network_traffic")

    print(f"\nTraining Statistics:")
    print(f"  Samples: {stats['training_samples']}")
    print(f"  Features: {stats['feature_count']}")
    print(f"  Detected Anomalies: {stats['detected_anomalies']} ({stats['anomaly_rate']}%)")
    print(f"  Avg Anomaly Score: {stats['avg_score']:.3f}")

    # Test on new data
    test_data = []
    for i in range(5):
        test_data.append({
            "source_ip": f"10.0.0.{100 + i}",
            "connection_count": 300,  # Anomalous
            "unique_destinations": 80,  # Anomalous
            "total_bytes_sent": 200000,  # Anomalous
            "total_bytes_received": 60000,
            "unique_ports": 30,  # Anomalous
            "avg_bytes_per_connection": 1100
        })

    test_df = pd.DataFrame(test_data)

    print("\n\nTesting on new data...")
    anomalies = detector.predict(test_df)

    print(f"\nDetected {len(anomalies)} anomalies:\n")
    for anomaly in anomalies:
        print(f"[{anomaly['severity'].upper()}] Index {anomaly['index']}")
        print(f"  Score: {anomaly['anomaly_score']:.3f}")
        print(f"  Features: {anomaly['features']}")
        print()

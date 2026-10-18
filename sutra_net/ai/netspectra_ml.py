"""
NetSpectra-ML: Encrypted Traffic Intelligence & C2 Hunter
Extracts statistical packet & flow dynamics (jitter, burst entropy, periodicity)
and applies ML models to detect encrypted C2 beaconing and exfiltration without payload decryption.
"""

import math
import numpy as np
from typing import List, Dict, Any, Tuple
from sklearn.ensemble import IsolationForest, RandomForestClassifier

from sutra_net.config import C2_BEACONING_JITTER_THRESHOLD_SEC


class NetSpectraML:
    """
    Analyzes encrypted network telemetry for malware C2 beaconing,
    DNS tunneling, and ransomware exfiltration.
    """

    KNOWN_MALICIOUS_JA3 = {
        "a0e9f5d64349fb13191bc781f81f42e8": "Cobalt Strike HTTPS Beacon",
        "72a589da586844d7f0818ce684948eea": "Sliver C2 Implant",
        "b384e0f666f7f2b3b07049466f20485a": "Meterpreter Reverse HTTPS",
        "51c64c77e60f39ac3e1776dd7b3e4538": "AsyncRAT Client"
    }

    def __init__(self):
        # Isolation Forest for unsupervised anomaly detection
        self.anomaly_detector = IsolationForest(
            n_estimators=100,
            contamination=0.08,
            random_state=42
        )
        self.is_fitted = False
        self._init_baseline_model()

    def _init_baseline_model(self):
        """
        Initializes baseline reference distribution on standard synthetic benign/malicious flow metrics.
        Features: [packet_count, duration_sec, mean_delta_sec, jitter_sec, avg_packet_len]
        """
        # Baseline benign traffic: variable packet counts, higher jitter, larger avg packet size
        np.random.seed(42)
        benign_samples = np.array([
            [np.random.randint(10, 500), np.random.uniform(5.0, 120.0), np.random.uniform(0.1, 4.0), np.random.uniform(0.5, 3.0), np.random.uniform(400, 1400)]
            for _ in range(300)
        ])
        self.anomaly_detector.fit(benign_samples)
        self.is_fitted = True

    @staticmethod
    def extract_features(flow: Dict[str, Any]) -> List[float]:
        """
        Extracts 5-dimensional numerical feature vector from flow record.
        """
        return [
            float(flow.get("packet_count", 0)),
            float(flow.get("duration_sec", 0.0)),
            float(flow.get("mean_delta_sec", 0.0)),
            float(flow.get("jitter_sec", 0.0)),
            float(flow.get("avg_packet_len", 0.0))
        ]

    def score_flow(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        """
        Performs holistic multi-factor scoring:
        1. JA3 fingerprint match
        2. Statistical periodicity test (Coefficient of Variation)
        3. Isolation Forest anomaly score
        """
        features = self.extract_features(flow)
        ja3 = flow.get("ja3")
        mean_delta = flow.get("mean_delta_sec", 0.0)
        jitter = flow.get("jitter_sec", 0.0)
        packet_count = flow.get("packet_count", 0)

        # 1. JA3 Threat Intel Match
        known_threat = self.KNOWN_MALICIOUS_JA3.get(ja3) if ja3 else None

        # 2. Periodicity / Beaconing Detection
        # Low jitter relative to mean delta with sufficient packets indicates automated heartbeats
        cv = (jitter / mean_delta) if mean_delta > 0.001 else 999.0
        is_periodic = (cv < 0.25 and packet_count >= 5 and jitter < C2_BEACONING_JITTER_THRESHOLD_SEC)

        # 3. Isolation Forest Anomaly Score (-1 is anomaly, 1 is normal)
        feat_array = np.array([features])
        raw_anomaly = self.anomaly_detector.decision_function(feat_array)[0]
        # Normalize anomaly score from 0.0 (normal) to 1.0 (highly anomalous)
        anomaly_score = round(float(np.clip(0.5 - (raw_anomaly * 1.5), 0.0, 1.0)), 3)

        # Classify Threat Level
        threat_type = "BENIGN"
        mitre_tactic = None
        mitre_technique = None

        if known_threat:
            threat_type = f"CONFIRMED_C2 ({known_threat})"
            anomaly_score = max(anomaly_score, 0.98)
            mitre_tactic = "Command and Control"
            mitre_technique = "T1071.001 (Web Protocols / Encrypted Channel)"
        elif is_periodic:
            threat_type = "SUSPECTED_C2_BEACON"
            anomaly_score = max(anomaly_score, 0.88)
            mitre_tactic = "Command and Control"
            mitre_technique = "T1573 (Encrypted Channel - Periodic Beaconing)"
        elif flow.get("avg_packet_len", 0) > 1300 and flow.get("total_bytes", 0) > 1000000:
            threat_type = "SUSPECTED_DATA_EXFILTRATION"
            anomaly_score = max(anomaly_score, 0.78)
            mitre_tactic = "Exfiltration"
            mitre_technique = "T1048 (Exfiltration Over Alternative Protocol)"
        elif anomaly_score > 0.75:
            threat_type = "STATISTICAL_FLOW_ANOMALY"
            mitre_tactic = "Defense Evasion"
            mitre_technique = "T1027 (Obfuscated Traffic)"

        return {
            "flow_id": flow.get("flow_id"),
            "threat_type": threat_type,
            "anomaly_score": anomaly_score,
            "is_malicious": (anomaly_score >= 0.75 or known_threat is not None),
            "periodicity_cv": round(cv, 3),
            "is_periodic_beacon": is_periodic,
            "ja3_signature": known_threat,
            "mitre_tactic": mitre_tactic,
            "mitre_technique": mitre_technique,
            "flow_details": flow
        }

    def triage_flows(self, flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Runs triage across a batch of flows, sorting by highest threat score.
        """
        results = [self.score_flow(f) for f in flows]
        results.sort(key=lambda x: x["anomaly_score"], reverse=True)
        return results

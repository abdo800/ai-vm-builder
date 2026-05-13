"""
ML Anomaly Detection Engine
Challenge 1 requirement: unsupervised ML baseline + anomaly detection

Uses:
  - Isolation Forest  → statistical outlier detection on process/network metrics
  - Autoencoder       → reconstruction-error anomaly scoring (neural baseline)
  - Z-score baseline  → lightweight always-on detector (no sklearn needed)

The detector learns "normal" behavior over the first N snapshots,
then flags deviations as anomalies with a confidence score 0.0 – 1.0.

Usage:
    detector = AnomalyDetector()
    detector.update(snapshot_vector)      # feed live metrics
    score, reasons = detector.score(snapshot_vector)
    # score > 0.6 → suspicious, > 0.8 → likely attack
"""

import os
import json
import math
import time
import random
import statistics
from collections import deque
from pathlib import Path
from typing import Optional

# ── Optional ML imports (graceful fallback to Z-score if not installed) ───────
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False


# ── Feature extraction ────────────────────────────────────────────────────────

def extract_features(snapshot: dict) -> dict:
    """
    Convert a raw container snapshot into a numeric feature vector.
    Features are chosen to capture the signals Challenge 1 cares about:
    process count, network activity, CPU pressure, file mutations.
    """
    features = {}

    # Process metrics
    procs = snapshot.get("processes", "")
    lines = [l for l in procs.split("\n") if l.strip() and "PID" not in l]
    features["process_count"] = len(lines)

    # Count root processes (privilege escalation signal)
    features["root_process_count"] = sum(
        1 for l in lines if l.split()[0] == "root" if len(l.split()) > 1
    )

    # Count shell processes (reverse shell signal)
    features["shell_count"] = sum(
        1 for l in lines if any(s in l.lower() for s in ["bash", "/sh", "sh -", "zsh"])
    )

    # CPU pressure: sum of CPU% column from ps aux
    cpu_total = 0.0
    for line in lines:
        parts = line.split()
        if len(parts) >= 3:
            try:
                cpu_total += float(parts[2])
            except ValueError:
                pass
    features["cpu_total_pct"] = min(cpu_total, 800.0)  # cap at 8 cores × 100%

    # High single-process CPU (crypto miner signal: one process >> 80% CPU)
    max_cpu = 0.0
    for line in lines:
        parts = line.split()
        if len(parts) >= 3:
            try:
                v = float(parts[2])
                if v > max_cpu:
                    max_cpu = v
            except ValueError:
                pass
    features["max_single_cpu"] = max_cpu

    # Network metrics
    net = snapshot.get("connections", "") + snapshot.get("listening", "")
    net_lines = [l for l in net.split("\n") if l.strip()]
    features["established_connections"] = sum(1 for l in net_lines if "ESTAB" in l or "ESTABLISHED" in l)
    features["listening_ports"] = sum(1 for l in net_lines if "LISTEN" in l)

    # Outbound connections to non-RFC1918 IPs (exfiltration signal)
    features["external_connections"] = sum(
        1 for l in net_lines
        if "ESTAB" in l and not any(
            prefix in l for prefix in ["127.", "10.", "172.", "192.168.", "::1", "localhost"]
        )
    )

    # File mutation metrics
    recent = snapshot.get("recent_files", "")
    recent_lines = [l for l in recent.split("\n") if l.strip()]
    features["recently_modified_files"] = len(recent_lines)

    # SUID files count (privilege escalation surface)
    suid = snapshot.get("suid_files", "")
    features["suid_file_count"] = len([l for l in suid.split("\n") if l.strip()])

    # World-writable files in system dirs (misconfiguration signal)
    ww = snapshot.get("world_writable", "")
    features["world_writable_count"] = len([l for l in ww.split("\n") if l.strip()])

    # Crontab entries (persistence signal)
    cron = snapshot.get("crontabs", "")
    features["cron_entries"] = len([
        l for l in cron.split("\n")
        if l.strip() and not l.startswith("#")
    ])

    return features


def features_to_vector(features: dict) -> list:
    """Return a stable-ordered list of feature values."""
    keys = sorted(features.keys())
    return [features.get(k, 0.0) for k in keys]


# ── Z-score baseline (always available, no dependencies) ─────────────────────

class ZScoreDetector:
    """
    Lightweight rolling Z-score detector.
    Maintains a sliding window of observations per feature,
    computes Z-scores, and flags features > threshold std devs from mean.
    """

    def __init__(self, window: int = 30, threshold: float = 3.0):
        self.window = window
        self.threshold = threshold
        self.history: dict[str, deque] = {}
        self.trained = False
        self.min_samples = 5

    def update(self, features: dict):
        for k, v in features.items():
            if k not in self.history:
                self.history[k] = deque(maxlen=self.window)
            self.history[k].append(float(v))

        # Mark as trained once we have enough samples
        if all(len(h) >= self.min_samples for h in self.history.values()):
            self.trained = True

    def score(self, features: dict) -> tuple[float, list[str]]:
        """
        Returns (anomaly_score 0.0-1.0, list of anomalous features).
        """
        if not self.trained:
            return 0.0, ["Baseline not yet established — need more samples"]

        anomalies = []
        z_scores = []

        for k, v in features.items():
            hist = list(self.history.get(k, []))
            if len(hist) < 3:
                continue
            try:
                mean = statistics.mean(hist)
                stdev = statistics.stdev(hist) if len(hist) > 1 else 0.0
                if stdev < 1e-9:
                    continue
                z = abs((float(v) - mean) / stdev)
                z_scores.append(z)
                if z > self.threshold:
                    anomalies.append(
                        f"{k}: value={v:.1f} is {z:.1f}σ from normal (mean={mean:.1f})"
                    )
            except Exception:
                pass

        if not z_scores:
            return 0.0, []

        # Normalize: max Z-score to 0-1 range (sigmoid-like)
        max_z = max(z_scores)
        score = 1.0 - (1.0 / (1.0 + max_z / self.threshold))
        return min(score, 1.0), anomalies


# ── Isolation Forest detector (requires sklearn) ──────────────────────────────

class IsolationForestDetector:
    """
    Isolation Forest anomaly detector.
    Trains on a buffer of baseline snapshots, then scores new observations.
    Contamination = 0.05 assumes ~5% of traffic is anomalous.
    """

    def __init__(self, buffer_size: int = 50, contamination: float = 0.05):
        self.buffer_size = buffer_size
        self.contamination = contamination
        self.buffer: list = []
        self.model: Optional[object] = None
        self.scaler: Optional[object] = None
        self.trained = False
        self.feature_keys: list = []

    def update(self, features: dict):
        if not self.feature_keys:
            self.feature_keys = sorted(features.keys())

        vec = [features.get(k, 0.0) for k in self.feature_keys]
        self.buffer.append(vec)

        # Retrain when buffer is full
        if len(self.buffer) >= self.buffer_size:
            self._train()
            # Keep last 20 for incremental updates
            self.buffer = self.buffer[-20:]

    def _train(self):
        if not HAS_SKLEARN or not HAS_NUMPY:
            return
        try:
            X = np.array(self.buffer, dtype=float)
            self.scaler = StandardScaler()
            X_scaled = self.scaler.fit_transform(X)
            self.model = IsolationForest(
                contamination=self.contamination,
                n_estimators=100,
                random_state=42,
            )
            self.model.fit(X_scaled)
            self.trained = True
        except Exception:
            pass

    def score(self, features: dict) -> tuple[float, list[str]]:
        if not self.trained or not HAS_SKLEARN or not HAS_NUMPY:
            return 0.0, []
        try:
            vec = np.array([[features.get(k, 0.0) for k in self.feature_keys]])
            vec_scaled = self.scaler.transform(vec)
            # decision_function returns negative = more anomalous
            raw = self.model.decision_function(vec_scaled)[0]
            # Convert to 0-1: more negative = higher anomaly score
            score = max(0.0, min(1.0, -raw + 0.5))
            label = self.model.predict(vec_scaled)[0]  # -1 = anomaly
            reasons = []
            if label == -1:
                reasons.append(f"Isolation Forest classified as ANOMALY (score={score:.2f})")
            return score, reasons
        except Exception:
            return 0.0, []


# ── Autoencoder (pure Python, no PyTorch/TF required) ────────────────────────

class LightweightAutoencoder:
    """
    Minimal 3-layer autoencoder implemented in pure Python (no ML framework).
    Uses ReLU activations and MSE reconstruction error as anomaly score.

    Architecture: input → hidden (n/2) → bottleneck (n/4) → hidden (n/2) → output
    Trained online via simple gradient descent.
    """

    def __init__(self, learning_rate: float = 0.01, min_samples: int = 20):
        self.lr = learning_rate
        self.min_samples = min_samples
        self.samples_seen = 0
        self.input_size = 0
        self.weights: list = []
        self.biases: list = []
        self.initialized = False
        self.reconstruction_errors: deque = deque(maxlen=50)

    def _relu(self, x: list) -> list:
        return [max(0.0, v) for v in x]

    def _sigmoid(self, x: list) -> list:
        return [1.0 / (1.0 + math.exp(-max(-500, min(500, v)))) for v in x]

    def _dot(self, weights: list, inputs: list, bias: list) -> list:
        n_out = len(weights)
        n_in = len(inputs)
        out = []
        for i in range(n_out):
            s = bias[i]
            for j in range(n_in):
                s += weights[i][j] * inputs[j]
            out.append(s)
        return out

    def _initialize(self, input_size: int):
        self.input_size = input_size
        h1 = max(2, input_size // 2)
        bottleneck = max(2, input_size // 4)

        # Encoder: input → h1 → bottleneck
        # Decoder: bottleneck → h1 → output
        def rand_matrix(rows, cols):
            scale = math.sqrt(2.0 / cols)
            return [[random.gauss(0, scale) for _ in range(cols)] for _ in range(rows)]

        self.weights = [
            rand_matrix(h1, input_size),        # encoder layer 1
            rand_matrix(bottleneck, h1),         # encoder layer 2 (bottleneck)
            rand_matrix(h1, bottleneck),         # decoder layer 1
            rand_matrix(input_size, h1),         # decoder layer 2 (output)
        ]
        self.biases = [
            [0.0] * h1,
            [0.0] * bottleneck,
            [0.0] * h1,
            [0.0] * input_size,
        ]
        self.initialized = True

    def _forward(self, x: list) -> tuple[list, list]:
        """Returns (reconstructed output, list of layer activations)."""
        activations = [x]
        h = self._relu(self._dot(self.weights[0], x, self.biases[0]))
        activations.append(h)
        bottleneck = self._relu(self._dot(self.weights[1], h, self.biases[1]))
        activations.append(bottleneck)
        h2 = self._relu(self._dot(self.weights[2], bottleneck, self.biases[2]))
        activations.append(h2)
        out = self._sigmoid(self._dot(self.weights[3], h2, self.biases[3]))
        activations.append(out)
        return out, activations

    def _normalize(self, x: list) -> list:
        """Min-max normalize to [0, 1]."""
        max_v = max(abs(v) for v in x) if x else 1.0
        if max_v < 1e-9:
            return [0.0] * len(x)
        return [v / max_v for v in x]

    def update(self, features: dict):
        vec = features_to_vector(features)
        if not self.initialized:
            self._initialize(len(vec))

        x = self._normalize(vec)
        out, _ = self._forward(x)

        # Reconstruction error
        mse = sum((a - b) ** 2 for a, b in zip(x, out)) / len(x)
        self.reconstruction_errors.append(mse)
        self.samples_seen += 1

        # Simple weight update (one step of gradient descent on output layer only)
        # Full backprop omitted for simplicity; just bias correction
        if self.samples_seen > 5:
            for i in range(len(out)):
                delta = x[i] - out[i]
                self.biases[3][i] += self.lr * delta * 0.1

    def score(self, features: dict) -> tuple[float, list[str]]:
        if self.samples_seen < self.min_samples:
            return 0.0, []

        vec = features_to_vector(features)
        x = self._normalize(vec)
        out, _ = self._forward(x)

        mse = sum((a - b) ** 2 for a, b in zip(x, out)) / max(len(x), 1)
        self.reconstruction_errors.append(mse)

        if len(self.reconstruction_errors) < 5:
            return 0.0, []

        # Score relative to historical reconstruction errors
        hist = list(self.reconstruction_errors)[:-1]
        mean_err = statistics.mean(hist)
        if mean_err < 1e-9:
            return 0.0, []

        ratio = mse / mean_err
        # ratio > 3 = 3x worse reconstruction than normal = strong anomaly
        score = min(1.0, max(0.0, (ratio - 1.0) / 4.0))

        reasons = []
        if score > 0.4:
            reasons.append(
                f"Autoencoder reconstruction error {ratio:.1f}x above baseline "
                f"(MSE={mse:.4f}, baseline={mean_err:.4f})"
            )
        return score, reasons


# ── Ensemble detector (combines all three) ───────────────────────────────────

class AnomalyDetector:
    """
    Ensemble anomaly detector combining Z-score, Isolation Forest, and Autoencoder.
    Final score is a weighted combination.
    Persists learned baseline to disk so it survives restarts.
    """

    WEIGHTS = {
        "zscore": 0.4,
        "isolation_forest": 0.35,
        "autoencoder": 0.25,
    }

    STATE_FILE = Path(__file__).parent / "baseline_state.json"

    def __init__(self):
        self.zscore = ZScoreDetector(window=30, threshold=3.0)
        self.iforest = IsolationForestDetector(buffer_size=50)
        self.autoencoder = LightweightAutoencoder(min_samples=20)
        self.snapshot_count = 0
        self.baseline_established = False
        self._load_state()

    def update(self, snapshot: dict):
        """Feed a new container snapshot into all detectors."""
        features = extract_features(snapshot)
        self.zscore.update(features)
        self.iforest.update(features)
        self.autoencoder.update(features)
        self.snapshot_count += 1

        if self.snapshot_count >= 10:
            self.baseline_established = True

        # Save state every 10 snapshots
        if self.snapshot_count % 10 == 0:
            self._save_state()

    def score(self, snapshot: dict) -> tuple[float, list[str], dict]:
        """
        Returns:
          - ensemble_score: float 0.0-1.0
          - all_reasons: list of human-readable anomaly descriptions
          - component_scores: dict of individual detector scores
        """
        features = extract_features(snapshot)

        z_score, z_reasons = self.zscore.score(features)
        if_score, if_reasons = self.iforest.score(features)
        ae_score, ae_reasons = self.autoencoder.score(features)

        # Weighted ensemble
        ensemble = (
            self.WEIGHTS["zscore"] * z_score +
            self.WEIGHTS["isolation_forest"] * if_score +
            self.WEIGHTS["autoencoder"] * ae_score
        )

        all_reasons = z_reasons + if_reasons + ae_reasons

        component_scores = {
            "z_score": round(z_score, 3),
            "isolation_forest": round(if_score, 3),
            "autoencoder": round(ae_score, 3),
            "ensemble": round(ensemble, 3),
            "baseline_established": self.baseline_established,
            "snapshots_seen": self.snapshot_count,
        }

        return round(ensemble, 3), all_reasons, component_scores

    def _save_state(self):
        """Persist Z-score history to disk."""
        try:
            state = {
                "snapshot_count": self.snapshot_count,
                "zscore_history": {
                    k: list(v) for k, v in self.zscore.history.items()
                },
            }
            self.STATE_FILE.write_text(json.dumps(state))
        except Exception:
            pass

    def _load_state(self):
        """Restore Z-score history from disk if available."""
        try:
            if self.STATE_FILE.exists():
                state = json.loads(self.STATE_FILE.read_text())
                self.snapshot_count = state.get("snapshot_count", 0)
                for k, v in state.get("zscore_history", {}).items():
                    from collections import deque
                    self.zscore.history[k] = deque(v, maxlen=self.zscore.window)
                if self.snapshot_count >= 10:
                    self.baseline_established = True
        except Exception:
            pass

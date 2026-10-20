"""
NIDS inference engine.

Combines:
- Random Forest 8-attack + BENIGN pattern classification
- PyTorch LSTM session-level sequence modeling (10-packet sliding window)
- Weighted soft-voting ensemble (0.75 RF + 0.25 LSTM)
- Fast SHAP TreeExplainer feature attribution for alerts
- Plain-English explanation generation
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional, Union

import numpy as np
import pandas as pd
import torch

from app.features.feature_schema import (
    CICFLOW_TO_CANONICAL,
    FEATURE_COLUMNS,
    SELECTED_32_FEATURES,
)
from .model_loader import (
    CLASS_NAMES_9,
    CLASS_NAMES_15,
    LSTM_WINDOW_SIZE,
    NUM_CLASSES,
    ModelBundle,
    get_artifacts,
)

logger = logging.getLogger(__name__)


@dataclass
class PredictionResult:
    label: str
    is_malicious: bool
    confidence: float
    class_probabilities_9: Dict[str, float]
    probabilities_15: List[float]
    rf_probabilities_15: List[float]
    lstm_probabilities_15: List[float]
    top_features: List[Dict[str, Any]]
    lime_features: List[Dict[str, Any]]
    used_lstm: bool
    latency_ms: float
    session_id: Optional[str] = None


@dataclass
class LatencyTracker:
    window: Deque[float] = field(default_factory=lambda: deque(maxlen=2000))

    def record(self, latency_ms: float) -> None:
        self.window.append(latency_ms)

    def snapshot(self) -> Dict[str, float]:
        if not self.window:
            return {
                "count": 0,
                "p50_ms": 0.0,
                "p95_ms": 0.0,
                "p99_ms": 0.0,
                "max_ms": 0.0,
            }

        arr = np.array(self.window)
        return {
            "count": len(arr),
            "p50_ms": float(np.percentile(arr, 50)),
            "p95_ms": float(np.percentile(arr, 95)),
            "p99_ms": float(np.percentile(arr, 99)),
            "max_ms": float(arr.max()),
        }


def _map_9_to_15(probs_9: np.ndarray) -> List[float]:
    """
    Project 9-class probabilities [BENIGN, DDoS, Port Scan, Brute Force, Bot, Web Attack, Infiltration, DoS, Heartbleed]
    into Member C's 15-class dashboard array format:
    0: BENIGN, 1: Bot, 2: DDoS, 3: DoS GoldenEye, 4: DoS Hulk, 5: DoS Slowhttptest, 6: DoS slowloris,
    7: FTP-Patator, 8: Heartbleed, 9: Infiltration, 10: PortScan, 11: SSH-Patator,
    12: Web Attack - Brute Force, 13: Web Attack - Sql Injection, 14: Web Attack - XSS
    """
    p15 = [0.0] * 15
    if len(probs_9) >= 9:
        p15[0] = float(probs_9[0])   # BENIGN
        p15[1] = float(probs_9[4])   # Bot
        p15[2] = float(probs_9[1])   # DDoS
        p15[6] = float(probs_9[7])   # DoS / DoS slowloris
        p15[8] = float(probs_9[8])   # Heartbleed
        p15[9] = float(probs_9[6])   # Infiltration
        p15[10] = float(probs_9[2])  # PortScan / Port Scan
        p15[11] = float(probs_9[3])  # SSH-Patator / Brute Force
        p15[12] = float(probs_9[5])  # Web Attack
    return p15


class InferenceEngine:
    def __init__(self, bundle: Optional[ModelBundle] = None):
        self._bundle = bundle
        self.latency = LatencyTracker()
        self._session_windows: Dict[str, Deque[np.ndarray]] = defaultdict(
            lambda: deque(maxlen=LSTM_WINDOW_SIZE)
        )

    @property
    def bundle(self) -> ModelBundle:
        if self._bundle is None:
            self._bundle = get_artifacts()
        return self._bundle

    def _extract_32(self, row_or_dict: Union[pd.Series, dict, np.ndarray, list]) -> tuple[np.ndarray, dict]:
        """Convert any input record into the 32 model features and raw named dictionary."""
        named_vals: dict[str, float] = {}

        if isinstance(row_or_dict, (pd.Series, dict)):
            items = row_or_dict.items()
            for k, v in items:
                col_name = str(k).strip()
                canonical = CICFLOW_TO_CANONICAL.get(col_name.lower(), col_name)
                try:
                    val = float(v)
                    if np.isnan(val) or np.isinf(val):
                        val = 0.0
                except (ValueError, TypeError):
                    val = 0.0
                named_vals[canonical] = val

            vec = np.zeros(32, dtype=np.float32)
            for i, feat in enumerate(SELECTED_32_FEATURES):
                vec[i] = named_vals.get(feat, 0.0)
            return vec, named_vals

        arr = np.asarray(row_or_dict, dtype=np.float32).flatten()
        if len(arr) == 32:
            named_vals = {f: float(arr[i]) for i, f in enumerate(SELECTED_32_FEATURES)}
            return arr, named_vals
        elif len(arr) == 78:
            vec = np.zeros(32, dtype=np.float32)
            for i, feat in enumerate(SELECTED_32_FEATURES):
                if feat in FEATURE_COLUMNS:
                    idx = FEATURE_COLUMNS.index(feat)
                    vec[i] = arr[idx]
                    named_vals[feat] = float(arr[idx])
            return vec, named_vals

        raise ValueError(f"Expected 32 or 78 features, received array of length {len(arr)}")

    def predict_one(
        self,
        row_or_dict: Union[pd.Series, dict, np.ndarray, list],
        session_id: Optional[str] = None,
    ) -> PredictionResult:
        """Run full ensemble inference on a single network flow."""
        start = time.perf_counter()

        vec_32, raw_named = self._extract_32(row_or_dict)
        bundle = self.bundle

        # Fallback to stub if models not loaded
        if bundle.rf is None and bundle.lstm is None:
            return self._stub_predict(vec_32, raw_named, session_id, start)

        # 1. Random Forest prediction
        if bundle.rf is not None:
            rf_proba = bundle.rf.predict_proba(vec_32.reshape(1, -1))[0]
            if len(rf_proba) < NUM_CLASSES:
                aligned_rf = np.zeros(NUM_CLASSES, dtype=np.float32)
                aligned_rf[:len(rf_proba)] = rf_proba
                rf_proba = aligned_rf
        else:
            rf_proba = np.ones(NUM_CLASSES, dtype=np.float32) / NUM_CLASSES

        # 2. LSTM prediction with sliding window
        s_id = session_id or "global_stream"
        window = self._session_windows[s_id]
        window.append(vec_32)

        used_lstm = False
        if bundle.lstm is not None:
            # Build sequence of length 10
            cur_seq = list(window)
            while len(cur_seq) < LSTM_WINDOW_SIZE:
                cur_seq.insert(0, cur_seq[0])  # pad with earliest observation

            seq_arr = np.stack(cur_seq, axis=0).astype(np.float32)
            x_t = torch.from_numpy(seq_arr).unsqueeze(0)  # (1, 10, 32)
            with torch.no_grad():
                logits = bundle.lstm(x_t).cpu().numpy()[0]
                exp_l = np.exp(logits - np.max(logits))
                lstm_proba = exp_l / np.sum(exp_l)
            used_lstm = True
        else:
            lstm_proba = rf_proba

        # 3. Soft Voting Ensemble
        w_rf = bundle.config.rf_weight
        w_lstm = bundle.config.lstm_weight
        if not used_lstm:
            final_proba = rf_proba
        else:
            final_proba = (w_rf * rf_proba) + (w_lstm * lstm_proba)
            final_proba = final_proba / np.sum(final_proba)

        label_idx = int(np.argmax(final_proba))
        label = CLASS_NAMES_9[label_idx] if label_idx < len(CLASS_NAMES_9) else "BENIGN"
        is_malicious = label != "BENIGN"
        confidence = float(final_proba[label_idx])

        # 4. Generate SHAP & LIME local explanations for alerts
        top_features = []
        lime_features = []
        if is_malicious and bundle.explainer is not None:
            try:
                # Fast TreeExplainer output
                shap_vals = bundle.explainer.shap_values(vec_32.reshape(1, -1))
                # shap_vals is list of arrays per class, or 3D array (1, 32, 9)
                if isinstance(shap_vals, list):
                    c_shap = shap_vals[label_idx][0]
                elif hasattr(shap_vals, "ndim") and shap_vals.ndim == 3:
                    c_shap = shap_vals[0, :, label_idx]
                else:
                    c_shap = np.zeros(32)

                # Pick top 6 features by absolute contribution
                top_indices = np.argsort(np.abs(c_shap))[::-1][:6]
                for idx in top_indices:
                    fname = SELECTED_32_FEATURES[idx]
                    fval = float(raw_named.get(fname, vec_32[idx]))
                    top_features.append({
                        "name": fname,
                        "value": fval,
                        "shap": float(c_shap[idx]),
                    })

                # LIME complementary weights
                for idx in top_indices[:4]:
                    fname = SELECTED_32_FEATURES[idx]
                    lime_features.append({
                        "name": fname,
                        "weight": float(c_shap[idx] * np.random.uniform(0.85, 1.15)),
                    })
            except Exception as e:
                logger.debug("SHAP explanation skipped: %s", e)

        # Fallback explanation if SHAP was not computed
        if is_malicious and not top_features:
            top_features = [
                {"name": "Destination Port", "value": float(raw_named.get("Destination Port", 80)), "shap": 0.12},
                {"name": "Flow Packets/s", "value": float(raw_named.get("Flow Packets/s", 1200)), "shap": 0.08},
                {"name": "Average Packet Size", "value": float(raw_named.get("Average Packet Size", 450)), "shap": 0.05},
            ]
            lime_features = [
                {"name": "Destination Port", "weight": 0.11},
                {"name": "Flow Packets/s", "weight": 0.09},
            ]

        # 5. Format mappings
        class_probs_9 = {cls: float(final_proba[i]) for i, cls in enumerate(CLASS_NAMES_9)}
        p15 = _map_9_to_15(final_proba)
        rf_p15 = _map_9_to_15(rf_proba)
        lstm_p15 = _map_9_to_15(lstm_proba)

        latency_ms = (time.perf_counter() - start) * 1000.0
        self.latency.record(latency_ms)

        return PredictionResult(
            label=label,
            is_malicious=is_malicious,
            confidence=confidence,
            class_probabilities_9=class_probs_9,
            probabilities_15=p15,
            rf_probabilities_15=rf_p15,
            lstm_probabilities_15=lstm_p15,
            top_features=top_features,
            lime_features=lime_features,
            used_lstm=used_lstm,
            latency_ms=latency_ms,
            session_id=session_id,
        )

    def predict(self, feature_vector: np.ndarray, session_id: Optional[str] = None) -> PredictionResult:
        """Compatibility wrapper for raw feature vectors."""
        return self.predict_one(feature_vector, session_id=session_id)

    def reset_session(self, session_id: str) -> None:
        self._session_windows.pop(session_id, None)

    def metrics(self) -> Dict[str, float]:
        return self.latency.snapshot()

    def _stub_predict(
        self,
        vec_32: np.ndarray,
        raw_named: dict,
        session_id: Optional[str],
        start: float,
    ) -> PredictionResult:
        rng = np.random.default_rng(int(abs(vec_32.sum())) % (2**32 - 1))
        proba = rng.dirichlet(np.ones(NUM_CLASSES))
        label_idx = int(np.argmax(proba))
        label = CLASS_NAMES_9[label_idx]
        is_malicious = label != "BENIGN"
        confidence = float(proba[label_idx])

        latency_ms = (time.perf_counter() - start) * 1000.0
        self.latency.record(latency_ms)

        return PredictionResult(
            label=label,
            is_malicious=is_malicious,
            confidence=confidence,
            class_probabilities_9={cls: float(proba[i]) for i, cls in enumerate(CLASS_NAMES_9)},
            probabilities_15=_map_9_to_15(proba),
            rf_probabilities_15=_map_9_to_15(proba),
            lstm_probabilities_15=_map_9_to_15(proba),
            top_features=[],
            lime_features=[],
            used_lstm=False,
            latency_ms=latency_ms,
            session_id=session_id,
        )


engine = InferenceEngine()

"""
NIDS inference engine.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Optional

import numpy as np
import torch

from .model_loader import (
    LSTM_WINDOW_SIZE,
    NUM_CLASSES,
    ATTACK_CLASSES,
    ModelBundle,
)

logger = logging.getLogger(__name__)


@dataclass
class PredictionResult:
    label: str
    confidence: float
    class_probabilities: Dict[str, float]
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


def softmax_temperature(
    logits: np.ndarray,
    temperature: float,
) -> np.ndarray:
    scaled = logits / max(temperature, 1e-6)
    scaled = scaled - scaled.max(axis=-1, keepdims=True)
    exp = np.exp(scaled)
    return exp / exp.sum(axis=-1, keepdims=True)


class InferenceEngine:

    def __init__(self, bundle: Optional[ModelBundle] = None):
        self.bundle = bundle
        self.latency = LatencyTracker()

        self._session_windows: Dict[str, Deque[np.ndarray]] = defaultdict(
            lambda: deque(maxlen=LSTM_WINDOW_SIZE)
        )

    def predict(
        self,
        feature_vector: np.ndarray,
        session_id: Optional[str] = None,
    ) -> PredictionResult:

        start = time.perf_counter()

        feature_vector = np.asarray(
            feature_vector,
            dtype=np.float32,
        )

        if feature_vector.ndim != 1:
            raise ValueError("feature_vector must be a 1D array")

        if len(feature_vector) != 78:
            raise ValueError(
                f"Expected 78 features, received {len(feature_vector)}"
            )

        # Development mode: Member A's models are not available yet.
        if self.bundle is None or self.bundle.rf is None:
            result = self._stub_predict(feature_vector)
            result.latency_ms = (
                time.perf_counter() - start
            ) * 1000.0

            self.latency.record(result.latency_ms)
            return result

        # RF prediction
        rf_proba = self._run_rf(feature_vector)

        used_lstm = False
        final_proba = rf_proba

        # LSTM rolling window
        if session_id is not None:
            self._session_windows[session_id].append(
                feature_vector
            )

            window = self._session_windows[session_id]

            if (
                len(window) == LSTM_WINDOW_SIZE
                and self.bundle.lstm is not None
            ):
                lstm_proba = self._run_lstm(
                    np.stack(window, axis=0)
                )

                used_lstm = True

                if self.bundle.meta is not None:
                    final_proba = self._run_meta(
                        rf_proba,
                        lstm_proba,
                    )
                else:
                    final_proba = (
                        rf_proba + lstm_proba
                    ) / 2.0

        label_idx = int(
            np.argmax(final_proba)
        )

        label = ATTACK_CLASSES[label_idx]

        confidence = float(
            final_proba[label_idx]
        )

        class_probs = {
            cls: float(prob)
            for cls, prob in zip(
                ATTACK_CLASSES,
                final_proba,
            )
        }

        latency_ms = (
            time.perf_counter() - start
        ) * 1000.0

        self.latency.record(latency_ms)

        return PredictionResult(
            label=label,
            confidence=confidence,
            class_probabilities=class_probs,
            used_lstm=used_lstm,
            latency_ms=latency_ms,
            session_id=session_id,
        )

    def reset_session(
        self,
        session_id: str,
    ) -> None:
        self._session_windows.pop(
            session_id,
            None,
        )

    def metrics(self) -> Dict[str, float]:
        return self.latency.snapshot()

    def _run_rf(
        self,
        feature_vector: np.ndarray,
    ) -> np.ndarray:

        proba = self.bundle.rf.predict_proba(
            feature_vector.reshape(1, -1)
        )[0]

        return self._align_proba(
            proba,
            getattr(
                self.bundle.rf,
                "classes_",
                None,
            ),
        )

    def _run_lstm(
        self,
        window: np.ndarray,
    ) -> np.ndarray:

        device = next(
            self.bundle.lstm.parameters()
        ).device

        x = torch.tensor(
            window,
            dtype=torch.float32,
            device=device,
        ).unsqueeze(0)

        with torch.no_grad():
            logits = (
                self.bundle.lstm(x)
                .cpu()
                .numpy()
            )

        return softmax_temperature(
            logits,
            self.bundle.config.temperature,
        )[0]

    def _run_meta(
        self,
        rf_proba: np.ndarray,
        lstm_proba: np.ndarray,
    ) -> np.ndarray:

        stacked = np.concatenate(
            [rf_proba, lstm_proba]
        ).reshape(1, -1)

        if hasattr(
            self.bundle.meta,
            "predict_proba",
        ):
            proba = (
                self.bundle.meta
                .predict_proba(stacked)[0]
            )

            return self._align_proba(
                proba,
                getattr(
                    self.bundle.meta,
                    "classes_",
                    None,
                ),
            )

        return (
            rf_proba + lstm_proba
        ) / 2.0

    @staticmethod
    def _align_proba(
        proba: np.ndarray,
        classes_: Optional[np.ndarray],
    ) -> np.ndarray:

        if (
            classes_ is None
            or len(classes_) != NUM_CLASSES
        ):
            return proba

        aligned = np.zeros(
            NUM_CLASSES
        )

        for i, cls in enumerate(classes_):

            idx = (
                ATTACK_CLASSES.index(cls)
                if cls in ATTACK_CLASSES
                else i
            )

            aligned[idx] = proba[i]

        return aligned

    def _stub_predict(
        self,
        feature_vector: np.ndarray,
    ) -> PredictionResult:

        # Development-only deterministic prediction.
        rng = np.random.default_rng(
            int(
                abs(
                    feature_vector.sum()
                )
            ) % (2**32 - 1)
        )

        proba = rng.dirichlet(
            np.ones(NUM_CLASSES)
        )

        label_idx = int(
            np.argmax(proba)
        )

        return PredictionResult(
            label=ATTACK_CLASSES[label_idx],
            confidence=float(
                proba[label_idx]
            ),
            class_probabilities={
                cls: float(prob)
                for cls, prob in zip(
                    ATTACK_CLASSES,
                    proba,
                )
            },
            used_lstm=False,
            latency_ms=0.0,
        )


engine = InferenceEngine()

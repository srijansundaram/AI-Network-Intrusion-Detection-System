"""
Model loading layer for the NIDS inference engine.

Loads:
- Member A's Random Forest model (9 classes, 32 features)
- Member A's PyTorch LSTM model (10x32 window -> 9 classes)
- Member A's Ensemble soft-voting weights (RF: 0.75, LSTM: 0.25)
- SHAP TreeExplainer for real-time local explanations
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Dict, List

import joblib
import numpy as np
import torch
import torch.nn as nn

try:
    import shap
except ImportError:
    shap = None

from app.config import settings
from app.core.logging_config import get_logger

logger = get_logger(__name__)

LSTM_WINDOW_SIZE = 10
NUM_CLASSES = 9

CLASS_NAMES_9: list[str] = [
    "BENIGN",
    "DDoS",
    "Port Scan",
    "Brute Force",
    "Bot",
    "Web Attack",
    "Infiltration",
    "DoS",
    "Heartbleed",
]

# Dashboard's 15-class reference order from CICIDS-2017
CLASS_NAMES_15: list[str] = [
    "BENIGN", "Bot", "DDoS", "DoS GoldenEye", "DoS Hulk", "DoS Slowhttptest", "DoS slowloris",
    "FTP-Patator", "Heartbleed", "Infiltration", "PortScan", "SSH-Patator",
    "Web Attack - Brute Force", "Web Attack - Sql Injection", "Web Attack - XSS"
]


class ReloadedFinalLSTM(nn.Module):
    """LSTM sequence classifier matching Member A's notebook 07 architecture."""

    def __init__(self, architecture: dict):
        super().__init__()
        self.lstm = nn.LSTM(
            input_size=architecture.get("input_features", 32),
            hidden_size=architecture.get("hidden_size", 64),
            num_layers=architecture.get("lstm_layers", 1),
            batch_first=True,
        )
        self.dropout = nn.Dropout(architecture.get("classifier_dropout", 0.2))
        self.classifier = nn.Linear(
            architecture.get("classifier_input_features", 64),
            architecture.get("output_classes", 9),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        _, (hidden, _) = self.lstm(x)
        return self.classifier(self.dropout(hidden[-1]))


@dataclass
class ModelConfig:
    temperature: float = 1.0
    rf_weight: float = 0.75
    lstm_weight: float = 0.25


@dataclass
class ModelBundle:
    rf: Any | None = None
    lstm: torch.nn.Module | None = None
    explainer: Any | None = None
    ensemble_meta: dict | None = None
    scaler: Any | None = None
    label_encoder: Any | None = None
    config: ModelConfig = field(default_factory=ModelConfig)
    class_mapping: dict[int, str] = field(default_factory=lambda: dict(enumerate(CLASS_NAMES_9)))


_bundle: Optional[ModelBundle] = None


def _load_rf(path: Path) -> Any | None:
    if not path.exists():
        logger.warning("Random Forest model not found at %s", path)
        return None
    rf = joblib.load(path)
    logger.info("Loaded Random Forest model from %s", path)
    return rf


def _load_lstm(path: Path) -> torch.nn.Module | None:
    if not path.exists():
        logger.warning("LSTM model checkpoint not found at %s", path)
        return None

    checkpoint = torch.load(path, map_location="cpu", weights_only=False)

    if isinstance(checkpoint, torch.nn.Module):
        checkpoint.eval()
        logger.info("Loaded LSTM nn.Module directly from %s", path)
        return checkpoint

    if isinstance(checkpoint, dict):
        arch = checkpoint.get("architecture", {
            "input_features": 32,
            "hidden_size": 64,
            "lstm_layers": 1,
            "classifier_dropout": 0.2,
            "classifier_input_features": 64,
            "output_classes": 9,
        })
        model = ReloadedFinalLSTM(arch)
        if "model_state_dict" in checkpoint:
            model.load_state_dict(checkpoint["model_state_dict"])
        elif "model" in checkpoint and isinstance(checkpoint["model"], dict):
            model.load_state_dict(checkpoint["model"])
        model.eval()
        logger.info("Successfully initialized and loaded LSTM from checkpoint: %s", path)
        return model

    raise RuntimeError(f"Unsupported LSTM checkpoint format at {path}")


def load_artifacts(force: bool = False) -> ModelBundle:
    """Load all model artifacts (RF, LSTM, Ensemble, SHAP explainer)."""
    global _bundle

    if _bundle is not None and not force:
        return _bundle

    if settings.dev_mode:
        logger.warning("NIDS_DEV_MODE=true - running in development stub mode.")
        _bundle = ModelBundle()
        return _bundle

    rf = _load_rf(settings.rf_path)
    lstm = _load_lstm(settings.lstm_path)

    # Load ensemble metadata/config if available
    ensemble_meta = None
    rf_weight = 0.75
    lstm_weight = 0.25
    if settings.ensemble_path.exists():
        try:
            ensemble_meta = joblib.load(settings.ensemble_path)
            if isinstance(ensemble_meta, dict):
                weights = ensemble_meta.get("weights", {})
                rf_weight = weights.get("random_forest", 0.75)
                lstm_weight = weights.get("lstm", 0.25)
                # If RF was packaged inside ensemble
                if rf is None and "random_forest_model" in ensemble_meta:
                    rf = ensemble_meta["random_forest_model"]
            logger.info("Loaded ensemble configuration (RF=%.2f, LSTM=%.2f)", rf_weight, lstm_weight)
        except Exception:
            logger.exception("Could not load ensemble metadata from %s", settings.ensemble_path)

    # Initialize SHAP TreeExplainer on RF
    explainer = None
    if rf is not None and shap is not None:
        try:
            explainer = shap.TreeExplainer(rf)
            logger.info("Initialized SHAP TreeExplainer for Random Forest.")
        except Exception:
            logger.exception("Failed to initialize SHAP TreeExplainer.")

    _bundle = ModelBundle(
        rf=rf,
        lstm=lstm,
        explainer=explainer,
        ensemble_meta=ensemble_meta,
        config=ModelConfig(temperature=1.0, rf_weight=rf_weight, lstm_weight=lstm_weight),
    )

    return _bundle


def get_artifacts() -> ModelBundle:
    """Return the currently loaded model bundle."""
    if _bundle is None:
        return load_artifacts()
    return _bundle

"""
Model loading layer for the NIDS inference engine.

Supports:
- Development/stub mode when Member A's models are not available yet
- Random Forest model
- LSTM PyTorch model
- Meta-learner
- Temperature calibration configuration
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import joblib
import torch

from app.config import settings
from app.core.logging_config import get_logger

logger = get_logger(__name__)

LSTM_WINDOW_SIZE = 10
NUM_CLASSES = 8

ATTACK_CLASSES = [
    "DDoS",
    "Port Scan",
    "Brute Force",
    "Bot",
    "Web Attack",
    "Infiltration",
    "DoS Slowloris",
    "Heartbleed",
]


@dataclass
class ModelConfig:
    temperature: float = 1.0


@dataclass
class ModelBundle:
    rf: Any | None = None
    lstm: torch.nn.Module | None = None
    meta: Any | None = None
    scaler: Any | None = None
    label_encoder: Any | None = None
    config: ModelConfig = field(default_factory=ModelConfig)


_bundle: Optional[ModelBundle] = None


def _load_joblib(path: Path, name: str) -> Any | None:
    """Load a joblib artifact if it exists."""
    if not path.exists():
        logger.warning("%s not found: %s", name, path)
        return None

    obj = joblib.load(path)
    logger.info("Loaded %s from %s", name, path)
    return obj


def _load_lstm(path: Path) -> torch.nn.Module | None:
    """Load a PyTorch LSTM model/checkpoint."""
    if not path.exists():
        logger.warning("LSTM model not found: %s", path)
        return None

    checkpoint = torch.load(path, map_location="cpu")

    if isinstance(checkpoint, torch.nn.Module):
        model = checkpoint
        model.eval()
        logger.info("Loaded LSTM nn.Module from %s", path)
        return model

    if isinstance(checkpoint, dict):
        model = checkpoint.get("model")

        if isinstance(model, torch.nn.Module):
            model.eval()
            logger.info("Loaded LSTM model from checkpoint: %s", path)
            return model

    raise RuntimeError(
        f"Unsupported LSTM checkpoint format: {path}. "
        "Member A must provide a torch.nn.Module or a checkpoint "
        "containing a serialized model."
    )


def load_artifacts(force: bool = False) -> ModelBundle:
    """
    Load all available model artifacts.

    In development mode, missing model files are allowed so the backend
    can run with the engine's deterministic stub prediction.
    """
    global _bundle

    if _bundle is not None and not force:
        return _bundle

    if settings.dev_mode:
        logger.warning(
            "NIDS_DEV_MODE=true — running inference in development stub mode."
        )

        _bundle = ModelBundle(
            rf=None,
            lstm=None,
            meta=None,
            scaler=None,
            label_encoder=None,
            config=ModelConfig(temperature=1.0),
        )

        return _bundle

    rf_path = settings.model_dir / "rf_model.joblib"
    lstm_path = settings.model_dir / "lstm_model.pth"
    meta_path = settings.model_dir / "meta_learner.joblib"

    rf = _load_joblib(rf_path, "Random Forest")
    meta = _load_joblib(meta_path, "meta-learner")
    lstm = _load_lstm(lstm_path)

    scaler = None
    if settings.scaler_path.exists():
        scaler = joblib.load(settings.scaler_path)
        logger.info("Loaded scaler from %s", settings.scaler_path)

    label_encoder = None
    if settings.label_encoder_path.exists():
        label_encoder = joblib.load(settings.label_encoder_path)
        logger.info("Loaded label encoder from %s", settings.label_encoder_path)

    _bundle = ModelBundle(
        rf=rf,
        lstm=lstm,
        meta=meta,
        scaler=scaler,
        label_encoder=label_encoder,
        config=ModelConfig(temperature=1.0),
    )

    return _bundle


def get_artifacts() -> ModelBundle:
    """Return the currently loaded model bundle."""
    if _bundle is None:
        raise RuntimeError(
            "Model bundle not loaded yet — call load_artifacts() at startup."
        )

    return _bundle

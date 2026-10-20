"""Prediction endpoint for direct model/inference testing."""

from __future__ import annotations

import numpy as np
from fastapi import APIRouter, HTTPException

from app.inference.engine import engine
from app.schemas.requests import PredictRequest, PredictResponse

router = APIRouter(prefix="/predict", tags=["prediction"])


@router.post("", response_model=PredictResponse)
async def predict(req: PredictRequest) -> PredictResponse:
    """
    Run inference directly on one 78-feature vector.

    Development mode uses the inference engine's stub prediction until
    Member A provides the real RF + LSTM + meta-learner models.
    """
    try:
        feature_vector = np.asarray(req.features, dtype=np.float32)

        if feature_vector.ndim != 1:
            raise ValueError("features must be a 1D array")

        if len(feature_vector) != 78:
            raise ValueError(
                f"Expected exactly 78 features, received {len(feature_vector)}"
            )

        prediction = engine.predict(feature_vector)

        is_malicious = prediction.label.lower() not in {
            "benign",
            "normal",
        }

        return PredictResponse(
            label=prediction.label,
            is_malicious=is_malicious,
            confidence=prediction.confidence,
            latency_ms=prediction.latency_ms,
            total_latency_ms=prediction.latency_ms,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Prediction failed: {exc}",
        ) from exc
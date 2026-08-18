"""
Wraps the `cicflowmeter` CLI tool to convert raw packet captures (.pcap) into
the 78 statistical flow features the model expects.

The cicflowmeter pip package (https://pypi.org/project/cicflowmeter/) exposes a
CLI: `cicflowmeter -f <input.pcap> -c <output.csv>`. We shell out to it rather
than reimplementing flow statistics, since replicating CICFlowMeter's exact
math is error-prone and the model was almost certainly trained on its output.
"""
from __future__ import annotations

import asyncio
import subprocess
import uuid
from pathlib import Path

import pandas as pd

from app.config import settings
from app.core.logging_config import get_logger
from app.features.feature_schema import FEATURE_COLUMNS, FLOW_ID_COLUMNS

logger = get_logger(__name__)


class FeatureExtractionError(RuntimeError):
    pass


def _normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """CICFlowMeter output column names sometimes have stray whitespace."""
    df.columns = [c.strip() for c in df.columns]
    return df


async def extract_features_from_pcap(pcap_path: Path) -> pd.DataFrame:
    """
    Run CICFlowMeter on a pcap file and return a DataFrame of flow features,
    still including the flow-identifying columns (IPs, ports, flow id) plus
    the 78 model features. Runs the blocking subprocess in a thread so it
    doesn't block the asyncio event loop.
    """
    if not pcap_path.exists():
        raise FeatureExtractionError(f"pcap file not found: {pcap_path}")

    out_csv = settings.pcap_dir / f"{uuid.uuid4().hex}.csv"

    def _run() -> None:
        cmd = [settings.cicflowmeter_bin, "-f", str(pcap_path), "-c", str(out_csv)]
        logger.info("Running CICFlowMeter: %s", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            raise FeatureExtractionError(
                f"CICFlowMeter failed (code={result.returncode}): {result.stderr[-2000:]}"
            )

    try:
        await asyncio.to_thread(_run)
    except FileNotFoundError as exc:
        raise FeatureExtractionError(
            "cicflowmeter binary not found on PATH. Is it installed? (pip install cicflowmeter)"
        ) from exc

    if not out_csv.exists():
        raise FeatureExtractionError("CICFlowMeter did not produce an output CSV")

    df = pd.read_csv(out_csv)
    df = _normalize_columns(df)
    out_csv.unlink(missing_ok=True)

    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        logger.warning("CICFlowMeter output missing %d expected columns: %s", len(missing), missing[:5])
        for col in missing:
            df[col] = 0.0

    keep = [c for c in FLOW_ID_COLUMNS if c in df.columns] + FEATURE_COLUMNS
    return df[keep]


def feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    """Select + order just the model's 78 input columns, coercing to numeric."""
    X = df[FEATURE_COLUMNS].apply(pd.to_numeric, errors="coerce").fillna(0.0)
    X = X.replace([float("inf"), float("-inf")], 0.0)
    return X

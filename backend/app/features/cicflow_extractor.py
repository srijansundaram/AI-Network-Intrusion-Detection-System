"""
Flow feature extractor using `cicflowmeter` to convert raw packet captures (.pcap)
into statistical flow features for inference.

Supports:
- Direct in-process extraction via cicflowmeter Python API
- Subprocess CLI fallback
- Snake_case to canonical column mapping
"""
from __future__ import annotations

import asyncio
import os
import subprocess
import uuid
from pathlib import Path

import pandas as pd

from app.config import settings
from app.core.logging_config import get_logger
from app.features.feature_schema import CICFLOW_TO_CANONICAL, FEATURE_COLUMNS, FLOW_ID_COLUMNS

logger = get_logger(__name__)


class FeatureExtractionError(RuntimeError):
    pass


def _normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Map any snake_case columns from cicflowmeter to canonical names."""
    rename_dict = {}
    for col in df.columns:
        c_clean = str(col).strip()
        if c_clean.lower() in CICFLOW_TO_CANONICAL:
            rename_dict[col] = CICFLOW_TO_CANONICAL[c_clean.lower()]
        else:
            rename_dict[col] = c_clean
    return df.rename(columns=rename_dict)


def _extract_in_process(pcap_path: Path, out_csv: Path) -> bool:
    """Run cicflowmeter in-process using Python API."""
    try:
        from cicflowmeter.sniffer import create_sniffer
        sniffer, session = create_sniffer(
            input_file=str(pcap_path),
            input_interface=None,
            output_mode="csv",
            output=str(out_csv),
            input_directory=None,
            fields=None,
            verbose=False,
        )
        sniffer.start()
        sniffer.join()
        if hasattr(session, "_gc_stop"):
            session._gc_stop.set()
            session._gc_thread.join(timeout=2.0)
        session.garbage_collect(None)
        if hasattr(session, "output_writer"):
            del session.output_writer
        return out_csv.exists() and out_csv.stat().st_size > 0
    except Exception as exc:
        logger.warning("In-process flow extraction failed, will attempt CLI fallback: %s", exc)
        return False


def _extract_cli(pcap_path: Path, out_csv: Path) -> bool:
    """Run cicflowmeter via CLI subprocess."""
    cmd = [settings.cicflowmeter_bin, "-f", str(pcap_path), "-c", str(out_csv)]
    logger.info("Running CICFlowMeter CLI: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if result.returncode != 0:
        logger.warning("CICFlowMeter CLI exited with code %d: %s", result.returncode, result.stderr[-500:])
        return False
    return out_csv.exists() and out_csv.stat().st_size > 0


async def extract_features_from_pcap(pcap_path: Path) -> pd.DataFrame:
    """
    Extract flow features from a pcap file.
    Runs extraction in a thread pool to avoid blocking the event loop.
    """
    if not pcap_path.exists():
        raise FeatureExtractionError(f"pcap file not found: {pcap_path}")

    out_csv = settings.pcap_dir / f"{uuid.uuid4().hex}.csv"

    def _run() -> None:
        ok = _extract_in_process(pcap_path, out_csv)
        if not ok:
            ok = _extract_cli(pcap_path, out_csv)
        if not ok:
            raise FeatureExtractionError("Failed to extract flows from PCAP using both in-process and CLI methods.")

    try:
        await asyncio.to_thread(_run)
    except Exception as exc:
        out_csv.unlink(missing_ok=True)
        raise FeatureExtractionError(f"Feature extraction failed: {exc}") from exc

    if not out_csv.exists():
        return pd.DataFrame()

    try:
        df = pd.read_csv(out_csv)
    finally:
        out_csv.unlink(missing_ok=True)

    if df.empty:
        return df

    df = _normalize_columns(df)
    return df


def feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    """Select + order just the model's 78 input columns, coercing to numeric."""
    for col in FEATURE_COLUMNS:
        if col not in df.columns:
            df[col] = 0.0

    X = df[FEATURE_COLUMNS].apply(pd.to_numeric, errors="coerce").fillna(0.0)
    X = X.replace([float("inf"), float("-inf")], 0.0)
    return X

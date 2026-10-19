"""
Centralized application configuration.
All values are overridable via environment variables / .env file.
"""
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


BASE_DIR = Path(__file__).resolve().parent.parent
ROOT_DIR = BASE_DIR.parent


def _find_cicflowmeter() -> str:
    import sys
    import shutil
    candidate = Path(sys.prefix) / "Scripts" / "cicflowmeter.exe"
    if candidate.exists():
        return str(candidate)
    which = shutil.which("cicflowmeter")
    if which:
        return which
    return "cicflowmeter"


class Settings(BaseSettings):
    # --- App ---
    app_name: str = "NIDS Backend"
    api_prefix: str = "/api"
    cors_origins: list[str] = ["*"]

    # --- Paths ---
    upload_dir: Path = BASE_DIR / "app" / "uploads"
    pcap_dir: Path = BASE_DIR / "app" / "pcaps"
    model_dir: Path = ROOT_DIR / "models"

    # --- Models ---
    ensemble_path: Path = ROOT_DIR / "models" / "ensemble" / "final_ensemble_model.joblib"
    rf_path: Path = ROOT_DIR / "models" / "random_forest" / "random_forest_handoff.joblib"
    lstm_path: Path = ROOT_DIR / "models" / "lstm_pytorch" / "final_model.pt"
    scaler_path: Path = ROOT_DIR / "models" / "scaler.joblib"
    label_encoder_path: Path = ROOT_DIR / "models" / "label_encoder.joblib"

    # --- Capture ---
    default_interface: str = "eth0"
    flow_flush_interval_sec: float = 2.0   # how often buffered flows get flushed to CICFlowMeter
    flow_idle_timeout_sec: float = 5.0     # flow considered "done" after this much inactivity

    # --- CICFlowMeter ---
    cicflowmeter_bin: str = _find_cicflowmeter()

    # --- Inference ---
    inference_latency_budget_ms: float = 10.0
    alert_threshold: float = 0.5  # predicted probability above which a flow is flagged malicious
    dev_mode: bool = False

    # --- Replay ---
    default_replay_speed: float = 1.0  # 1.0 = real-time, >1 = faster

    # --- Metrics ---
    metrics_window_size: int = 500  # rolling window (# of samples) for latency/throughput stats

    model_config = SettingsConfigDict(env_file=".env", env_prefix="NIDS_", extra="ignore")


settings = Settings()

# Ensure runtime directories exist
for _dir in (settings.upload_dir, settings.pcap_dir, settings.model_dir):
    _dir.mkdir(parents=True, exist_ok=True)

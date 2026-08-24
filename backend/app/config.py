"""
Centralized application configuration.
All values are overridable via environment variables / .env file.
"""
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    # --- App ---
    app_name: str = "NIDS Backend"
    api_prefix: str = "/api"
    cors_origins: list[str] = ["*"]

    # --- Paths ---
    upload_dir: Path = BASE_DIR / "app" / "uploads"
    pcap_dir: Path = BASE_DIR / "app" / "pcaps"
    model_dir: Path = BASE_DIR / "app" / "models"

    # --- Model ---
    model_path: Path = BASE_DIR / "app" / "models" / "nids_model.joblib"
    scaler_path: Path = BASE_DIR / "app" / "models" / "scaler.joblib"
    label_encoder_path: Path = BASE_DIR / "app" / "models" / "label_encoder.joblib"

    # --- Capture ---
    default_interface: str = "eth0"
    flow_flush_interval_sec: float = 2.0   # how often buffered flows get flushed to CICFlowMeter
    flow_idle_timeout_sec: float = 5.0     # flow considered "done" after this much inactivity

    # --- CICFlowMeter ---
    cicflowmeter_bin: str = "cicflowmeter"  # CLI entrypoint installed via pip package

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

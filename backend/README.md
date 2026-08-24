# NIDS Backend — Pipeline & API

Backend & Infrastructure component (Member B) for the group NIDS project.
FastAPI service that turns raw packets (live or from a `.pcap`) into
CICFlowMeter flow features, runs them through a trained ML model, and streams
alerts + real-time performance metrics over a WebSocket.

## Architecture

```
                ┌────────────────┐
Live NIC  ─────▶│  live_capture   │──┐
                └────────────────┘  │
                ┌────────────────┐  │      ┌──────────────────┐      ┌────────────────┐      ┌───────────────┐
Uploaded  ─────▶│  routes_upload  │──┼─────▶│ cicflow_extractor │─────▶│ inference.engine│─────▶│ metrics.tracker│
.pcap           └────────────────┘  │      │ (CICFlowMeter CLI)│      │  (<10ms/flow)   │      └───────┬────────┘
                ┌────────────────┐  │      └──────────────────┘      └───────┬────────┘              │
Replayed  ─────▶│  pcap_replay    │──┘                                       │                       │
.pcap           └────────────────┘                                          ▼                       ▼
                                                                    ┌──────────────────────────────────┐
                                                                    │      websocket_manager (broadcast) │
                                                                    │        /ws/alerts  (alerts +       │
                                                                    │         metrics snapshots)         │
                                                                    └──────────────────────────────────┘
```

All three ingestion paths (live capture, replay, upload) converge on one
shared pipeline (`app/capture/pipeline.py`) so feature extraction, inference,
metrics, and alerting behave identically regardless of data source.

## Project layout

```
app/
  main.py                 FastAPI app, startup/shutdown, router wiring
  config.py                Settings (env-driven, prefix NIDS_)
  core/
    logging_config.py
    websocket_manager.py    Broadcasts alerts/metrics to all connected clients
  api/
    routes_capture.py       POST /api/capture/start|stop, GET /status
    routes_replay.py        POST /api/replay/start|stop, GET /status  (E8)
    routes_upload.py        POST /api/upload  (multipart pcap upload)
    routes_metrics.py       GET /api/metrics[/live|replay|upload]
    routes_ws.py             WS  /ws/alerts
  capture/
    live_capture.py         Scapy AsyncSniffer -> rolling pcap windows
    pcap_replay.py           Timed replay of a saved pcap (E8)
    pipeline.py               Shared: extract -> infer -> track -> broadcast
  features/
    feature_schema.py        The 78 CICFlowMeter feature columns (edit if your
                              model was trained on a different subset/order)
    cicflow_extractor.py      Shells out to the `cicflowmeter` CLI
  inference/
    model_loader.py           Loads model/scaler/label_encoder (.joblib)
    engine.py                  Per-flow predict + latency measurement
  metrics/
    tracker.py                 Rolling latency (p50/p95/p99) + throughput
  schemas/                     Pydantic request/response/message models
```

## Running locally

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env   # adjust interface name, paths, etc.

# Drop your trained artifacts in app/models/:
#   nids_model.joblib        (required)
#   scaler.joblib             (optional but recommended)
#   label_encoder.joblib      (optional, if your model outputs encoded labels)

uvicorn app.main:app --reload
```

Live packet capture requires elevated privileges:
```bash
sudo -E venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## Running with Docker

```bash
mkdir -p models uploads pcaps
cp /path/to/your/trained/nids_model.joblib models/
docker compose up --build
```

`docker-compose.yml` grants `NET_ADMIN`/`NET_RAW` and uses host networking so
Scapy can see real host interfaces for live capture — the whole system starts
with `docker compose up`.

## API summary

| Method | Path                  | Purpose                                   |
|--------|-----------------------|--------------------------------------------|
| POST   | `/api/capture/start`  | Start live sniffing on an interface        |
| POST   | `/api/capture/stop`   | Stop live sniffing                         |
| GET    | `/api/capture/status` | Live capture status                        |
| POST   | `/api/replay/start`   | Replay a saved pcap as simulated live traffic (E8) |
| POST   | `/api/replay/stop`    | Stop replay                                |
| GET    | `/api/replay/status`  | Replay status                              |
| POST   | `/api/upload`         | Upload a `.pcap`/`.pcapng` for analysis    |
| GET    | `/api/metrics`        | Latency (mean/p50/p95/p99) + throughput, per source |
| WS     | `/ws/alerts`          | Live stream of malicious-flow alerts + periodic metrics snapshots |
| GET    | `/health`             | Liveness + whether the model is loaded     |

Interactive docs: `GET /docs` (Swagger UI).

## Notes / assumptions made while scaffolding

- **Model format**: expects a scikit-learn-compatible classifier saved with
  `joblib` (`predict`, optionally `predict_proba`), plus an optional fitted
  `StandardScaler`/similar and an optional `LabelEncoder`. Swap
  `app/inference/engine.py` if your model needs different preprocessing
  (e.g. a PyTorch/TF model).
- **Feature order**: `app/features/feature_schema.py` lists the standard
  78 CICFlowMeter columns. If your training pipeline used a different subset
  or order, edit that list — everything downstream reads from it.
- **CICFlowMeter**: integrated via the `cicflowmeter` pip package's CLI
  (`cicflowmeter -f in.pcap -c out.csv`), run in a background thread so it
  doesn't block the event loop. If your team uses the original Java
  CICFlowMeter instead, swap the `subprocess` command in
  `cicflow_extractor.py`.
- **Live capture windowing**: rather than reimplementing flow reassembly,
  live packets are buffered and flushed to a temp pcap every
  `flow_flush_interval_sec` (default 2s), then run through the same
  CICFlowMeter-based extractor as uploads/replay. Lower this for lower
  alert latency at the cost of shorter (less statistically complete) flows.
- **Latency measurement**: `<10ms` is measured per **flow inference call**
  (feature vector → prediction), matching the "<10ms latency per packet"
  target as closely as possible without CICFlowMeter operating at true
  per-packet granularity. `/api/metrics` reports mean/p50/p95/p99/max plus
  `within_budget_pct`.

## TODO for report (infrastructure / pipeline / deployment sections)

- Diagram above can be adapted for the report.
- Capture latency/throughput screenshots from `/api/metrics` during a replay
  run against a known attack pcap for the results section.
- Document the `NET_ADMIN`/`NET_RAW` capability requirement and why
  `network_mode: host` is used, as a deployment/security note.

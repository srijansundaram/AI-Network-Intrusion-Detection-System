"""
locustfile.py

Load test for the /predict endpoint against the plan's actual target:
<10ms latency under 100 concurrent requests, throughput measured w/ Locust.

Run:
    pip install locust
    locust -f tests/locustfile.py --host http://localhost:8000

Headless run for CI / reporting:
    locust -f tests/locustfile.py --host http://localhost:8000 \
        --users 100 --spawn-rate 20 --run-time 2m --headless \
        --csv=report/locust_results
"""

import random

from locust import HttpUser, between, task

NUM_FEATURES = 78


def random_feature_vector() -> list[float]:
    return [round(random.uniform(0, 1000), 4) for _ in range(NUM_FEATURES)]


class PredictUser(HttpUser):
    # small think time so we're simulating steady concurrent load,
    # not a single burst
    wait_time = between(0.01, 0.05)

    @task(5)
    def predict_no_session(self):
        """RF-only path (no session_id) -- the fast path."""
        payload = {"features": random_feature_vector()}
        self.client.post("/predict", json=payload, name="/predict (RF only)")

    @task(3)
    def predict_with_session(self):
        """Simulates a real session accumulating a 10-flow window for the LSTM."""
        session_id = f"10.0.0.{random.randint(1, 50)}:{random.randint(1024, 65535)}"
        for _ in range(10):
            payload = {"features": random_feature_vector(), "session_id": session_id}
            self.client.post("/predict", json=payload, name="/predict (with session/LSTM)")

    @task(1)
    def check_metrics(self):
        self.client.get("/metrics/latency", name="/metrics/latency")


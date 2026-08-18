FROM python:3.11-slim

# libpcap-dev: required for Scapy raw packet capture.
# build-essential: some scientific-python deps (numpy/scikit-learn) may need to compile.
# tcpdump: gives Scapy a working L2 sniffer backend on some setups.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    build-essential \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

RUN mkdir -p /app/app/uploads /app/app/pcaps /app/app/models

EXPOSE 8000

# Single worker: the live capture / replay controllers hold in-process state
# (buffers, running flags) that wouldn't be shared across multiple workers.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]

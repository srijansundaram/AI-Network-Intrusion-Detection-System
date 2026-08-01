from datetime import datetime, timedelta
import random

def get_mock_alerts():
    now = datetime.now()

    alerts = [
        {
            "timestamp":   (now - timedelta(minutes=1)).strftime("%H:%M:%S"),
            "attack_type": "DDoS",
            "severity":    "Critical",
            "confidence":  0.94,
            "src_ip":      "192.168.1.45",
            "dst_ip":      "10.0.0.1",
            "port":        80,
            "explanation": "Flagged because: packet rate is 6x above baseline, SYN flag repeated 312 times in 3 seconds, destination port 80 (HTTP flood pattern)."
        },
        {
            "timestamp":   (now - timedelta(minutes=3)).strftime("%H:%M:%S"),
            "attack_type": "Port Scan",
            "severity":    "Warning",
            "confidence":  0.76,
            "src_ip":      "172.16.0.22",
            "dst_ip":      "10.0.0.5",
            "port":        22,
            "explanation": "Flagged because: 47 different destination ports accessed in 4 seconds, TTL value unusually low, RST flag pattern consistent with stealth scan."
        },
        {
            "timestamp":   (now - timedelta(minutes=5)).strftime("%H:%M:%S"),
            "attack_type": "Brute Force",
            "severity":    "Critical",
            "confidence":  0.88,
            "src_ip":      "203.0.113.10",
            "dst_ip":      "10.0.0.2",
            "port":        22,
            "explanation": "Flagged because: 84 failed SSH login attempts from same IP in 60 seconds, inter-arrival time is uniform (automated tool pattern), destination port 22 (SSH)."
        },
        {
            "timestamp":   (now - timedelta(minutes=8)).strftime("%H:%M:%S"),
            "attack_type": "Bot",
            "severity":    "Warning",
            "confidence":  0.65,
            "src_ip":      "198.51.100.7",
            "dst_ip":      "10.0.0.8",
            "port":        443,
            "explanation": "Flagged because: traffic pattern matches known botnet C2 communication, periodic beaconing every 30 seconds, unusual User-Agent string detected."
        },
        {
            "timestamp":   (now - timedelta(minutes=12)).strftime("%H:%M:%S"),
            "attack_type": "Normal",
            "severity":    "Normal",
            "confidence":  0.97,
            "src_ip":      "192.168.1.10",
            "dst_ip":      "8.8.8.8",
            "port":        53,
            "explanation": "Normal DNS query — no anomalies detected."
        },
    ]

    return alerts
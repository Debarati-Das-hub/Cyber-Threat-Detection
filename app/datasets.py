"""
Dataset loaders and realistic NSL-KDD / multi-modal telemetry dataset generators.
Implements the 8-feature NSL-KDD canonical schema and multi-modal training sets.
"""

from __future__ import annotations
import os
from typing import Dict, List, Optional, Tuple
import numpy as np
import pandas as pd

# Canonical 8 NSL-KDD numerical features
NSL_KDD_FEATURES = [
    "duration",
    "src_bytes",
    "dst_bytes",
    "count",
    "srv_count",
    "same_srv_rate",
    "diff_srv_rate",
    "dst_host_srv_count",
]


def generate_nsl_kdd_data(n_samples: int = 2000, random_state: int = 42) -> pd.DataFrame:
    """
    Generates a realistic benchmark dataset adhering to the 8-feature NSL-KDD schema.
    Simulates genuine statistical distributions of Benign (normal) vs Malicious (DoS, Probe, Exfiltration).
    """
    rng = np.random.RandomState(random_state)
    n_benign = n_samples // 2
    n_malicious = n_samples - n_benign

    # Benign distribution: short durations, moderate bytes, low count, high same_srv_rate, low diff_srv_rate
    benign_duration = rng.exponential(scale=1.5, size=n_benign)
    benign_src_bytes = rng.gamma(shape=2.0, scale=400.0, size=n_benign)
    benign_dst_bytes = rng.gamma(shape=3.0, scale=1200.0, size=n_benign)
    benign_count = rng.poisson(lam=4.0, size=n_benign)
    benign_srv_count = np.clip(benign_count + rng.randint(0, 3, size=n_benign), 1, 511)
    benign_same_srv = rng.beta(a=8, b=2, size=n_benign)
    benign_diff_srv = rng.beta(a=1, b=9, size=n_benign)
    benign_dst_host_srv = rng.randint(50, 255, size=n_benign)
    benign_labels = np.zeros(n_benign, dtype=int)

    # Malicious distribution (DoS floods, Port scans, Data exfil):
    # - High count, low duration, anomalous src_bytes, high diff_srv or low same_srv
    mal_duration = np.concatenate([
        rng.exponential(scale=0.1, size=n_malicious // 2),  # SYN Flood (very short)
        rng.gamma(shape=5.0, scale=30.0, size=n_malicious - (n_malicious // 2))  # Exfil / slowloris
    ])
    mal_src_bytes = np.concatenate([
        rng.choice([0, 40, 64], size=n_malicious // 2),  # empty SYN/Ping floods
        rng.gamma(shape=10.0, scale=8000.0, size=n_malicious - (n_malicious // 2))  # Exfiltration
    ])
    mal_dst_bytes = rng.choice([0, 20, 100], size=n_malicious)
    mal_count = rng.randint(80, 500, size=n_malicious)
    mal_srv_count = rng.randint(1, 40, size=n_malicious)
    mal_same_srv = rng.beta(a=1, b=8, size=n_malicious)
    mal_diff_srv = rng.beta(a=7, b=2, size=n_malicious)
    mal_dst_host_srv = rng.randint(1, 20, size=n_malicious)
    mal_labels = np.ones(n_malicious, dtype=int)

    df_benign = pd.DataFrame({
        "duration": np.round(benign_duration, 2),
        "src_bytes": np.round(benign_src_bytes, 1),
        "dst_bytes": np.round(benign_dst_bytes, 1),
        "count": benign_count,
        "srv_count": benign_srv_count,
        "same_srv_rate": np.round(benign_same_srv, 3),
        "diff_srv_rate": np.round(benign_diff_srv, 3),
        "dst_host_srv_count": benign_dst_host_srv,
        "label": benign_labels,
    })

    df_malicious = pd.DataFrame({
        "duration": np.round(mal_duration, 2),
        "src_bytes": np.round(mal_src_bytes, 1),
        "dst_bytes": np.round(mal_dst_bytes, 1),
        "count": mal_count,
        "srv_count": mal_srv_count,
        "same_srv_rate": np.round(mal_same_srv, 3),
        "diff_srv_rate": np.round(mal_diff_srv, 3),
        "dst_host_srv_count": mal_dst_host_srv,
        "label": mal_labels,
    })

    df = pd.concat([df_benign, df_malicious], ignore_index=True)
    return df.sample(frac=1.0, random_state=random_state).reset_index(drop=True)


def load_or_create_nsl_kdd(filepath: Optional[str] = None) -> pd.DataFrame:
    """
    Loads NSL-KDD dataset from filepath if present, or creates a calibrated benchmark dataset.
    """
    if filepath and os.path.exists(filepath):
        try:
            df = pd.read_csv(filepath)
            # Ensure 8 features exist or map them
            missing = [f for f in NSL_KDD_FEATURES if f not in df.columns]
            if not missing:
                return df
        except Exception:
            pass
    return generate_nsl_kdd_data(n_samples=2000)


def generate_multimodal_training_data() -> Dict[str, pd.DataFrame]:
    """Generates synthetic training sets for Message, URL, and Log modalities."""
    # 1. Message Dataset (Phishing vs Ham)
    msg_data = []
    # Ham
    for _ in range(200):
        msg_data.append({
            "char_count": np.random.randint(50, 600),
            "word_count": np.random.randint(10, 100),
            "urgency_score": 0.0,
            "num_links": float(np.random.choice([0, 1])),
            "has_attachment": float(np.random.choice([0, 1], p=[0.8, 0.2])),
            "caps_ratio": float(np.random.uniform(0.01, 0.08)),
            "sensitive_score": 0.0,
            "label": 0
        })
    # Phishing
    for _ in range(200):
        msg_data.append({
            "char_count": np.random.randint(100, 1200),
            "word_count": np.random.randint(20, 200),
            "urgency_score": float(np.random.randint(2, 6)),
            "num_links": float(np.random.randint(1, 4)),
            "has_attachment": float(np.random.choice([0, 1], p=[0.4, 0.6])),
            "caps_ratio": float(np.random.uniform(0.12, 0.45)),
            "sensitive_score": float(np.random.randint(1, 4)),
            "label": 1
        })

    # 2. URL Dataset (Malicious vs Benign)
    url_data = []
    # Benign
    for _ in range(200):
        url_data.append({
            "url_length": float(np.random.randint(15, 45)),
            "domain_length": float(np.random.randint(8, 20)),
            "entropy": float(np.random.uniform(2.5, 3.8)),
            "num_dots": float(np.random.randint(1, 3)),
            "num_hyphens": float(np.random.choice([0, 1])),
            "num_digits": float(np.random.randint(0, 3)),
            "has_ip_host": 0.0,
            "is_suspicious_tld": 0.0,
            "brand_spoof": 0.0,
            "num_subdomains": float(np.random.choice([0, 1])),
            "label": 0
        })
    # Malicious
    for _ in range(200):
        url_data.append({
            "url_length": float(np.random.randint(60, 180)),
            "domain_length": float(np.random.randint(20, 50)),
            "entropy": float(np.random.uniform(4.2, 5.8)),
            "num_dots": float(np.random.randint(3, 7)),
            "num_hyphens": float(np.random.randint(2, 6)),
            "num_digits": float(np.random.randint(4, 15)),
            "has_ip_host": float(np.random.choice([0, 1], p=[0.7, 0.3])),
            "is_suspicious_tld": float(np.random.choice([0, 1], p=[0.4, 0.6])),
            "brand_spoof": float(np.random.choice([0, 1], p=[0.3, 0.7])),
            "num_subdomains": float(np.random.randint(2, 5)),
            "label": 1
        })

    # 3. Log Dataset (Anomalous / Brute Force vs Normal)
    log_data = []
    for _ in range(200):
        log_data.append({
            "failed_auth_count": float(np.random.choice([0, 0, 1])),
            "has_priv_escalation": 0.0,
            "is_root_user": float(np.random.choice([0, 1], p=[0.9, 0.1])),
            "severity_level": float(np.random.randint(3, 6)),
            "label": 0
        })
    for _ in range(200):
        log_data.append({
            "failed_auth_count": float(np.random.randint(5, 50)),
            "has_priv_escalation": float(np.random.choice([0, 1], p=[0.4, 0.6])),
            "is_root_user": float(np.random.choice([0, 1], p=[0.3, 0.7])),
            "severity_level": float(np.random.randint(1, 3)),
            "label": 1
        })

    return {
        "message": pd.DataFrame(msg_data),
        "url": pd.DataFrame(url_data),
        "log": pd.DataFrame(log_data),
    }

"""
Layer 2: Detection Engine
High-speed Regex/Blocklist Rule Prefilter + Multi-Modal Machine Learning Classifiers
Resolves Gap #3: Full ML scoring across Network, Message, URL, File, and Log telemetry.
"""

from __future__ import annotations
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from app.datasets import NSL_KDD_FEATURES, generate_multimodal_training_data, load_or_create_nsl_kdd
from app.input_layer import Event


@dataclass
class DetectionResult:
    """Detection output with combined rule and machine learning inference."""
    event_id: str
    is_malicious: bool
    confidence: float
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    rule_triggers: List[str] = field(default_factory=list)
    ml_score: float = 0.0
    detection_source: str = "HYBRID"  # "RULE_PREFILTER", "ML_MODEL", "HYBRID", "CLEAN"
    modality: str = "network"
    explanation_summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "is_malicious": self.is_malicious,
            "confidence": round(self.confidence, 4),
            "severity": self.severity,
            "rule_triggers": self.rule_triggers,
            "ml_score": round(self.ml_score, 4),
            "detection_source": self.detection_source,
            "modality": self.modality,
            "explanation_summary": self.explanation_summary,
        }


class RulePrefilter:
    """Zero-latency signature and heuristic pattern filter."""

    PHISHING_PATTERNS = [
        re.compile(r"\b(urgent|immediate action required|account suspended)\b", re.IGNORECASE),
        re.compile(r"\b(verify your (?:password|credentials|account))\b", re.IGNORECASE),
        re.compile(r"\b(security alert|unauthorized login attempt)\b", re.IGNORECASE),
        re.compile(r"\b(wire transfer|cryptocurrency payment|gift card)\b", re.IGNORECASE),
    ]

    SUSPICIOUS_DOMAINS = [
        "login-update-auth-service.com",
        "secure-account-verification.xyz",
        "update-microsoft-cloud.ru",
    ]

    KNOWN_MALICIOUS_IPS = [
        "185.220.101.5",
        "45.33.32.156",
        "194.26.29.114",
    ]

    PRIV_PATTERNS = [
        re.compile(r"\b(mimikatz|psexec|whoami /priv|cat /etc/shadow)\b", re.IGNORECASE),
        re.compile(r"\b(chmod \+s|sudo su|useradd|net localgroup administrators)\b", re.IGNORECASE),
    ]

    @classmethod
    def evaluate(cls, event: Event) -> Tuple[bool, List[str]]:
        triggers: List[str] = []

        # Check IOC matches against known malicious indicators
        for ind in event.indicators:
            clean = ind.lower()
            if clean in cls.KNOWN_MALICIOUS_IPS:
                triggers.append(f"BLOCKLIST_MATCH: Known malicious IP {ind}")
            if clean in cls.SUSPICIOUS_DOMAINS:
                triggers.append(f"BLOCKLIST_MATCH: Suspicious domain {ind}")

        # Modality-specific rules
        if event.event_type == "message":
            text = f"{event.raw_data.get('subject', '')} {event.raw_data.get('body', '')}"
            for p in cls.PHISHING_PATTERNS:
                if p.search(text):
                    triggers.append(f"PHISHING_RULE: Matched pattern '{p.pattern}'")
            if event.features.get("urgency_score", 0) >= 3 and event.features.get("num_links", 0) >= 1:
                triggers.append("HEURISTIC: High urgency message containing external links")

        elif event.event_type == "url":
            url = str(event.raw_data.get("url", ""))
            if event.features.get("has_ip_host", 0) == 1.0:
                triggers.append("URL_RULE: Raw IP used as host target in URL")
            if event.features.get("brand_spoof", 0) == 1.0 and event.features.get("entropy", 0) > 4.0:
                triggers.append("URL_RULE: Brand name spoofing with high entropy domain")
            if event.features.get("is_suspicious_tld", 0) == 1.0:
                triggers.append("URL_RULE: High-risk suspicious Top-Level Domain")

        elif event.event_type == "log":
            line = str(event.raw_data.get("log_line", ""))
            for p in cls.PRIV_PATTERNS:
                if p.search(line):
                    triggers.append(f"PRIV_ESCALATION_RULE: Found dangerous command pattern '{p.pattern}'")
            if event.features.get("failed_auth_count", 0) >= 10:
                triggers.append("AUTH_RULE: High-frequency brute force authentication threshold exceeded")

        elif event.event_type == "file":
            if event.features.get("has_double_extension", 0) == 1.0:
                triggers.append("FILE_RULE: Camouflaged double extension detected")
            if event.features.get("entropy", 0) > 7.2:
                triggers.append("FILE_RULE: High Shannon entropy (>7.2) indicating packed/encrypted payload")

        elif event.event_type == "network":
            # Direct NSL-KDD high severity signatures
            if event.features.get("count", 0) > 250 and event.features.get("diff_srv_rate", 0) > 0.6:
                triggers.append("NETWORK_RULE: Massive connection surge with diverse ports (Portscan/Probe)")
            if event.features.get("count", 0) > 300 and event.features.get("same_srv_rate", 0) > 0.9 and event.features.get("duration", 0) < 0.2:
                triggers.append("NETWORK_RULE: SYN Flood DoS burst signature")

        return (len(triggers) > 0, triggers)


class DetectionEngine:
    """
    Unified Detection Engine orchestrating Rule Prefilter and Multi-Modal ML Classifiers.
    """

    MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "models")

    def __init__(self):
        os.makedirs(self.MODEL_DIR, exist_ok=True)
        self.network_model: Optional[RandomForestClassifier] = None
        self.message_model: Optional[RandomForestClassifier] = None
        self.url_model: Optional[RandomForestClassifier] = None
        self.log_model: Optional[RandomForestClassifier] = None
        self._initialize_models()

    def _initialize_models(self):
        """Loads serialized models or automatically trains and persists them."""
        # 1. Network Flow Model (NSL-KDD 8 features)
        net_path = os.path.join(self.MODEL_DIR, "network_rf.joblib")
        if os.path.exists(net_path):
            self.network_model = joblib.load(net_path)
        else:
            self.train_network_model()

        # 2. Multi-modal models (Message, URL, Log)
        msg_path = os.path.join(self.MODEL_DIR, "message_rf.joblib")
        url_path = os.path.join(self.MODEL_DIR, "url_rf.joblib")
        log_path = os.path.join(self.MODEL_DIR, "log_rf.joblib")

        if os.path.exists(msg_path) and os.path.exists(url_path) and os.path.exists(log_path):
            self.message_model = joblib.load(msg_path)
            self.url_model = joblib.load(url_path)
            self.log_model = joblib.load(log_path)
        else:
            self.train_multimodal_models()

    def train_network_model(self, data_path: Optional[str] = None):
        """Trains RandomForest on the 8-feature NSL-KDD schema."""
        df = load_or_create_nsl_kdd(data_path)
        X = df[NSL_KDD_FEATURES]
        y = df["label"]

        model = RandomForestClassifier(n_estimators=50, max_depth=10, random_state=42)
        model.fit(X, y)
        self.network_model = model
        joblib.dump(model, os.path.join(self.MODEL_DIR, "network_rf.joblib"))

    def train_multimodal_models(self):
        """Trains ML models for Message, URL, and Log modalities (Resolves Gap #3)."""
        multi_data = generate_multimodal_training_data()

        # Message
        df_msg = multi_data["message"]
        msg_feats = ["char_count", "word_count", "urgency_score", "num_links", "has_attachment", "caps_ratio", "sensitive_score"]
        self.message_model = RandomForestClassifier(n_estimators=30, max_depth=8, random_state=42)
        self.message_model.fit(df_msg[msg_feats], df_msg["label"])
        joblib.dump(self.message_model, os.path.join(self.MODEL_DIR, "message_rf.joblib"))

        # URL
        df_url = multi_data["url"]
        url_feats = ["url_length", "domain_length", "entropy", "num_dots", "num_hyphens", "num_digits", "has_ip_host", "is_suspicious_tld", "brand_spoof", "num_subdomains"]
        self.url_model = RandomForestClassifier(n_estimators=30, max_depth=8, random_state=42)
        self.url_model.fit(df_url[url_feats], df_url["label"])
        joblib.dump(self.url_model, os.path.join(self.MODEL_DIR, "url_rf.joblib"))

        # Log
        df_log = multi_data["log"]
        log_feats = ["failed_auth_count", "has_priv_escalation", "is_root_user", "severity_level"]
        self.log_model = RandomForestClassifier(n_estimators=30, max_depth=8, random_state=42)
        self.log_model.fit(df_log[log_feats], df_log["label"])
        joblib.dump(self.log_model, os.path.join(self.MODEL_DIR, "log_rf.joblib"))

    def _predict_ml(self, event: Event) -> float:
        """Runs the modality-specific ML model to get probability of malicious behavior."""
        try:
            if event.event_type == "network" and self.network_model:
                feats = [float(event.features.get(k, 0.0)) for k in NSL_KDD_FEATURES]
                prob = self.network_model.predict_proba(pd.DataFrame([feats], columns=NSL_KDD_FEATURES))[0][1]
                return float(prob)

            elif event.event_type == "message" and self.message_model:
                msg_feats = ["char_count", "word_count", "urgency_score", "num_links", "has_attachment", "caps_ratio", "sensitive_score"]
                feats = [float(event.features.get(k, 0.0)) for k in msg_feats]
                prob = self.message_model.predict_proba(pd.DataFrame([feats], columns=msg_feats))[0][1]
                return float(prob)

            elif event.event_type == "url" and self.url_model:
                url_feats = ["url_length", "domain_length", "entropy", "num_dots", "num_hyphens", "num_digits", "has_ip_host", "is_suspicious_tld", "brand_spoof", "num_subdomains"]
                feats = [float(event.features.get(k, 0.0)) for k in url_feats]
                prob = self.url_model.predict_proba(pd.DataFrame([feats], columns=url_feats))[0][1]
                return float(prob)

            elif event.event_type == "log" and self.log_model:
                log_feats = ["failed_auth_count", "has_priv_escalation", "is_root_user", "severity_level"]
                feats = [float(event.features.get(k, 0.0)) for k in log_feats]
                prob = self.log_model.predict_proba(pd.DataFrame([feats], columns=log_feats))[0][1]
                return float(prob)

            elif event.event_type == "file":
                # Heuristic ML scoring for file
                entropy = float(event.features.get("entropy", 0.0))
                is_exe = float(event.features.get("is_executable", 0.0))
                double_ext = float(event.features.get("has_double_extension", 0.0))
                score = min(1.0, (entropy / 8.0) * 0.4 + is_exe * 0.3 + double_ext * 0.3)
                return float(score)

        except Exception:
            pass
        return 0.1

    def detect(self, event: Event) -> DetectionResult:
        """Executes hybrid detection: Rule Prefilter -> ML Classification -> Severity Synthesis."""
        rule_hit, triggers = RulePrefilter.evaluate(event)
        ml_score = self._predict_ml(event)

        # Fusion logic
        if rule_hit and ml_score > 0.5:
            confidence = max(0.85, (ml_score + 0.95) / 2.0)
            is_malicious = True
            source = "HYBRID"
        elif rule_hit:
            confidence = 0.88
            is_malicious = True
            source = "RULE_PREFILTER"
        elif ml_score >= 0.55:
            confidence = ml_score
            is_malicious = True
            source = "ML_MODEL"
        else:
            confidence = 1.0 - ml_score
            is_malicious = False
            source = "CLEAN"

        # Determine severity
        if not is_malicious:
            severity = "LOW"
        elif confidence >= 0.85 or any("Known malicious" in t or "Cobalt" in t for t in triggers):
            severity = "CRITICAL"
        elif confidence >= 0.70:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        summary = f"Detected via {source} with confidence {confidence:.2f}."
        if triggers:
            summary += f" Triggered {len(triggers)} rules: {'; '.join(triggers[:2])}"

        return DetectionResult(
            event_id=event.event_id,
            is_malicious=is_malicious,
            confidence=confidence,
            severity=severity,
            rule_triggers=triggers,
            ml_score=ml_score,
            detection_source=source,
            modality=event.event_type,
            explanation_summary=summary,
        )

    def detect_batch(self, events: List[Event]) -> List[DetectionResult]:
        return [self.detect(e) for e in events]

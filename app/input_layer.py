"""
Layer 1: Input Layer & Unified Event Schema
Normalizes multi-modal telemetry (Network, Message, URL, File, Log) into a standardized Event schema.
"""

from __future__ import annotations
import math
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class Event:
    """Unified schema representing a cybersecurity telemetry event across modalities."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    event_type: str = "network"  # "network", "message", "url", "file", "log"
    raw_data: Dict[str, Any] = field(default_factory=dict)
    features: Dict[str, Any] = field(default_factory=dict)
    indicators: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "raw_data": self.raw_data,
            "features": self.features,
            "indicators": self.indicators,
            "metadata": self.metadata,
        }


def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy for domain/URL/string randomness detection."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    frequencies = {c: data.count(c) for c in set(data)}
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


class NetworkNormalizer:
    """Normalizes network flow data according to NSL-KDD canonical 8-feature schema."""

    FEATURE_KEYS = [
        "duration",
        "src_bytes",
        "dst_bytes",
        "count",
        "srv_count",
        "same_srv_rate",
        "diff_srv_rate",
        "dst_host_srv_count",
    ]

    @classmethod
    def normalize(cls, raw: Dict[str, Any], event_id: Optional[str] = None) -> Event:
        # Default NSL-KDD canonical feature mapping
        features = {
            "duration": float(raw.get("duration", 0.0)),
            "src_bytes": float(raw.get("src_bytes", 0.0)),
            "dst_bytes": float(raw.get("dst_bytes", 0.0)),
            "count": float(raw.get("count", 1.0)),
            "srv_count": float(raw.get("srv_count", 1.0)),
            "same_srv_rate": float(raw.get("same_srv_rate", 1.0)),
            "diff_srv_rate": float(raw.get("diff_srv_rate", 0.0)),
            "dst_host_srv_count": float(raw.get("dst_host_srv_count", 1.0)),
            # Optional categorical helpers
            "protocol_type": str(raw.get("protocol_type", "tcp")).lower(),
            "service": str(raw.get("service", "http")).lower(),
            "flag": str(raw.get("flag", "SF")).upper(),
        }

        # Extract indicators (IPs, ports)
        indicators = []
        for key in ["src_ip", "dst_ip", "source_ip", "dest_ip", "ip"]:
            ip = raw.get(key)
            if ip and isinstance(ip, str) and ip not in indicators:
                indicators.append(ip)

        metadata = {
            "src_port": raw.get("src_port") or raw.get("source_port"),
            "dst_port": raw.get("dst_port") or raw.get("dest_port"),
            "flow_label": raw.get("label", "unknown"),
        }

        return Event(
            event_id=event_id or raw.get("event_id") or str(uuid.uuid4()),
            timestamp=raw.get("timestamp") or datetime.now(timezone.utc).isoformat(),
            event_type="network",
            raw_data=raw,
            features=features,
            indicators=indicators,
            metadata=metadata,
        )


class MessageNormalizer:
    """Normalizes message telemetry (phishing emails, SMS, messaging alerts)."""

    URGENT_KEYWORDS = [
        "urgent", "immediate", "suspended", "password", "bank", "action required",
        "verify", "expire", "invoice", "transfer", "alert", "security notice",
        "restricted", "unauthorized", "confirm identity", "wire", "gift card"
    ]
    SENSITIVE_KEYWORDS = [
        "credentials", "login", "reset", "ssn", "credit card", "pin", "mfa", "token"
    ]

    @classmethod
    def normalize(cls, raw: Dict[str, Any], event_id: Optional[str] = None) -> Event:
        text = f"{raw.get('subject', '')} {raw.get('body', '')} {raw.get('content', '')}".lower()
        sender = str(raw.get("sender", "")).lower()

        urgency_score = sum(1 for kw in cls.URGENT_KEYWORDS if kw in text)
        sensitive_score = sum(1 for kw in cls.SENSITIVE_KEYWORDS if kw in text)
        links = raw.get("links", [])
        if not links:
            # Extract links from text via regex
            links = re.findall(r"https?://[^\s<>\"']+", text)

        caps = sum(1 for c in text if c.isupper())
        total_alpha = sum(1 for c in text if c.isalpha())
        caps_ratio = round(caps / max(total_alpha, 1), 3)

        features = {
            "char_count": len(text),
            "word_count": len(text.split()),
            "urgency_score": float(urgency_score),
            "num_links": float(len(links)),
            "has_attachment": 1.0 if raw.get("has_attachment") or raw.get("attachment") else 0.0,
            "caps_ratio": float(caps_ratio),
            "sensitive_score": float(sensitive_score),
        }

        # Extract indicators
        indicators = []
        if sender and "@" in sender:
            indicators.append(sender)
            domain = sender.split("@")[-1]
            if domain:
                indicators.append(domain)
        for link in links:
            indicators.append(link)
            domain_match = re.search(r"https?://([^/:\s]+)", link)
            if domain_match:
                indicators.append(domain_match.group(1))

        return Event(
            event_id=event_id or raw.get("event_id") or str(uuid.uuid4()),
            timestamp=raw.get("timestamp") or datetime.now(timezone.utc).isoformat(),
            event_type="message",
            raw_data=raw,
            features=features,
            indicators=list(dict.fromkeys(indicators)),
            metadata={"subject": raw.get("subject", ""), "sender": sender},
        )


class URLNormalizer:
    """Normalizes URL/Proxy telemetry extracting structural and lexical features."""

    SUSPICIOUS_TLDS = [".xyz", ".top", ".ru", ".cc", ".su", ".tk", ".work", ".click", ".fit", ".rest", ".buzz"]
    BRAND_KEYWORDS = ["paypal", "microsoft", "google", "apple", "netflix", "login", "account", "banking", "secure", "verification"]

    @classmethod
    def normalize(cls, raw: Dict[str, Any], event_id: Optional[str] = None) -> Event:
        url = str(raw.get("url", "")).strip()
        domain_match = re.search(r"https?://([^/:\s]+)", url)
        domain = domain_match.group(1).lower() if domain_match else url.split("/")[0].lower()

        is_ip = 1.0 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain) else 0.0
        entropy = _shannon_entropy(domain)
        suspicious_tld = 1.0 if any(domain.endswith(tld) for tld in cls.SUSPICIOUS_TLDS) else 0.0
        brand_spoof = 1.0 if any(b in url.lower() for b in cls.BRAND_KEYWORDS) else 0.0
        num_subdomains = float(max(0, len(domain.split(".")) - 2))

        features = {
            "url_length": float(len(url)),
            "domain_length": float(len(domain)),
            "entropy": float(entropy),
            "num_dots": float(url.count(".")),
            "num_hyphens": float(url.count("-")),
            "num_digits": float(sum(1 for c in url if c.isdigit())),
            "has_ip_host": is_ip,
            "is_suspicious_tld": suspicious_tld,
            "brand_spoof": brand_spoof,
            "num_subdomains": num_subdomains,
        }

        indicators = []
        if url:
            indicators.append(url)
        if domain:
            indicators.append(domain)

        return Event(
            event_id=event_id or raw.get("event_id") or str(uuid.uuid4()),
            timestamp=raw.get("timestamp") or datetime.now(timezone.utc).isoformat(),
            event_type="url",
            raw_data=raw,
            features=features,
            indicators=list(dict.fromkeys(indicators)),
            metadata={"domain": domain, "referrer": raw.get("referrer", "")},
        )


class FileNormalizer:
    """Normalizes endpoint file/malware events."""

    EXECUTABLE_EXTS = [".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".sh", ".elf", ".scr", ".hta"]

    @classmethod
    def normalize(cls, raw: Dict[str, Any], event_id: Optional[str] = None) -> Event:
        filename = str(raw.get("file_name") or raw.get("filename") or "").lower()
        file_path = str(raw.get("file_path") or raw.get("path") or "").lower()
        file_size = float(raw.get("file_size", 0.0))
        entropy = float(raw.get("entropy", 5.0))

        is_exe = 1.0 if any(filename.endswith(ext) for ext in cls.EXECUTABLE_EXTS) else 0.0
        double_ext = 1.0 if len(filename.split(".")) > 2 else 0.0
        in_temp = 1.0 if any(t in file_path for t in ["temp", "appdata", "tmp", "downloads"]) else 0.0

        features = {
            "file_size": file_size,
            "entropy": entropy,
            "is_executable": is_exe,
            "has_double_extension": double_ext,
            "in_temp_dir": in_temp,
        }

        indicators = []
        for key in ["hash", "sha256", "md5", "sha1"]:
            h = raw.get(key)
            if h and isinstance(h, str) and h not in indicators:
                indicators.append(h.lower())
        if filename:
            indicators.append(filename)

        return Event(
            event_id=event_id or raw.get("event_id") or str(uuid.uuid4()),
            timestamp=raw.get("timestamp") or datetime.now(timezone.utc).isoformat(),
            event_type="file",
            raw_data=raw,
            features=features,
            indicators=indicators,
            metadata={"file_name": filename, "file_path": file_path},
        )


class LogNormalizer:
    """Normalizes authentication, audit, and syslog telemetry."""

    PRIV_COMMANDS = ["sudo", "su -", "chmod +s", "whoami", "mimikatz", "psexec", "/etc/shadow", "net user", "rundll32"]

    @classmethod
    def normalize(cls, raw: Dict[str, Any], event_id: Optional[str] = None) -> Event:
        line = str(raw.get("log_line") or raw.get("message") or "").lower()
        failed_count = float(raw.get("failed_auth_count", 0.0))
        if failed_count == 0.0 and any(w in line for w in ["failed password", "authentication failure", "invalid user", "login failed"]):
            failed_count = 1.0

        has_priv = 1.0 if any(cmd in line for cmd in cls.PRIV_COMMANDS) else 0.0
        user = str(raw.get("user", "")).lower()
        is_root = 1.0 if (user in ["root", "admin", "administrator", "system"] or "root" in line) else 0.0

        features = {
            "failed_auth_count": failed_count,
            "has_priv_escalation": has_priv,
            "is_root_user": is_root,
            "severity_level": float(raw.get("severity", raw.get("level", 3))),
        }

        indicators = []
        # Extract IPs from log line
        ip_matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
        for ip in ip_matches:
            if ip not in indicators:
                indicators.append(ip)
        if user and user not in ["root", "admin"]:
            indicators.append(user)

        return Event(
            event_id=event_id or raw.get("event_id") or str(uuid.uuid4()),
            timestamp=raw.get("timestamp") or datetime.now(timezone.utc).isoformat(),
            event_type="log",
            raw_data=raw,
            features=features,
            indicators=indicators,
            metadata={"source": raw.get("source", "auth"), "user": user},
        )


class InputNormalizer:
    """Unified dispatcher for all telemetry modalities."""

    NORMALIZERS = {
        "network": NetworkNormalizer,
        "message": MessageNormalizer,
        "url": URLNormalizer,
        "file": FileNormalizer,
        "log": LogNormalizer,
    }

    @classmethod
    def normalize(cls, raw: Dict[str, Any], event_type: Optional[str] = None) -> Event:
        modality = (event_type or raw.get("event_type") or "network").lower()
        normalizer = cls.NORMALIZERS.get(modality, NetworkNormalizer)
        return normalizer.normalize(raw)

    @classmethod
    def normalize_batch(cls, raw_events: List[Dict[str, Any]]) -> List[Event]:
        return [cls.normalize(item) for item in raw_events]

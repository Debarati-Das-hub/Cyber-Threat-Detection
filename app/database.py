"""
Persistence Layer (SQLite Database)
Resolves Gap #5: Provides durable storage for events, incident clusters, IOCs, and investigation reports.
"""

from __future__ import annotations
import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.detection_engine import DetectionResult
from app.input_layer import Event
from app.intelligence_engine import IncidentCluster
from app.threat_intel import ThreatIntelResult

DB_PATH = os.getenv("DATABASE_PATH", "cyber_threats.db")


def get_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path or DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Optional[str] = None):
    """Initializes tables for events, incidents, IOCs, and analytics."""
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT,
                event_type TEXT,
                raw_data TEXT,
                features TEXT,
                indicators TEXT,
                severity TEXT,
                confidence REAL,
                is_malicious INTEGER,
                ml_score REAL,
                detection_source TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                created_at TEXT,
                risk_score REAL,
                attack_summary TEXT,
                event_ids TEXT,
                shared_iocs TEXT,
                mitre_techniques TEXT,
                report_markdown TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS iocs (
                ioc TEXT PRIMARY KEY,
                ioc_type TEXT,
                reputation_score REAL,
                is_malicious INTEGER,
                abuse_confidence INTEGER,
                source TEXT,
                country TEXT,
                isp TEXT,
                last_seen TEXT
            )
        """)
        conn.commit()


class DatabaseService:
    """Service wrapping all CRUD operations on the SQLite cyber threat database."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or DB_PATH
        init_db(self.db_path)

    def save_event(self, event: Event, detection: Optional[DetectionResult] = None):
        with get_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO events
                (event_id, timestamp, event_type, raw_data, features, indicators, severity, confidence, is_malicious, ml_score, detection_source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.event_id,
                event.timestamp,
                event.event_type,
                json.dumps(event.raw_data),
                json.dumps(event.features),
                json.dumps(event.indicators),
                detection.severity if detection else "INFO",
                detection.confidence if detection else 0.0,
                1 if detection and detection.is_malicious else 0,
                detection.ml_score if detection else 0.0,
                detection.detection_source if detection else "UNKNOWN",
            ))
            conn.commit()

    def save_incident(self, cluster: IncidentCluster, report_markdown: str):
        with get_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO incidents
                (incident_id, created_at, risk_score, attack_summary, event_ids, shared_iocs, mitre_techniques, report_markdown)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cluster.cluster_id,
                datetime.now(timezone.utc).isoformat(),
                cluster.risk_score,
                cluster.attack_summary,
                json.dumps(cluster.event_ids),
                json.dumps(cluster.shared_iocs),
                json.dumps(cluster.mitre_techniques),
                report_markdown,
            ))
            conn.commit()

    def save_ioc(self, intel: ThreatIntelResult):
        with get_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO iocs
                (ioc, ioc_type, reputation_score, is_malicious, abuse_confidence, source, country, isp, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                intel.ioc.lower(),
                intel.ioc_type,
                intel.reputation_score,
                1 if intel.is_malicious else 0,
                intel.abuse_confidence_score,
                intel.source,
                intel.country or "Unknown",
                intel.isp_or_owner or "Unknown",
                datetime.now(timezone.utc).isoformat(),
            ))
            conn.commit()

    def get_recent_incidents(self, limit: int = 20) -> List[Dict[str, Any]]:
        with get_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            results = []
            for r in rows:
                results.append({
                    "incident_id": r["incident_id"],
                    "created_at": r["created_at"],
                    "risk_score": r["risk_score"],
                    "attack_summary": r["attack_summary"],
                    "event_ids": json.loads(r["event_ids"]),
                    "shared_iocs": json.loads(r["shared_iocs"]),
                    "mitre_techniques": json.loads(r["mitre_techniques"]),
                    "report_markdown": r["report_markdown"],
                })
            return results

    def get_incident_by_id(self, incident_id: str) -> Optional[Dict[str, Any]]:
        with get_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))
            r = cursor.fetchone()
            if not r:
                return None
            return {
                "incident_id": r["incident_id"],
                "created_at": r["created_at"],
                "risk_score": r["risk_score"],
                "attack_summary": r["attack_summary"],
                "event_ids": json.loads(r["event_ids"]),
                "shared_iocs": json.loads(r["shared_iocs"]),
                "mitre_techniques": json.loads(r["mitre_techniques"]),
                "report_markdown": r["report_markdown"],
            }

    def get_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        with get_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            results = []
            for r in rows:
                results.append({
                    "event_id": r["event_id"],
                    "timestamp": r["timestamp"],
                    "event_type": r["event_type"],
                    "raw_data": json.loads(r["raw_data"]),
                    "features": json.loads(r["features"]),
                    "indicators": json.loads(r["indicators"]),
                    "severity": r["severity"],
                    "confidence": r["confidence"],
                    "is_malicious": bool(r["is_malicious"]),
                    "ml_score": r["ml_score"],
                    "detection_source": r["detection_source"],
                })
            return results

    def get_stats(self) -> Dict[str, Any]:
        with get_connection(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM events")
            total_events = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM events WHERE is_malicious = 1")
            malicious_events = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM incidents")
            total_incidents = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM iocs WHERE is_malicious = 1")
            malicious_iocs = cursor.fetchone()[0]

            return {
                "total_events": total_events,
                "malicious_events": malicious_events,
                "clean_events": total_events - malicious_events,
                "total_incidents": total_incidents,
                "tracked_malicious_iocs": malicious_iocs,
            }

"""
FastAPI Server & REST API Gateway
Exposes /api/analyze, /api/demo, /api/health, /api/incidents, /api/stats, /api/mitre,
and serves the Cyber SOC Analyst & Explainable AI dashboard.
"""

from __future__ import annotations
import os
from typing import Any, Dict, List, Optional
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.auth import verify_api_key
from app.database import DatabaseService
from app.detection_engine import DetectionEngine
from app.explainability_engine import ExplainabilityEngine
from app.input_layer import InputNormalizer
from app.intelligence_engine import IntelligenceEngine, MITRE_ATTACK_DB

# App initialization
app = FastAPI(
    title="Explainable Cyber Threat Intelligence Platform",
    description="4-Layer Telemetry Detection, Multi-modal ML, Threat Intel & XAI (DiCE + Alibi)",
    version="2.0.0"
)

# CORS configuration
origins_env = os.getenv("CORS_ORIGINS", "*")
allowed_origins = [o.strip() for o in origins_env.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins if allowed_origins != ["*"] else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pipeline instances
db_service = DatabaseService()
detection_engine = DetectionEngine()
intelligence_engine = IntelligenceEngine()
explainability_engine = ExplainabilityEngine(detection_engine)


class AnalyzeRequest(BaseModel):
    events: List[Dict[str, Any]] = Field(..., description="Array of raw or normalized event objects")


@app.get("/api/health")
def health():
    """System health check and component operational status."""
    return {
        "status": "healthy",
        "pipeline_version": "2.0.0",
        "models": {
            "network_rf": detection_engine.network_model is not None,
            "message_rf": detection_engine.message_model is not None,
            "url_rf": detection_engine.url_model is not None,
            "log_rf": detection_engine.log_model is not None,
            "alibi_anchor": explainability_engine.anchor_explainer is not None,
            "dice_counterfactual": explainability_engine.dice_explainer is not None,
        },
        "threat_intel": {
            "abuseipdb_configured": bool(intelligence_engine.threat_intel.abuseipdb.api_key),
            "virustotal_configured": bool(intelligence_engine.threat_intel.virustotal.api_key),
            "cached_threat_indicators": len(intelligence_engine.threat_intel.cache),
        },
        "database": {
            "status": "connected",
            "path": db_service.db_path,
        }
    }


@app.get("/api/mitre")
def get_mitre_techniques():
    """Returns the full MITRE ATT&CK Enterprise Matrix database."""
    return {"techniques": list(MITRE_ATTACK_DB.values())}


@app.get("/api/stats")
def get_stats():
    """Returns aggregated incident and event metrics from SQLite."""
    return db_service.get_stats()


@app.get("/api/incidents")
def list_incidents(limit: int = 20):
    """Returns historical incident clusters from persistent storage."""
    return {"incidents": db_service.get_recent_incidents(limit=limit)}


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str):
    """Fetches a specific incident by ID including full markdown report."""
    incident = db_service.get_incident_by_id(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@app.post("/api/analyze")
def analyze(payload: AnalyzeRequest, authorized: bool = Depends(verify_api_key)):
    """
    Executes the full 4-Layer Cyber Threat Detection & Explainability pipeline:
    1. Normalization (Multi-modal Event schema)
    2. Detection (Fast Rule Prefilter + Multi-modal ML)
    3. Intelligence (AbuseIPDB/VirusTotal IOC lookup, MITRE mapping, Graph clustering)
    4. Explainability (Alibi Anchors, DiCE Counterfactuals, Evidence Graph, Incident Reports)
    5. Persistence (Durable storage in SQLite)
    """
    if not payload.events:
        raise HTTPException(status_code=400, detail="No events provided for analysis.")

    # 1. Normalize
    events = InputNormalizer.normalize_batch(payload.events)

    # 2. Detect
    detections = detection_engine.detect_batch(events)
    det_map = {d.event_id: d for d in detections}

    # Save events to database
    for ev in events:
        db_service.save_event(ev, det_map.get(ev.event_id))

    # 3. Intelligence & Clustering
    clusters, threat_graph, intel_lookup = intelligence_engine.cluster_campaigns(events, detections)

    # Save queried IOCs
    for intel in intel_lookup.values():
        db_service.save_ioc(intel)

    # 4. Explainability & Evidence Graph Generation
    explanations = [explainability_engine.explain_event(ev, det_map[ev.event_id]) for ev in events]
    exp_map = {x.event_id: x for x in explanations}

    cluster_reports: Dict[str, str] = {}
    evidence_graphs: Dict[str, Dict[str, Any]] = {}

    for cluster in clusters:
        report = explainability_engine.generate_incident_report(cluster, events, detections, explanations)
        cluster_reports[cluster.cluster_id] = report
        db_service.save_incident(cluster, report)

        # Build evidence subgraph
        ev_graph = explainability_engine.build_evidence_graph(cluster, events, detections, explanations)
        # Convert to serializable format for canvas visualization
        nodes = []
        for n, data in ev_graph.nodes(data=True):
            nodes.append({"id": n, **data})
        edges = []
        for u, v, data in ev_graph.edges(data=True):
            edges.append({"source": u, "target": v, **data})

        evidence_graphs[cluster.cluster_id] = {
            "nodes": nodes,
            "edges": edges,
        }

    # Also serialize full threat graph for global network view
    threat_nodes = []
    for n, data in threat_graph.nodes(data=True):
        threat_nodes.append({"id": n, **data})
    threat_edges = []
    for u, v, data in threat_graph.edges(data=True):
        threat_edges.append({"source": u, "target": v, **data})

    return {
        "events": [e.to_dict() for e in events],
        "detections": [d.to_dict() for d in detections],
        "threat_intel": {k: v.to_dict() for k, v in intel_lookup.items()},
        "clusters": [c.to_dict() for c in clusters],
        "explanations": [x.to_dict() for x in explanations],
        "evidence_graphs": evidence_graphs,
        "threat_graph": {
            "nodes": threat_nodes,
            "edges": threat_edges,
        },
        "reports": cluster_reports,
    }


@app.get("/api/demo")
def run_demo():
    """
    Executes an out-of-the-box multi-stage cyber campaign demonstration:
    - Stage 1: Spear-phishing message with credential harvesting domain
    - Stage 2: C2 Beaconing to known threat IP (185.220.101.5)
    - Stage 3: SSH Brute force attack log with root escalation attempt
    - Stage 4: Network SYN flood / port reconnaissance flow
    - Stage 5: Legitimate benign traffic for baseline contrast
    """
    demo_events = [
        # 1. Phishing Email
        {
            "event_type": "message",
            "sender": "security-update@login-update-auth-service.com",
            "subject": "URGENT: Immediate Account Verification Required",
            "body": "Your corporate account will be suspended in 24 hours. Please click to verify your password immediately: https://login-update-auth-service.com/login",
            "has_attachment": True,
        },
        # 2. URL Telemetry
        {
            "event_type": "url",
            "url": "http://185.220.101.5:8080/payload.exe",
            "referrer": "https://login-update-auth-service.com/login",
        },
        # 3. Log Telemetry (Auth Brute Force & Priv Escalation)
        {
            "event_type": "log",
            "log_line": "Failed password for root from 185.220.101.5 port 44322 ssh2. User attempted sudo su - and mimikatz extraction.",
            "failed_auth_count": 28,
            "user": "root",
            "severity": 1,
        },
        # 4. Network Flow (SYN Flood / Reconnaissance Flow matching NSL-KDD schema)
        {
            "event_type": "network",
            "src_ip": "185.220.101.5",
            "dst_ip": "10.0.0.15",
            "duration": 0.05,
            "src_bytes": 0.0,
            "dst_bytes": 0.0,
            "count": 420.0,
            "srv_count": 8.0,
            "same_srv_rate": 0.05,
            "diff_srv_rate": 0.95,
            "dst_host_srv_count": 2.0,
            "protocol_type": "tcp",
            "service": "private",
            "flag": "S0",
        },
        # 5. Benign Normal Network Flow
        {
            "event_type": "network",
            "src_ip": "10.0.0.22",
            "dst_ip": "142.250.190.46",
            "duration": 1.45,
            "src_bytes": 482.0,
            "dst_bytes": 2840.0,
            "count": 3.0,
            "srv_count": 4.0,
            "same_srv_rate": 1.0,
            "diff_srv_rate": 0.0,
            "dst_host_srv_count": 180.0,
            "protocol_type": "tcp",
            "service": "http",
            "flag": "SF",
        },
    ]

    req = AnalyzeRequest(events=demo_events)
    return analyze(req, authorized=True)


# Serve Static Frontend Console
static_dir = os.path.join(os.path.dirname(__file__), "..", "static")
if os.path.exists(static_dir):
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")

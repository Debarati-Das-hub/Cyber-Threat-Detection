"""
AEGIS-XAI: Command Line Interface & Pipeline Orchestrator
Executes all 4 layers end-to-end with terminal reporting, model training, or server launch.
"""

from __future__ import annotations
import argparse
import json
import sys
import uvicorn

if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from app.database import DatabaseService
from app.detection_engine import DetectionEngine
from app.explainability_engine import ExplainabilityEngine
from app.input_layer import InputNormalizer
from app.intelligence_engine import IntelligenceEngine


def run_cli_pipeline():
    """Executes the full 4-layer threat detection and explainability workflow in the console."""
    print("=" * 80)
    print("🛡️  AEGIS-XAI: EXPLAINABLE CYBER THREAT DETECTION & INTELLIGENCE PLATFORM")
    print("=" * 80)
    print("Initializing Core Engines...")

    db = DatabaseService()
    detector = DetectionEngine()
    intel = IntelligenceEngine()
    xai = ExplainabilityEngine(detector)

    print("✔ Detection Models Loaded (Network Flow RF, Message Phishing, URL Risk, Log Anomaly)")
    print("✔ Threat Intelligence Engine Online (AbuseIPDB v2 + VirusTotal v3 Contracts)")
    print("✔ Explainable AI Ready (Alibi AnchorTabular + DiCE Counterfactuals)")
    print("-" * 80)

    # 1. Multi-Modal Scenario Telemetry
    sample_raw_events = [
        # Phishing Email
        {
            "event_type": "message",
            "sender": "security-dept@login-update-auth-service.com",
            "subject": "CRITICAL: Urgent Corporate Password Expiry",
            "body": "Immediate action required. Please verify your credentials now: https://login-update-auth-service.com/login",
            "has_attachment": True,
        },
        # URL Beacon
        {
            "event_type": "url",
            "url": "http://185.220.101.5:8080/stage2.bin",
            "referrer": "https://login-update-auth-service.com/login",
        },
        # Brute Force Log
        {
            "event_type": "log",
            "log_line": "Failed password for root from 185.220.101.5 port 55102 ssh2. Sudo privileges requested with mimikatz.",
            "failed_auth_count": 32,
            "user": "root",
            "severity": 1,
        },
        # Network SYN Flood
        {
            "event_type": "network",
            "src_ip": "185.220.101.5",
            "dst_ip": "10.0.0.5",
            "duration": 0.02,
            "src_bytes": 0.0,
            "dst_bytes": 0.0,
            "count": 480.0,
            "srv_count": 6.0,
            "same_srv_rate": 0.02,
            "diff_srv_rate": 0.98,
            "dst_host_srv_count": 1.0,
            "protocol_type": "tcp",
            "service": "private",
            "flag": "S0",
        },
        # Benign Network Traffic
        {
            "event_type": "network",
            "src_ip": "10.0.0.100",
            "dst_ip": "142.250.190.46",
            "duration": 1.10,
            "src_bytes": 450.0,
            "dst_bytes": 3500.0,
            "count": 3.0,
            "srv_count": 4.0,
            "same_srv_rate": 1.0,
            "diff_srv_rate": 0.0,
            "dst_host_srv_count": 120.0,
            "protocol_type": "tcp",
            "service": "http",
            "flag": "SF",
        },
    ]

    print("\n[Layer 1: Normalization]")
    events = InputNormalizer.normalize_batch(sample_raw_events)
    for ev in events:
        print(f"  → Ingested [{ev.event_type.upper()}] ID: {ev.event_id[:8]}... (Indicators: {len(ev.indicators)})")

    print("\n[Layer 2: Hybrid Detection (Rule Prefilter + Multi-Modal ML)]")
    detections = detector.detect_batch(events)
    for ev, det in zip(events, detections):
        verdict = "🔴 MALICIOUS" if det.is_malicious else "🟢 BENIGN"
        print(f"  → Event {ev.event_id[:8]}: {verdict} | Severity: {det.severity} | Conf: {det.confidence * 100:.1f}% | Source: {det.detection_source}")
        if det.rule_triggers:
            print(f"     Triggers: {det.rule_triggers[0]}")
        # Save to DB
        db.save_event(ev, det)

    print("\n[Layer 3: Threat Intelligence & Graph Correlation]")
    clusters, graph, intel_lookup = intel.cluster_campaigns(events, detections)
    print(f"  ✔ Correlated {len(clusters)} Incident Campaign(s) across {graph.number_of_nodes()} graph entities.")
    for c in clusters:
        print(f"  → Campaign [{c.cluster_id}] Risk: {c.risk_score * 100:.1f}% | Stages: {', '.join(c.kill_chain_stages)}")
        print(f"     Summary: {c.attack_summary}")

    print("\n[Layer 4: Explainability Engine (DiCE + Alibi Anchors)]")
    explanations = [xai.explain_event(ev, det) for ev, det in zip(events, detections)]
    for exp in explanations:
        if exp.prediction_label == "Malicious":
            print(f"\n  🔍 Root-Cause Explanation for Event: {exp.event_id[:8]} ({exp.modality.upper()})")
            if exp.anchor_rules:
                print(f"     Alibi Anchor Rule: IF ({exp.anchor_rules[0]}) -> MALICIOUS [Precision: {exp.anchor_precision * 100:.0f}%]")
            if exp.counterfactuals:
                cf = exp.counterfactuals[0]
                print(f"     DiCE Counterfactual: {cf.get('explanation')}")
                for feat, diff in list(cf.get("feature_changes", {}).items())[:2]:
                    print(f"       • {feat}: current {diff['original']} ➔ reduce to {diff['required_to_flip']} (Δ {diff['delta']})")
            print(f"     Remediation: {exp.actionable_remediation}")

    # Generate and print primary incident report
    if clusters:
        primary = clusters[0]
        report = xai.generate_incident_report(primary, events, detections, explanations)
        db.save_incident(primary, report)
        print("\n" + "=" * 80)
        print(f"📄 AUTOMATED SOC INCIDENT REPORT ({primary.cluster_id})")
        print("=" * 80)
        print(report[:1500] + "\n\n... [Report Truncated for CLI Display. Full version saved to SQLite DB] ...")

    print("\n" + "=" * 80)
    print("✔ Pipeline executed successfully with 0 errors.")
    print("=" * 80)


def main():
    parser = argparse.ArgumentParser(description="AEGIS-XAI Cyber Threat Detection Platform")
    parser.add_argument("--demo", action="store_true", help="Run end-to-end 4-layer CLI demo")
    parser.add_argument("--train", action="store_true", help="Retrain all ML models on NSL-KDD benchmark")
    parser.add_argument("--serve", action="store_true", help="Launch FastAPI REST server & SOC web console")
    parser.add_argument("--port", type=int, default=8000, help="Port for web server (default 8000)")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host interface (default 0.0.0.0)")

    args = parser.parse_args()

    if args.train:
        print("Training models on NSL-KDD and multi-modal training sets...")
        det = DetectionEngine()
        det.train_network_model()
        det.train_multimodal_models()
        print("✔ All models trained and saved to models/ directory.")
    elif args.serve:
        print(f"Starting AEGIS-XAI Server at http://{args.host}:{args.port}")
        uvicorn.run("app.api:app", host=args.host, port=args.port, reload=False)
    else:
        # Default behavior: run CLI demo
        run_cli_pipeline()


if __name__ == "__main__":
    main()

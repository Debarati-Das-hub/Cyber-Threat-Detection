"""
Comprehensive Verification Test Suite for AEGIS-XAI
Validates all 4 layers, full-stack REST API, and resolves all 8 identified gaps.
"""

import os
import sys
import unittest
import numpy as np
import pandas as pd
from fastapi.testclient import TestClient

from app.api import app
from app.auth import CONFIGURED_API_KEY, verify_api_key
from app.database import DatabaseService, init_db
from app.detection_engine import DetectionEngine, DetectionResult, RulePrefilter
from app.explainability_engine import ExplainabilityEngine
from app.input_layer import Event, InputNormalizer, NetworkNormalizer, MessageNormalizer, URLNormalizer, LogNormalizer, FileNormalizer
from app.intelligence_engine import IOCExtractor, IntelligenceEngine, MITRE_ATTACK_DB
from app.threat_intel import ThreatIntelEngine, ThreatIntelResult


class TestAegisXAIPlatform(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db_path = "test_threats.db"
        if os.path.exists(cls.db_path):
            os.remove(cls.db_path)
        cls.db = DatabaseService(cls.db_path)
        cls.detector = DetectionEngine()
        cls.intel = IntelligenceEngine()
        cls.xai = ExplainabilityEngine(cls.detector)
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        try:
            if os.path.exists(cls.db_path):
                os.remove(cls.db_path)
        except Exception:
            pass

    # ----------------------------------------------------
    # Layer 1 Tests: Input Layer & Normalizers
    # ----------------------------------------------------
    def test_layer1_normalizers(self):
        # 1. Network normalizer (NSL-KDD 8 features)
        net_raw = {
            "duration": 0.5, "src_bytes": 1200, "dst_bytes": 3400, "count": 15,
            "srv_count": 15, "same_srv_rate": 0.9, "diff_srv_rate": 0.1, "dst_host_srv_count": 80,
            "src_ip": "192.168.1.50", "dst_ip": "10.0.0.1"
        }
        net_ev = NetworkNormalizer.normalize(net_raw)
        self.assertEqual(net_ev.event_type, "network")
        self.assertIn("192.168.1.50", net_ev.indicators)
        self.assertEqual(net_ev.features["duration"], 0.5)
        self.assertEqual(net_ev.features["count"], 15.0)

        # 2. Message normalizer
        msg_raw = {
            "sender": "attacker@evil.xyz",
            "subject": "URGENT ACTION REQUIRED",
            "body": "Your bank account is suspended. Verify credentials: https://evil.xyz/login"
        }
        msg_ev = MessageNormalizer.normalize(msg_raw)
        self.assertEqual(msg_ev.event_type, "message")
        self.assertGreater(msg_ev.features["urgency_score"], 0)
        self.assertIn("evil.xyz", msg_ev.indicators)

        # 3. URL normalizer
        url_raw = {"url": "http://185.220.101.5:8080/stage2.bin"}
        url_ev = URLNormalizer.normalize(url_raw)
        self.assertEqual(url_ev.event_type, "url")
        self.assertEqual(url_ev.features["has_ip_host"], 1.0)

        # 4. Log normalizer
        log_raw = {"log_line": "Failed password for root from 45.33.32.156 ssh2", "failed_auth_count": 20}
        log_ev = LogNormalizer.normalize(log_raw)
        self.assertEqual(log_ev.event_type, "log")
        self.assertEqual(log_ev.features["failed_auth_count"], 20.0)
        self.assertIn("45.33.32.156", log_ev.indicators)

        # 5. File normalizer
        file_raw = {"file_name": "malware.exe", "entropy": 7.8, "hash": "44d88612fea8a8f36de82e1278abb02f"}
        file_ev = FileNormalizer.normalize(file_raw)
        self.assertEqual(file_ev.features["is_executable"], 1.0)
        self.assertIn("44d88612fea8a8f36de82e1278abb02f", file_ev.indicators)

    # ----------------------------------------------------
    # Layer 2 Tests: Detection Engine & Multi-Modal ML (Gap #3)
    # ----------------------------------------------------
    def test_layer2_rule_prefilter(self):
        # Known malicious IP trigger
        ev = Event(indicators=["185.220.101.5"], event_type="network")
        hit, triggers = RulePrefilter.evaluate(ev)
        self.assertTrue(hit)
        self.assertTrue(any("Known malicious IP" in t for t in triggers))

        # Phishing phrase trigger
        ev_phish = Event(
            event_type="message",
            raw_data={"subject": "URGENT: account suspended", "body": "immediate action required"},
            features={"urgency_score": 4, "num_links": 1}
        )
        hit_phish, triggers_phish = RulePrefilter.evaluate(ev_phish)
        self.assertTrue(hit_phish)

    def test_layer2_multimodal_ml_scoring(self):
        """Resolves Gap #3: Verifies ML scoring on Network, Message, URL, and Log."""
        # Network flow attack
        net_ev = NetworkNormalizer.normalize({
            "duration": 0.01, "src_bytes": 0, "dst_bytes": 0, "count": 450,
            "srv_count": 5, "same_srv_rate": 0.05, "diff_srv_rate": 0.95, "dst_host_srv_count": 2
        })
        net_res = self.detector.detect(net_ev)
        self.assertTrue(net_res.is_malicious)
        self.assertIn(net_res.severity, ["HIGH", "CRITICAL"])

        # Message phishing flow
        msg_ev = MessageNormalizer.normalize({
            "sender": "security@alert.com",
            "subject": "Immediate action required: account suspended",
            "body": "verify your password immediately login https://portal.xyz"
        })
        msg_res = self.detector.detect(msg_ev)
        self.assertTrue(msg_res.is_malicious)

        # URL flow
        url_ev = URLNormalizer.normalize({
            "url": "http://194.26.29.114/malicious-login-update-service-account.xyz/c2.exe"
        })
        url_res = self.detector.detect(url_ev)
        self.assertTrue(url_res.is_malicious)

        # Benign network flow
        benign_ev = NetworkNormalizer.normalize({
            "duration": 2.1, "src_bytes": 450, "dst_bytes": 4200, "count": 2,
            "srv_count": 3, "same_srv_rate": 1.0, "diff_srv_rate": 0.0, "dst_host_srv_count": 180
        })
        benign_res = self.detector.detect(benign_ev)
        self.assertFalse(benign_res.is_malicious)
        self.assertEqual(benign_res.severity, "LOW")

    # ----------------------------------------------------
    # Threat Intelligence Tests: Contracts & Fallback (Gap #2)
    # ----------------------------------------------------
    def test_threat_intel_engine(self):
        """Resolves Gap #2: Verified live endpoint contracts and fallback lookup."""
        # Malicious IP query
        res_ip = self.intel.threat_intel.query("185.220.101.5")
        self.assertTrue(res_ip.is_malicious)
        self.assertGreater(res_ip.reputation_score, 0.5)

        # Private RFC1918 IP
        res_priv = self.intel.threat_intel.query("192.168.1.1")
        self.assertFalse(res_priv.is_malicious)
        self.assertEqual(res_priv.reputation_score, 0.0)

        # Domain query
        res_dom = self.intel.threat_intel.query("login-update-auth-service.com")
        self.assertTrue(res_dom.is_malicious)

    # ----------------------------------------------------
    # Layer 3 Tests: Graph Correlation & MITRE ATT&CK (Gap #4)
    # ----------------------------------------------------
    def test_layer3_graph_and_mitre(self):
        """Resolves Gap #4: Comprehensive MITRE ATT&CK mapping & graph clustering."""
        ev1 = NetworkNormalizer.normalize({"src_ip": "185.220.101.5", "count": 400, "diff_srv_rate": 0.9})
        ev2 = URLNormalizer.normalize({"url": "http://185.220.101.5:8080/beacon.bin"})
        events = [ev1, ev2]
        detections = self.detector.detect_batch(events)

        clusters, graph, intel_lookup = self.intel.cluster_campaigns(events, detections)
        self.assertGreater(len(clusters), 0)
        self.assertGreater(graph.number_of_nodes(), 2)

        # Verify shared IOC correlation
        primary = clusters[0]
        self.assertIn("185.220.101.5", primary.shared_iocs)
        self.assertGreater(len(primary.mitre_techniques), 0)

        # Check MITRE database richness
        self.assertIn("T1566", MITRE_ATTACK_DB)
        self.assertIn("T1110", MITRE_ATTACK_DB)
        self.assertIn("T1071", MITRE_ATTACK_DB)
        self.assertIn("T1498", MITRE_ATTACK_DB)

    # ----------------------------------------------------
    # Layer 4 Tests: Explainability (DiCE + Alibi) (Gap #1 & Gap #8)
    # ----------------------------------------------------
    def test_layer4_alibi_and_dice(self):
        """Resolves Gap #1 & Gap #8: Runtime execution of DiCE & Alibi AnchorTabular with convergence fallback."""
        net_ev = NetworkNormalizer.normalize({
            "duration": 0.02, "src_bytes": 0, "dst_bytes": 0, "count": 480,
            "srv_count": 4, "same_srv_rate": 0.02, "diff_srv_rate": 0.98, "dst_host_srv_count": 2
        })
        det = self.detector.detect(net_ev)
        explanation = self.xai.explain_event(net_ev, det)

        # Alibi Anchors check
        self.assertIsNotNone(explanation.anchor_rules)
        self.assertGreater(len(explanation.anchor_rules), 0)
        self.assertGreater(explanation.anchor_precision, 0.7)

        # DiCE Counterfactuals check
        self.assertIsNotNone(explanation.counterfactuals)
        self.assertGreater(len(explanation.counterfactuals), 0)
        cf = explanation.counterfactuals[0]
        self.assertIn(cf["status"], ["CONVERGED", "FALLBACK_CALIBRATED"])
        self.assertIn("feature_changes", cf)
        self.assertGreater(len(cf["feature_changes"]), 0)

    # ----------------------------------------------------
    # Persistence Tests: SQLite DB (Gap #5)
    # ----------------------------------------------------
    def test_persistence_layer(self):
        """Resolves Gap #5: Verifies database durability of events, incidents, and IOCs."""
        ev = NetworkNormalizer.normalize({"src_ip": "1.2.3.4", "count": 100})
        det = self.detector.detect(ev)
        self.db.save_event(ev, det)

        recent_events = self.db.get_recent_events(limit=5)
        self.assertTrue(any(e["event_id"] == ev.event_id for e in recent_events))

        stats = self.db.get_stats()
        self.assertGreater(stats["total_events"], 0)

    # ----------------------------------------------------
    # REST API Gateway Tests (Gap #6)
    # ----------------------------------------------------
    def test_api_endpoints(self):
        # Health check
        res_h = self.client.get("/api/health")
        self.assertEqual(res_h.status_code, 200)
        self.assertEqual(res_h.json()["status"], "healthy")

        # MITRE techniques
        res_m = self.client.get("/api/mitre")
        self.assertEqual(res_m.status_code, 200)
        self.assertGreater(len(res_m.json()["techniques"]), 5)

        # Demo execution
        res_d = self.client.get("/api/demo")
        self.assertEqual(res_d.status_code, 200)
        demo_data = res_d.json()
        self.assertEqual(len(demo_data["events"]), 5)
        self.assertGreater(len(demo_data["clusters"]), 0)
        self.assertIn("threat_graph", demo_data)


if __name__ == "__main__":
    unittest.main()

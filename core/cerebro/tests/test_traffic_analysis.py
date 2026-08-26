import sys
import unittest
from pathlib import Path

CEREBRO_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CEREBRO_DIR))

from traffic_analysis import EventReplayGuard, TrafficBaselineModel, TrafficRateMonitor, has_strong_dos_signature


def event(src, dst, message="SIS ICMP detectado", protocol="ids_alert"):
    return {
        "src_ip": src,
        "dst_ip": dst,
        "protocol": protocol,
        "source": "snort",
        "message": message,
        "raw_log": message,
    }


class TrafficRateMonitorTests(unittest.TestCase):
    def setUp(self):
        self.monitor = TrafficRateMonitor(
            window_seconds=5,
            flow_min_events=120,
            flow_min_eps=20,
            destination_min_events=250,
            destination_min_eps=40,
        )

    def test_high_global_volume_spread_across_hosts_is_not_a_flood(self):
        docs = [event(f"10.0.{i // 250}.{i % 250 + 1}", f"192.168.{i // 250}.{i % 250 + 1}") for i in range(600)]
        metrics = self.monitor.observe(docs, now=10)
        self.assertGreater(metrics["accepted_eps"], 100)
        self.assertFalse(metrics["flood_keys"])

    def test_normal_ping_exchange_is_not_a_flood(self):
        docs = [event("192.168.1.88", "192.168.1.82", protocol="icmp") for _ in range(50)]
        metrics = self.monitor.observe(docs, now=10)
        self.assertFalse(self.monitor.is_flood(docs[0], metrics))

    def test_large_but_non_flood_icmp_burst_stays_normal(self):
        docs = [event("192.168.1.88", "192.168.1.82", protocol="icmp") for _ in range(600)]
        metrics = self.monitor.observe(docs, now=10)
        self.assertFalse(self.monitor.is_flood(docs[0], metrics))

    def test_sustained_icmp_flood_requires_icmp_thresholds(self):
        docs = [event("66.66.66.66", "192.168.1.88", protocol="icmp") for _ in range(1000)]
        metrics = self.monitor.observe(docs, now=10)
        self.assertTrue(self.monitor.is_flood(docs[0], metrics))
        self.assertEqual("icmp_flood", metrics["reasons"][("66.66.66.66", "192.168.1.88", "icmp")])

    def test_replayed_backlog_is_not_counted_as_live_rate(self):
        docs = [
            {**event("192.168.1.88", "192.168.1.82", protocol="icmp"), "_event_epoch": 100}
            for _ in range(2000)
        ]
        metrics = self.monitor.observe(docs, now=1000)
        self.assertEqual(0, metrics["fresh_events"])
        self.assertEqual(2000, metrics["stale_events"])
        self.assertFalse(metrics["flood_keys"])

    def test_concentrated_flow_is_a_flood(self):
        docs = [event("66.66.66.66", "192.168.1.88", protocol="tcp") for _ in range(150)]
        metrics = self.monitor.observe(docs, now=10)
        self.assertTrue(self.monitor.is_flood(docs[0], metrics))
        self.assertEqual("concentrated_flow", metrics["reasons"][("66.66.66.66", "192.168.1.88", "tcp")])

    def test_distributed_destination_flood_is_detected(self):
        docs = [event(f"10.0.0.{i % 250 + 1}", "192.168.1.88", protocol="tcp") for i in range(300)]
        metrics = self.monitor.observe(docs, now=10)
        self.assertTrue(all(self.monitor.is_flood(doc, metrics) for doc in docs))

    def test_strong_signature_is_evidence_but_dos_check_text_is_not(self):
        attack = event("66.66.66.66", "192.168.1.88", "DOS ATTACK CRITICAL FLOOD")
        check = event("192.168.1.1", "192.168.1.2", "SIS SCADA DoS Check")
        self.assertTrue(has_strong_dos_signature(attack))
        self.assertFalse(has_strong_dos_signature(check))


class EventReplayGuardTests(unittest.TestCase):
    def test_exact_replay_is_accepted_once_within_ttl(self):
        guard = EventReplayGuard(ttl_seconds=10)
        self.assertTrue(guard.accept("snort|same alert", now=100))
        self.assertFalse(guard.accept("snort|same alert", now=101))
        self.assertTrue(guard.accept("snort|different alert", now=101))
        self.assertTrue(guard.accept("snort|same alert", now=111))


class TrafficBaselineModelTests(unittest.TestCase):
    def test_repeated_normal_profile_stays_normal_after_training(self):
        model = TrafficBaselineModel(min_samples=10, history_size=30)
        metrics = {
            "accepted_eps": 5,
            "max_flow_eps": 1,
            "unique_pairs": 10,
            "snort_ratio": 0.2,
            "flood_keys": set(),
        }
        score = 0.5
        for _ in range(40):
            score = model.score(metrics)
        self.assertTrue(model.trained)
        self.assertGreaterEqual(score, -0.10)

    def test_confirmed_flood_is_not_learned_as_normal(self):
        model = TrafficBaselineModel(min_samples=3, history_size=10)
        metrics = {
            "accepted_eps": 100,
            "max_flow_eps": 100,
            "unique_pairs": 1,
            "snort_ratio": 1,
            "flood_keys": {("a", "b", "tcp")},
        }
        self.assertEqual(0.5, model.score(metrics))
        self.assertEqual(0, len(model.history))


if __name__ == "__main__":
    unittest.main()

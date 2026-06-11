import json
import sys
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

CEREBRO_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CEREBRO_DIR))

from main import _event_epoch, normalizar_evento


class EventNormalizationTests(unittest.TestCase):
    def test_snort_ipv6_alert_is_discarded(self):
        event = {
            "log": {"file": {"path": "/logs/snort/alert"}},
            "fields": {"source_type": "snort"},
            "message": "[**] [1:1:1] alerta [**] {IPV6-ICMP} fe80::1 -> ff02::1",
        }
        self.assertIsNone(normalizar_evento(json.dumps(event)))

    def test_zeek_ipv6_event_is_discarded(self):
        event = {
            "log": {"file": {"path": "/logs/zeek/conn.log"}},
            "message": json.dumps({"id.orig_h": "2001:db8::1", "id.resp_h": "2001:db8::2"}),
        }
        self.assertIsNone(normalizar_evento(json.dumps(event)))

    def test_legacy_test_alert_is_discarded(self):
        event = {
            "log": {"file": {"path": "/logs/snort/alert"}},
            "fields": {"source_type": "snort"},
            "message": "[**] [1:1000005:1] [TEST] Ping Detectado en WiFi [**] {ICMP} 192.168.6.243 -> 192.168.6.192",
        }
        self.assertIsNone(normalizar_evento(json.dumps(event)))

    def test_new_sis_icmp_alert_is_preserved(self):
        event = {
            "log": {"file": {"path": "/logs/snort/alert"}},
            "fields": {"source_type": "snort"},
            "message": "[**] [1:1100802:1] SIS ICMP detectado [**] {ICMP} 192.168.6.243 -> 192.168.6.192",
        }
        normalized = normalizar_evento(json.dumps(event))
        self.assertIsNotNone(normalized)
        self.assertIn("SIS ICMP detectado", normalized["message"])

    def test_zeek_metric_without_endpoints_is_discarded(self):
        event = {
            "log": {"file": {"path": "/logs/zeek/metrics.log"}},
            "message": json.dumps({"peer": "zeek", "metric_type": "counter", "name": "zeek_dns"}),
        }
        self.assertIsNone(normalizar_evento(json.dumps(event)))

    def test_explicit_unspecified_flow_is_discarded(self):
        event = {
            "log": {"file": {"path": "/logs/snort/alert"}},
            "fields": {"source_type": "snort"},
            "message": "[**] malformed event [**] 0.0.0.0 -> 0.0.0.0",
        }
        self.assertIsNone(normalizar_evento(json.dumps(event)))

    def test_zeek_epoch_is_preserved_as_source_time(self):
        now = time.time()
        message = {"ts": now - 2, "id.orig_h": "192.168.1.1", "id.resp_h": "192.168.1.2"}
        self.assertAlmostEqual(now - 2, _event_epoch({}, message, now=now), places=3)

    def test_recent_snort_timestamp_is_preserved_as_source_time(self):
        now = time.time()
        stamp = datetime.fromtimestamp(now - 2, timezone.utc).strftime("%m/%d-%H:%M:%S.%f")
        parsed = _event_epoch({}, f"{stamp} [**] SIS ICMP detectado", now=now)
        self.assertAlmostEqual(now - 2, parsed, delta=1)

    def test_stale_snort_replay_is_discarded(self):
        stale = datetime.fromtimestamp(time.time() - 600, timezone.utc).strftime("%m/%d-%H:%M:%S.%f")
        event = {
            "log": {"file": {"path": "/logs/snort/alert"}},
            "fields": {"source_type": "snort"},
            "message": f"{stale} [**] [1:1100802:1] SIS ICMP detectado [**] {{ICMP}} 192.168.1.88 -> 192.168.1.83",
        }
        self.assertIsNone(normalizar_evento(json.dumps(event)))

    def test_ipv4_event_is_preserved(self):
        event = {
            "log": {"file": {"path": "/logs/snort/alert"}},
            "fields": {"source_type": "snort"},
            "message": "[**] {ICMP} 192.168.6.243 -> 192.168.6.192",
        }
        normalized = normalizar_evento(json.dumps(event))
        self.assertEqual("192.168.6.243", normalized["src_ip"])
        self.assertEqual("192.168.6.192", normalized["dst_ip"])
        self.assertEqual("icmp", normalized["protocol"])


if __name__ == "__main__":
    unittest.main()

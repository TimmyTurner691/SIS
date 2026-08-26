import json
import sys
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

CEREBRO_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CEREBRO_DIR))

from main import _event_epoch, _index_epoch, infer_application_protocol, normalizar_evento


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

    def test_stale_snort_replay_remains_visible_but_keeps_sensor_time(self):
        now = time.time()
        stale_epoch = now - 600
        stale = datetime.fromtimestamp(stale_epoch, timezone.utc).strftime("%m/%d-%H:%M:%S.%f")
        ingested = datetime.fromtimestamp(now, timezone.utc).isoformat().replace("+00:00", "Z")
        event = {
            "@timestamp": ingested,
            "log": {"file": {"path": "/logs/snort/alert"}},
            "source_type": "snort",
            "message": f"{stale} [**] [1:1100802:1] SIS ICMP detectado [**] {{ICMP}} 192.168.1.88 -> 192.168.1.83",
        }
        normalized = normalizar_evento(json.dumps(event))
        self.assertIsNotNone(normalized)
        self.assertAlmostEqual(stale_epoch, normalized["_event_epoch"], delta=1)
        self.assertAlmostEqual(now, datetime.fromisoformat(normalized["@timestamp"]).timestamp(), delta=1)
        self.assertEqual("snort", normalized["source"])

    def test_filebeat_timestamp_controls_dashboard_visibility(self):
        now = time.time()
        event = {"@timestamp": datetime.fromtimestamp(now, timezone.utc).isoformat()}
        self.assertAlmostEqual(now, _index_epoch(event, now=now + 500), delta=1)

    def test_missing_filebeat_timestamp_falls_back_to_ingestion_time(self):
        self.assertEqual(1234, _index_epoch({}, now=1234))

    def test_stale_zeek_sensor_time_is_still_indexed_at_filebeat_time(self):
        now = time.time()
        ingested = datetime.fromtimestamp(now, timezone.utc).isoformat().replace("+00:00", "Z")
        event = {
            "@timestamp": ingested,
            "source_type": "zeek",
            "log": {"file": {"path": "/logs/zeek/conn.log"}},
            "message": json.dumps({
                "ts": now - 3600,
                "id.orig_h": "192.168.1.10",
                "id.resp_h": "192.168.1.20",
                "proto": "tcp",
            }),
        }
        normalized = normalizar_evento(json.dumps(event))
        self.assertIsNotNone(normalized)
        self.assertAlmostEqual(now - 3600, normalized["_event_epoch"], delta=1)
        self.assertAlmostEqual(now, datetime.fromisoformat(normalized["@timestamp"]).timestamp(), delta=1)
        self.assertEqual("tcp", normalized["protocol"])

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

    def test_snort_ssh_is_inferred_from_ports(self):
        event = {
            "source_type": "snort",
            "message": "[**] [1:1100403:1] Connection attempt [**] {TCP} 192.168.1.83:42631 -> 192.168.1.85:22",
        }
        normalized = normalizar_evento(json.dumps(event))
        self.assertEqual("ssh", normalized["protocol"])
        self.assertEqual("tcp", normalized["transport_protocol"])
        self.assertEqual(42631, normalized["src_port"])
        self.assertEqual(22, normalized["dst_port"])

    def test_signature_marker_takes_precedence_over_transport(self):
        self.assertEqual("ssh", infer_application_protocol("SIS Linux SSH detectado", 50000, 22, "tcp"))


if __name__ == "__main__":
    unittest.main()

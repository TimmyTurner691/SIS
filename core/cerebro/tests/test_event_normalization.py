import json
import sys
import unittest
from pathlib import Path

CEREBRO_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CEREBRO_DIR))

from main import normalizar_evento


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

    def test_ipv4_event_is_preserved(self):
        event = {
            "log": {"file": {"path": "/logs/snort/alert"}},
            "fields": {"source_type": "snort"},
            "message": "[**] {ICMP} 192.168.6.243 -> 192.168.6.192",
        }
        normalized = normalizar_evento(json.dumps(event))
        self.assertEqual("192.168.6.243", normalized["src_ip"])
        self.assertEqual("192.168.6.192", normalized["dst_ip"])


if __name__ == "__main__":
    unittest.main()

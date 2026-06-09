import json
import sys
import unittest
from pathlib import Path

CEREBRO_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CEREBRO_DIR))

from event_filter import contains_ipv6, is_ipv6_address, is_legacy_test_alert


class EventFilterTests(unittest.TestCase):
    def test_ipv6_address_is_detected(self):
        self.assertTrue(is_ipv6_address("fe80::b620:4"))
        self.assertTrue(contains_ipv6("{IPV6-ICMP} fe80::1 -> ff02::1"))

    def test_nested_zeek_ipv6_is_detected(self):
        event = {"id": {"orig_h": "2001:db8::10", "resp_h": "2001:db8::20"}}
        self.assertTrue(contains_ipv6(event))
        self.assertTrue(contains_ipv6(json.dumps(event)))

    def test_ipv4_and_timestamps_are_not_rejected(self):
        self.assertFalse(contains_ipv6("2026-06-09T16:14:58 192.168.6.243 -> 192.168.6.192"))
        self.assertFalse(contains_ipv6({"id.orig_h": "10.0.0.1", "id.resp_h": "10.0.0.2"}))


class LegacyAlertFilterTests(unittest.TestCase):
    def test_legacy_alert_is_detected_by_snort_header_or_message(self):
        self.assertTrue(is_legacy_test_alert('[**] [1:1000005:1] cualquier texto [**]'))
        self.assertTrue(is_legacy_test_alert('[TEST] Ping Detectado en WiFi'))
        self.assertFalse(is_legacy_test_alert('[**] [1:1100802:1] SIS ICMP detectado [**]'))


if __name__ == "__main__":
    unittest.main()

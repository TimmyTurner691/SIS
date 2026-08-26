import json
import sys
import unittest
from pathlib import Path

CEREBRO_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CEREBRO_DIR))

from event_filter import contains_ipv6, is_ipv6_address, is_legacy_test_alert, is_unspecified_traffic


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


class UnspecifiedTrafficFilterTests(unittest.TestCase):
    def test_pair_of_unspecified_endpoints_is_trash(self):
        self.assertTrue(is_unspecified_traffic({"src_ip": "0.0.0.0", "dst_ip": "0.0.0.0"}))
        self.assertTrue(is_unspecified_traffic("0.0.0.0 -> 0.0.0.0"))

    def test_single_unspecified_endpoint_is_not_discarded(self):
        self.assertFalse(is_unspecified_traffic({"src_ip": "0.0.0.0", "dst_ip": "192.168.1.10"}))
        self.assertFalse(is_unspecified_traffic({"src_ip": "192.168.1.10", "dst_ip": "0.0.0.0"}))


if __name__ == "__main__":
    unittest.main()

from event_filter import is_loopback_or_test_traffic


def test_loopback_and_test_traffic_is_filtered():
    assert is_loopback_or_test_traffic({"src_ip": "127.0.0.1", "dst_ip": "10.0.0.2"})
    assert is_loopback_or_test_traffic({"src_ip": "::1", "dst_ip": "10.0.0.2"})
    assert is_loopback_or_test_traffic("IEC104 TESTFR activation")
    assert not is_loopback_or_test_traffic({"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"})

import sys
import unittest
from pathlib import Path

STREAMLIT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(STREAMLIT_DIR))

from event_visibility import contains_ipv6, is_legacy_test_alert, is_visible_event


class EventVisibilityTests(unittest.TestCase):
    def test_legacy_test_history_is_hidden(self):
        event = {
            "raw_log": "06/02-20:44:50 [**] [1:1000005:1] [TEST] Ping Detectado en WiFi [**]",
            "src_ip": "192.168.6.192",
            "dst_ip": "192.168.6.243",
        }
        self.assertTrue(is_legacy_test_alert(event))
        self.assertFalse(is_visible_event(event))

    def test_new_sis_icmp_alert_is_visible(self):
        event = {
            "raw_log": "[**] [1:1100802:1] SIS ICMP detectado [**] {ICMP} 192.168.6.192 -> 192.168.6.243",
            "src_ip": "192.168.6.192",
            "dst_ip": "192.168.6.243",
        }
        self.assertFalse(is_legacy_test_alert(event))
        self.assertTrue(is_visible_event(event))

    def test_ipv6_history_is_hidden(self):
        self.assertTrue(contains_ipv6({"raw_log": "{IPV6-ICMP} fe80::1 -> ff02::1"}))
        self.assertFalse(is_visible_event({"raw_log": "{IPV6-ICMP} fe80::1 -> ff02::1"}))


if __name__ == "__main__":
    unittest.main()

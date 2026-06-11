import sys
import unittest
from pathlib import Path

STREAMLIT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(STREAMLIT_DIR))

from event_visibility import contains_ipv6, is_legacy_icmp_flood, is_legacy_test_alert, is_legacy_unconfirmed_flood, is_unspecified_traffic, is_visible_event


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

    def test_unspecified_endpoint_pair_is_hidden_everywhere(self):
        event = {
            "raw_log": '{"peer":"zeek","metric_type":"counter"}',
            "src_ip": "0.0.0.0",
            "dst_ip": "0.0.0.0",
        }
        self.assertTrue(is_unspecified_traffic(event))
        self.assertFalse(is_visible_event(event))

    def test_real_ipv4_flow_remains_visible(self):
        event = {"src_ip": "192.168.6.192", "dst_ip": "192.168.6.243"}
        self.assertFalse(is_unspecified_traffic(event))
        self.assertTrue(is_visible_event(event))

    def test_legacy_global_flood_false_positive_is_hidden(self):
        event = {"mitre_msg": "CRÍTICO: Inundación de Red (DoS)", "src_ip": "192.168.1.1", "dst_ip": "192.168.1.2"}
        self.assertTrue(is_legacy_unconfirmed_flood(event))
        self.assertFalse(is_visible_event(event))

    def test_legacy_confirmed_icmp_false_positive_is_hidden(self):
        event = {
            "mitre_msg": "CRÍTICO: Inundación de Red (DoS) confirmada",
            "dos_confirmed": True,
            "protocol": "icmp",
        }
        self.assertTrue(is_legacy_icmp_flood(event))
        self.assertFalse(is_visible_event(event))

    def test_legacy_icmp_message_is_hidden_even_with_old_protocol_value(self):
        event = {
            "dos_confirmed": True,
            "protocol": "ids_alert",
            "message": "SIS ICMP detectado {ICMP}",
        }
        self.assertTrue(is_legacy_icmp_flood(event))
        self.assertFalse(is_visible_event(event))

    def test_new_confirmed_flood_remains_visible(self):
        event = {
            "mitre_msg": "CRÍTICO: Inundación de Red (DoS) confirmada",
            "dos_confirmed": True,
            "protocol": "icmp",
            "detection_model_version": 2,
        }
        self.assertFalse(is_legacy_unconfirmed_flood(event))
        self.assertFalse(is_legacy_icmp_flood(event))
        self.assertTrue(is_visible_event(event))

    def test_ipv6_history_is_hidden(self):
        self.assertTrue(contains_ipv6({"raw_log": "{IPV6-ICMP} fe80::1 -> ff02::1"}))
        self.assertFalse(is_visible_event({"raw_log": "{IPV6-ICMP} fe80::1 -> ff02::1"}))


if __name__ == "__main__":
    unittest.main()

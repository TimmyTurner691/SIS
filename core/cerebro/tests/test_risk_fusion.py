import sys
import unittest
from pathlib import Path

CEREBRO_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CEREBRO_DIR))

from main import RiskFusionEngine


class RiskFusionTests(unittest.TestCase):
    def setUp(self):
        self.engine = RiskFusionEngine()
        self.engine.inventory = {"192.168.1.82": "CRITICAL"}
        self.icmp = {
            "source": "snort",
            "protocol": "ids_alert",
            "src_ip": "192.168.1.88",
            "dst_ip": "192.168.1.82",
            "message": "SIS ICMP detectado {ICMP}",
            "raw_log": "SIS ICMP detectado {ICMP}",
            "comando_humano": "Alerta IDS",
        }

    def test_normal_icmp_on_critical_asset_stays_low(self):
        result = self.engine.evaluar_riesgo(dict(self.icmp), 0.5, False)
        self.assertEqual("BAJO", result["risk_label"])
        self.assertEqual(5, result["risk_total_score"])
        self.assertFalse(result["dos_confirmed"])
        self.assertEqual("Monitorización normal", result["mitre_msg"])

    def test_ml_anomaly_alone_cannot_make_normal_icmp_critical(self):
        result = self.engine.evaluar_riesgo(dict(self.icmp), -0.5, False)
        self.assertEqual("MEDIO", result["risk_label"])
        self.assertEqual(10, result["risk_total_score"])
        self.assertFalse(result["dos_confirmed"])

    def test_confirmed_flood_is_critical(self):
        result = self.engine.evaluar_riesgo(
            dict(self.icmp),
            -1.0,
            True,
            detection_reason="concentrated_flow",
            traffic_metrics={"accepted_eps": 40, "max_flow_eps": 30},
        )
        self.assertEqual("CRÍTICO", result["risk_label"])
        self.assertEqual(25, result["risk_total_score"])
        self.assertTrue(result["dos_confirmed"])
        self.assertEqual("concentrated_flow", result["detection_reason"])


if __name__ == "__main__":
    unittest.main()

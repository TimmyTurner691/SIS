import sys
import unittest
from pathlib import Path
from unittest.mock import Mock

CEREBRO_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CEREBRO_DIR))

from main import INDEX_NAME, purge_trash_events


class TrashEventCleanupTests(unittest.TestCase):
    def test_cleanup_targets_legacy_alerts_and_unspecified_flows(self):
        es = Mock()
        es.delete_by_query.return_value = {"deleted": 12}

        deleted = purge_trash_events(es)

        self.assertEqual(12, deleted)
        kwargs = es.delete_by_query.call_args.kwargs
        self.assertEqual(INDEX_NAME, kwargs["index"])
        serialized_query = str(kwargs["body"])
        self.assertIn("1000005", serialized_query)
        self.assertIn("Ping Detectado en WiFi", serialized_query)
        self.assertIn("src_ip", serialized_query)
        self.assertIn("dst_ip", serialized_query)
        self.assertIn("0.0.0.0", serialized_query)
        self.assertIn("CRÍTICO: Inundación de Red (DoS)", serialized_query)
        self.assertIn("dos_confirmed", serialized_query)
        self.assertNotIn("1100802", serialized_query)
        self.assertNotIn("SIS ICMP detectado", serialized_query)

    def test_cleanup_failure_does_not_stop_cerebro(self):
        es = Mock()
        es.delete_by_query.side_effect = RuntimeError("índice no disponible")
        self.assertEqual(0, purge_trash_events(es))


if __name__ == "__main__":
    unittest.main()

import json
import tempfile
import unittest
from pathlib import Path

from signature_manager import SignatureError, SignatureManager, validate_rules


class SignatureManagerTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.base = Path(self.tempdir.name)
        (self.base / "snort_rules/packages").mkdir(parents=True)
        (self.base / "control").mkdir()
        self.write_json("catalog.json", {"packages": [
            {"id": "ot", "name": "OT", "rule_file": "ot.rules", "default_installed": True},
            {"id": "web", "name": "Web", "rule_file": "web.rules", "default_installed": True},
        ]})
        self.write_json("profiles.json", {"profiles": [
            {"id": "ot-only", "name": "OT", "enabled_packages": ["ot"]}
        ]})
        self.write_json("state.json", {"version": 1, "packages": {
            "ot": {"installed": True, "enabled": False},
            "web": {"installed": True, "enabled": False},
        }})
        (self.base / "snort_rules/packages/ot.rules").write_text(
            'alert tcp any any -> any 2404 (msg:"OT"; sid:1; rev:1;)\n'
        )
        (self.base / "snort_rules/packages/web.rules").write_text(
            'alert tcp any any -> any 80 (msg:"Web"; sid:2; rev:1;)\n'
        )
        self.manager = SignatureManager(self.base)

    def tearDown(self):
        self.tempdir.cleanup()

    def write_json(self, name, payload):
        (self.base / name).write_text(json.dumps(payload))

    def test_set_packages_generates_only_enabled_rules(self):
        state = self.manager.set_packages(["ot", "web"], ["web"])
        effective = self.manager.effective_path.read_text()
        self.assertNotIn('msg:"OT"', effective)
        self.assertIn('msg:"Web"', effective)
        self.assertEqual(1, state["effective_rule_count"])

    def test_profile_installs_and_enables_its_packages(self):
        state = self.manager.apply_profile("ot-only")
        self.assertTrue(state["packages"]["ot"]["enabled"])
        self.assertFalse(state["packages"]["web"]["enabled"])
        self.assertEqual("ot-only", state["profile"])

    def test_enabled_package_must_be_installed(self):
        with self.assertRaises(SignatureError):
            self.manager.set_packages([], ["ot"])

    def test_duplicate_sid_is_rejected(self):
        with self.assertRaisesRegex(SignatureError, "SID duplicado"):
            validate_rules(
                'alert tcp any any -> any 1 (msg:"A"; sid:7;)\n'
                'alert tcp any any -> any 2 (msg:"B"; sid:7;)\n'
            )

    def test_legacy_test_sid_is_rejected(self):
        with self.assertRaisesRegex(SignatureError, "SID heredado no permitido"):
            validate_rules(
                'alert icmp any any -> any any (msg:"[TEST] Ping Detectado en WiFi"; sid:1000005;)\n'
            )


if __name__ == "__main__":
    unittest.main()

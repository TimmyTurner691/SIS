import unittest
from pathlib import Path

from signature_manager import SignatureManager


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


class SignatureCatalogTests(unittest.TestCase):
    def setUp(self):
        self.manager = SignatureManager(REPOSITORY_ROOT / "reglas_firmas")

    def test_every_catalog_package_has_valid_rules_and_unique_global_sids(self):
        rows = self.manager.package_rows()
        self.assertEqual(
            {"iec104", "modbus", "iec61850", "windows", "linux", "web", "dns", "smb", "otros"},
            {row["id"] for row in rows},
        )
        state = self.manager.load_state()
        for package_state in state["packages"].values():
            package_state.update(installed=True, enabled=True)
        _, enabled_names, sids = self.manager.build_effective_rules(state)
        self.assertEqual(len(rows), len(enabled_names))
        self.assertEqual(len(sids), len(set(sids)))
        self.assertTrue(all(row["rule_count"] > 0 for row in rows))

    def test_profiles_only_reference_catalog_packages(self):
        package_ids = {package["id"] for package in self.manager.catalog()}
        self.assertEqual(4, len(self.manager.profiles()))
        for profile in self.manager.profiles():
            self.assertTrue(set(profile["enabled_packages"]) <= package_ids)


if __name__ == "__main__":
    unittest.main()

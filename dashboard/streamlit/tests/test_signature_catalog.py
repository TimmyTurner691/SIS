import unittest
from pathlib import Path

from signature_manager import SignatureManager, validate_rules


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

    def test_dns_package_uses_its_reserved_sid_block(self):
        dns_path = REPOSITORY_ROOT / "reglas_firmas/snort_rules/packages/dns.rules"
        dns_text = dns_path.read_text(encoding="utf-8")
        sids = validate_rules(dns_text)

        self.assertEqual(55, len(sids))
        self.assertEqual(list(range(1100601, 1100656)), sids)
        self.assertNotIn("sid:1206", dns_text)
        self.assertIn('msg:"SIS DNS possible repeated hex label tunnel"', dns_text)
        self.assertIn('msg:"SIS DNS HTTPS/SVCB query observed"', dns_text)

    def test_each_package_stays_inside_its_reserved_sid_block(self):
        expected_blocks = {
            "iec104": 1100000,
            "modbus": 1100100,
            "iec61850": 1100200,
            "windows": 1100300,
            "linux": 1100400,
            "web": 1100500,
            "dns": 1100600,
            "smb": 1100700,
            "otros": 1100800,
        }
        for package in self.manager.catalog():
            rule_path = self.manager.packages_dir / package["rule_file"]
            sids = validate_rules(rule_path.read_text(encoding="utf-8"))
            lower = expected_blocks[package["id"]] + 1
            upper = expected_blocks[package["id"]] + 99
            self.assertTrue(
                all(lower <= sid <= upper for sid in sids),
                f"{package['id']} contiene un SID fuera de {lower}-{upper}",
            )

    def test_profiles_only_reference_catalog_packages(self):
        package_ids = {package["id"] for package in self.manager.catalog()}
        self.assertEqual(4, len(self.manager.profiles()))
        for profile in self.manager.profiles():
            self.assertTrue(set(profile["enabled_packages"]) <= package_ids)


if __name__ == "__main__":
    unittest.main()

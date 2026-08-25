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

    def test_iec104_package_uses_reserved_starter_and_expansion_blocks(self):
        iec_path = REPOSITORY_ROOT / "reglas_firmas/snort_rules/packages/iec104.rules"
        iec_text = iec_path.read_text(encoding="utf-8")
        sids = validate_rules(iec_text)

        self.assertEqual(108, len(sids))
        self.assertEqual([1100001, 1100002], sids[:2])
        self.assertEqual(list(range(1110001, 1110107)), sids[2:])
        self.assertNotIn("sid:1200", iec_text)
        self.assertIn('msg:"SIS IEC104 U-frame STARTDT activation"', iec_text)
        self.assertIn('msg:"SIS IEC104 typeid 105 C_RP_NA_1 reset process command"', iec_text)
        self.assertIn('msg:"SIS IEC104 reserved or unusual typeid 80"', iec_text)

    def test_modbus_package_uses_reserved_starter_and_expansion_blocks(self):
        modbus_path = REPOSITORY_ROOT / "reglas_firmas/snort_rules/packages/modbus.rules"
        modbus_text = modbus_path.read_text(encoding="utf-8")
        sids = validate_rules(modbus_text)

        self.assertEqual(114, len(sids))
        self.assertEqual([1100101, 1100102], sids[:2])
        self.assertEqual(list(range(1111001, 1111113)), sids[2:])
        self.assertNotIn("sid:1201", modbus_text)
        self.assertIn('msg:"SIS MODBUS high request rate possible polling abuse"', modbus_text)
        self.assertIn('msg:"SIS MODBUS function 16 write multiple registers"', modbus_text)
        self.assertIn(
            'msg:"SIS MODBUS exception response for function 43 encapsulated interface transport"',
            modbus_text,
        )
        self.assertIn('msg:"SIS MODBUS reserved or unusual function code 80"', modbus_text)
        self.assertIn('msg:"SIS MODBUS unusual unit id 255"', modbus_text)

    def test_iec61850_package_uses_its_reserved_sid_block(self):
        iec_path = REPOSITORY_ROOT / "reglas_firmas/snort_rules/packages/iec61850.rules"
        iec_text = iec_path.read_text(encoding="utf-8")
        sids = validate_rules(iec_text)

        self.assertEqual(42, len(sids))
        self.assertEqual(list(range(1100201, 1100243)), sids)
        self.assertNotIn("sid:1202", iec_text)
        self.assertIn('msg:"SIS IEC61850 ACSE association request AARQ"', iec_text)
        self.assertIn('msg:"SIS IEC61850 MMS write string"', iec_text)
        self.assertIn('msg:"SIS IEC61850 IEC61850 logical node XCBR"', iec_text)
        self.assertIn('msg:"SIS IEC61850 unusually large MMS payload over 4096 bytes"', iec_text)

    def test_linux_package_uses_its_reserved_sid_block(self):
        linux_path = REPOSITORY_ROOT / "reglas_firmas/snort_rules/packages/linux.rules"
        linux_text = linux_path.read_text(encoding="utf-8")
        sids = validate_rules(linux_text)

        self.assertEqual(86, len(sids))
        self.assertEqual(list(range(1100401, 1100487)), sids)
        self.assertNotIn("sid:1204", linux_text)
        self.assertIn('msg:"SIS LINUX interactive bash reverse shell"', linux_text)
        self.assertIn('msg:"SIS LINUX systemd service write"', linux_text)
        self.assertIn('msg:"SIS LINUX docker privileged run"', linux_text)
        self.assertIn('msg:"SIS LINUX cloud metadata linux curl"', linux_text)
        self.assertIn('msg:"SIS LINUX wget pipe sh"', linux_text)
        self.assertIn('content:"|7C| sh"', linux_text)
        self.assertNotIn('content:"\\| sh"', linux_text)

    def test_windows_package_uses_its_reserved_sid_block(self):
        windows_path = REPOSITORY_ROOT / "reglas_firmas/snort_rules/packages/windows.rules"
        windows_text = windows_path.read_text(encoding="utf-8")
        sids = validate_rules(windows_text)

        self.assertEqual(85, len(sids))
        self.assertEqual(list(range(1100301, 1100386)), sids)
        self.assertNotIn("sid:1203", windows_text)
        self.assertIn('msg:"SIS WINDOWS possible RDP brute force scan"', windows_text)
        self.assertIn('msg:"SIS WINDOWS powershell encoded command"', windows_text)
        self.assertIn('msg:"SIS WINDOWS mimikatz sekurlsa logonpasswords"', windows_text)
        self.assertIn('msg:"SIS WINDOWS vssadmin delete shadows"', windows_text)
        self.assertIn('content:"net group |22|Domain Admins|22|"', windows_text)
        self.assertIn('content:"|5C|msagent_"', windows_text)

    def test_otros_package_uses_its_reserved_sid_block(self):
        otros_path = REPOSITORY_ROOT / "reglas_firmas/snort_rules/packages/otros.rules"
        otros_text = otros_path.read_text(encoding="utf-8")
        sids = validate_rules(otros_text)

        self.assertEqual(70, len(sids))
        self.assertEqual(list(range(1100801, 1100871)), sids)
        self.assertNotIn("sid:1208", otros_text)
        self.assertIn('msg:"SIS OTROS ICMP echo high rate possible ping flood"', otros_text)
        self.assertIn('msg:"SIS OTROS Cobalt Strike marker"', otros_text)
        self.assertIn('msg:"SIS OTROS Docker API create container"', otros_text)
        self.assertIn('msg:"SIS OTROS SSDP M-SEARCH amplification"', otros_text)
        self.assertIn('msg:"SIS OTROS DHCP discover flood marker"', otros_text)
        self.assertIn('content:"X5O!P%@AP[4|5C|PZX54(P^)7CC)7}$EICAR"', otros_text)

    def test_smb_package_uses_its_reserved_sid_block(self):
        smb_path = REPOSITORY_ROOT / "reglas_firmas/snort_rules/packages/smb.rules"
        smb_text = smb_path.read_text(encoding="utf-8")
        sids = validate_rules(smb_text)

        self.assertEqual(56, len(sids))
        self.assertEqual(list(range(1100701, 1100757)), sids)
        self.assertNotIn("sid:1207", smb_text)
        self.assertIn('msg:"SIS SMB possible brute force/session storm"', smb_text)
        self.assertIn('msg:"SIS SMB psexec service marker"', smb_text)
        self.assertIn('msg:"SIS SMB samr named pipe access"', smb_text)
        self.assertIn('msg:"SIS SMB ntds dit access string"', smb_text)
        self.assertIn('msg:"SIS SMB eternalblue ms17-010 keyword"', smb_text)
        self.assertIn('content:"|5C|samr"', smb_text)

    def test_each_package_stays_inside_its_reserved_sid_ranges(self):
        expected_ranges = {
            "iec104": [(1100001, 1100099), (1110001, 1110199)],
            "modbus": [(1100101, 1100199), (1111001, 1111199)],
            "iec61850": [(1100201, 1100299)],
            "windows": [(1100301, 1100399)],
            "linux": [(1100401, 1100499)],
            "web": [(1100501, 1100599)],
            "dns": [(1100601, 1100699)],
            "smb": [(1100701, 1100799)],
            "otros": [(1100801, 1100899)],
        }
        for package in self.manager.catalog():
            rule_path = self.manager.packages_dir / package["rule_file"]
            sids = validate_rules(rule_path.read_text(encoding="utf-8"))
            ranges = expected_ranges[package["id"]]
            self.assertTrue(
                all(any(lower <= sid <= upper for lower, upper in ranges) for sid in sids),
                f"{package['id']} contiene un SID fuera de sus rangos reservados {ranges}",
            )

    def test_profiles_only_reference_catalog_packages(self):
        package_ids = {package["id"] for package in self.manager.catalog()}
        self.assertEqual(4, len(self.manager.profiles()))
        for profile in self.manager.profiles():
            self.assertTrue(set(profile["enabled_packages"]) <= package_ids)


if __name__ == "__main__":
    unittest.main()

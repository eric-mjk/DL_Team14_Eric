import unittest

from src.normalizer import authority_identity, sp_identity


class SpIdentityTest(unittest.TestCase):
    def test_symbolic_names(self):
        self.assertEqual(sp_identity("LockingSP"), ("LockingSP", "0000020500000002"))
        self.assertEqual(sp_identity("adminsp"), ("AdminSP", "0000020500000001"))
        self.assertEqual(sp_identity("Admin SP"), ("AdminSP", "0000020500000001"))

    def test_uid_formats(self):
        self.assertEqual(sp_identity("0000020500000002"), ("LockingSP", "0000020500000002"))
        self.assertEqual(sp_identity("00 00 02 05 00 00 00 01"), ("AdminSP", "0000020500000001"))
        self.assertEqual(sp_identity("0x0000020500000001"), ("AdminSP", "0000020500000001"))

    def test_none(self):
        self.assertEqual(sp_identity(None), (None, None))


class AuthorityIdentityTest(unittest.TestCase):
    def test_symbolic_names(self):
        self.assertEqual(authority_identity("Admin1"), ("Admin1", None))
        self.assertEqual(authority_identity("user 2"), ("User2", None))
        self.assertEqual(authority_identity("SID"), ("SID", None))
        self.assertEqual(authority_identity("anybody"), ("Anybody", None))
        self.assertEqual(authority_identity("PSID"), ("PSID", None))

    def test_uid_formats(self):
        self.assertEqual(
            authority_identity("00 00 00 09 00 01 00 01"), ("Admin1", "0000000900010001")
        )
        self.assertEqual(
            authority_identity("0x0000000900010001"), ("Admin1", "0000000900010001")
        )

    def test_unknown_text_falls_back(self):
        name, uid = authority_identity("WeirdAuthority")
        self.assertIsNotNone(name)


if __name__ == "__main__":
    unittest.main()

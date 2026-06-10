import unittest

from src.normalizer import (
    canonical_credential,
    credential_is_empty,
    credentials_equal,
)


PIN_TEXT = "New_SID_Password"
PIN_HEX = "4E65775F5349445F50617373776F7264"  # utf-8 bytes of PIN_TEXT
PIN_HEX_MEDIUM_ATOM = "D010" + PIN_HEX  # medium bytes atom, length 0x10


class CanonicalCredentialTest(unittest.TestCase):
    def test_hex_case_and_prefix(self):
        self.assertEqual(canonical_credential("0x" + PIN_HEX.lower()), PIN_HEX)
        self.assertEqual(canonical_credential(PIN_HEX.lower()), PIN_HEX)

    def test_spaced_hex(self):
        spaced = " ".join(PIN_HEX[i : i + 2] for i in range(0, len(PIN_HEX), 2))
        self.assertEqual(canonical_credential(spaced), PIN_HEX)

    def test_bytes_and_int_list(self):
        raw = bytes.fromhex(PIN_HEX)
        self.assertEqual(canonical_credential(raw), PIN_HEX)
        self.assertEqual(canonical_credential(list(raw)), PIN_HEX)

    def test_plain_text_kept(self):
        self.assertEqual(canonical_credential("SIDVAL"), "SIDVAL")


class CredentialsEqualTest(unittest.TestCase):
    def test_exact(self):
        self.assertTrue(credentials_equal("SIDVAL", "SIDVAL"))

    def test_hex_variants(self):
        self.assertTrue(credentials_equal("0x" + PIN_HEX.lower(), PIN_HEX))
        self.assertTrue(
            credentials_equal(
                " ".join(PIN_HEX[i : i + 2] for i in range(0, len(PIN_HEX), 2)),
                PIN_HEX.lower(),
            )
        )

    def test_text_vs_hex_of_text(self):
        self.assertTrue(credentials_equal(PIN_TEXT, PIN_HEX))
        self.assertTrue(credentials_equal(PIN_HEX, PIN_TEXT))

    def test_atom_wrapped_vs_raw(self):
        self.assertTrue(credentials_equal(PIN_HEX_MEDIUM_ATOM, PIN_HEX))
        # short bytes atom: 0xA0 | len for a 4-byte payload
        self.assertTrue(credentials_equal("A4" + "DEADBEEF", "DEADBEEF"))

    def test_atom_header_with_wrong_length_not_stripped(self):
        self.assertFalse(credentials_equal("D011" + PIN_HEX, PIN_HEX))

    def test_distinct_values_not_equal(self):
        self.assertFalse(credentials_equal("SIDVAL", "OTHERVAL"))
        self.assertFalse(credentials_equal(PIN_HEX, PIN_HEX[:-2] + "00"))
        self.assertFalse(credentials_equal(None, PIN_HEX))

    def test_bytes_vs_hex_string(self):
        self.assertTrue(credentials_equal(bytes.fromhex(PIN_HEX), PIN_HEX.lower()))


class CredentialIsEmptyTest(unittest.TestCase):
    def test_empty_forms(self):
        self.assertTrue(credential_is_empty(None))
        self.assertTrue(credential_is_empty(""))
        self.assertTrue(credential_is_empty(b""))
        self.assertTrue(credential_is_empty([]))
        self.assertFalse(credential_is_empty("00"))


if __name__ == "__main__":
    unittest.main()

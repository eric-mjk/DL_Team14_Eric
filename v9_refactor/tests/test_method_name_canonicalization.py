import unittest

from src.normalizer import canonical_method_name, normalize_record


class CanonicalMethodNameTest(unittest.TestCase):
    def test_case_variants(self):
        for variant in ("StartSession", "STARTSESSION", "startsession", "Start Session", "start_session"):
            self.assertEqual(canonical_method_name(variant), "StartSession")

    def test_all_known_method_spellings(self):
        self.assertEqual(canonical_method_name("REVERTSP"), "RevertSP")
        self.assertEqual(canonical_method_name("genkey"), "GenKey")
        self.assertEqual(canonical_method_name("get_acl"), "GetACL")
        self.assertEqual(canonical_method_name("hmac"), "HMAC")

    def test_unknown_names_kept(self):
        self.assertEqual(canonical_method_name("VendorThing"), "VendorThing")
        self.assertIsNone(canonical_method_name(None))
        self.assertIsNone(canonical_method_name("  "))

    def test_normalize_record_dispatchable_method(self):
        record = {
            "input": {
                "method": {
                    "name": "GEN_KEY",
                    "uid": None,
                    "args": {"required": {}, "optional": {}},
                },
                "invoking_id": {"uid": "00 00 08 06 00 03 00 01", "name": "K_AES_256"},
            },
            "output": {"return_values": [], "status_codes": "SUCCESS"},
        }
        event = normalize_record(record)
        self.assertEqual(event["method"], "GenKey")
        self.assertFalse(event["method_inferred"])


if __name__ == "__main__":
    unittest.main()

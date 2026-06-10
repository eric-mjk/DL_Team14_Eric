import unittest

from src.normalizer import normalize_record


def _start_session(required):
    return {
        "index": 1,
        "input": {
            "method": {
                "name": "StartSession",
                "uid": "00 00 00 06 00 00 02 02",
                "args": {"required": required, "optional": {}},
            },
            "invoking_id": {"uid": "00 00 00 00 00 00 00 FF", "name": "SMUID"},
        },
        "output": {
            "return_values": {"HostSessionID": "00000001", "SPSessionID": "00001234"},
            "status_codes": "SUCCESS",
        },
    }


class PositionalRequiredArgsTest(unittest.TestCase):
    def test_named_required_args_unchanged(self):
        event = normalize_record(
            _start_session(
                {"HostSessionID": 1, "SPID": "0000020500000001", "Write": 1}
            )
        )
        self.assertEqual(event["sp"], "AdminSP")
        self.assertTrue(event["write"])

    def test_positional_required_list_mapped_by_signature(self):
        event = normalize_record(
            _start_session([1, "0000020500000001", 1])
        )
        self.assertEqual(event["method"], "StartSession")
        self.assertEqual(event["sp"], "AdminSP")
        self.assertTrue(event["write"])
        self.assertEqual(event["required_parameters"].get("HostSessionID"), 1)

    def test_positional_list_with_named_dict_items(self):
        event = normalize_record(
            _start_session([1, "0000020500000001", {"Write": 1}])
        )
        self.assertEqual(event["sp"], "AdminSP")
        self.assertTrue(event["write"])

    def test_unknown_method_positional_list_not_guessed(self):
        record = _start_session([1, "0000020500000001", 1])
        record["input"]["method"]["name"] = "VendorThing"
        record["input"]["method"]["uid"] = None
        event = normalize_record(record)
        self.assertEqual(event["required_parameters"], {})


if __name__ == "__main__":
    unittest.main()

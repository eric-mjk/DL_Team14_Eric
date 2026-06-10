import unittest

from src.normalizer import normalize_record
from src.oracle import judge_final
from src.state import apply_event, initial_state


def _get(invoking_uid, invoking_name, cellblock, status="SUCCESS", return_values=None):
    return normalize_record(
        {
            "index": 5,
            "input": {
                "method": {
                    "name": "Get",
                    "args": {"required": {"Cellblock": cellblock}, "optional": {}},
                },
                "invoking_id": {"uid": invoking_uid, "name": invoking_name},
            },
            "output": {"return_values": return_values or [], "status_codes": status},
        }
    )


def _open_locking_session(state):
    state["locking_sp_active"] = True
    state["sp_lifecycle"]["LockingSP"] = "Manufactured"
    session = state["session"]
    session["open"] = True
    session["sp"] = "LockingSP"
    session["write"] = True
    session["authority"] = "Admin1"
    session["authorities"].add("Admin1")
    return state


def _learn_mbr_size(state, size_bytes):
    event = normalize_record(
        {
            "index": 1,
            "input": {
                "method": {
                    "name": "Get",
                    "args": {
                        "required": {"Cellblock": {"startColumn": 7, "endColumn": 7}},
                        "optional": {},
                    },
                },
                "invoking_id": {"uid": "00 00 00 01 00 00 08 04", "name": "Table"},
            },
            "output": {"return_values": [{"7": size_bytes}], "status_codes": "SUCCESS"},
        }
    )
    apply_event(state, event)


class CellblockRowRulesTest(unittest.TestCase):
    def test_byte_table_row_read_in_bounds_not_flagged(self):
        state = _open_locking_session(initial_state())
        _learn_mbr_size(state, 1048576)
        event = _get(
            "00 00 08 04 00 00 00 00",
            "MBR",
            {"startRow": 0, "endRow": 511},
            return_values=[{"Bytes": "00"}],
        )
        result = judge_final(state, event)
        self.assertEqual(result.verdict, "pass")

    def test_byte_table_row_read_out_of_bounds_must_fail(self):
        state = _open_locking_session(initial_state())
        _learn_mbr_size(state, 1024)
        event = _get(
            "00 00 08 04 00 00 00 00",
            "MBR",
            {"startRow": 0, "endRow": 4096},
            return_values=[{"Bytes": "00"}],
        )
        result = judge_final(state, event)
        # device returned SUCCESS for an out-of-bounds read -> verdict fail
        self.assertEqual(result.verdict, "fail")
        self.assertIn("out of bounds", result.reason)

    def test_byte_table_column_cellblock_must_fail(self):
        state = _open_locking_session(initial_state())
        event = _get(
            "00 00 08 04 00 00 00 00",
            "MBR",
            {"startColumn": 3, "endColumn": 3},
            return_values=[{"Bytes": "00"}],
        )
        result = judge_final(state, event)
        self.assertEqual(result.verdict, "fail")
        self.assertIn("column values", result.reason)

    def test_object_get_with_row_values_must_fail(self):
        state = _open_locking_session(initial_state())
        event = _get(
            "00 00 08 02 00 00 00 01",
            "Locking_Global",
            {"startRow": 0, "endRow": 1},
            return_values=[[{"3": 0}]],
        )
        result = judge_final(state, event)
        self.assertEqual(result.verdict, "fail")
        self.assertIn("row values", result.reason)


if __name__ == "__main__":
    unittest.main()

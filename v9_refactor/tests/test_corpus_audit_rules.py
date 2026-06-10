import unittest

from src.normalizer import normalize_record
from src.oracle import judge_final
from src.state import apply_event, canonical_life_cycle_state, initial_state


def _open_admin_session(state):
    session = state["session"]
    session["open"] = True
    session["sp"] = "AdminSP"
    session["write"] = True
    session["authority"] = "SID"
    session["authorities"].add("SID")
    return state


def _set(invoking_uid, invoking_name, values, status="SUCCESS"):
    return normalize_record(
        {
            "index": 5,
            "input": {
                "method": {
                    "name": "Set",
                    "args": {"required": {}, "optional": {"Values": [values]}},
                },
                "invoking_id": {"uid": invoking_uid, "name": invoking_name},
            },
            "output": {"return_values": [], "status_codes": status},
        }
    )


class LifeCycleStateMappingTest(unittest.TestCase):
    def test_numeric_enum_values(self):
        self.assertEqual(canonical_life_cycle_state(8), "Manufactured-Inactive")
        self.assertEqual(canonical_life_cycle_state(9), "Manufactured")
        self.assertEqual(canonical_life_cycle_state("9"), "Manufactured")
        self.assertEqual(canonical_life_cycle_state(13), "Failed")

    def test_text_state_names(self):
        self.assertEqual(canonical_life_cycle_state("Manufactured-Inactive"), "Manufactured-Inactive")
        self.assertEqual(canonical_life_cycle_state("manufactured inactive"), "Manufactured-Inactive")
        self.assertEqual(canonical_life_cycle_state("ISSUED-DISABLED"), "Issued-Disabled")

    def test_ambiguous_values_not_mapped(self):
        self.assertIsNone(canonical_life_cycle_state(True))
        self.assertIsNone(canonical_life_cycle_state(0))
        self.assertIsNone(canonical_life_cycle_state(1))
        self.assertIsNone(canonical_life_cycle_state("enabled"))

    def test_numeric_lifecycle_get_updates_state(self):
        state = _open_admin_session(initial_state())
        event = normalize_record(
            {
                "index": 3,
                "input": {
                    "method": {
                        "name": "Get",
                        "args": {
                            "required": {"Cellblock": {"startColumn": 6, "endColumn": 6}},
                            "optional": {},
                        },
                    },
                    "invoking_id": {"uid": "00 00 02 05 00 00 00 02", "name": "SP_Locking"},
                },
                "output": {"return_values": [[{"6": 9}]], "status_codes": "SUCCESS"},
            }
        )
        apply_event(state, event)
        self.assertEqual(state["sp_lifecycle"]["LockingSP"], "Manufactured")
        self.assertTrue(state["locking_sp_active"])


class AdminSpProtectionTest(unittest.TestCase):
    def test_disabling_admin_sp_must_fail(self):
        state = _open_admin_session(initial_state())
        event = _set("00 00 00 02 00 00 00 01", "SPInfo", {"6": False})
        result = judge_final(state, event)
        self.assertEqual(result.verdict, "fail")
        self.assertIn("cannot be disabled", result.reason)

    def test_disabling_admin_sp_rejected_passes(self):
        state = _open_admin_session(initial_state())
        event = _set("00 00 00 02 00 00 00 01", "SPInfo", {"6": False}, status="NOT_AUTHORIZED")
        result = judge_final(state, event)
        self.assertEqual(result.verdict, "pass")

    def test_freezing_admin_sp_must_fail(self):
        state = _open_admin_session(initial_state())
        event = _set("00 00 02 05 00 00 00 01", "SP", {"7": True})
        result = judge_final(state, event)
        self.assertEqual(result.verdict, "fail")
        self.assertIn("cannot be frozen", result.reason)


class SpFrozenWritableTest(unittest.TestCase):
    def test_frozen_column_not_read_only_for_non_admin_sp(self):
        from src.spec_docs import read_only_columns_for_family

        read_only = read_only_columns_for_family("SP")
        self.assertNotIn(7, read_only)
        self.assertIn(6, read_only)


if __name__ == "__main__":
    unittest.main()

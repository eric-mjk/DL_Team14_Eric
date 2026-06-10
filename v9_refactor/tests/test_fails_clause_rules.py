import unittest

from src.normalizer import normalize_record
from src.oracle import judge_final
from src.state import apply_event, initial_state


USER1_UID = "00 00 00 09 00 03 00 01"
SM_UID = "00 00 00 00 00 00 00 FF"


def _open_locking_session(state, authority=None):
    state["locking_sp_active"] = True
    state["sp_lifecycle"]["LockingSP"] = "Manufactured"
    session = state["session"]
    session["open"] = True
    session["sp"] = "LockingSP"
    session["write"] = True
    if authority:
        session["authority"] = authority
        session["authorities"].add(authority)
    return state


def _authenticate_challenge(index, return_challenge, status="SUCCESS"):
    return normalize_record(
        {
            "index": index,
            "input": {
                "method": {
                    "name": "Authenticate",
                    "args": {"required": {"Authority": USER1_UID}, "optional": {}},
                },
                "invoking_id": {"uid": SM_UID, "name": "SMUID"},
            },
            "output": {
                "return_values": [{"Challenge": return_challenge}],
                "status_codes": status,
            },
        }
    )


def _authenticate_proof(index, proof, result, status="SUCCESS"):
    return normalize_record(
        {
            "index": index,
            "input": {
                "method": {
                    "name": "Authenticate",
                    "args": {
                        "required": {"Authority": USER1_UID},
                        "optional": {"Proof": proof},
                    },
                },
                "invoking_id": {"uid": SM_UID, "name": "SMUID"},
            },
            "output": {
                "return_values": [{"Result": result}],
                "status_codes": status,
            },
        }
    )


class ProofReplayTest(unittest.TestCase):
    def _state_with_sign_user(self):
        state = _open_locking_session(initial_state())
        state["authority_rows"]["User1"] = {
            "name": "User1",
            "enabled": True,
            "is_class": False,
            "class": "Users",
            "operation": "Sign",
            "source": "LockingSP",
        }
        return state

    def _replay_states(self, second_challenge, final_result):
        state = self._state_with_sign_user()
        apply_event(state, _authenticate_challenge(1, "AA11"))
        apply_event(state, _authenticate_proof(2, "DEADBEEF", True))
        apply_event(state, _authenticate_challenge(3, second_challenge))
        final = _authenticate_proof(4, "DEADBEEF", final_result)
        return judge_final(state, final)

    def test_replayed_proof_accepted_for_new_challenge_fails(self):
        result = self._replay_states(second_challenge="BB22", final_result=True)
        self.assertEqual(result.verdict, "fail")
        self.assertIn("replayed", result.reason)

    def test_replayed_proof_rejected_passes(self):
        result = self._replay_states(second_challenge="BB22", final_result=False)
        self.assertEqual(result.verdict, "pass")

    def test_same_challenge_reissued_does_not_flag_replay(self):
        result = self._replay_states(second_challenge="AA11", final_result=True)
        self.assertEqual(result.verdict, "pass")

    def test_fresh_proof_for_new_challenge_passes(self):
        state = self._state_with_sign_user()
        apply_event(state, _authenticate_challenge(1, "AA11"))
        apply_event(state, _authenticate_proof(2, "DEADBEEF", True))
        apply_event(state, _authenticate_challenge(3, "BB22"))
        final = _authenticate_proof(4, "CAFEBABE", True)
        result = judge_final(state, final)
        self.assertEqual(result.verdict, "pass")


def _add_ace(index, invoking_uid, ace_uid, status="SUCCESS"):
    return normalize_record(
        {
            "index": index,
            "input": {
                "method": {
                    "name": "AddACE",
                    "args": {
                        "required": {},
                        "optional": {
                            "InvokingID": invoking_uid,
                            "MethodID": "00 00 00 06 00 00 00 16",
                            "ACE": ace_uid,
                        },
                    },
                },
                "invoking_id": {"uid": "00 00 00 07 00 00 00 01", "name": "AccessControl"},
            },
            "output": {"return_values": [], "status_codes": status},
        }
    )


class MetaAclFailsClauseTest(unittest.TestCase):
    def _state_with_dynamic_acl_row(self):
        # AddACE is not in the Opal AdminSP/LockingSP method sets, so this
        # exercises an issued-SP session where meta-ACL methods are available.
        state = initial_state()
        session = state["session"]
        session["open"] = True
        session["sp"] = "SP_0003"
        session["write"] = True
        session["authority"] = "Admin1"
        session["authorities"].add("Admin1")
        state["access_control_rows"].append(
            {
                "uid": None,
                "name": "DynTable_Get_ACL",
                "invoking_uid": "0000090000000001",
                "invoking_name": "DynTable",
                "method": "Get",
                "ace_refs": ["0000000800000001"],
                "add_ace_acl_refs": ["0000000800000001"],
                "remove_ace_acl_refs": ["0000000800000001"],
                "delete_method_acl_refs": ["0000000800000001"],
                "get_acl_acl_refs": ["0000000800000001"],
                "source": "trajectory",
                "sp": "SP_0003",
                "dynamic_table_uid": "0000090000000001",
            }
        )
        return state

    def test_duplicate_add_ace_on_concrete_dynamic_row_fails(self):
        state = self._state_with_dynamic_acl_row()
        event = _add_ace(5, "00 00 09 00 00 00 00 01", "00 00 00 08 00 00 00 01")
        result = judge_final(state, event)
        # device returned SUCCESS for a duplicate AddACE -> non-compliant
        self.assertEqual(result.verdict, "fail")
        self.assertIn("already present", result.reason)

    def test_new_ace_add_on_concrete_dynamic_row_passes(self):
        state = self._state_with_dynamic_acl_row()
        event = _add_ace(5, "00 00 09 00 00 00 00 01", "00 00 00 08 00 00 00 02")
        result = judge_final(state, event)
        self.assertEqual(result.verdict, "pass")

    def test_non_ace_family_ace_parameter_is_invalid(self):
        state = self._state_with_dynamic_acl_row()
        event = _add_ace(5, "00 00 09 00 00 00 00 01", "00 00 00 09 00 00 00 01")
        result = judge_final(state, event)
        self.assertEqual(result.verdict, "fail")


def _set_uid_column(index, status="SUCCESS"):
    return normalize_record(
        {
            "index": index,
            "input": {
                "method": {
                    "name": "Set",
                    "args": {
                        "required": {},
                        "optional": {"Values": [{"0": "0000123400005678"}]},
                    },
                },
                "invoking_id": {"uid": "00 00 11 02 00 00 00 01", "name": "VendorObj"},
            },
            "output": {"return_values": [], "status_codes": status},
        }
    )


class SystemCellWriteTest(unittest.TestCase):
    def test_set_uid_column_on_unknown_family_must_fail(self):
        state = _open_locking_session(initial_state(), authority="Admin1")
        result = judge_final(state, _set_uid_column(5))
        self.assertEqual(result.verdict, "fail")
        self.assertIn("read-only", result.reason)

    def test_set_uid_column_rejection_passes(self):
        state = _open_locking_session(initial_state(), authority="Admin1")
        result = judge_final(state, _set_uid_column(5, status="INVALID_PARAMETER"))
        self.assertEqual(result.verdict, "pass")


def _set_clock_high(index, status="SUCCESS"):
    return normalize_record(
        {
            "index": index,
            "input": {
                "method": {
                    "name": "SetClockHigh",
                    "args": {"required": {}, "optional": {"ExactTime": "20260610"}},
                },
                "invoking_id": {"uid": "00 00 04 01 00 00 00 01", "name": "ClockTime"},
            },
            "output": {"return_values": [], "status_codes": status},
        }
    )


class ClockTrustModeTest(unittest.TestCase):
    def _state(self, trust_mode):
        state = _open_locking_session(initial_state(), authority="Admin1")
        state["session"]["sp"] = "AdminSP"
        if trust_mode is not None:
            state["clock_trust_mode"] = trust_mode
        return state

    def test_set_clock_high_with_high_trustmode_must_fail(self):
        state = self._state("high")
        result = judge_final(state, _set_clock_high(5))
        self.assertEqual(result.verdict, "fail")
        self.assertIn("TrustMode", result.reason)

    def test_set_clock_high_rejected_with_high_trustmode_passes(self):
        state = self._state("high")
        result = judge_final(state, _set_clock_high(5, status="FAIL"))
        self.assertEqual(result.verdict, "pass")

    def test_set_clock_high_with_low_trustmode_unconstrained(self):
        state = self._state("low")
        result = judge_final(state, _set_clock_high(5))
        self.assertEqual(result.verdict, "pass")

    def test_unknown_trustmode_not_judged(self):
        state = self._state(None)
        result = judge_final(state, _set_clock_high(5))
        self.assertEqual(result.verdict, "pass")


if __name__ == "__main__":
    unittest.main()

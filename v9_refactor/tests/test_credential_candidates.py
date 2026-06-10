import unittest

from src.oracle import credential_matches
from src.state import (
    add_credential_candidate,
    apply_event,
    initial_state,
)
from src.normalizer import normalize_record


def _get_msid(msid):
    return normalize_record(
        {
            "index": 2,
            "input": {
                "method": {
                    "name": "Get",
                    "args": {
                        "required": {"Cellblock": {"startColumn": 3, "endColumn": 3}},
                        "optional": {},
                    },
                },
                "invoking_id": {"uid": "00 00 00 0B 00 00 84 02", "name": "C_PIN_MSID"},
            },
            "output": {"return_values": [[{"3": msid}]], "status_codes": "SUCCESS"},
        }
    )


def _start_session_sid(challenge, status="SUCCESS"):
    return normalize_record(
        {
            "index": 4,
            "input": {
                "method": {
                    "name": "StartSession",
                    "args": {
                        "required": {"HostSessionID": 1, "SPID": "0000020500000001", "Write": 1},
                        "optional": {
                            "HostSigningAuthority": "0000000900000006",
                            "HostChallenge": challenge,
                        },
                    },
                },
                "invoking_id": {"uid": "00 00 00 00 00 00 00 FF", "name": "SMUID"},
            },
            "output": {
                "return_values": {"HostSessionID": "00000001", "SPSessionID": "00006572"},
                "status_codes": status,
            },
        }
    )


class InitialSidPinCandidateTest(unittest.TestCase):
    def test_msid_observation_is_candidate_not_assignment(self):
        state = initial_state()
        state["session"].update({"open": True, "sp": "AdminSP", "write": True})
        apply_event(state, _get_msid("MSIDVAL"))
        self.assertIsNone(state["credentials"]["SID"])
        self.assertEqual(state["credential_candidates"].get("SID"), ["MSIDVAL"])

    def test_candidate_match_authenticates(self):
        state = initial_state()
        add_credential_candidate(state, "SID", "MSIDVAL")
        self.assertTrue(credential_matches(state, "SID", "MSIDVAL"))

    def test_candidate_mismatch_is_unknown_not_false(self):
        # Public tc3-tc20: the real initial SID PIN is vendor-unique != MSID,
        # so a non-MSID challenge must stay UNKNOWN (None), not contradicted.
        state = initial_state()
        add_credential_candidate(state, "SID", "MSIDVAL")
        self.assertIsNone(credential_matches(state, "SID", "3P5ADJBHFA4JJN57"))

    def test_successful_session_learns_actual_pin_and_clears_candidates(self):
        state = initial_state()
        add_credential_candidate(state, "SID", "MSIDVAL")
        apply_event(state, _start_session_sid("VENDORPIN"))
        self.assertEqual(state["credentials"]["SID"], "VENDORPIN")
        self.assertNotIn("SID", state.get("credential_candidates", {}))
        # later mismatching challenge is now genuinely contradicted
        self.assertIs(credential_matches(state, "SID", "WRONG"), False)

    def test_discovery_indicator_zero_makes_msid_authoritative(self):
        state = initial_state()
        state["initial_sid_pin_is_msid"] = True
        state["session"].update({"open": True, "sp": "AdminSP", "write": True})
        apply_event(state, _get_msid("MSIDVAL"))
        self.assertEqual(state["credentials"]["SID"], "MSIDVAL")
        self.assertIs(credential_matches(state, "SID", "OTHER"), False)


if __name__ == "__main__":
    unittest.main()

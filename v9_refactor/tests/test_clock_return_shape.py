import unittest

from src.oracle import judge_final
from src.state import initial_state


def _clock_state():
    state = initial_state()
    state["session"].update({
        "open": True,
        "sp": "AdminSP",
        "write": True,
        "authorities": {"SID"},
    })
    state["pending_clock_lag"] = "SetLagHigh"
    return state


def _set_lag_high_event(return_values):
    return _clock_event("SetLagHigh", return_values, {"LagTime": 1})


def _clock_event(method, return_values, parameters):
    return {
        "index": 0,
        "kind": "method",
        "method": method,
        "object": "ClockTime",
        "object_uid": "0000001000000001",
        "object_family": "ClockTime",
        "status": "success",
        "parameters": parameters,
        "raw": {"output": {"return_values": return_values}},
    }


class ClockReturnShapeTest(unittest.TestCase):
    def test_set_lag_high_accepts_missing_low_preserved_for_public_trace_compatibility(self):
        result = judge_final(_clock_state(), _set_lag_high_event({}))

        self.assertEqual(result.verdict, "pass")

    def test_set_lag_high_accepts_boolean_low_preserved_when_present(self):
        result = judge_final(_clock_state(), _set_lag_high_event({"LowPreserved": True}))

        self.assertEqual(result.verdict, "pass")

    def test_set_lag_high_rejects_non_boolean_low_preserved_when_present(self):
        result = judge_final(_clock_state(), _set_lag_high_event({"LowPreserved": "notbool"}))

        self.assertEqual(result.verdict, "fail")
        self.assertEqual(result.expected_status, "success_with_boolean_lowpreserved")
        self.assertEqual(result.policy_source, "return_shape")

    def test_set_lag_high_rejects_non_boolean_numeric_low_preserved_when_present(self):
        result = judge_final(_clock_state(), _set_lag_high_event({"LowPreserved": 2}))

        self.assertEqual(result.verdict, "fail")
        self.assertEqual(result.expected_status, "success_with_boolean_lowpreserved")
        self.assertEqual(result.policy_source, "return_shape")

    def test_set_clock_high_success_requires_empty_return_values(self):
        state = _clock_state()
        state["pending_clock_lag"] = None

        ok = judge_final(state, _clock_event("SetClockHigh", {}, {"ExactTime": 1}))
        bad = judge_final(state, _clock_event("SetClockHigh", {"Result": True}, {"ExactTime": 1}))

        self.assertEqual(ok.verdict, "pass")
        self.assertEqual(bad.verdict, "fail")
        self.assertEqual(bad.policy_source, "return_shape")
        self.assertEqual(bad.expected_status, "success_empty_result")

    def test_set_clock_low_success_requires_empty_return_values(self):
        state = _clock_state()
        state["pending_clock_lag"] = None

        ok = judge_final(state, _clock_event("SetClockLow", {}, {"ExactTime": 1}))
        bad = judge_final(state, _clock_event("SetClockLow", {"Result": True}, {"ExactTime": 1}))

        self.assertEqual(ok.verdict, "pass")
        self.assertEqual(bad.verdict, "fail")
        self.assertEqual(bad.policy_source, "return_shape")
        self.assertEqual(bad.expected_status, "success_empty_result")

    def test_set_lag_low_success_requires_empty_return_values(self):
        state = _clock_state()
        state["pending_clock_lag"] = "SetLagLow"

        ok = judge_final(state, _clock_event("SetLagLow", {}, {"LagTime": 1}))
        bad = judge_final(state, _clock_event("SetLagLow", {"Result": True}, {"LagTime": 1}))

        self.assertEqual(ok.verdict, "pass")
        self.assertEqual(bad.verdict, "fail")
        self.assertEqual(bad.policy_source, "return_shape")
        self.assertEqual(bad.expected_status, "success_empty_result")


if __name__ == "__main__":
    unittest.main()

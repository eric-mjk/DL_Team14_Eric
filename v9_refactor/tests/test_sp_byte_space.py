import unittest

from src.oracle import judge_final
from src.state import apply_event, initial_state


def _open_sp_state(sp="AdminSP"):
    state = initial_state()
    state["session"].update({
        "open": True,
        "sp": sp,
        "write": False,
        "authorities": set(),
    })
    return state


def _spinfo_get_event(size, size_in_use, *, index=0):
    return {
        "index": index,
        "kind": "method",
        "method": "Get",
        "object": "SPInfo",
        "object_uid": "0000000100000001",
        "object_family": "SPInfo",
        "status": "success",
        "parameters": {},
        "return_columns": {3: size, 4: size_in_use},
        "raw": {"output": {"return_values": {}}},
    }


def _spinfo_set_event(size, size_in_use, *, index=0):
    return {
        "index": index,
        "kind": "method",
        "method": "Set",
        "object": "SPInfo",
        "object_uid": "0000000200000001",
        "object_family": "SPInfo",
        "status": "success",
        "parameters": {"Values": {3: size, 4: size_in_use}},
        "value_columns": {3: size, 4: size_in_use},
        "raw": {"output": {"return_values": {}}},
    }


def _spinfo_enabled_set_event(enabled, *, status="success", index=0):
    return {
        "index": index,
        "kind": "method",
        "method": "Set",
        "object": "SPInfo",
        "object_uid": "0000000200000001",
        "object_family": "SPInfo",
        "status": status,
        "parameters": {"Values": {6: enabled}},
        "value_columns": {6: enabled},
        "raw": {"output": {"return_values": {}}},
    }


def _get_free_space_event(free_space, *, index=1):
    return {
        "index": index,
        "kind": "method",
        "method": "GetFreeSpace",
        "object": "AdminSP",
        "object_uid": "0000020500000001",
        "object_family": "SP",
        "status": "success",
        "parameters": {},
        "raw": {"output": {"return_values": {"FreeSpace": free_space}}},
    }


class SPByteSpaceStateMachineTest(unittest.TestCase):
    def test_spinfo_get_learns_concrete_free_byte_bound(self):
        state = _open_sp_state()

        apply_event(state, _spinfo_get_event(1000, 750))

        self.assertEqual(
            state["sp_byte_space"]["AdminSP"],
            {
                "sp": "AdminSP",
                "source": "SPInfo.Get",
                "size": 1000,
                "size_in_use": 750,
                "free": 250,
            },
        )

    def test_get_free_space_passes_when_returned_value_is_within_learned_spinfo_bound(self):
        state = _open_sp_state()
        apply_event(state, _spinfo_get_event(1000, 750))

        result = judge_final(state, _get_free_space_event(250))

        self.assertEqual(result.verdict, "pass")

    def test_get_free_space_rejects_success_above_learned_spinfo_bound(self):
        state = _open_sp_state()
        apply_event(state, _spinfo_get_event(1000, 750))

        result = judge_final(state, _get_free_space_event(300))

        self.assertEqual(result.verdict, "fail")
        self.assertEqual(result.policy_source, "sp_byte_space_state")
        self.assertEqual(result.expected_status, "success_with_bounded_freespace")

    def test_spinfo_partial_or_inverted_counters_do_not_invent_bound(self):
        state = _open_sp_state()

        apply_event(state, _spinfo_get_event(100, 125))

        self.assertNotIn("free", state["sp_byte_space"]["AdminSP"])
        result = judge_final(state, _get_free_space_event(300))
        self.assertEqual(result.verdict, "pass")

    def test_spinfo_inverted_refresh_clears_previous_free_bound(self):
        state = _open_sp_state()
        apply_event(state, _spinfo_get_event(1000, 750))

        apply_event(state, _spinfo_get_event(100, 125, index=1))

        self.assertNotIn("free", state["sp_byte_space"]["AdminSP"])
        result = judge_final(state, _get_free_space_event(300, index=2))
        self.assertEqual(result.verdict, "pass")

    def test_spinfo_set_size_columns_is_rejected_and_not_learned_as_capacity(self):
        state = _open_sp_state()
        state["session"].update({"write": True, "authorities": {"SID"}})
        event = _spinfo_set_event(1000, 750)

        result = judge_final(state, event)

        self.assertEqual(result.verdict, "fail")
        self.assertEqual(result.policy_source, "table_schema")
        apply_event(state, event)
        self.assertNotIn("AdminSP", state["sp_byte_space"])

    def test_spinfo_enabled_set_is_authorized_for_sp_owner_and_updates_lifecycle(self):
        state = _open_sp_state("SP_00AB")
        state["session"].update({"write": True, "authorities": {"SID"}})
        state["sp_lifecycle"]["SP_00AB"] = "Issued-Disabled"
        event = _spinfo_enabled_set_event(True)

        result = judge_final(state, event)

        self.assertEqual(result.verdict, "pass")
        apply_event(state, event)
        self.assertEqual(state["sp_lifecycle"]["SP_00AB"], "Issued")

    def test_spinfo_enabled_set_without_owner_authority_is_rejected(self):
        state = _open_sp_state("SP_00AB")
        state["session"].update({"write": True, "authorities": set()})

        result = judge_final(state, _spinfo_enabled_set_event(True))

        self.assertEqual(result.verdict, "fail")
        self.assertEqual(result.expected_status, "auth_error")

    def test_spinfo_enabled_set_does_not_poison_capacity_evidence(self):
        state = _open_sp_state("SP_00AB")
        state["session"].update({"write": True, "authorities": {"SID"}})

        apply_event(state, _spinfo_enabled_set_event(False))

        self.assertEqual(state["sp_lifecycle"]["SP_00AB"], "Issued-Disabled")
        self.assertNotIn("SP_00AB", state["sp_byte_space"])


if __name__ == "__main__":
    unittest.main()

import unittest

from src.oracle import judge_final
from src.state import apply_event, initial_state


def _admin_write_state():
    state = initial_state()
    state["session"].update({
        "open": True,
        "sp": "AdminSP",
        "write": True,
        "authorities": {"SID"},
    })
    state["sp_issuance_space"] = {"free": 4096, "source": "TPerInfo.SpaceForIssuance"}
    return state


def _issue_sp_event(size=4, returned_size=4):
    return {
        "index": 0,
        "kind": "method",
        "method": "IssueSP",
        "object": "AdminSP",
        "object_uid": "0000020500000001",
        "object_family": "SP",
        "status": "success",
        "parameters": {
            "SPName": "Issued One",
            "Size": size,
            "Templates": [{"Template": {"uid": "0000020400000001"}}],
            "Enabled": True,
        },
        "raw": {
            "output": {
                "return_values": {
                    "UID": {"uid": "00000205000000AB"},
                    "Size": returned_size,
                }
            }
        },
    }


def _get_free_space_event(free_space):
    return {
        "index": 1,
        "kind": "method",
        "method": "GetFreeSpace",
        "object": "SP_00AB",
        "object_uid": "00000205000000AB",
        "object_family": "SP",
        "status": "success",
        "parameters": {},
        "raw": {"output": {"return_values": {"FreeSpace": free_space}}},
    }


class IssueSPStateMachineTest(unittest.TestCase):
    def test_successful_issuesp_records_nested_returned_uid_and_template_uid(self):
        state = _admin_write_state()

        apply_event(state, _issue_sp_event())

        self.assertIn("00000205000000AB", state["issued_sps"])
        self.assertEqual(
            state["issued_sps"]["00000205000000AB"],
            {
                "uid": "00000205000000AB",
                "sp": "SP_00AB",
                "name": "Issued One",
                "size": 2048,
                "size_blocks": 4,
                "requested_size_blocks": 4,
                "size_evidence": "returned_size",
                "size_is_exact": True,
                "templates": ["0000020400000001"],
                "enabled": True,
                "source": "IssueSP",
            },
        )
        self.assertEqual(state["sp_issuance_space"]["free"], 2048)
        self.assertEqual(state["sp_lifecycle"]["SP_00AB"], "Issued")

    def test_issuesp_rejects_request_above_byte_space_after_block_conversion(self):
        state = _admin_write_state()

        result = judge_final(state, _issue_sp_event(size=9, returned_size=9))

        self.assertEqual(result.verdict, "fail")
        self.assertEqual(result.expected_status, "insufficient_space")
        self.assertEqual(result.policy_source, "TPerInfo.SpaceForIssuance")

    def test_issuesp_rejects_large_block_request_not_byte_scale(self):
        state = _admin_write_state()

        result = judge_final(state, _issue_sp_event(size=512, returned_size=512))

        self.assertEqual(result.verdict, "fail")
        self.assertEqual(result.expected_status, "insufficient_space")
        self.assertEqual(result.policy_source, "TPerInfo.SpaceForIssuance")

    def test_issuesp_legacy_no_return_exact_free_preserves_public_trace_bound(self):
        state = _admin_write_state()
        event = _issue_sp_event(size=4096, returned_size=4096)
        event["raw"]["output"]["return_values"].pop("Size")

        result = judge_final(state, event)

        self.assertEqual(result.verdict, "pass")
        apply_event(state, event)
        self.assertEqual(state["issued_sps"]["00000205000000AB"]["size"], 4096)
        self.assertEqual(state["issued_sps"]["00000205000000AB"]["size_blocks"], 4096)
        self.assertEqual(state["issued_sps"]["00000205000000AB"]["size_evidence"], "legacy_request_bound")
        self.assertFalse(state["issued_sps"]["00000205000000AB"]["size_is_exact"])

    def test_issuesp_public_no_return_without_known_free_preserves_legacy_bound(self):
        state = _admin_write_state()
        state.pop("sp_issuance_space", None)
        event = _issue_sp_event(size=4096, returned_size=4096)
        event["raw"]["output"]["return_values"].pop("Size")

        apply_event(state, event)

        self.assertEqual(state["issued_sps"]["00000205000000AB"]["size"], 4096)
        self.assertEqual(state["issued_sps"]["00000205000000AB"]["size_blocks"], 4096)
        self.assertEqual(state["issued_sps"]["00000205000000AB"]["size_evidence"], "legacy_request_bound")
        self.assertFalse(state["issued_sps"]["00000205000000AB"]["size_is_exact"])

        state["session"].update({
            "open": True,
            "sp": "SP_00AB",
            "write": False,
            "authorities": set(),
        })
        result = judge_final(state, _get_free_space_event(4097))
        self.assertEqual(result.verdict, "fail")
        self.assertEqual(result.policy_source, "issued_sp_state")

    def test_issuesp_rejects_returned_allocation_above_byte_space_after_block_conversion(self):
        state = _admin_write_state()

        result = judge_final(state, _issue_sp_event(size=8, returned_size=9))

        self.assertEqual(result.verdict, "fail")
        self.assertEqual(result.expected_status, "success_with_available_size")
        self.assertEqual(result.policy_source, "TPerInfo.SpaceForIssuance")

    def test_get_free_space_uses_issued_sp_byte_allocation_bound(self):
        state = _admin_write_state()
        apply_event(state, _issue_sp_event(size=4, returned_size=4))
        state["session"].update({
            "open": True,
            "sp": "SP_00AB",
            "write": False,
            "authorities": set(),
        })

        result = judge_final(state, _get_free_space_event(4096))

        self.assertEqual(result.verdict, "fail")
        self.assertEqual(result.policy_source, "issued_sp_state")
        self.assertEqual(result.expected_status, "success_with_bounded_freespace")


if __name__ == "__main__":
    unittest.main()

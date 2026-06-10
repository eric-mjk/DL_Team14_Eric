import unittest

from src.normalizer import normalize_trajectory
from src.oracle import judge_final
from src.state import apply_event, initial_state


def _write(index, lba, pattern):
    return {
        "index": index,
        "input": {"command": "Write", "args": {"LBA": lba, "pattern": pattern}},
        "output": {"command": "Write", "args": {"result": "pass"}},
    }


def _read(index, lba, result):
    return {
        "index": index,
        "input": {"command": "Read", "args": {"LBA": lba}},
        "output": {"command": "Read", "args": {"result": result}},
    }


def _set_mbr_enable(index):
    return {
        "index": index,
        "input": {
            "method": {
                "name": "Set",
                "args": {"required": {}, "optional": {"Values": [{"1": True}]}},
            },
            "invoking_id": {"uid": "00 00 08 03 00 00 00 01", "name": "MBRControl"},
        },
        "output": {"return_values": [], "status_codes": "SUCCESS"},
    }


def _get_mbr_table_rows(index, rows):
    return {
        "index": index,
        "input": {
            "method": {
                "name": "Get",
                "args": {
                    "required": {
                        "Cellblock": {"startColumn": 7, "endColumn": 7}
                    },
                    "optional": {},
                },
            },
            "invoking_id": {"uid": "00 00 00 01 00 00 08 04", "name": "Table"},
        },
        "output": {"return_values": [{"7": rows}], "status_codes": "SUCCESS"},
    }


def _run(steps):
    events = normalize_trajectory(steps)
    state = initial_state()
    for event in events[:-1]:
        apply_event(state, event)
    return judge_final(state, events[-1]), state


class MbrShadowLeakTest(unittest.TestCase):
    def test_shadow_read_returning_user_pattern_fails(self):
        steps = [
            _write(1, "100 ~ 107", "8E"),
            _set_mbr_enable(2),
            _read(3, "100 ~ 107", "8E"),
        ]
        result, _ = _run(steps)
        self.assertEqual(result.verdict, "fail")
        self.assertIn("user-data", result.reason)

    def test_shadow_read_returning_other_data_passes(self):
        steps = [
            _write(1, "100 ~ 107", "8E"),
            _set_mbr_enable(2),
            _read(3, "100 ~ 107", "00"),
        ]
        result, _ = _run(steps)
        self.assertEqual(result.verdict, "pass")


class MbrShadowSizeEvidenceTest(unittest.TestCase):
    def test_learned_size_overrides_default(self):
        # MBR table size 1 MiB => shadow covers LBA 0..2047 only.
        steps = [
            _get_mbr_table_rows(1, 1048576),
            _write(2, "3000 ~ 3007", "8E"),
            _set_mbr_enable(3),
            _read(4, "3000 ~ 3007", "8E"),
        ]
        result, state = _run(steps)
        self.assertEqual(state["mbr"].get("table_size_lbas"), 2047)
        # LBA 3000 is outside the learned shadow: normal read semantics apply,
        # and the written pattern reading back is compliant.
        self.assertEqual(result.verdict, "pass")
        self.assertNotIn("MBR", result.reason)

    def test_default_size_treats_low_lba_as_shadow(self):
        steps = [
            _write(1, "3000 ~ 3007", "8E"),
            _set_mbr_enable(2),
            _read(3, "3000 ~ 3007", "8E"),
        ]
        result, state = _run(steps)
        self.assertIsNone(state["mbr"].get("table_size_lbas"))
        # Without size evidence the 128 MiB default applies: LBA 3000 is inside
        # the shadow and the read returned the user-data pattern -> leak.
        self.assertEqual(result.verdict, "fail")


if __name__ == "__main__":
    unittest.main()

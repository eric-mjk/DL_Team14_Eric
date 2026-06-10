import unittest

from src.normalizer import normalize_record
from src.oracle import judge_final
from src.state import default_locking_range, initial_state


def _read(lba, result):
    return normalize_record(
        {
            "index": 9,
            "input": {"command": "Read", "args": {"LBA": lba}},
            "output": {"command": "Read", "args": {"result": result}},
        }
    )


def _write(lba, status="pass"):
    return normalize_record(
        {
            "index": 9,
            "input": {"command": "Write", "args": {"LBA": lba, "pattern": "8E"}},
            "output": {"command": "Write", "args": {"result": status}},
        }
    )


def _state_with_two_unlocked_ranges(range_crossing=None):
    state = initial_state()
    for name, start, length in (("Range1", 0, 100), ("Range2", 100, 100)):
        entry = default_locking_range(name)
        entry.update(
            {
                "range_start": start,
                "range_length": length,
                "read_lock_enabled": False,
                "write_lock_enabled": False,
                "read_locked": False,
                "write_locked": False,
            }
        )
        state["locking_ranges"][name] = entry
    state["range_crossing_behavior"] = range_crossing
    return state


class RangeCrossingReadTest(unittest.TestCase):
    def test_bit_zero_processes_unlocked_crossing_read(self):
        state = _state_with_two_unlocked_ranges(range_crossing=False)
        result = judge_final(state, _read("50 ~ 150", "AB"))
        self.assertEqual(result.verdict, "pass")

    def test_unknown_bit_keeps_protected_expectation(self):
        state = _state_with_two_unlocked_ranges(range_crossing=None)
        result = judge_final(state, _read("50 ~ 150", "AB"))
        self.assertEqual(result.verdict, "fail")
        result = judge_final(state, _read("50 ~ 150", "DATA_PROTECTION_ERROR"))
        self.assertEqual(result.verdict, "pass")

    def test_locked_overlap_still_protected_even_with_bit_zero(self):
        state = _state_with_two_unlocked_ranges(range_crossing=False)
        state["locking_ranges"]["Range2"].update(
            {"read_lock_enabled": True, "read_locked": True}
        )
        result = judge_final(state, _read("50 ~ 150", "AB"))
        self.assertEqual(result.verdict, "fail")


class RangeCrossingWriteTest(unittest.TestCase):
    def test_bit_zero_processes_unlocked_crossing_write(self):
        state = _state_with_two_unlocked_ranges(range_crossing=False)
        result = judge_final(state, _write("50 ~ 150"))
        self.assertEqual(result.verdict, "pass")

    def test_unknown_bit_expects_rejection(self):
        state = _state_with_two_unlocked_ranges(range_crossing=None)
        result = judge_final(state, _write("50 ~ 150", status="pass"))
        self.assertEqual(result.verdict, "fail")


if __name__ == "__main__":
    unittest.main()

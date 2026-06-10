import unittest

from src.normalizer import normalize_trajectory
from src.oracle import judge_final, overlapping_write_segments, segments_cover_range
from src.state import apply_event, initial_state


def _write(index, lba, pattern, status="pass"):
    return {
        "index": index,
        "input": {"command": "Write", "args": {"LBA": lba, "pattern": pattern}},
        "output": {"command": "Write", "args": {"result": status}},
    }


def _read(index, lba, result):
    return {
        "index": index,
        "input": {"command": "Read", "args": {"LBA": lba}},
        "output": {"command": "Read", "args": {"result": result}},
    }


def _run(steps):
    events = normalize_trajectory(steps)
    state = initial_state()
    for event in events[:-1]:
        apply_event(state, event)
    return judge_final(state, events[-1]), state


class WriteSegmentTrackingTest(unittest.TestCase):
    def test_overlapping_write_clips_older_segment(self):
        events = normalize_trajectory(
            [_write(1, "80 ~ 87", "8E"), _write(2, "84 ~ 89", "AA")]
        )
        state = initial_state()
        for event in events:
            apply_event(state, event)
        segments = state["write_segments"]
        self.assertEqual(
            [(s["start"], s["end"], s["pattern"]) for s in segments],
            [(80, 83, "8E"), (84, 89, "AA")],
        )
        self.assertTrue(segments_cover_range(segments, (80, 89)))
        self.assertFalse(segments_cover_range(segments, (78, 89)))
        self.assertEqual(len(overlapping_write_segments(state, (83, 84))), 2)


class SegmentReadOracleTest(unittest.TestCase):
    def test_exact_read_returns_pattern_passes(self):
        result, _ = _run([_write(1, "80 ~ 87", "8E"), _read(2, "80 ~ 87", "8E")])
        self.assertEqual(result.verdict, "pass")

    def test_exact_read_wrong_pattern_fails(self):
        result, _ = _run([_write(1, "80 ~ 87", "8E"), _read(2, "80 ~ 87", "FF")])
        self.assertEqual(result.verdict, "fail")

    def test_subrange_read_of_single_write_expects_same_pattern(self):
        result, _ = _run([_write(1, "80 ~ 87", "8E"), _read(2, "82 ~ 85", "8E")])
        self.assertEqual(result.verdict, "pass")
        result, _ = _run([_write(1, "80 ~ 87", "8E"), _read(2, "82 ~ 85", "FF")])
        self.assertEqual(result.verdict, "fail")

    def test_read_spanning_two_writes_accepts_either_pattern(self):
        steps = [_write(1, "80 ~ 83", "8E"), _write(2, "84 ~ 87", "AA")]
        result, _ = _run(steps + [_read(3, "80 ~ 87", "8E")])
        self.assertEqual(result.verdict, "pass")
        result, _ = _run(steps + [_read(3, "80 ~ 87", "AA")])
        self.assertEqual(result.verdict, "pass")

    def test_read_spanning_two_writes_rejects_foreign_pattern(self):
        steps = [_write(1, "80 ~ 83", "8E"), _write(2, "84 ~ 87", "AA")]
        result, _ = _run(steps + [_read(3, "80 ~ 87", "BB")])
        self.assertEqual(result.verdict, "fail")

    def test_partially_written_range_is_not_contradicted(self):
        # Read extends beyond the written range: unwritten data is undefined,
        # so a non-matching result must not be judged as a violation.
        result, _ = _run([_write(1, "80 ~ 83", "8E"), _read(2, "80 ~ 99", "BB")])
        self.assertEqual(result.verdict, "pass")

    def test_newer_write_wins_for_overlap_region(self):
        steps = [
            _write(1, "80 ~ 87", "8E"),
            _write(2, "84 ~ 87", "AA"),
            _read(3, "84 ~ 87", "AA"),
        ]
        result, _ = _run(steps)
        self.assertEqual(result.verdict, "pass")
        steps[-1] = _read(3, "84 ~ 87", "8E")
        result, _ = _run(steps)
        self.assertEqual(result.verdict, "fail")


if __name__ == "__main__":
    unittest.main()

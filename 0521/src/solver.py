import os

from .normalizer import normalize_trajectory
from .oracle import judge_final
from .state import track_state


def state_summary(state):
    session = state["session"]
    credentials = ",".join(sorted(k for k, v in state["credentials"].items() if v is not None)) or "none"
    ranges = []
    for name, entry in sorted(state["locking_ranges"].items()):
        ranges.append(
            f"{name}:start={entry.get('range_start')} len={entry.get('range_length')} "
            f"r={int(bool(entry.get('read_lock_enabled')))}:{int(bool(entry.get('read_locked')))} "
            f"w={int(bool(entry.get('write_lock_enabled')))}:{int(bool(entry.get('write_locked')))}"
        )
    range_text = "; ".join(ranges) if ranges else "none"
    authorities = ",".join(sorted(session.get("authorities") or [])) or "none"
    key_gens = ",".join(
        f"{name}:{count}" for name, count in sorted(state.get("key_generations_by_range", {}).items())
    ) or "none"
    lifecycle = ",".join(
        f"{name}:{value}" for name, value in sorted(state.get("sp_lifecycle", {}).items())
    ) or "none"
    return (
        f"session=open={session.get('open')} sp={session.get('sp')} write={session.get('write')} "
        f"auth={authorities} failed={session.get('had_failure')} lifecycle={lifecycle} "
        f"active_locking_sp={state.get('locking_sp_active')} "
        f"credentials={credentials} key_gens={key_gens} ranges=[{range_text}]"
    )


class Solver:
    def __init__(self):
        self.debug = os.environ.get("SOLVER_DEBUG") == "1"

    def predict(self, dataset):
        """Predict labels for the full dataset.

        dataset: list of {"id": str, "steps": list[dict]}.
        returns: dict mapping id -> "pass" or "fail".

        Override this method to do cross-trajectory inference, retrieval
        over the whole dataset, or batched generation. The baseline just
        loops case-by-case via predict_one.
        """
        predictions = {}
        for item in dataset:
            predictions[item["id"]] = self.predict_one(item["steps"])
        return predictions

    def predict_one(self, steps):
        if not steps:
            return "fail"

        events = normalize_trajectory(steps)
        state = track_state(events[:-1])
        result = judge_final(state, events[-1])
        if self.debug:
            final = events[-1]
            refs = ",".join(result.spec_refs) if result.spec_refs else "none"
            print(
                "final="
                f"{final.get('kind')}:{final.get('method') or final.get('command')} "
                f"object={final.get('object')} family={final.get('object_family')} "
                f"status={final.get('status')} expected={result.expected_status} "
                f"actual={result.actual_status} verdict={result.verdict} "
                f"refs={refs} state=({state_summary(state)}) reason={result.reason}"
            )
        return result.verdict

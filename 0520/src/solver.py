import os

from .normalizer import normalize_trajectory
from .oracle import judge_final
from .state import track_state


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
            print(
                "final="
                f"{final.get('kind')}:{final.get('method') or final.get('command')} "
                f"object={final.get('object')} status={final.get('status')} "
                f"verdict={result.verdict} reason={result.reason}"
            )
        return result.verdict

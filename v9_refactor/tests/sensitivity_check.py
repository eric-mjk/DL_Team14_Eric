"""Semantic sensitivity harness — the inverse of metamorphic_check.py.

Metamorphic testing asserts verdicts DON'T change under meaning-preserving
edits. This harness asserts verdicts DO change under meaning-CHANGING edits:
take a PASS-labeled case, break a protocol precondition in the prefix (or
corrupt the final response), and check the oracle flips to FAIL. A non-flip is
a candidate false-PASS hole — a rule that exists but does not fire.

Non-flips are findings to triage, not hard failures: some rules are
deliberately lenient (unknown-tolerant) and some mutations do not produce a
judgeable contradiction. Use the per-family flip rate and the non-flip list.

Usage:
    PYTHONPATH=v9_refactor python3 v9_refactor/tests/sensitivity_check.py [dataset dirs...]
"""

from __future__ import annotations

import copy
import json
import sys
from collections import Counter
from pathlib import Path

from src.normalizer import normalize_trajectory
from src.oracle import judge_final
from src.state import apply_event, initial_state


PROTECTED_FINAL_METHODS = {
    "Set", "GenKey", "Activate", "Revert", "RevertSP", "DeleteSP", "IssueSP",
    "CreateTable", "CreateRow", "DeleteRow", "AddACE", "RemoveACE", "DeleteMethod",
}


def _load_steps(path):
    case = json.loads(Path(path).read_text())
    if isinstance(case, dict) and "steps" in case:
        return case["steps"]
    return case


def _dataset_files(root):
    root = Path(root)
    testcases = root / "testcases"
    base = testcases if testcases.is_dir() else root
    return sorted(base.glob("*.json"))


def _labels(root):
    label_file = Path(root) / "label.jsonl"
    labels = {}
    if label_file.exists():
        for line in label_file.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
                labels[row["filename"]] = row["label"]
            except Exception:  # noqa: BLE001
                continue
    return labels

def _judge(steps):
    events = normalize_trajectory(steps)
    state = initial_state()
    for event in events[:-1]:
        apply_event(state, event)
    return judge_final(state, events[-1])


def _method_name(step):
    method = (step.get("input") or {}).get("method")
    if isinstance(method, dict):
        return method.get("name")
    return None


def _args(step):
    method = (step.get("input") or {}).get("method")
    if isinstance(method, dict) and isinstance(method.get("args"), dict):
        return method["args"]
    return None


# --- mutation families (each returns mutated steps or None if inapplicable) --

def mut_strip_authentication(steps):
    """Remove all authentication evidence from the prefix: Authenticate steps
    are dropped; StartSession loses HostSigningAuthority/HostChallenge.
    A previously authorized successful final protected op should now FAIL."""
    final_method = _method_name(steps[-1])
    if final_method not in PROTECTED_FINAL_METHODS:
        return None
    out_status = str(((steps[-1].get("output") or {}).get("status_codes")) or "")
    if out_status.strip().upper() not in {"SUCCESS"}:
        return None
    mutated = []
    touched = False
    for step in steps[:-1]:
        name = _method_name(step)
        if name == "Authenticate":
            touched = True
            continue
        step = copy.deepcopy(step)
        args = _args(step)
        if name == "StartSession" and args:
            for section in ("required", "optional"):
                section_dict = args.get(section)
                if isinstance(section_dict, dict):
                    for key in ("HostSigningAuthority", "HostChallenge", "Authority", "Proof"):
                        if key in section_dict:
                            del section_dict[key]
                            touched = True
        mutated.append(step)
    if not touched:
        return None
    mutated.append(copy.deepcopy(steps[-1]))
    return mutated


def mut_remove_activate(steps):
    """Drop successful Activate steps from the prefix. A final successful
    LockingSP-dependent op should now FAIL (LockingSP inactive)."""
    has_activate = any(_method_name(s) == "Activate" for s in steps[:-1])
    if not has_activate:
        return None
    out_status = str(((steps[-1].get("output") or {}).get("status_codes")) or "")
    if out_status.strip().upper() not in {"SUCCESS"}:
        return None
    mutated = [copy.deepcopy(s) for s in steps if not (_method_name(s) == "Activate" and s is not steps[-1])]
    if len(mutated) == len(steps):
        return None
    return mutated


def mut_corrupt_sync_session_id(steps):
    """Corrupt the SPSessionID echoed by a final SyncSession; must FAIL."""
    if _method_name(steps[-1]) != "SyncSession":
        return None
    mutated = [copy.deepcopy(s) for s in steps]
    final = mutated[-1]
    args = _args(final)
    if not args:
        return None
    for section in ("required", "optional"):
        section_dict = args.get(section)
        if isinstance(section_dict, dict) and "SPSessionID" in section_dict:
            section_dict["SPSessionID"] = 0xDEAD
            return mutated
    return None


def mut_drop_session(steps):
    """Remove the StartSession that opens the session for a successful final
    in-session method; the success should now FAIL (no open session)."""
    final_method = _method_name(steps[-1])
    if final_method in {None, "StartSession", "Properties"}:
        return None
    out_status = str(((steps[-1].get("output") or {}).get("status_codes")) or "")
    if out_status.strip().upper() != "SUCCESS":
        return None
    # find last StartSession before final with SUCCESS
    last_idx = None
    for idx, step in enumerate(steps[:-1]):
        if _method_name(step) == "StartSession":
            last_idx = idx
    if last_idx is None:
        return None
    mutated = [copy.deepcopy(s) for i, s in enumerate(steps) if i != last_idx]
    return mutated


MUTATIONS = {
    "strip_authentication": mut_strip_authentication,
    "remove_activate": mut_remove_activate,
    "corrupt_sync_session_id": mut_corrupt_sync_session_id,
    "drop_session": mut_drop_session,
}


def main(argv):
    roots = argv[1:]
    if not roots:
        candidates = [*sorted(Path("new_datasets").glob("*/")), Path("dataset")]
        roots = [str(c) for c in candidates if c.is_dir() and _dataset_files(c)]

    flips = Counter()
    applicable = Counter()
    non_flips = []
    for root in roots:
        labels = _labels(root)
        for path in _dataset_files(root):
            label = labels.get(path.name)
            if label != "pass":
                continue
            steps = _load_steps(path)
            if not isinstance(steps, list) or len(steps) < 2:
                continue
            baseline = _judge(steps).verdict
            if baseline != "pass":
                continue
            for name, mutate in MUTATIONS.items():
                try:
                    mutated = mutate(steps)
                except Exception:  # noqa: BLE001
                    mutated = None
                if mutated is None:
                    continue
                applicable[name] += 1
                try:
                    result = _judge(mutated)
                except Exception:  # noqa: BLE001
                    continue
                if result.verdict == "fail":
                    flips[name] += 1
                else:
                    non_flips.append((name, path.name, result.reason[:100]))

    print("=== Sensitivity (verdict-flip) results on PASS-labeled cases ===")
    for name in MUTATIONS:
        total = applicable[name]
        if not total:
            continue
        rate = 100.0 * flips[name] / total
        print(f"  {name}: flipped {flips[name]}/{total} ({rate:.0f}%)")
    print(f"\nnon-flips to triage: {len(non_flips)}")
    shown = Counter()
    for name, filename, reason in non_flips:
        if shown[name] >= 5:
            continue
        shown[name] += 1
        print(f"  [{name}] {filename}\n      still-pass reason: {reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

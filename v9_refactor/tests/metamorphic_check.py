"""Metamorphic robustness harness for the deterministic state machine.

Applies semantics-preserving encoding mutations to local labeled testcases and
asserts that the solver verdict is invariant. Every flip found here is a real
input-format robustness bug reproduced locally, independent of guessing the
hidden-set distribution.

Standalone usage (from the repo root or v9_refactor/):

    PYTHONPATH=v9_refactor python3 v9_refactor/tests/metamorphic_check.py \
        new_datasets/default_20_dataset

With no arguments it sweeps every dataset directory it can find under
``new_datasets/`` plus ``dataset/``.
"""

from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path

from src.normalizer import _STATUS_NUMERIC
from src.solver import Solver

_STATUS_TO_NUMERIC = {name: code for code, name in _STATUS_NUMERIC.items()}
_UID_KEYS = {
    "uid",
    "spid",
    "hostsigningauthority",
    "authority",
    "signingauthority",
    "invokingid",
    "methodid",
}
_CREDENTIAL_KEYS = {"hostchallenge", "challenge", "proof"}


def _walk(value, fn, key=None):
    """Depth-first transform: fn(key, value) -> replacement or None to recurse."""
    replaced = fn(key, value)
    if replaced is not None:
        return replaced
    if isinstance(value, dict):
        return {k: _walk(v, fn, key=k) for k, v in value.items()}
    if isinstance(value, list):
        return [_walk(item, fn, key=key) for item in value]
    return value


def _mutate_status(steps, transform):
    def fn(key, value):
        if (
            isinstance(key, str)
            and key.lower() == "status_codes"
            and isinstance(value, str)
        ):
            return transform(value)
        return None

    return _walk(copy.deepcopy(steps), fn)


def mut_status_lowercase(steps):
    return _mutate_status(steps, lambda s: s.lower())


def mut_status_spaced(steps):
    return _mutate_status(steps, lambda s: s.replace("_", " "))


def mut_status_dashed(steps):
    return _mutate_status(steps, lambda s: s.replace("_", "-"))


def mut_status_numeric(steps):
    def transform(s):
        canonical = s.strip().lower().replace("-", "_").replace(" ", "_")
        code = _STATUS_TO_NUMERIC.get(canonical)
        return code if code is not None else s

    out = []
    for step in copy.deepcopy(steps):
        def fn(key, value):
            if (
                isinstance(key, str)
                and key.lower() == "status_codes"
                and isinstance(value, str)
            ):
                return transform(value)
            return None

        out.append(_walk(step, fn))
    return out


def mut_status_hex_string(steps):
    def transform(s):
        canonical = s.strip().lower().replace("-", "_").replace(" ", "_")
        code = _STATUS_TO_NUMERIC.get(canonical)
        return f"0x{code:02X}" if code is not None else s

    return _mutate_status(steps, transform)


def _hexlike(text):
    return bool(
        re.fullmatch(r"(0[xX])?[0-9A-Fa-f]{2}([ :]?[0-9A-Fa-f]{2})*", text.strip())
    )


def mut_uid_compact_0x(steps):
    """Spaced UIDs -> 0x-prefixed compact lowercase."""

    def fn(key, value):
        if (
            isinstance(key, str)
            and key.lower() in _UID_KEYS
            and isinstance(value, str)
            and _hexlike(value)
        ):
            compact = re.sub(r"[^0-9A-Fa-f]", "", value)
            return "0x" + compact.lower()
        return None

    return _walk(copy.deepcopy(steps), fn)


def mut_uid_spaced_upper(steps):
    """Compact UIDs -> byte-spaced uppercase."""

    def fn(key, value):
        if (
            isinstance(key, str)
            and key.lower() in _UID_KEYS
            and isinstance(value, str)
            and _hexlike(value)
        ):
            compact = re.sub(r"[^0-9A-Fa-f]", "", value).upper()
            if len(compact) % 2 == 0:
                return " ".join(compact[i : i + 2] for i in range(0, len(compact), 2))
        return None

    return _walk(copy.deepcopy(steps), fn)


def mut_arg_keys_lowercase(steps):
    """Lower-case the method arg parameter names (top level of required/optional)."""

    def lower_args(args):
        if not isinstance(args, dict):
            return args
        out = dict(args)
        for section in ("required", "optional"):
            if isinstance(out.get(section), dict):
                out[section] = {str(k).lower(): v for k, v in out[section].items()}
        return out

    mutated = copy.deepcopy(steps)
    for step in mutated:
        inp = step.get("input") if isinstance(step, dict) else None
        method = inp.get("method") if isinstance(inp, dict) else None
        if isinstance(method, dict) and isinstance(method.get("args"), dict):
            method["args"] = lower_args(method["args"])
    return mutated


def mut_command_case(steps):
    def fn(key, value):
        if isinstance(key, str) and key.lower() == "command" and isinstance(value, str):
            return value.upper() if value.islower() or value.istitle() else value.lower()
        return None

    return _walk(copy.deepcopy(steps), fn)


def mut_lba_compact(steps):
    def fn(key, value):
        if isinstance(key, str) and key.upper() == "LBA" and isinstance(value, str):
            return value.replace(" ", "")
        return None

    return _walk(copy.deepcopy(steps), fn)


def mut_lba_hex(steps):
    def fn(key, value):
        if isinstance(key, str) and key.upper() == "LBA" and isinstance(value, str):
            if re.search(r"\d", value) and "0x" not in value.lower():
                return re.sub(r"\d+", lambda m: f"0x{int(m.group()):X}", value)
        return None

    return _walk(copy.deepcopy(steps), fn)


def mut_extra_unknown_fields(steps):
    mutated = copy.deepcopy(steps)
    for step in mutated:
        if isinstance(step, dict):
            step["vendor_note"] = "x"
            if isinstance(step.get("input"), dict):
                step["input"]["vendor_reserved"] = 0
    return mutated


def mut_drop_index(steps):
    mutated = copy.deepcopy(steps)
    for step in mutated:
        if isinstance(step, dict):
            step.pop("index", None)
    return mutated


def mut_credential_lowercase_hex(steps):
    def fn(key, value):
        if (
            isinstance(key, str)
            and key.lower() in _CREDENTIAL_KEYS
            and isinstance(value, str)
            and _hexlike(value)
        ):
            return value.lower()
        return None

    return _walk(copy.deepcopy(steps), fn)


def mut_pattern_result_lowercase(steps):
    def fn(key, value):
        if (
            isinstance(key, str)
            and key.lower() in {"pattern", "result"}
            and isinstance(value, str)
            and _hexlike(value)
        ):
            return value.lower()
        return None

    return _walk(copy.deepcopy(steps), fn)


_POSITIONAL_SIGS = {
    "StartSession": ["HostSessionID", "SPID", "Write"],
    "SyncSession": ["HostSessionID", "SPSessionID"],
    "Authenticate": ["Authority", "Proof"],
    "Random": ["Count"],
}


def mut_required_positional(steps):
    """Encode required args as a positional list (core/5.2.3.1 method encoding)."""
    mutated = copy.deepcopy(steps)
    for step in mutated:
        inp = step.get("input") if isinstance(step, dict) else None
        method = inp.get("method") if isinstance(inp, dict) else None
        if not isinstance(method, dict):
            continue
        signature = _POSITIONAL_SIGS.get(method.get("name"))
        args = method.get("args")
        if not signature or not isinstance(args, dict):
            continue
        required = args.get("required")
        if not isinstance(required, dict) or not required:
            continue
        keys = list(required.keys())
        if keys != signature[: len(keys)]:
            continue
        args["required"] = [required[k] for k in keys]
    return mutated


def mut_method_name_case(steps):
    """Upper-case TCG method names; canonicalization must restore dispatch."""
    mutated = copy.deepcopy(steps)
    for step in mutated:
        inp = step.get("input") if isinstance(step, dict) else None
        method = inp.get("method") if isinstance(inp, dict) else None
        if isinstance(method, dict) and isinstance(method.get("name"), str):
            method["name"] = method["name"].upper()
    return mutated


def mut_method_name_snake(steps):
    """Snake-case TCG method names (StartSession -> start_session)."""
    mutated = copy.deepcopy(steps)
    for step in mutated:
        inp = step.get("input") if isinstance(step, dict) else None
        method = inp.get("method") if isinstance(inp, dict) else None
        if isinstance(method, dict) and isinstance(method.get("name"), str):
            name = method["name"]
            method["name"] = re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()
    return mutated


_SYMBOLIC_UIDS = {
    "0000020500000001": "AdminSP",
    "0000020500000002": "LockingSP",
    "0000000900000001": "Anybody",
    "0000000900000002": "Admins",
    "0000000900000006": "SID",
    "0000000900010001": "Admin1",
    "0000000900030001": "User1",
}


def mut_symbolic_sp_and_authority(steps):
    """Replace well-known SPID/authority UIDs with their symbolic names."""

    def fn(key, value):
        if (
            isinstance(key, str)
            and key.lower() in {"spid", "hostsigningauthority", "authority", "signingauthority"}
            and isinstance(value, str)
        ):
            compact = re.sub(r"[^0-9A-Fa-f]", "", re.sub(r"^0[xX]", "", value)).upper()
            symbolic = _SYMBOLIC_UIDS.get(compact)
            if symbolic:
                return symbolic
        return None

    return _walk(copy.deepcopy(steps), fn)


MUTATIONS = {
    "required_positional": mut_required_positional,
    "method_name_case": mut_method_name_case,
    "method_name_snake": mut_method_name_snake,
    "symbolic_sp_authority": mut_symbolic_sp_and_authority,
    "status_lowercase": mut_status_lowercase,
    "status_spaced": mut_status_spaced,
    "status_dashed": mut_status_dashed,
    "status_numeric": mut_status_numeric,
    "status_hex_string": mut_status_hex_string,
    "uid_compact_0x": mut_uid_compact_0x,
    "uid_spaced_upper": mut_uid_spaced_upper,
    "arg_keys_lowercase": mut_arg_keys_lowercase,
    "command_case": mut_command_case,
    "lba_compact": mut_lba_compact,
    "lba_hex": mut_lba_hex,
    "extra_unknown_fields": mut_extra_unknown_fields,
    "drop_index": mut_drop_index,
    "credential_lowercase_hex": mut_credential_lowercase_hex,
    "pattern_result_lowercase": mut_pattern_result_lowercase,
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


def run_dataset(solver, root, mutation_names=None):
    names = mutation_names or list(MUTATIONS)
    flips = []
    checked = 0
    for path in _dataset_files(root):
        steps = _load_steps(path)
        if not isinstance(steps, list) or not steps:
            continue
        baseline = solver.predict_one(steps)
        for name in names:
            mutated = MUTATIONS[name](steps)
            verdict = solver.predict_one(mutated)
            checked += 1
            if verdict != baseline:
                flips.append((str(path), name, baseline, verdict))
    return checked, flips


def main(argv):
    roots = argv[1:]
    if not roots:
        candidates = [
            *sorted(Path("new_datasets").glob("*/")),
            Path("dataset"),
        ]
        roots = [str(c) for c in candidates if c.is_dir() and _dataset_files(c)]
    solver = Solver()
    total_checked = 0
    total_flips = []
    for root in roots:
        checked, flips = run_dataset(solver, root)
        total_checked += checked
        total_flips.extend(flips)
        status = "OK" if not flips else f"{len(flips)} FLIPS"
        print(f"{root}: {checked} mutant predictions, {status}")
        for path, name, baseline, verdict in flips:
            print(f"  FLIP {name}: {path} baseline={baseline} mutant={verdict}")
    print(
        f"TOTAL: {total_checked} mutant predictions, {len(total_flips)} verdict flips"
    )
    return 1 if total_flips else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

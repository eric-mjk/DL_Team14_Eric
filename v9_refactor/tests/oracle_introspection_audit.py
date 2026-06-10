"""Oracle introspection audits.

Audit 1 (right-for-wrong-reason): for every FAIL-labeled local case, compare the
defect encoded in the filename with the reason/rule the oracle actually used.
A correct verdict justified by an unrelated rule is a latent bug: hidden-set
variants of the same defect will not be caught.

Audit 2 (prefix self-consistency): judge every *prefix* event of every local
trajectory against the tracked state at that point. Prefix events are device
behavior the generator produced as compliant setup (only final events carry the
injected defect), so prefix events our oracle would FAIL are either deliberate
setup anomalies or trigger-happy rules that will false-FAIL hidden targets.

Usage:
    PYTHONPATH=v9_refactor python3 v9_refactor/tests/oracle_introspection_audit.py [dataset dirs...]
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

from src.normalizer import normalize_trajectory
from src.oracle import judge_final
from src.state import apply_event, initial_state


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


def _judge(steps):
    events = normalize_trajectory(steps)
    state = initial_state()
    for event in events[:-1]:
        apply_event(state, event)
    return judge_final(state, events[-1]), events, state


# --- Audit 1: filename defect vs firing rule ---------------------------------

_STOP_TOKENS = {
    "core", "opal", "cross", "fail", "pass", "syn", "case", "json", "test",
    "tc", "the", "with", "and", "for", "not", "into",
}

# filename token -> set of substrings expected in reason/policy_source text
_TOKEN_HINTS = {
    "trylimit": ("trylimit", "locked out", "lockout", "tries"),
    "lockout": ("locked out", "trylimit", "lockout"),
    "genkey": ("genkey", "key"),
    "mbr": ("mbr",),
    "locking": ("lock",),
    "locked": ("lock",),
    "unlock": ("lock",),
    "revert": ("revert",),
    "revertsp": ("revertsp", "revert"),
    "activate": ("activate", "active"),
    "session": ("session",),
    "startsession": ("session",),
    "authenticate": ("authenticat", "credential", "proof", "challenge"),
    "auth": ("authenticat", "authorit", "credential", "not_authorized", "auth"),
    "pin": ("pin", "credential", "c_pin"),
    "credential": ("credential", "pin"),
    "getfreespace": ("freespace", "free space"),
    "getfreerows": ("freerows", "free rows", "rows_free", "rowsfree"),
    "issuesp": ("issuesp", "issue", "issuance", "issued"),
    "issued": ("issued", "issuesp"),
    "createtable": ("createtable", "table"),
    "createrow": ("createrow", "row"),
    "deleterow": ("deleterow", "row"),
    "delete": ("delete",),
    "discovery": ("discovery", "descriptor", "feature"),
    "properties": ("properties",),
    "random": ("random", "count"),
    "stir": ("stir",),
    "clock": ("clock", "lag"),
    "log": ("log",),
    "ace": ("ace", "acl", "policy", "access"),
    "acl": ("acl", "ace", "policy", "access"),
    "range": ("range",),
    "read": ("read", "pattern", "data"),
    "write": ("write", "lock", "data"),
    "shadow": ("shadow", "mbr"),
    "size": ("size", "bytes", "space"),
    "exceeds": ("exceed", "bound", "larger", "below", "minimum"),
    "wrong": (),
    "missing": ("missing", "omitted", "include"),
    "next": ("next",),
    "byte": ("byte",),
    "granularity": ("granularity",),
    "timeout": ("timeout",),
    "frozen": ("frozen", "freeze"),
    "disabled": ("disabled", "disable"),
    "lifecycle": ("lifecycle", "life cycle", "manufactured", "issued"),
    "duplicate": ("duplicate", "already", "conflict"),
    "unique": ("unique", "conflict"),
    "syncsession": ("syncsession", "session"),
    "hostchallenge": ("challenge", "credential"),
    "cellblock": ("cellblock", "column"),
    "column": ("column",),
    "sid": ("sid",),
    "msid": ("msid",),
    "admin": ("admin",),
    "user": ("user",),
    "psid": ("psid",),
    "tper": ("tper",),
    "template": ("template",),
    "sp": ("sp",),
}


def audit_reasons(roots):
    mismatches = []
    checked = 0
    for root in roots:
        for path in _dataset_files(root):
            name = path.stem.lower()
            if "fail" not in name:
                continue
            steps = _load_steps(path)
            if not isinstance(steps, list) or not steps:
                continue
            result, _events, _state = _judge(steps)
            checked += 1
            if result.verdict != "fail":
                mismatches.append((str(path), "VERDICT_WRONG", result.reason[:120]))
                continue
            haystack = " ".join(
                str(x)
                for x in (result.reason, result.policy_source, result.expected_status, " ".join(result.spec_refs or ()))
            ).lower()
            tokens = [t for t in re.split(r"[^a-z]+", name) if len(t) > 2 and t not in _STOP_TOKENS]
            hints = []
            hit = False
            for token in tokens:
                for needle in _TOKEN_HINTS.get(token, (token,)):
                    hints.append(needle)
                    if needle and needle in haystack:
                        hit = True
                        break
                if hit:
                    break
            if not hit:
                mismatches.append((str(path), "REASON_MISMATCH", result.reason[:150]))
    return checked, mismatches


# --- Audit 2: prefix self-consistency ----------------------------------------

def audit_prefixes(roots):
    flagged = []
    total_prefix_events = 0
    by_reason = Counter()
    for root in roots:
        for path in _dataset_files(root):
            steps = _load_steps(path)
            if not isinstance(steps, list) or len(steps) < 2:
                continue
            events = normalize_trajectory(steps)
            state = initial_state()
            for position, event in enumerate(events[:-1]):
                result = judge_final(state, event)
                total_prefix_events += 1
                if result.verdict == "fail":
                    key = result.reason[:110]
                    by_reason[key] += 1
                    if by_reason[key] <= 3:  # keep a few examples per reason
                        flagged.append(
                            (
                                str(path),
                                position,
                                event.get("method") or event.get("command") or event.get("kind"),
                                event.get("status"),
                                key,
                            )
                        )
                apply_event(state, event)
    return total_prefix_events, by_reason, flagged


def main(argv):
    roots = argv[1:]
    if not roots:
        candidates = [*sorted(Path("new_datasets").glob("*/")), Path("dataset")]
        roots = [str(c) for c in candidates if c.is_dir() and _dataset_files(c)]

    print("=== Audit 1: right-for-wrong-reason (FAIL-labeled cases) ===")
    checked, mismatches = audit_reasons(roots)
    print(f"checked {checked} FAIL cases; {len(mismatches)} need review")
    for path, kind, reason in mismatches:
        print(f"  [{kind}] {Path(path).name}\n      firing reason: {reason}")

    print()
    print("=== Audit 2: prefix self-consistency ===")
    total, by_reason, flagged = audit_prefixes(roots)
    fail_count = sum(by_reason.values())
    print(f"judged {total} prefix events; {fail_count} would be FAIL ({100.0*fail_count/max(total,1):.2f}%)")
    print("\nprefix-FAIL reasons by frequency:")
    for reason, count in by_reason.most_common():
        print(f"  {count:5d}  {reason}")
    print("\nexamples (up to 3 per reason):")
    for path, position, method, status, reason in flagged:
        print(f"  {Path(path).name} step#{position} {method} status={status}\n      {reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

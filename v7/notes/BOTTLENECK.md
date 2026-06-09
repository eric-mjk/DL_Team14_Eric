# Plan: Fix Oracle Systematic False Positives (80.5% → higher)

---

## Project Onboarding (for handoff to a fresh agent)

### What this project is

`/workspace/Eric/ws` contains a **TCG Storage / Opal SSD protocol oracle** for a competition. The oracle is a deterministic rule-based verifier that reads a "trajectory" — a sequence of SSD command/response pairs (StartSession, Get, Set, Authenticate, Revert, etc.) — and decides whether the **final** response is protocol-compliant.

Output: exactly `"pass"` or `"fail"` per trajectory. A verdict judges spec compliance — not whether the SSD returned SUCCESS.

### Active code (v7)

All active work is in `v7/`:

| File | Role |
|------|------|
| `v7/src/solver.py` | Entry point — `Solver.predict_one(steps)` → normalizes → track_state → judge_final → verdict |
| `v7/src/normalizer.py` | Converts raw JSON step records to canonical event dicts |
| `v7/src/state.py` | Replays prefix events (all but last) to build protocol state |
| `v7/src/oracle.py` | Judges the final event against accumulated state — **this is the file to edit** |
| `v7/src/spec_docs.py` | Spec metadata, column maps, coverage helpers |
| `v7/src/spec_tables.py` | Static Opal table/policy constants |

### Evaluation commands

```bash
# Public dataset (must stay at 100.00):
python3 v7/evaluate.py

# Synthetic regression suite (must stay at 57/57):
cd v7/customtest_57 && python3 generate_synthetic.py --check-only

# Compile check:
python3 -m py_compile v7/src/*.py

# Debug one trajectory:
SOLVER_DEBUG=1 python3 -c "
import json, sys
sys.path.insert(0, 'v7')
from src.solver import Solver
with open('dataset/testcases/tc14.json') as f: steps = json.load(f)
print(Solver().predict_one(steps))
"
```

### Leaderboard situation

- Public dataset: 20 test cases (tc1–tc10 = pass, tc11–tc20 = fail). Oracle scores **100%**.
- Hidden dataset: **100 test cases, exactly 50 pass / 50 fail**. Oracle scores **80.5%** since v5.
- **Math proof that oracle is too permissive**: 50 pass × 100% + 50 fail × X% = 80.5 → X ≈ 61%. Oracle correctly identifies ~100% of pass cases but only ~61% of fail cases. It is emitting false positives (says "pass" when it should say "fail") on ~19–20 hidden fail cases.
- Adding more synthetic test cases has **not helped** — the circular loop problem: synthetic cases are based on our own understanding, so fixing the oracle to match them just validates our own assumptions. The hidden test distribution is unknown.

### How oracle.py works (key internal structure)

`judge_final(state, event)` dispatches to one of 33 specific `judge_*` functions based on the method name. Unrecognized methods fall to `fallback()`.

Each judge function computes an **expected status** and compares it to the **actual status** from the event. If they match, verdict = "pass"; if not, verdict = "fail".

Status classes used (broader than raw strings):
- `"success"` → SUCCESS
- `"auth_error"` → NOT_AUTHORIZED, AUTHORITY_LOCKED_OUT
- `"invalid_parameter"` → INVALID_PARAMETER, INVALID_COMMAND, etc.
- `"resource_error"` → SP_BUSY, SP_FAILED, SP_DISABLED, etc.
- `"error"` / `"data_success"` → catch-alls

Expected status can be a **set** (e.g., `{"success", "auth_error"}`) meaning either is acceptable — this is the main source of permissiveness.

Key helper functions in oracle.py:
- `session_open_for(state, sp, write_required=False)` — checks if an open session exists for a given SP
- `session_has_authority(state, authority=None)` — True if ANY authority is in the session (or matches specific authority)
- `session_has_admin_authority(state, sp=None)` — True only for Admin* or SID authority (stricter)
- `object_sp(event)` — returns which SP owns the target object ("AdminSP", "LockingSP", etc.)
- `credential_matches(state, authority, proof)` — True/False/None (None = credential not tracked)
- `pass_result(reason, confidence, ...)` — always returns verdict="pass" regardless of actual status
- `expected_status_result(event, expected, reason, ...)` — compares expected vs actual, returns RuleResult

State dict (built by state.py from prefix events):
```python
state = {
    "session": {"open": bool, "sp": str, "write": bool, "authorities": set},
    "credentials": {"SID": str|None, "MSID": str|None, "Admin1": str|None, ...},
    "locking_ranges": {range_name: {"read_locked": bool, "write_locked": bool, ...}},
    "locking_sp_active": bool,
    "sp_lifecycle": {"AdminSP": "Manufactured", "LockingSP": "Manufactured-Inactive"|"Manufactured"},
    "authority_rows": [...],
    "trylimit_by_authority": {...},
    "failed_auth_counts": {...},
    ...
}
```

Only SUCCESSFUL prefix operations mutate state. Failed Set/GenKey/Revert/StartSession don't change state.

### What the public fail cases test (verified by reading tc11–tc20)

All public fail cases catch the violation via **status code mismatch**:
- tc11: Properties returns INVALID_PARAMETER (oracle expects SUCCESS) → fail
- tc12: Get C_PIN returns NOT_AUTHORIZED (oracle expects SUCCESS with admin session) → fail
- tc13: StartSession returns NOT_AUTHORIZED after wrong challenge (oracle expects SUCCESS when credential tracked and matches) → fail
- tc14: Final StartSession uses "aaaaaa..." challenge after credential tracked as "f620e538..." from prior Set C_PIN → mismatch → expected auth_error, actual SUCCESS → fail
- tc15: Activate invoked on UID `0000010500000004` (not LockingSP `0000020500000002`) → oracle expects INVALID_PARAMETER → actual SUCCESS → fail
- tc16/tc17: Set/StartSession with wrong credentials → status mismatch → fail
- tc18: Get Locking returns INVALID_PARAMETER (oracle expects SUCCESS with admin) → fail
- tc19: Get MBRControl returns FAIL status code (oracle expects SUCCESS) → fail

The oracle handles all of these correctly. The hidden tests must test **scenarios where the device returns SUCCESS but the oracle should say the operation was unauthorized (and thus the SUCCESS response is wrong)**.

---

## Root Cause: Three Permissive Paths in oracle.py

The oracle says "pass" on ~19–20 hidden fail cases because it expects "success" too broadly. Three specific code locations cause this:

### Path 1 — `judge_get()` final fallback, line ~2064 (NO session check)

```python
# Current (oracle.py, end of judge_get function):
return expected_status_result(event, "success", "Get on non-sensitive discovery object should succeed.", rule_key="get")
```

Every `Get` on a family not explicitly handled (TPerInfo, DataRemovalMechanism, Log, LogList, MethodID, Column, and any other unmapped family) reaches this line. There is **no session check**. If the device returns SUCCESS for a Get without an open session, oracle says "pass". The spec requires an open session for all table-method calls.

`_CELL_OMIT_FAMILIES` at line ~1866 includes these families, but the explicit `if family in {...}` condition at line ~2052 only handles `{"Authority", "MediaKey", "ACE", "AccessControl", "SecretProtect", "DataStore"}` — leaving the others to fall to the unconditional line.

### Path 2 — `judge_set()` generic fallback, lines ~2170–2176 (any authority)

```python
# Current:
expected = state["session"].get("open") and state["session"].get("write") and session_has_authority(state)
```

`session_has_authority(state)` with NO argument returns True if **any** authority is authenticated — User1, User2, PSID, anyone. For Set on objects not in explicit family list (C_PIN, Locking, MBRControl, Authority, C_PIN_MSID), oracle accepts any authenticated write session. A non-admin (User1) Set on a non-standard target returning SUCCESS → oracle says "pass".

### Path 3 — `fallback()` write-method check, lines ~2993–2996 (any authority)

```python
# Current:
expected = state["session"].get("open") and (
    not method.lower().startswith(("set", "gen", "activate", "revert", "delete", "create"))
    or (state["session"].get("write") and session_has_authority(state))
)
```

Same problem for methods the oracle has no explicit judge for. Any authenticated write session passes the check. Most write-like operations require admin-level authority.

---

## Fixes (all in `v7/src/oracle.py`)

### Fix 1 — Add session check to `judge_get()` fallback

Find the line at the very end of `judge_get()`:
```python
return expected_status_result(event, "success", "Get on non-sensitive discovery object should succeed.", rule_key="get")
```

Replace with:
```python
_final_sp = target_sp or state["session"].get("sp")
_session_ok = not _final_sp or session_open_for(state, _final_sp)
return expected_status_result(
    event,
    "success" if _session_ok else "auth_error",
    "Get on discovery/metadata object requires an open session in the target SP.",
    rule_key="get",
)
```

`target_sp` is already a local variable in `judge_get()` (assigned near line 1769). Use it directly — no new computation needed.

### Fix 2 — Require admin in `judge_set()` generic fallback

Find the block near the end of `judge_set()` after all the specific-family branches:
```python
expected = state["session"].get("open") and state["session"].get("write") and session_has_authority(state)
return expected_status_result(
    event,
    "success" if expected else "auth_error",
    "Protected Set fallback requires an authenticated write session.",
    rule_key="set",
)
```

Replace with:
```python
_set_sp = object_sp(event) or state["session"].get("sp")
expected = (
    state["session"].get("open")
    and state["session"].get("write")
    and session_has_admin_authority(state, _set_sp)
)
return expected_status_result(
    event,
    "success" if expected else "auth_error",
    "Protected Set fallback requires an admin-level authenticated write session.",
    rule_key="set",
)
```

### Fix 3 — Require admin in `fallback()` write-method branch

Find `fallback()` function (near line 2984). Replace the permission check:
```python
# Before:
expected = state["session"].get("open") and (
    not method.lower().startswith(("set", "gen", "activate", "revert", "delete", "create"))
    or (state["session"].get("write") and session_has_authority(state))
)

# After:
_fb_sp = state["session"].get("sp")
expected = state["session"].get("open") and (
    not method.lower().startswith(("set", "gen", "activate", "revert", "delete", "create"))
    or (state["session"].get("write") and session_has_admin_authority(state, _fb_sp))
)
```

---

## Helper functions to reuse (all already in oracle.py)

- `session_open_for(state, sp, write_required=False)` — checks if a session is open for a given SP name
- `session_has_admin_authority(state, sp=None)` — line ~295, requires Admin* or SID authority
- `object_sp(event)` — returns which SP the target object belongs to
- `target_sp` — already a local variable in `judge_get()`, available at the line being changed

---

## Execution plan

Apply in order, verifying after each step:

1. Apply Fix 1 → `python3 v7/evaluate.py` → must be 100.00
2. Apply Fix 2 → `python3 v7/evaluate.py` → must be 100.00
3. Apply Fix 3 → `python3 v7/evaluate.py` → must be 100.00
4. `python3 -m py_compile v7/src/*.py` → no errors
5. `cd v7/customtest_57 && python3 generate_synthetic.py --check-only` → must be 57/57
6. Submit to leaderboard

---

## Why NOT other approaches

- **ace_policy_decision partial-column saw_unknown (lines ~560–566)**: The comment at that location explains this is intentional — blocking here would wrongly deny legitimate admin writes on columns not enumerated in any single ACE (opal/4.3.1.7 Table 39). Leave this alone.
- **pass_result for StartSession/Authenticate (lines ~1565–1583, ~1736–1743)**: When a credential is truly unknown (not tracked from any Get C_PIN or Set C_PIN), the oracle cannot verify → changing this risks hurting pass cases where credentials are correct but untracked. These paths only fire when credential is None. Leave for now.
- **Adding more synthetic tests**: Proven ineffective due to the circular loop — tests based on our own spec understanding just validate the oracle against itself. No new signal.
- **Return value validation** (beyond what already exists): Locking column value validation (lines 1949–1971) and SP lifecycle validation (lines 1876–1907) are already implemented. Adding more requires complex state correlation and has higher regression risk. Do only after Phase 1 fixes are measured.

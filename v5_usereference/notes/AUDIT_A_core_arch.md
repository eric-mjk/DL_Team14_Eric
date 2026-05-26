# Spec Audit — Agent A: Core Architecture & Tables (sections 1–4, 5.1–5.2)

## Summary

- Files read: ~180 spec files (core/1.*.txt, core/2.*.txt, core/3.*.txt, core/4.*.txt, core/5.1.*.txt, core/5.2.*.txt), plus oracle.py, state.py, spec_tables.py, normalizer.py, solver.py
- Discrepancies found: 4 (critical: 1, minor: 3)
- Already-fixed bugs: excluded per task instructions

### Critical architectural finding

`oracle.py` is **not** in the active evaluation path. `evaluate.py` imports `Solver` from `solver.py`, and `solver.py` has its own independent rule logic — it never imports `oracle.py`. Therefore bugs in `oracle.py` do not affect scores on the public dataset. Discrepancies A-001 and A-002 are logged for completeness but affect the inactive module only. Discrepancies A-003 and A-004 affect both modules.

---

## Discrepancies

### A-001: oracle.py StartSession — missing INVALID_PARAMETER for class authority as HostSigningAuthority

- **Spec section**: core/5.1.5.11
- **What spec says**: "This status code SHALL be sent as the SyncSession method status code if the preceding StartSession method's HostSigningAuthority parameter is a class authority." (SP 5.1.5.11, last paragraph)
- **What code currently does**: `oracle.py` `judge_start_session` (lines 1256–1330) checks authority existence and enabled/locked-out state, then checks the credential challenge, but never calls `authority_is_class()` on the `HostSigningAuthority`. A class authority (e.g. Admins, Users) passed as HostSigningAuthority would not be rejected; the oracle would accept a matching challenge or fall through to the confidence-0.55 branch.
- **Impact**: oracle.py only. `solver.py` `_expected_start_session` (line 549) already correctly calls `self._is_class_authority(authority)` and returns `INVALID_PARAMETER` before any credential check.
- **Severity**: critical (for oracle.py; no scoring impact because oracle.py is unused)
- **Fix needed**: In `oracle.py` `judge_start_session`, after resolving `authority` and before the `authority_enabled` check, add:
  ```python
  if authority and authority_is_class(state, authority):
      return expected_status_result(event, "invalid_parameter",
          "HostSigningAuthority is a class authority; spec 5.1.5.11 requires INVALID_PARAMETER.",
          rule_key="start_session")
  ```

---

### A-002: oracle.py GetACL — wrong status for wrong InvokingID (INVALID_PARAMETER vs NOT_AUTHORIZED)

- **Spec section**: core/5.1.5.2
- **What spec says**: "This status code SHALL be returned if the GetACL method invocation is performed with an InvokingID other than that of the AccessControl table." The status is explicitly NOT_AUTHORIZED (section 5.1.5.2), not INVALID_PARAMETER.
- **What code currently does**: `oracle.py` `judge_meta_acl` (lines 1924–1936) returns `"invalid_parameter"` when `event.get("object_family") != "AccessControl"`:
  ```python
  if event.get("object_family") != "AccessControl":
      return expected_status_result(event, "invalid_parameter",
          f"{method} target must be the AccessControl table.", rule_key="meta_acl")
  ```
  This uses the wrong status class — the spec mandates NOT_AUTHORIZED.
- **Impact**: oracle.py only. solver.py has no explicit GetACL/AddACE/RemoveACE handling (falls through to `ExpectedOutcome(status="SUCCESS")` default).
- **Severity**: minor (oracle.py unused; GetACL not exercised by public tc1–tc20)
- **Fix needed**: Change `"invalid_parameter"` to `"auth_error"` in that branch of `judge_meta_acl`:
  ```python
  if event.get("object_family") != "AccessControl":
      return expected_status_result(event, "auth_error",
          f"{method} target must be the AccessControl table (spec 5.1.5.2: NOT_AUTHORIZED).",
          rule_key="meta_acl")
  ```

---

### A-003: SP lifecycle states (Issued-Disabled, Issued-Frozen, Failed) not tracked or enforced

- **Spec section**: core/4.5.2, 4.5.3, 4.5.5; core/5.1.5.4, 5.1.5.5, 5.1.5.6
- **What spec says**:
  - Issued-Disabled (4.5.2): all method invocations except Authenticate, Set(Enabled), and DeleteSP SHALL fail with SP_DISABLED.
  - Issued-Frozen (4.5.3): session startup SHALL fail with SP_FROZEN (5.1.5.6 says "SHALL be returned").
  - Failed (4.5.5): session startup SHALL respond with SP_FAIL.
- **What code currently does**:
  - `state.py` `initial_state()` sets `sp_lifecycle` to `"Manufactured"` / `"Manufactured-Inactive"` for AdminSP / LockingSP, which are Opal Manufactured-state values — not the Core lifecycle states Issued-Disabled / Issued-Frozen / Failed.
  - `state.py` never transitions `sp_lifecycle` to "Issued-Disabled", "Issued-Frozen", or "Failed" in response to any event.
  - `oracle.py` never reads `sp_lifecycle` at all (zero grep hits in oracle.py for `sp_lifecycle`).
  - `solver.py` `ProtocolState` has no `sp_lifecycle` field; it only tracks `activated_sps` (a set for the Opal activation state).
  - No status class in `oracle.py` or `solver.py` ever produces `SP_DISABLED`, `SP_FROZEN`, or `SP_FAIL` as an expected outcome.
- **Severity**: minor (none of tc1–tc20 exercises disabled/frozen/failed SP lifecycle; the Opal SSC mandates only Manufactured/Manufactured-Inactive/Manufactured-Personalized states, so in practice public test cases will not trigger these paths)
- **Fix needed** (if completeness is required):
  - Add tracking for when an SP's `Enabled` column is set to False in `state.py` (transition `sp_lifecycle` to "Issued-Disabled").
  - In `oracle.py` `judge_start_session`, check `sp_lifecycle` and return `SP_DISABLED` / `SP_FROZEN` / `SP_FAIL` accordingly before other checks.
  - In `solver.py` `_expected_start_session`, add a check: if the SP is in disabled/frozen/failed state, return `ExpectedOutcome(status="SP_DISABLED")` etc.

---

### A-004: AUTHORITY_LOCKED_OUT condition 2 (Uses/Limit columns) not tracked

- **Spec section**: core/5.1.5.15
- **What spec says**: AUTHORITY_LOCKED_OUT MAY be returned under two conditions:
  1. C_PIN TryLimit reached (Tries == TryLimit, TryLimit != 0) — for password-authenticated authorities.
  2. Uses column of the authority reaches its Limit column value (Uses != 0) — for any authority.
- **What code currently does**:
  - `state.py` `initial_state()` initializes `trylimit_by_authority` and `failed_auth_counts`, correctly tracking condition 1.
  - `oracle.py` `is_authority_locked_out()` checks only `failed_auth_counts >= trylimit_by_authority` — condition 1 only.
  - `solver.py` `ProtocolState` has no `uses_by_authority` or `limit_by_authority` fields; the `_expected_start_session` and `_expected_authenticate` methods have no lockout check for condition 2.
  - No code reads or updates an `authority.Uses` / `authority.Limit` field anywhere.
- **Severity**: minor (condition 2 requires per-authority use tracking; not exercised by tc1–tc20 and likely not relevant to the Opal SSC test cases in the dataset)
- **Fix needed** (if completeness is required):
  - In `state.py`, initialize `uses_by_authority: dict[str, int] = {}` and `limit_by_authority: dict[str, int] = {}`.
  - On each successful Authenticate/StartSession for an authority, increment `uses_by_authority[authority]`.
  - In `oracle.py` `is_authority_locked_out`, add condition 2 check: `uses_by_authority.get(auth, 0) >= limit_by_authority.get(auth, 0) > 0`.
  - Mirror the same check in `solver.py`.

# Spec Audit — Agent B: Core Method Specifications (section 5.3)

## Summary

- Files read: 58 spec files (core/5.3.*.txt), plus oracle.py, state.py, spec_tables.py, normalizer.py, solver.py
- Discrepancies found: 8 (critical: 4, minor: 4)
- Already-fixed bugs: 19 (excluded per task instructions)

---

## Discrepancies

### B-001: Authenticate — missing INVALID_PARAMETER when Proof supplied to non-Password/non-Anybody authority

- **Spec section**: core/5.3.4.1.14.1 item 1c
- **What spec says**: In the Awaiting Challenge state, if "a proof is supplied to a non-Password/non-Anybody authority", the TPer SHALL respond with `INVALID_PARAMETER`.
- **What code currently does**: `oracle.py` `judge_authenticate` (approx. lines 1333–1422) looks up `authority_rows` from state but never reads the `operation` field of the authority. A non-Password authority with a proof value is allowed to fall through to credential comparison, producing the wrong status code.
- **Severity**: critical
- **Fix needed**: In `judge_authenticate`, after resolving the authority row, read `auth_row.get("operation")`. If `operation not in (None, "Password", "Anybody")` and `event` contains a non-None proof value, return `RuleResult("fail", 1.0, "INVALID_PARAMETER: proof supplied to non-Password authority")`.

---

### B-002: Authenticate — missing SUCCESS+False for Exchange/TPerExchange/TPerSign authority

- **Spec section**: core/5.3.4.1.3 (Operation column semantics), core/5.3.4.1.14.1 item 5a
- **What spec says**: Authorities with `Operation = Exchange` or `TPerExchange` or `TPerSign` are key-exchange or TPer-side authorities. When `Authenticate` is invoked against such an authority, the TPer SHALL return `SUCCESS` with the authentication result `False` (authentication did not succeed).
- **What code currently does**: `oracle.py` `judge_authenticate` has no branch for `operation in ("Exchange", "TPerExchange", "TPerSign")`. The call falls through to credential comparison logic, which may return either pass or fail depending on whether the proof matches the stored credential bytes — which is incorrect.
- **Severity**: critical
- **Fix needed**: In `judge_authenticate`, after resolving `operation`, add:
  ```python
  if operation in ("Exchange", "TPerExchange", "TPerSign"):
      # Spec: returns SUCCESS, auth=False
      return RuleResult("pass", 1.0, "SUCCESS+False: Exchange/TPer authority cannot authenticate via Authenticate method")
  ```
  Note: `state.py` `apply_authority_columns` already tracks `operation` at col 9, so the data is available.

---

### B-003: StartSession — missing error when Exchange/TPerExchange/TPerSign authority used as HostSigningAuthority

- **Spec section**: core/5.3.4.1.3
- **What spec says**: "Referencing an authority with this Operation column value [Exchange, TPerExchange, TPerSign] in another authority parameter of the session startup methods SHALL result in an error."  This means using such an authority as the `HostSigningAuthority` parameter in `StartSession` is forbidden.
- **What code currently does**: `oracle.py` `judge_start_session` (approx. lines 1256–1330) validates existence of the authority and whether the SP is active, but never inspects the `operation` field of the authority being used as `HostSigningAuthority`. An `Exchange` authority would be accepted silently.
- **Severity**: critical
- **Fix needed**: In `judge_start_session`, after resolving the `HostSigningAuthority` from state, check `auth_row.get("operation")`. If `operation in ("Exchange", "TPerExchange", "TPerSign")`, return `RuleResult("fail", 1.0, "NOT_AUTHORIZED or error: Exchange/TPer authority used as HostSigningAuthority")`.

---

### B-004: GenKey — C_RSA / C_EC / C_AES credential objects wrongly rejected with INVALID_PARAMETER

- **Spec section**: core/5.3.3.16
- **What spec says**: `GenKey` is valid on "any of the C_AES_*, K_AES_*, C_EC_*, C_PIN, C_RSA_*, or C_HMAC_* tables". All of these are legitimate targets.
- **What code currently does**: `oracle.py` `judge_gen_key` line ~1704:
  ```python
  if family != "MediaKey" and not event.get("key_range"):
      return RuleResult("fail", 0.95, "INVALID_PARAMETER: GenKey on non-key object without key_range")
  ```
  In `normalizer.py`, C_RSA/C_EC/C_AES objects are not mapped in `object_family()` and therefore return `family = None`. They also have `key_range = None`. This combination satisfies the condition `family != "MediaKey" and not key_range`, causing them to be rejected — even though they are valid credential GenKey targets per spec.
- **Severity**: minor (not exercised by the public tc1–tc20 dataset, but wrong per spec)
- **Fix needed**: Two parts:
  1. `normalizer.py` `object_family()`: add mappings for `"C_RSA"`, `"C_EC"`, `"C_AES"` families (e.g., return `"CredentialKey"` for these).
  2. `oracle.py` `judge_gen_key`: change the guard to allow both MediaKey objects AND credential key objects. The helper `credential_object_target(event)` (already defined at approx. line 1741) correctly identifies C_PIN, C_RSA, C_EC, C_AES, C_HMAC targets — use it instead of the `family != "MediaKey" and not key_range` check.

---

### B-005: C_PIN.Tries (col 6) incorrectly marked read-only in spec_docs.py

- **Spec section**: core/5.3.4.1.1.2
- **What spec says**: "The value of the Tries column MAY be reset from the host by successful invocation of the Set method on that cell to set the value to 0." This is an explicit host-writable permission on the Tries column (subject to normal access control).
- **What code currently does**: `spec_docs.py` `READ_ONLY_COLUMNS`:
  ```python
  "C_PIN": {0, 1, 2, 6}   # col 6 = Tries
  ```
  `oracle.py` `read_only_set_columns()` checks this set and returns an auth/invalid-parameter error whenever the host attempts `Set C_PIN col 6`. This blocks a spec-permitted operation.
- **Severity**: critical (a host attempt to reset Tries to 0 — which the spec explicitly permits — will be wrongly judged as a FAIL)
- **Fix needed**: In `spec_docs.py`, change:
  ```python
  "C_PIN": {0, 1, 2, 6}
  ```
  to:
  ```python
  "C_PIN": {0, 1, 2}
  ```
  Col 6 (Tries) is host-writable (only to value 0, but the writability check in the oracle does not validate the value being written — it only checks column write-ability, so removing 6 from the read-only set is correct).

---

### B-006: Authority.Limit / Authority.Uses not enforced during authentication

- **Spec section**: core/5.3.2.10 (Authority table, columns 15–16)
- **What spec says**: The `Limit` column (col 15) and `Uses` column (col 16) of the Authority table control how many times an authority may be used for authentication. If `Limit != 0` and `Uses >= Limit`, the authority SHALL NOT authenticate successfully.
- **What code currently does**: `oracle.py` never checks `authority_row.get("limit")` or `authority_row.get("uses")`. `state.py` tracks neither column (only C_PIN TryLimit/Tries are tracked). `spec_docs.py` `COLUMN_NAME_NUMBERS["Authority"]` includes `"limit": 15` and `"uses": 16`, confirming spec awareness, but no enforcement path exists.
- **Severity**: minor
- **Fix needed**:
  1. `state.py` `apply_authority_columns`: store `limit` (col 15) and `uses` (col 16) in the authority row dict.
  2. `state.py` `apply_successful_authenticate` (or equivalent): increment `uses` for the authenticated authority on each successful authentication.
  3. `oracle.py` `judge_authenticate`: before allowing authentication, check:
     ```python
     limit = auth_row.get("limit", 0)
     uses = auth_row.get("uses", 0)
     if limit != 0 and uses >= limit:
         return RuleResult("fail", 1.0, "NOT_AUTHORIZED: Authority.Uses >= Authority.Limit")
     ```

---

### B-007: SetPackage on C_PIN does not reset Tries counter in state

- **Spec section**: core/5.3.4.1.1.2
- **What spec says**: "Successful invocation of methods on a C_PIN object that modify the value of the PIN column also set the value of that object's Tries column to 0. These methods are GenKey, Set, **and SetPackage**." (Emphasis added.)
- **What code currently does**: `state.py` handles Tries reset in `apply_successful_gen_key` (for GenKey) and `apply_successful_set` (for Set on col 3). However, `apply_event` (lines 885–975) has no `"SetPackage"` case, so a successful `SetPackage` that changes the PIN does not trigger a Tries reset.
- **Severity**: minor
- **Fix needed**: In `state.py` `apply_event`, add a handler for `method == "SetPackage"` that calls `apply_successful_set_package(event, state)` (or inline the Tries reset logic). Specifically: if the SetPackage target is a C_PIN object, set `state.credentials[authority]["tries"] = 0`.

---

### B-008: ACE with empty BooleanExpr resolves to None (unknown) instead of False

- **Spec section**: core/5.3.4.3.3 (ACE evaluation)
- **What spec says**: "If the BooleanExpr column value is an empty list, that ACE cannot be satisfied and as such always resolves to False." An ACE that evaluates to False means the authority is NOT authorized.
- **What code currently does**: `oracle.py` `evaluate_boolean_expr(None)` or `evaluate_boolean_expr([])` returns `None` (treated as "unknown"). `ace_policy_decision` treats `None` returns as `saw_unknown = True`, which causes the function to return `None` (no decision), allowing a subsequent fallback path that may grant access.
- **Severity**: minor
- **Fix needed**: In `oracle.py` `evaluate_boolean_expr`, handle the empty/None case explicitly:
  ```python
  if not expr:  # None or empty list
      return False  # spec: empty BooleanExpr = ACE always False = not satisfied
  ```
  Then `ace_policy_decision` will receive `False` for that ACE and correctly return `NOT_AUTHORIZED` rather than deferring to fallback.

---

---

## Second Pass — Additional Discrepancies

### Second Pass Summary

Areas re-examined and disposition:

- **spec_tables.py POLICIES dict**: Found one genuine discrepancy (B-009). All `require_authenticated` flags and `allowed_authorities` sets are broadly correct for the public dataset; see B-009 for the ActiveKey contradiction.
- **solver.py vs oracle.py divergences**: Found three genuine divergences (B-010, B-011, B-012) beyond the already-noted Operation-column gap.
- **Edge cases in method specs**: Found one genuine new discrepancy (B-013) relating to conditional `NOT_AUTHORIZED` vs empty-ACL behavior.
- **normalizer.py**: No new object/method normalization gaps beyond B-004. The `BAD_LOCKING_SP_UID` hardcoding was examined and documented as a near-miss (B-014).

---

### B-009: spec_tables.py `_LOCKING_WRITABLE_COLS` includes ActiveKey (col 10 / hex "a"), contradicting Opal ACE table

- **Spec section**: opal/4.3.1.7 (Locking SP ACE Table Preconfiguration)
- **What spec says**: The Opal LockingSP ACE table defines Get ACEs that include `ActiveKey` in their `Columns` list (`ACE_Locking_RangeN_Get_RangeStartToActiveKey`), but defines NO Set ACE that includes `ActiveKey`. The only Locking Set ACEs that Opal defines cover `ReadLocked`, `WriteLocked`, `ReadLockEnabled`, `WriteLockEnabled`, `LockOnReset`, `RangeStart`, and `RangeLength`. There is no `ACE_Locking_*_Set_ActiveKey`. Per core/5.3.4.3: "If the ACL column for an access control association is empty (contains no ACEs), then that InvokingID/MethodID combination SHALL NOT be invocable. Attempts to invoke it SHALL fail with NOT_AUTHORIZED." ActiveKey Set has no ACE → always NOT_AUTHORIZED.
- **What code currently does**: `spec_tables.py` line ~157 `_LOCKING_WRITABLE_COLS = frozenset([..., "a", "b", ...])` includes `"a"` (hex for column 10 = ActiveKey) and `"b"` (NextKey) as writable. When `solver.py`'s `_expected_locking_set` checks `if not set(values).issubset(allowed)`, a Set targeting ActiveKey would be incorrectly allowed. By contrast, `spec_docs.py` line 242 correctly marks `"Locking": {0, 1, 2, 10, 12, 17, 18, 19}` (col 10 = ActiveKey read-only), so `oracle.py` would correctly fire the read-only check. This is an inconsistency between the two subsystems.
- **Severity**: minor (only affects solver.py path; oracle.py handles it correctly via spec_docs.py)
- **Fix needed**: In `spec_tables.py`, remove `"a"` from `_LOCKING_WRITABLE_COLS`. ActiveKey (col 10 / "a") has no Opal Set ACE and is correctly blocked by the read-only columns guard in oracle.py. Note: NextKey ("b", col 11) IS writable during IDLE state per core/5.7.2.2.12; it may remain.

---

### B-010: solver.py `_expected_authenticate` always returns SUCCESS regardless of credential match

- **Spec section**: core/5.3.4.1.14.1 items 3–5
- **What spec says**: Authenticate returns `SUCCESS` with result `True` only if the proof is correct; it returns `SUCCESS` with result `False` if the authority is disabled or the proof is wrong. A compliant SSD MAY NOT return `SUCCESS` with result `True` when the submitted proof does not match the stored credential.
- **What code currently does**: `solver.py` `_expected_authenticate` lines 622–625:
  ```python
  credential = self._credential_for_authority(authority)
  if credential is not None and self._values_equal(proof, credential):
      return ExpectedOutcome(status="SUCCESS")
  return ExpectedOutcome(status="SUCCESS")
  ```
  Both branches (credential matches AND credential does not match) return `ExpectedOutcome(status="SUCCESS")`. The comparison at line 623 does nothing — the fallthrough on line 625 unconditionally returns SUCCESS regardless. The `_compare_with_actual` method (lines 747–759) partially compensates by checking `auth_result`, but only when `expected.status == "SUCCESS"` and using a separate credential re-lookup — it does not cover the case where the status itself should be different.
  
  By contrast, `oracle.py` `judge_authenticate` correctly returns `fail_result` when `match is False` and the actual response is not `SUCCESS+False` or `auth_error`.
- **Severity**: critical — solver.py will judge an Authenticate with a wrong proof and `SUCCESS+True` as passing, where oracle.py would correctly flag it as a FAIL.
- **Fix needed**: In `solver.py` `_expected_authenticate`, replace the unconditional `return ExpectedOutcome(status="SUCCESS")` fallthrough with:
  ```python
  # Credential known, proof does not match → expect SUCCESS+False or NOT_AUTHORIZED
  if credential is not None:
      return ExpectedOutcome(
          status="SUCCESS",
          required_values={"Success": False},  # auth result must be False
      )
  # Credential unknown → accept either outcome
  return ExpectedOutcome(allowed_statuses={"SUCCESS", "NOT_AUTHORIZED"})
  ```

---

### B-011: solver.py `_expected_cpin_set` rejects Set on col 6 (Tries), contradicting spec 5.3.4.1.1.2

- **Spec section**: core/5.3.4.1.1.2
- **What spec says**: "The value of the Tries column MAY be reset from the host by successful invocation of the Set method on that cell to set the value to 0 (access control SHALL be properly fulfilled)." — the host is explicitly permitted to Set col 6 (Tries) to 0.
- **What code currently does**: `solver.py` `_expected_cpin_set` line 961:
  ```python
  if set(values) != {"3"}:
      return ExpectedOutcome(status="INVALID_PARAMETER")
  ```
  Any Set on C_PIN that includes a column other than col 3 (PIN) is rejected with INVALID_PARAMETER. In particular, a Set with `{"6"}` (Tries reset to 0) would be wrongly judged as FAIL.
  
  Note that this same bug was previously identified in `spec_docs.py` as B-005 (which marks col 6 as read-only in the oracle). B-011 is the parallel bug in the solver path. Both must be fixed for the two subsystems to agree.
- **Severity**: critical — same scenario as B-005 but in a different code path
- **Fix needed**: In `solver.py` `_expected_cpin_set`, change the column guard to allow col 3 (PIN) and col 6 (Tries set-to-0). Minimally: replace `if set(values) != {"3"}:` with `if not set(values).issubset({"3", "6"}):`.

---

### B-012: solver.py `_expected_authenticate` mishandles disabled authorities (returns SUCCESS instead of SUCCESS+False)

- **Spec section**: core/5.3.4.1.4, core/5.3.4.1.14.1 item 5a
- **What spec says**: "Attempts to authenticate a disabled authority using the Authenticate method SHALL return a result of False and a method status of SUCCESS."
- **What code currently does**: `solver.py` `_expected_authenticate` lines 617–618:
  ```python
  if authority not in self.state.enabled_authorities:
      return ExpectedOutcome(status="SUCCESS")
  ```
  This only checks for status=SUCCESS. The result (`auth_result=False`) is not checked. When `_compare_with_actual` runs (line 747), it enters the `expected.status == "SUCCESS"` branch and checks `should_succeed` against the actual auth_result. However, `should_succeed` is computed as:
  ```python
  should_succeed = authority == ANYBODY_AUTHORITY or (
      authority in self.state.enabled_authorities and self._values_equal(proof, credential)
  )
  ```
  For a disabled authority, `authority not in enabled_authorities` makes `should_succeed = False`. If `actual_result` is `True` (authentication succeeded despite being disabled), the check `actual_result != should_succeed` → `True != False` would return `False` — correctly flagging it as a FAIL. So partial correctness exists.

  BUT the problem is: if the actual auth_result returned is `None` (not present in the response), `_compare_with_actual` skips the result check entirely (`if actual_result is not None and actual_result != should_succeed`), accepting any SUCCESS status as compliant even if the auth result is absent. The oracle.py explicitly checks that `auth_result is False` for the disabled-authority case.
- **Severity**: minor — only triggers when SSD response omits the auth result boolean field
- **Fix needed**: In `solver.py` `_compare_with_actual` authentication branch, when `should_succeed is False` and `actual_result is None`, treat the verdict as uncertain (return True/pass with low confidence) rather than silently accepting, OR require `auth_result is False` explicitly as oracle.py does.

---

### B-013: oracle.py `ace_policy_decision` — empty ACL treated as unknown rather than NOT_AUTHORIZED

- **Spec section**: core/5.3.4.3
- **What spec says**: "If the ACL column for an access control association is empty (contains no ACEs), then that InvokingID/MethodID combination SHALL NOT be invocable. Attempts to invoke it SHALL fail with status code NOT_AUTHORIZED."
- **What code currently does**: `oracle.py` `ace_policy_decision` (lines 479–526): when an `access_control_rows` match is found but `refs = row.get("ace_refs") or []` is empty, the code sets `saw_unknown = True` (line 500). If all matched rows have empty `ace_refs`, the function returns `None` (no decision, line 526), causing the calling `policy_status_result` to skip the ACE check entirely — allowing the operation to fall through to family-level fallback logic, which may grant access.

  Note: this differs from B-008 (which was about empty `BooleanExpr` within an ACE resolving to `None`). B-013 is about an AccessControl row that EXISTS but has an empty ACL (no ACE references at all). The spec mandates NOT_AUTHORIZED; the code produces `None` (unknown → grant via fallback).
- **Severity**: minor — only triggered if the spec index correctly populates an AccessControl row with an empty `ace_refs` list; most rows have non-empty ACL columns. In practice, this path fires when parsed preconfiguration tables yield an AccessControl row without extracting ACE refs.
- **Fix needed**: In `oracle.py` `ace_policy_decision`, change the empty-refs handling:
  ```python
  refs = row.get("ace_refs") or []
  if not refs:
      # ACL column is empty → spec mandates NOT_AUTHORIZED (core/5.3.4.3)
      saw_denied = True
      denied_source = f"AccessControl:{row.get('source') or row.get('name')} empty ACL"
      continue
  ```
  This converts the empty-ACL case from "unknown" to "denied", matching the spec's SHALL.

---

### B-014 (near-miss, not a code bug): normalizer.py `BAD_LOCKING_SP_UID` hardcoded value

- **Spec section**: N/A (implementation concern)
- **Observation**: `normalizer.py` line 11 defines `BAD_LOCKING_SP_UID = "0000010500000004"` and maps it to `"NonLockingSP"` in `canonical_object`. This is a hardcoded UID used to simulate a "bad" or incorrect SP UID in test cases. The oracle's `judge_start_session` would then see `sp = "NonLockingSP"` (not "AdminSP" or "LockingSP") and correctly predict failure.
  
  However, test cases using a *different* incorrect SP UID (not exactly `0000010500000004`) would NOT be recognized as "NonLockingSP". They would fall through `canonical_object` to the `uid.startswith("00000205")` check (only matches valid SP UIDs), returning `None` or the UID string. The `canonical_sp` function maps `0000010500000004` through neither branch, so `event["sp"]` would be `None` or an opaque string. `judge_start_session` tests `if sp is None` → returns INVALID_PARAMETER, which would predict a fail — that may or may not be correct depending on the actual spec behavior for unknown SP UIDs (spec says FAIL for unknown SPID, so the prediction may coincidentally be correct).
  
  This is not a new bug per se, but documents a brittleness: the "bad SP UID" pattern depends on using exactly `0000010500000004`.
- **Severity**: informational — no code change needed unless hidden test cases use other bad SP UIDs.

---

## Files Audited

| File | Lines | Role |
|---|---|---|
| `src/oracle.py` | ~2260 | Main rule oracle — primary source of discrepancies |
| `src/state.py` | ~976 | State tracker — SetPackage and Authority.Uses gaps |
| `src/spec_docs.py` | ~300 | Column definitions — Tries read-only bug |
| `src/normalizer.py` | ~665 | Object normalization — C_RSA/C_EC/C_AES family gap |
| `src/spec_tables.py` | ~393 | Legacy policy tables — no new discrepancies found |
| `src/solver.py` | ~1382 | Legacy solver — same Operation-column gap as oracle.py (separate code path) |

## Spec Sections Reviewed

- core/5.3.2.1 – 5.3.2.20 (all data structure tables: SPInfo, Table, Column, ACE, Authority, C_PIN, C_RSA, C_AES, C_EC variants)
- core/5.3.3.1 – 5.3.3.18 (all method specifications: Get, Set, Next, Authenticate, StartSession, EndSession, GenKey, Revert, Activate, etc.)
- core/5.3.4.1.1 – 5.3.4.1.14.1 (authentication mechanics: TryLimit, Tries, Awaiting Challenge state machine, Operation column semantics)
- core/5.3.4.2.1 – 5.3.4.2.7 (table management methods)
- core/5.3.4.3 – 5.3.4.6 (access control, SetPackage, logging)
- core/5.3.5.1 (Base Template lifecycle)

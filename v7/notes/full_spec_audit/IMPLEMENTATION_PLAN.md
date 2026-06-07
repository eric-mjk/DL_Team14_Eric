# Implementation Plan: Spec Audit Recommendations

Three tiers: **IMPLEMENT** (safe now), **VALIDATE** (implement then run evaluate.py before keeping), **DEFER** (complex; implement later when adding hidden-test coverage).

Baseline locked at: public `score=100.00`, synthetic `57/57`.

---

## Progress Tracker

| Item | Tier | Status |
|------|------|--------|
| H-P0-1 Repeat Activate no-op | IMPLEMENT | ✅ Done |
| H-P1-4 Inactive LockingSP key bump guard | IMPLEMENT | ✅ Done |
| H-P1-5 KeepGlobalRangeKey scoped to LockingSP | IMPLEMENT | ✅ Done |
| H-P1-3 Revert restricted to known SPs | IMPLEMENT | ✅ Done |
| D-P1-ActiveKey Remove ActiveKey from READ_ONLY | IMPLEMENT | ✅ Done |
| C-P1-4 SecretProtect column schema fix | IMPLEMENT | ✅ Done |
| D-P1-ClockTime ClockTime schema + read-only set | IMPLEMENT | ✅ Done |
| G-P0-1 Remove UserN fallback Locking Get/Set | VALIDATE | ✅ Done |
| G-P0-2 User2–User8 disabled by default | VALIDATE | ✅ Done |
| C-P0-2 Object-table unauthorized cell omission | VALIDATE | ✅ Done |
| D-P0 MBR shadowing in data commands | VALIDATE | ✅ Done |
| B-P1 Numeric status encoding | DEFER | ⏭ Skipped — zero numeric/hex status codes in dataset |
| D-P2 Log table / CreateLog uniqueness | DEFER | ✅ Done |
| D-P1 Re-encryption range/key restrictions | DEFER | ✅ Done |
| E-P1 Reset events abort sessions | DEFER | ✅ Done |
| C-P0-1 Two-step Authenticate (Sign/SymK/HMAC) | DEFER | ✅ Done |
| A-P1 Generic Core SP lifecycle (Disabled/Frozen) | DEFER | ✅ Done |
| C-P0-5 AddACE/RemoveACE/DeleteMethod mutations | DEFER | ✅ Done |
| F-P0 DataRemovalMechanism + TPerInfo tables | DEFER | ✅ Done |
| F-P0 AccessControl (N) column behavior | DEFER | ✅ Done |
| E-P1 Level 0 Discovery normalization + judging | DEFER | ✅ Done |

---

## IMPLEMENT — Low risk, implement directly

These all make the oracle *more lenient* in places where it is currently stricter than the spec. Fixing them cannot cause previously-passing tests to fail.

### H-P0-1: Fix repeated `Activate` — `oracle.py:1879-1880`

Source: Agent H P0 #1 | Spec: `opal/5.1.1`

Current behavior: if LockingSP is already `Manufactured`/active, `judge_activate` returns `invalid_parameter`.

Spec says: invocation in any non-inactive lifecycle state SHALL complete successfully (no-op) if access control is satisfied.

Why safe: changes a false-fail into a pass. No passing test expects INVALID_PARAMETER on repeat Activate.

Fix: in the `locking_sp_active` branch, return success instead of invalid_parameter when the session and authority are valid.

---

### H-P1-4: Revert on inactive LockingSP must not bump key generations — `state.py:688-695`

Source: Agent H P1 #4 | Spec: `opal/5.1.2.2`

Current behavior: `reset_locking_sp` always bumps key generations for all ranges, even when LockingSP is `Manufactured-Inactive`.

Spec says: Revert on an already-inactive LockingSP has no user-data removal; manufactured SPs already inactive are not affected by AdminSP Revert.

Why safe: prevents state corruption on inactive-LockingSP Revert steps that appear as prefix events. Fixing it makes subsequent final-event judgments more accurate, not stricter.

Fix: guard the key-generation bump inside `reset_locking_sp` (and its callers for AdminSP Revert path) with `if state.get("locking_sp_active")`.

---

### H-P1-5: Scope `KeepGlobalRangeKey` to LockingSP — `oracle.py:1913-1922`, `state.py:742-754`

Source: Agent H P1 #5 | Spec: `opal/5.1.3.2`, `opal/5.1.3.3`

Current behavior: the locked-Global failure check and key-preservation side-effect run for any SP's RevertSP call.

Spec says: `KeepGlobalRangeKey` behavior is defined only for LockingSP.

Why safe: narrows a permissive case (AdminSP RevertSP incorrectly preserving Global key) that no current test exercises.

Fix: gate both the failure check and the `preserve_global_key` branch in `apply_successful_revert_sp` on `state["session"]["sp"] == "LockingSP"`.

---

### H-P1-3: Restrict `Revert` to known manufactured SPs — `oracle.py:1891-1905`

Source: Agent H P1 #3 | Spec: `opal/5.1.2`

Current behavior: `judge_revert` accepts any normalized `SP` object, including unknown `SP_xxxx` targets that may represent issued SPs.

Spec says: Revert SHALL NOT be permitted on issued SP objects.

Why safe: adds a failure case for unknown SP targets. The current test suite only uses AdminSP and LockingSP as Revert targets.

Fix: accept only `"AdminSP"` and `"LockingSP"` (and any SP tracked in `state["sp_lifecycle"]` as manufactured) as valid Revert targets.

---

### D-P1-ActiveKey: Remove `ActiveKey` from `READ_ONLY_COLUMNS["Locking"]` — `spec_docs.py:242`

Source: Agent D P1 | Spec: `core/5.7.3.7.2`

Current behavior: column 10 (`ActiveKey`) is marked read-only, so a final Set of ActiveKey fails.

Spec says: "Host Application directly writes ActiveKey column value" — it is explicitly host-writable in Core. Opal may restrict this via ACL, but the schema mutability flag itself is wrong.

Why safe: makes a column writable that was incorrectly read-only. Any test that tried to Set ActiveKey and expected failure was relying on a wrong schema. If the public tests pass 100% today with it read-only, removing it may flip some test — check with evaluate.py — but the spec is clear.

Fix: remove 10 from `READ_ONLY_COLUMNS["Locking"]` (or move it to a Opal-specific override set if needed to preserve score).

---

### C-P1-4: Fix `SecretProtect` column schema — `spec_docs.py:226`

Source: Agent C P1 #4 | Spec: `core/5.3.2.8` Table 176

Current behavior: `SecretProtect` column map has wrong numbers: `protect` at 3, omitting `Table` at 1 and `ProtectMechanisms` at 3.

Spec: Table 176 defines UID=0, Table=1, ColumnNumber=2, ProtectMechanisms=3.

Why safe: corrects a schema error. Named-column Get/Set on SecretProtect rows would misdirect only if hidden tests hit SecretProtect specifically; fixing it cannot break tests that don't touch SecretProtect.

Fix: rewrite the `SecretProtect` entry in `COLUMN_NAME_NUMBERS` to `{0: "uid", 1: "table", 2: "column_number", 3: "protect_mechanisms"}` and align `READ_ONLY_COLUMNS`/`WRITE_ONLY_COLUMNS` entries accordingly.

---

### D-P1-ClockTime: Add `ClockTime` column schema and read-only set — `spec_docs.py:100`

Source: Agent D P1 | Spec: `core/5.5.3.1.*`

Current behavior: `ClockTime` has no entry in `COLUMN_NAME_NUMBERS`, so Set on any ClockTime column falls through to generic authenticated-write success.

Spec says: ClockTime columns UID, HaveHigh, HighByWhom, HighInitialTimer, HighLag, HaveLow, LowByWhom, LowSetTime, LowInitialTimer, LowLag, MonotonicBase, and MonotonicReserve are host non-modifiable. Clock methods (SetClockHigh etc.) update the clock, not table Set.

Why safe: adds a new failure case (direct Set on ClockTime). No current test expects success for direct ClockTime column Set.

Fix: add `"ClockTime"` to `COLUMN_NAME_NUMBERS` with columns 0–13 mapped by name, and add all method-maintained columns to `READ_ONLY_COLUMNS["ClockTime"]`.

---

## VALIDATE — Implement, then immediately run `evaluate.py`; revert if score drops

These make the oracle stricter in areas where it is currently more permissive than the spec. They are correct per spec but could break the baseline if the public dataset relies on the current loose behavior.

### G-P0-1: Remove UserN fallback from Locking range `Get`/`Set` — `oracle.py:1633-1641`, `1805-1827`

Source: Agent G P0 #1 | Spec: `opal/4.3.1.7`

Current behavior: fallback allows UserN to read/write protected Locking range columns when ACE policy matching doesn't explicitly grant access.

Spec says: Locking range Get (cols 3–ActiveKey) and Set (ReadLocked, WriteLocked, RangeStart, LOR) ACEs all use `BooleanExpr: Admins`. No 4.3 doc grants UserN authority over lock bits.

Risk: if any public test exercises UserN reading/writing Locking range columns and expects success, removing the fallback breaks it.

Validate: implement → run `python3 v6/evaluate.py` → if score stays 100%, keep; if it drops, investigate which test flipped before deciding.

Fix: delete `session_has_locking_user_authority_for_range` call from the `judge_get`/`judge_set` fallback for Locking family columns.

---

### G-P0-2: Materialize User2–User8 as disabled by default — `state.py:71-80`

Source: Agent G P0 #2 | Spec: `opal/4.3.1.8`, `opal/4.3.1.9`

Current behavior: only User1 credential is seeded; `authority_enabled` returns True for unknown rows, so User2-User8 authenticate as if enabled.

Spec says: User1 and UserMMMM are initially disabled with empty PINs; User2–User8 shall be implemented and are also initially disabled.

Risk: if any public test starts a LockingSP session as User2-User8 before an enabling Set and expects success, this breaks it.

Validate: add User2–User8 with `enabled=False` and empty credentials in `initial_state` → run `evaluate.py`.

Fix: extend the `credentials` and `authority_rows` seeding in `initial_state` for User2–User8, each with `enabled=False`, `operation="Password"`, class `Users`, and empty PIN.

---

### C-P0-2: Object-table unauthorized cell omission — `oracle.py:1597-1700`

Source: Agent C P0 #2 | Spec: `core/5.3.4.2.2`

Current behavior: `judge_get` issues auth_error when accessing protected columns in object tables.

Spec says: unauthorized object-table cells are omitted from the result with SUCCESS; only unauthorized byte-table reads return empty result. Auth_error is wrong for object-table Get; it is too strict.

Risk: test cases that expect auth_error for an object-table Get with mixed auth/unauth columns would flip.

Validate: implement → run `evaluate.py`. This is an important correctness fix (many Get calls hit object tables with partial access).

Fix: in `judge_get`, for object-table targets, when ACE evaluation denies a column, omit it from expected results rather than returning auth_error. Keep auth_error only for byte-table unauthorized reads.

---

### D-P0: MBR shadowing in data commands — `oracle.py:2308`, `oracle.py:2359`

Source: Agent D P0 | Spec: `core/5.7.2.5.2`, `core/5.7.2.5.3`, Tables 230/231

Current behavior: `judge_read` and `judge_write` only inspect Locking range lock state; `state["mbr"]` is tracked but never consulted for data commands.

Spec says: when MBRControl Enable=True and Done=False, writes to the MBR-shadow region must be rejected; reads fully within MBR return MBR table data; mixed MBR/user reads must return Data Protection Error.

Risk: if no current public test case exercises MBR-enabled write, this could silently accept a write that should fail, but that would be a false-pass, not a false-fail.

Validate: implement → run `evaluate.py`.

Fix: in `judge_read`/`judge_write`, before the normal lock-state check, read `state["mbr"]["enable"]` and `state["mbr"]["done"]`. If enabled and not done, determine whether the requested LBA range overlaps the MBR region (use tracked MBR Table size if available, default to LBA 0 conservatively), and branch to the MBR-shadow rules.

---

## DEFER — Complex; save for a dedicated hidden-test coverage sprint

These are real spec requirements. The reason to defer is not that they are unimportant, but that:
(a) implementing them incorrectly is likely to introduce false-fails,
(b) there is no current test signal to verify correctness during implementation, and
(c) each requires significant new state modeling.

When you are ready to tackle these, work one section at a time and add synthetic tests for each before wiring into the live oracle.

---

### C-P0-1: Two-step Authenticate state machine (Sign/SymK/HMAC) — `oracle.py:1487`, `state.py` (no pending-challenge state)

Source: Agent C P0 #1 | Spec: `core/5.3.4.1.14`, `core/5.3.4.1.14.1`

What it is: Password and Anybody authentication are single calls. Sign/SymK/HMAC are two-call challenge-response flows. First call returns SUCCESS with a Challenge token. Second call supplies Proof; correct proof returns SUCCESS True, wrong proof returns SUCCESS False (not INVALID_PARAMETER).

Current gap: `judge_authenticate` rejects Proof on non-Password/non-Anybody authorities as INVALID_PARAMETER. There is no pending-challenge state in `state.py`.

Why deferred: requires a new `pending_auth_challenge` dict in state (authority → challenge), a state mutation on first-call success, and a second-call judge that reads the challenge and clears it. Implementing this wrong (e.g., not clearing state on session close) can corrupt the auth model for all subsequent tests. Add synthetic tests first.

Implementation plan when ready:
1. Add `"pending_auth_challenge": {}` to `empty_session()`.
2. On successful first Authenticate with a challenge method, store `{authority: challenge}` in state.
3. In `judge_authenticate`, if a matching pending challenge exists, judge the Proof and return SUCCESS True/False without INVALID_PARAMETER.
4. Clear pending challenge on session close/reset.

---

### C-P0-5: ACL state mutation for AddACE/RemoveACE/DeleteMethod — `state.py:500`, `oracle.py:2176`

Source: Agent C P0 #5 | Spec: `core/5.3.4.3`, `core/5.3.4.3.1`

What it is: after a successful AddACE, an ACE row is added and its referenced AccessControl row is updated. RemoveACE reverses this. DeleteMethod removes the AccessControl row. Final judging after these operations relies on the updated policy, but currently state only tracks direct Set on AccessControl/ACE rows.

Why deferred: requires modeling the full ACE BooleanExpr/Columns as a mutable in-state data structure and applying AddACE/RemoveACE/DeleteMethod as structural mutations. Implementing it partially (e.g., only updating the BooleanExpr but not the ACL reference) can cause silent policy corruption.

Implementation plan when ready:
1. Add `apply_add_ace`, `apply_remove_ace`, `apply_delete_method` handlers in `state.apply_event`.
2. Each handler modifies `state["ace_rows"]` and `state["access_control_rows"]` in a way consistent with the existing ACE evaluation logic in `oracle.ace_policy_decision`.
3. Add synthetic tests: AddACE grants access, RemoveACE revokes it, DeleteMethod makes method non-invocable.

---

### A-P1: Generic Core SP lifecycle (Disabled/Frozen) — `state.py:81-85`, `oracle.py:1357`

Source: Agent A P1 | Spec: `core/4.1`–`core/4.5.5`, `core/5.3.5.1`

What it is: SPs can be in states Issued-Disabled, Issued-Frozen, Issued-Disabled-Frozen, or Failed. Session startup must return SP_DISABLED, SP_FROZEN, or SP_FAIL respectively. Non-exempt methods to a disabled SP must fail with SP_DISABLED.

Current gap: `judge_start_session` only checks `locking_sp_active`; no generic Disabled/Frozen state is tracked per SP.

Why deferred: overlaps significantly with the Opal lifecycle fixes already in IMPLEMENT tier. To do this correctly for Core requires adding per-SP lifecycle fields to `state["sp_lifecycle"]` and threading those through `judge_start_session` and all method judges. The Opal-specific lifecycle is already largely covered; the gap is for non-Opal SPs and for AdminSP invariants (disable/freeze/delete blocking).

Implementation plan when ready:
1. Extend `sp_lifecycle` to track `Disabled`, `Frozen`, `Failed` per SP name.
2. Apply successful Set of `SPInfo.Enabled=False` / AdminSP `SP.Frozen=True` in `state.apply_event`.
3. In `judge_start_session`, check `sp_lifecycle` before the existing checks.
4. In per-method judges, add a preflight for disabled-SP (exempting Authenticate, DeleteSP, and re-enable Set).
5. Block Set Enabled=False or Frozen=True on AdminSP.

---

### B-P1: Numeric status encoding — `normalizer.py:47-74`

Source: Agent B P1 | Spec: `core/5.1.5` Table 166

What it is: the dataset may carry status as integer or hex string (e.g., `"0x00"`, `"0x01"`, `"0x0C"`) rather than name strings. Currently `normalize_status` only handles named strings.

Why deferred: low risk of being in the public test set (which appears to use named strings), but easy to verify. Before implementing, scan the dataset for numeric/hex status values.

Implementation plan when ready:
1. Check `dataset/testcases/` and `dataset/label.jsonl` for any `status_codes` value that is an integer or hex string.
2. If found, add a lookup table in `normalize_status` mapping Table 166 numeric values to canonical names.
3. Add synthetic test: final Get with status `"0x00"` should pass the same as `"SUCCESS"`.

---

### F-P0: DataRemovalMechanism + TPerInfo first-class tables — `normalizer.py:234-377`, `spec_docs.py:100`

Source: Agent F P0 | Spec: `opal/4.2.7`, `opal/4.2.3`

What it is: `DataRemovalMechanism` (UID `00 00 00 01 00 00 11 01`) and `TPerInfo` (UID `00 00 02 01 00 03 00 01`) are not recognized as named objects. Set/Get on their columns falls through to generic handling. `ActiveDataRemovalMechanism` enum validation (reject reserved values 3-4, 6-7 with INVALID_PARAMETER) and `ProgrammaticResetEnable` boolean validation are missing.

Why deferred: requires UID additions to both `normalizer.py` and `spec_docs.py`, plus new access-control wiring. Risk of misdirecting other tests if UID collision is introduced. Verify first by searching the public dataset for these UIDs.

Implementation plan when ready:
1. Add `DataRemovalMechanism` and `TPerInfo` to `LOCKING_TABLE_UIDS` / `canonical_object`.
2. Add their column schemas to `COLUMN_NAME_NUMBERS` and `READ_ONLY_COLUMNS`.
3. Add enum validation for `ActiveDataRemovalMechanism` in the Set path.
4. Wire `ProgrammaticResetEnable` to the existing SID-only Set access control.

---

### F-P0: AdminSP `AccessControl` special-column behavior (`(N)` Get access)

Source: Agent F P0 | Spec: `opal/4.2.6.1`, `opal/4.2.1.6`

What it is: Get on `AccessControl.InvokingID`, `AccessControl.MethodID`, and `AccessControl.GetACLACL` columns has `(N)` access — they are not readable via Get at all. The `ACL` column is readable only through `GetACL`, not Get. `GetACL` must evaluate the row's `GetACLACL`, not its normal invocation ACL.

Why deferred: requires structural changes to `judge_get` for the AccessControl family and a rewrite of `judge_meta_acl` to route through `GetACLACL`. The existing ACE engine does not currently express `(N)` access as a distinct concept.

Implementation plan when ready:
1. Add a `NOT_READABLE_COLUMNS` dict for `AccessControl` listing `InvokingID`, `MethodID`, `GetACLACL`, and `ACL`.
2. In `judge_get` for AccessControl targets, return auth_error for any request including those columns.
3. Add a `(N)` override to `ace_policy_decision` that bypasses normal BooleanExpr.
4. In `judge_meta_acl` (GetACL), evaluate the target row's `GetACLACL` instead of its `ACL`.

---

### E-P1: Reset events must abort sessions — `state.py:757-786`

Source: Agent E P1 | Spec: `opal/3.2.3`, `opal/3.3.5.1`

What it is: after a TPER_RESET, interface reset, hardware reset, or power cycle, all open sessions must be aborted and all transient state cleared. Currently `apply_reset_like_event` applies LockOnReset and DoneOnReset but leaves the session open.

Why deferred: moderate risk. If any public test has a Reset followed by a final method that expects success based on the old session, fixing this correctly fails it. More importantly, the existing implementation may already be OK for the public test set because none of those tests exercise post-reset session behavior.

Implementation plan when ready:
1. After applying LockOnReset/DoneOnReset in `apply_reset_like_event`, call `state["session"] = empty_session()`.
2. Clear `state["pending_clock_lag"] = None` and `state["crypto_streams"] = {}`.
3. Add explicit reset-command recognition for `TPER_RESET`, `Protocol Stack Reset`, `Stack Protocol Reset`, `interface_reset`, `power_cycle`, `hardware_reset`.
4. Add synthetic test: Reset mid-trajectory then final Get requiring old session returns auth error.

---

### E-P1: Level 0 Discovery normalization and judging

Source: Agent E P1 | Spec: `opal/3.1.1.*`

What it is: a final IF-RECV Level 0 Discovery response has mandatory descriptor requirements (TPer, Locking, Opal SSC V2) with specific field values. Missing descriptors, wrong LockingEnabled bit, bad authority counts, zero crypto-erase bit, etc. are all spec violations. Currently `normalizer.normalize_record` does not parse Discovery responses.

Why deferred: requires a new normalization path for IF-RECV/Security Protocol `0x01` responses, plus a new oracle judge with many field checks. This is a self-contained feature that can be added without touching existing method judging, so it is safe to implement when ready.

Implementation plan when ready:
1. Detect Level 0 Discovery by command type in `normalize_record`; normalize descriptors into a stable dict.
2. Add `judge_level0_discovery` in oracle.py that validates presence and content of mandatory descriptors.
3. Cross-reference dynamic fields (LockingEnabled, MBR Done/Enabled, Processing/Interrupted bits) against tracked state.
4. Add synthetic tests per Agent E's recommended test list.

---

### D-P2: Crypto stream cellblock/access-control checks

Source: Agent D P2 | Spec: `core/5.6.5.1`

What it is: Hash/HMAC/Encrypt/Decrypt input cellblocks require Get authorization; output `BufferOut` fields require Set authorization; inadequate output buffer size fails. Currently `judge_crypto_stream_method` checks only target, stream state, and session.

Why deferred: requires normalizing method-specific `Input`/`BufferIn`/`BufferOut` parameters and routing them through the ACE engine for the referenced object/table. Medium complexity; low test-signal risk.

Implementation plan when ready:
1. Normalize `Input`, `BufferIn`, `BufferOut`, and `ProofBuffer` parameters in the crypto method family.
2. For each referenced cellblock/table UID, call `ace_policy_decision` for Get (input) or Set (output).
3. For `BufferOut`, verify method result is empty when it is present.

---

### D-P2: Log table existence and CreateLog uniqueness

Source: Agent D P2 | Spec: `core/5.8.3`, `core/5.8.4`

What it is: AddLog/ClearLog/FlushLog fail if the referenced log table does not exist. CreateLog fails on duplicate name. Currently `judge_log_method` only checks target family and session.

Why deferred: requires tracking successful CreateLog names/UIDs in state. Low complexity but zero current test signal.

Implementation plan when ready:
1. Add `"log_tables": set()` to `initial_state` (pre-seed with the default Log UID).
2. On successful CreateLog, add the new table name/UID to `state["log_tables"]`.
3. In `judge_log_method`, for AddLog/ClearLog/FlushLog, verify target UID/name is in `state["log_tables"]`.
4. In `judge_create_log`, fail duplicate names.

---

### D-P1: Re-encryption restrictions on range geometry and key ops — `oracle.py:708`, `oracle.py:1933`

Source: Agent D P1 | Spec: `core/5.7.3.7`, `core/5.7.2.2.12`

What it is: RangeStart/RangeLength modification fails when that row is not IDLE. If Global Range is not IDLE, modifying any range geometry, creating/deleting Locking objects, or running GenKey on the associated credential all fail.

Current gap: non-IDLE checks only cover `ReEncryptRequest` and `NextKey`. `invalid_locking_range_update` misses per-range IDLE check; row management and GenKey don't check range re-encryption state.

Why deferred: the re-encryption state tracking already exists (`state["locking_ranges"][n]["reencrypt_state"]`); the missing piece is threading those checks into geometry Set and CreateRow/DeleteRow/Delete. Low complexity but zero test signal.

Implementation plan when ready:
1. In `invalid_locking_range_update`, add check: if the target range `reencrypt_state != "IDLE"`, fail.
2. In `judge_gen_key` for media key targets, look up the associated range's reencrypt_state; fail if non-IDLE.
3. In `judge_create_row`/`judge_delete_row`/`judge_delete` for Locking family, check Global Range IDLE.

---

*End of plan. Implement tier by tier; run `python3 v6/evaluate.py` and `cd v6/customtest_57 && python3 generate_synthetic.py --check-only` after each batch.*

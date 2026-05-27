# Verification Agent 2: IMPLEMENT/VALIDATE Code Audit

Scope: inspected `IMPLEMENTATION_PLAN.md`, current git diff, and current `v6/src/{normalizer.py,oracle.py,spec_docs.py,state.py}`. I did not edit source or testcase files.

## Summary

| Item | Verdict |
|---|---|
| H-P0-1 Repeat Activate no-op | Partial |
| H-P1-4 Inactive LockingSP key bump guard | Correct |
| H-P1-5 KeepGlobalRangeKey scoping | Correct |
| H-P1-3 Revert target restriction | Correct |
| D-P1-ActiveKey schema | Correct |
| C-P1-4 SecretProtect schema | Correct |
| D-P1-ClockTime schema/read-only | Partial |
| G-P0-1 Remove UserN Locking fallback | Correct |
| G-P0-2 User2-User8 disabled defaults | Partial |
| C-P0-2 Object-table unauthorized cell omission | Partial |
| D-P0 MBR shadowing in read/write | Partial |

## Findings

### H-P0-1 Repeat Activate no-op: Partial

Source:
- `oracle.judge_activate`, `v6/src/oracle.py:1954-1974`
- `state.apply_successful_activate`, `v6/src/state.py:727-734`

Expected behavior: `Activate` on an already active/non-inactive LockingSP must complete successfully if access control is satisfied and otherwise be a no-op. It must not re-run first-activation side effects.

Implementation:
- The oracle side is correct: `judge_activate` returns `success` instead of `invalid_parameter` when `state["locking_sp_active"]` is already true (`oracle.py:1958-1967`).
- The state side is not a no-op. `apply_successful_activate` always sets `locking_sp_active = True`, sets lifecycle to `Manufactured`, and overwrites `Admin1` with current `SID` (`state.py:727-734`). A repeated successful Activate in the prefix can corrupt later credential judgments if Admin1 was changed after initial activation.

Recommended fix: in `apply_successful_activate`, return immediately when `state.get("locking_sp_active")` is already true. Only perform SID-to-Admin1 propagation on the inactive-to-active transition.

### H-P1-4 Inactive LockingSP key bump guard: Correct

Source:
- `state.reset_locking_sp`, `v6/src/state.py:764-780`
- callers `apply_successful_revert`, `v6/src/state.py:802-819`, and `apply_successful_revert_sp`, `v6/src/state.py:822-835`

Expected behavior: Revert of an already inactive LockingSP must not model user-data removal or media-key eradication.

Implementation: `reset_locking_sp` captures `locking_was_active` and only bumps key generations inside `if locking_was_active` (`state.py:764-775`). The reset still returns the SP, ranges, MBR, and credentials to defaults, which is consistent with the lifecycle reset path.

Recommended fix: none for this plan item.

### H-P1-5 KeepGlobalRangeKey scoping: Correct

Source:
- `oracle.judge_revert_sp`, `v6/src/oracle.py:2010-2033`
- `state.apply_successful_revert_sp`, `v6/src/state.py:822-835`

Expected behavior: `KeepGlobalRangeKey` is defined only for LockingSP `RevertSP`; it must not affect AdminSP `RevertSP`.

Implementation:
- The locked-Global failure check is gated by `sp == "LockingSP"` (`oracle.py:2015-2025`).
- State preservation is also gated by `sp == "LockingSP"`, and AdminSP passes `preserve_global_key=False` (`state.py:822-830`).

Recommended fix: none.

### H-P1-3 Revert target restriction: Correct

Source:
- `oracle.judge_revert`, `v6/src/oracle.py:1977-2007`
- `normalizer.canonical_sp`, `v6/src/normalizer.py:167-175`

Expected behavior: Opal `Revert` should be permitted only for known manufactured SPs, not unknown/issued SP rows.

Implementation: `judge_revert` rejects non-SP families, then accepts only `AdminSP`, `LockingSP`, or tracked SPs whose lifecycle string contains `manufactured`; otherwise it returns an error (`oracle.py:1977-1995`). Unknown SP UIDs normalize to `SP_xxxx` via `canonical_sp` (`normalizer.py:167-175`), so they are rejected unless explicitly tracked as manufactured.

Recommended fix: none.

### D-P1-ActiveKey schema: Correct

Source:
- `spec_docs.COLUMN_NAME_NUMBERS["Locking"]`, `v6/src/spec_docs.py:111-134`
- `spec_docs.READ_ONLY_COLUMNS["Locking"]`, `v6/src/spec_docs.py:262-280`

Expected behavior: Locking column 10, `ActiveKey`, must be schema-writable; policy/range rules may still restrict it, but it must not be treated as a read-only column.

Implementation: `activekey` maps to column 10 (`spec_docs.py:121-123`), and column 10 is no longer in the Locking read-only set (`spec_docs.py:267`).

Recommended fix: none for the schema item.

### C-P1-4 SecretProtect schema: Correct

Source:
- `normalizer.canonical_object`, `v6/src/normalizer.py:292-293`
- `normalizer.object_family`, `v6/src/normalizer.py:377-378`
- `spec_docs.COLUMN_NAME_NUMBERS["SecretProtect"]`, `v6/src/spec_docs.py:235`
- `spec_docs.READ_ONLY_COLUMNS["SecretProtect"]`, `v6/src/spec_docs.py:275`

Expected behavior: SecretProtect columns are UID=0, Table=1, ColumnNumber=2, ProtectMechanisms=3.

Implementation: UID prefix `0000001D` normalizes to SecretProtect, and the column map now matches the Core SecretProtect table (`spec_docs.py:235`). The read-only set no longer incorrectly marks columns 1 and 2 read-only (`spec_docs.py:275`).

Recommended fix: none.

### D-P1-ClockTime schema/read-only: Partial

Source:
- `normalizer.canonical_object`, `v6/src/normalizer.py:267-268`
- `normalizer.object_family`, `v6/src/normalizer.py:354-355`
- `spec_docs.COLUMN_NAME_NUMBERS["ClockTime"]`, `v6/src/spec_docs.py:236-251`
- `spec_docs.READ_ONLY_COLUMNS["ClockTime"]`, `v6/src/spec_docs.py:276`

Expected behavior: ClockTime schema should match Core Table 218: UID=0, HaveHigh=1, HighByWhom=2, HighSetTime=3, HighInitialTimer=4, HighLag=5, HaveLow=6, LowByWhom=7, LowSetTime=8, LowInitialTimer=9, LowLag=10, MonotonicBase=11, MonotonicReserve=12, TrustMode=13. Direct table `Set` to these method-maintained columns should be rejected as read-only/non-modifiable.

Implementation:
- Family recognition is implemented (`normalizer.py:267-268`, `normalizer.py:354-355`).
- Read-only enforcement covers columns `0..13` (`spec_docs.py:276`).
- The schema map is wrong. It adds non-ClockTime columns `name` and `commonname` at 1 and 2, shifts the real fields by two, omits `HighSetTime`, and omits `TrustMode` (`spec_docs.py:236-251`).

Impact: numeric `Set` attempts are blocked, but named hidden cases normalize to the wrong columns or fail as unrecognized. Named `HighSetTime`, `LowLag`, `MonotonicReserve`, and `TrustMode` are especially affected.

Recommended fix: replace the ClockTime column map with the exact Table 218 mapping above, then keep `READ_ONLY_COLUMNS["ClockTime"] = set(range(14))`.

### G-P0-1 Remove UserN Locking fallback: Correct

Source:
- stale helper `oracle.session_has_locking_user_authority_for_range`, `v6/src/oracle.py:287-301`
- `oracle.judge_get` Locking fallback, `v6/src/oracle.py:1713-1760`
- `oracle.judge_set` Locking fallback, `v6/src/oracle.py:1898-1907`

Expected behavior: fallback Locking range Get/Set for protected columns should require Admin authority in LockingSP. UserN should not be granted access by fallback logic.

Implementation: `judge_get` now permits protected Locking columns only for public columns or LockingSP Admin authority (`oracle.py:1713-1728`). `judge_set` now requires `authenticated_locking_admin_write` for all Locking sets (`oracle.py:1898-1907`). The old UserN matching helper remains but has no call sites.

Recommended fix: remove the dead `session_has_locking_user_authority_for_range` helper or update its misleading comment so future changes do not reintroduce the fallback.

### G-P0-2 User2-User8 disabled defaults: Partial

Source:
- `state.initial_state`, `v6/src/state.py:66-128`
- `oracle.authority_classes_for`, `v6/src/oracle.py:225-242`
- `state.reset_locking_sp`, `v6/src/state.py:781-788`
- `state.reset_access_policy_scope`, `v6/src/state.py:440-487`

Expected behavior: User2-User8 should exist with empty PINs, be initially disabled, use Password operation, and be members of the Users class. LockingSP reset should restore those defaults.

Implementation:
- Empty credentials are seeded (`state.py:80-87`).
- Disabled authority rows are seeded (`state.py:117-127`).
- The seeded rows do not set `"class": "Users"`. Because `authority_classes_for` only applies the UserN fallback when no authority row exists (`oracle.py:225-242`), adding explicit rows without a class removes User2-User8 from the Users class.
- `reset_locking_sp` resets only User1 credential directly (`state.py:781-787`). `reset_access_policy_scope` does not restore these synthetic rows because `policy_row_scope` does not treat `source="LockingSP"` as LockingSP scope (`state.py:425-426`, `state.py:468-477`). If User2 was enabled/changed during a prefix, reset can leave it enabled.

Recommended fix: seed User2-User8 with `"class": "Users"` and a scope field such as `"sp": "LockingSP"`. Also reset User2-User8 credentials to empty in `reset_locking_sp`, or make `reset_access_policy_scope` reliably restore the synthetic defaults.

### C-P0-2 Object-table unauthorized cell omission: Partial

Source:
- `oracle.judge_get`, `v6/src/oracle.py:1623-1792`
- `_CELL_OMIT_FAMILIES`, `v6/src/oracle.py:1657-1661`
- policy override, `v6/src/oracle.py:1663-1678`
- family fallback, `v6/src/oracle.py:1780-1790`

Expected behavior: for object-table `Get`, unauthorized cells are omitted and method status is SUCCESS. Unauthorized byte-table reads are different; they do not use object-cell omission.

Implementation:
- There is a cell-omit path for `Authority`, `ACE`, `AccessControl`, and `SecretProtect` (`oracle.py:1657-1678`, `oracle.py:1780-1790`).
- The expected status is `{"success", "auth_error"}` rather than strict `success` (`oracle.py:1670-1677`, `oracle.py:1784-1788`). That still accepts the behavior the item was meant to reject.
- It does not validate that unauthorized cells are actually omitted from `return_columns`.
- It is family-limited. Other object-table families still return `auth_error` in fallback paths, for example protected Locking object-table columns (`oracle.py:1713-1728`).

Recommended fix: when an open session makes an object-table `Get` but ACE evaluation denies requested cells, expect `success` and verify denied columns are absent from `event["return_columns"]`. Keep `auth_error` for no-session/method-level failures and for byte tables. Apply the rule by table kind/family, not only the current four-family allowlist.

### D-P0 MBR shadowing in read/write: Partial

Source:
- `oracle._mbr_shadow_active`, `v6/src/oracle.py:2462-2464`
- `oracle._mbr_shadow_overlap`, `v6/src/oracle.py:2467-2476`
- `oracle.judge_read`, `v6/src/oracle.py:2479-2564`
- `oracle.judge_write`, `v6/src/oracle.py:2567-2606`
- `state.merge_mbr_columns`, `v6/src/state.py:387-393`
- `spec_docs.default_mbr_control`, `v6/src/spec_docs.py:658-671`

Expected behavior: when MBRControl Enable=True and Done=False, reads fully within the MBR shadow region return MBR table data, reads spanning MBR and user regions return Data Protection Error, and writes starting in the MBR shadow region return Data Protection Error. The MBR region extends from LBA 0 through the LBA that maps to the end of the MBR table.

Implementation:
- The high-level read/write branches exist before normal lock-state checks (`oracle.py:2483-2517`, `oracle.py:2571-2588`).
- MBRControl Enable/Done state is tracked from table Get/Set (`state.py:387-393`, `state.py:653-654`, `state.py:723-724`).
- Region sizing is incomplete. `_mbr_shadow_overlap` uses `mbr.get("table_size_lbas", 0)` (`oracle.py:2471-2475`), but no inspected code populates `table_size_lbas`; `default_mbr_control` only seeds Enable/Done/DoneOnReset (`spec_docs.py:658-671`). In practice this protects only LBA 0 unless another uninspected path injects the size.
- Read success inside MBR shadow is accepted as any non-data-error result and is not compared to MBR table contents (`oracle.py:2502-2517`).

Recommended fix: derive and store `table_size_lbas` from the MBR Table row size in the Table table (or Opal's minimum 128 MB converted through logical block size when no better data exists). Track MBR byte-table writes separately and, when possible, compare shadow reads against that table data rather than accepting any non-error.


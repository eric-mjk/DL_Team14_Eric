# Spec Audit — Core Crypto/Locking Templates & Opal SSC

## Summary

- Spec files read: ~85 files across core/5.4–5.8, core/6.x, and all opal/4.x–5.x documents
- Implementation files read: oracle.py (2260 lines), state.py (976 lines), spec_docs.py, spec_tables.py, normalizer.py, solver.py
- Discrepancies found: 8 (critical: 1, medium: 2, minor: 5)
- Already-fixed bugs excluded: 17 (per task instructions) + 8 from Agent B (B-001–B-008)

---

## Discrepancies

### C-001: Random method — Count > 32 not validated

- **Spec section**: opal/4.2.9.1 ("Random")
- **What spec says**: "The Count parameter SHALL NOT be greater than 32. If Count is greater than 32, the TPer SHALL return `INVALID_PARAMETER`."
- **What code currently does**: `oracle.py` `judge_random` (lines 1716–1727) only checks `count < 0`:
  ```python
  if count is not None and count < 0:
      return expected_status_result(event, "invalid_parameter", ...)
  ```
  A Count of 33 or higher passes through and the function predicts `success`, causing a `fail` verdict when the compliant SSD correctly returns `INVALID_PARAMETER`.
- **Severity**: critical
- **Fix needed**: Add an upper-bound check in `judge_random`:
  ```python
  if count is not None and count > 32:
      return expected_status_result(event, "invalid_parameter",
          "Random Count SHALL NOT exceed 32 (opal/4.2.9.1).", rule_key="random")
  ```

---

### C-002: Locking RangeStart / RangeLength Set not blocked when re-encryption is active

- **Spec section**: core/5.7.3.7 ("Re-Encryption")
- **What spec says**: "Attempts to modify the RangeStart and RangeLength columns of a Locking object that is undergoing re-encryption SHALL fail." Re-encryption is defined as `ReEncryptState != IDLE (1)`.
- **What code currently does**: `oracle.py` `invalid_locking_range_update` (lines 673–694) validates only range overlap and negative lengths. It does **not** inspect `ReEncryptState` at all. The other re-encryption guards (`invalid_reencrypt_request` and `invalid_next_key_update`) cover columns 13 and 11 respectively, but nothing guards columns 3 (RangeStart) and 4 (RangeLength) when `ReEncryptState != IDLE`. The spec violation is unconditional — no ACE policy table covers this, so `policy_status_result` cannot save it.
- **Severity**: medium
- **Fix needed**: In `invalid_locking_range_update`, after the family/columns check, add:
  ```python
  current = (state.get("locking_ranges") or {}).get(range_name) or {}
  state_value = reencrypt_state_value(current.get("reencrypt_state"))
  if state_value is not None and state_value != 1:  # 1 = IDLE
      return True
  ```
  Insert this before the bounds computation to short-circuit early with `True` (invalid).

---

### C-003: Global Range re-encryption blocks ALL Locking objects' RangeStart/RangeLength Set — not implemented

- **Spec section**: core/5.7.3.7
- **What spec says**: When the Global Range is undergoing re-encryption (`ReEncryptState != IDLE`), "it is not permitted to modify the RangeStart or RangeLength columns of any Locking object" — including non-global ranges.
- **What code currently does**: `invalid_locking_range_update` checks only the per-range `ReEncryptState` for its own range (after C-002 fix). There is no cross-range check for the Global Range's state. If Global Range is ACTIVE(3), Set RangeStart on Range1 would not be blocked.
- **Severity**: medium
- **Fix needed**: After the per-range IDLE check (added in C-002), also check the Global Range:
  ```python
  global_range = (state.get("locking_ranges") or {}).get("Global") or {}
  global_state = reencrypt_state_value(global_range.get("reencrypt_state"))
  if global_state is not None and global_state != 1:
      return True
  ```

---

### C-004: Authority Set fallback allows Admin* in AdminSP — spec requires SID only (ACE_Set_Enabled)

- **Spec section**: opal/4.2.1.5 (AdminSP AccessControl Table), opal/4.2.1.6 (AdminSP ACE Table)
- **What spec says**: All Authority Set rows in the AdminSP AccessControl Table reference `ACE_Set_Enabled`. The ACE table defines `ACE_Set_Enabled` as `BooleanExpr = "SID"`, `Columns = "Enabled"`. Only SID may set Authority.Enabled in the AdminSP.
- **What code currently does**: `oracle.py` `judge_set` (line 1615–1622) — the fallback path for Authority Set:
  ```python
  if family == "Authority":
      expected = session_open_for(state, target_sp, write_required=True) and session_has_admin_authority(state, target_sp)
  ```
  `session_has_admin_authority(state, "AdminSP")` returns `True` for SID **or** any Admin* authority. This fallback fires only when `policy_status_result` returns `None` (no matching AccessControl row pattern resolved). If the AccessControl table loaded from `spec_index.json` omits a specific AdminN authority UID (e.g., a test uses a non-preconfigured admin), the fallback would incorrectly grant authorization.
- **Severity**: minor (triggered only when ACE policy lookup misses)
- **Fix needed**: Tighten the Authority fallback for AdminSP:
  ```python
  if family == "Authority":
      if target_sp == "AdminSP":
          expected = session_open_for(state, target_sp, write_required=True) and session_has_authority(state, "SID")
      else:
          expected = session_open_for(state, target_sp, write_required=True) and session_has_admin_authority(state, target_sp)
  ```

---

### C-005: judge_get fallback for Authority/MediaKey/ACE/AccessControl/SecretProtect/DataStore always requires admin — contradicts several ACE_Anybody entries

- **Spec section**: opal/4.2.1.5 (AdminSP — Authority Get = ACE_Anybody); opal/4.3.1.6 (LockingSP — SecretProtect Get = ACE_Anybody; MediaKey/K_AES Get = ACE_K_AES_Mode = Anybody)
- **What spec says**:
  - AdminSP: ALL Authority object Get rows use `ACE_Anybody` → anybody in an open AdminSP session may read Authority objects.
  - LockingSP: SecretProtect Get rows use `ACE_Anybody`; K_AES_128/256 Get rows use `ACE_K_AES_Mode` (BooleanExpr = "Anybody"); only ACE Get rows require `ACE_ACE_Get_All` (Admins); DataStore Get uses `ACE_DataStore_Get_All` (Admins).
- **What code currently does**: `oracle.py` `judge_get` (lines 1510–1517):
  ```python
  if family in {"Authority", "MediaKey", "ACE", "AccessControl", "SecretProtect", "DataStore"}:
      expected = session_open_for(state, target_sp) and session_has_admin_authority(state, target_sp)
  ```
  This fallback fires only when `policy_status_result` returns `None`. When it fires, it incorrectly requires admin authority for Authority (AdminSP), SecretProtect (LockingSP), and MediaKey/K_AES (LockingSP) objects — all of which are actually Anybody-accessible. Only ACE and DataStore Get legitimately require admin.
- **Severity**: minor (fallback-only; correctly handled when ACE policy rows are loaded)
- **Fix needed**: Split the fallback by family and by SP to align with spec:
  ```python
  if family == "Authority":
      # AdminSP: ACE_Anybody; LockingSP: ACE_Authority_Get_All for full row, ACE_Anybody_Get_CommonName for UID/CommonName
      expected = session_open_for(state, target_sp)
  elif family == "SecretProtect":
      expected = session_open_for(state, "LockingSP")
  elif family == "MediaKey":
      expected = session_open_for(state, "LockingSP")
  elif family in {"ACE", "AccessControl", "DataStore"}:
      expected = session_open_for(state, target_sp) and session_has_admin_authority(state, target_sp)
  ```

---

### C-006: LockingSP Authority Set ACE split not reflected in judge_set fallback

- **Spec section**: opal/4.3.1.6 (LockingSP AccessControl Table, Authority Set rows)
- **What spec says**: Authority Set in the LockingSP has two ACEs per object:
  - `ACE_Authority_Set_Enabled` — controls who may set the `Enabled` column
  - `ACE_Admins_Set_CommonName` (or `ACE_User1_Set_CommonName` / `ACE_UserMMMM_Set_CommonName`) — controls who may set the `CommonName` column
  These are separate column-scoped ACEs; Admin1 can set Enabled on Admin2–Admin4; User1 may set its own CommonName.
- **What code currently does**: The fallback at `judge_set` line 1615–1622 treats all Authority Set as a single admin-write check, ignoring the column-level split and the per-authority CommonName ACE for User1.
- **Severity**: minor (fallback-only; policy_status_result handles this when ACE rows are loaded)
- **Fix needed**: If the fallback must be used, distinguish column 5 (Enabled) from column 2 (CommonName) and validate accordingly. In practice, ensure the spec_index.json ACE rows for `ACE_Authority_Set_Enabled` and `ACE_User1_Set_CommonName` / `ACE_Admins_Set_CommonName` are correctly parsed and loaded, so `policy_status_result` intercepts these before the fallback runs.

---

### C-007: RevertSP KeepGlobalRangeKey=TRUE — FAIL condition when Global Range is both Read+Write locked not enforced

- **Spec section**: opal/5.1.3.2 ("RevertSP")
- **What spec says**: "If the KeepGlobalRangeKey parameter is TRUE and the Global Range is both read locked and write locked, the TPer SHALL fail the RevertSP method with a FAIL status."
- **What code currently does**: `oracle.py` `judge_revert_sp` (lines 1658–1710) checks whether Admin1 is authenticated and whether the LockingSP is active, but does not inspect the current locking state of the Global Range when `KeepGlobalRangeKey=True`. The `state["locking_ranges"]["Global"]` dict contains `read_lock_enabled` and `write_lock_enabled`, so the data is available.
- **Severity**: minor
- **Fix needed**: In `judge_revert_sp`, after verifying the session auth, add:
  ```python
  keep_key = event.get("keep_global_range_key")
  if keep_key:
      global_range = (state.get("locking_ranges") or {}).get("Global") or {}
      rd_locked = global_range.get("read_lock_enabled") or global_range.get("read_locked")
      wr_locked = global_range.get("write_lock_enabled") or global_range.get("write_locked")
      if rd_locked and wr_locked:
          return RuleResult("fail", 1.0, "FAIL: RevertSP KeepGlobalRangeKey=TRUE but Global Range is both Read+Write locked (opal/5.1.3.2)")
  ```

---

### C-008: LockingSP Original Factory State — spec requires Manufactured-Inactive; oracle does not validate SP lifecycle state

- **Spec section**: opal/5.2.2 ("Manufactured SP Life Cycle States")
- **What spec says**: "If the Locking SP is a Manufactured SP, then its Original Factory State SHALL be Manufactured-Inactive." This means before `Activate` is called, the LockingSP is in `Manufactured-Inactive` state, not `Manufactured`. `Activate` transitions from `Manufactured-Inactive` to `Manufactured`.
- **What code currently does**: `oracle.py` `judge_activate` (lines 1633–1643) checks only that the session is an authenticated SID AdminSP write session. `state.py` tracks `locking_sp_active` (False = Manufactured-Inactive, True = Manufactured) but not other lifecycle states. There is no guard for attempting a second `Activate` on an already-active (Manufactured) LockingSP, which should return `INVALID_PARAMETER` or similar per the lifecycle diagram (no Manufactured→Manufactured transition for the Activate method).
- **Severity**: minor
- **Fix needed**: In `judge_activate`, add a check that the LockingSP is not already active (i.e., `locking_sp_active` must be False):
  ```python
  if state.get("locking_sp_active"):
      return RuleResult("fail", 1.0, "INVALID_PARAMETER or error: LockingSP is already in Manufactured state; Activate is only valid from Manufactured-Inactive.")
  ```
  The current code would predict `success` for a double-Activate, when the spec indicates only one activation path exists.

---

## Files Audited

| File | Lines | Role |
|---|---|---|
| `src/oracle.py` | 2260 | Main rule oracle — primary source of discrepancies |
| `src/state.py` | 976 | State tracker — locking range state access |
| `src/spec_docs.py` | ~1300 | Column definitions and ACE/AccessControl policy loading |
| `src/spec_tables.py` | 393 | Legacy policy tables — no new discrepancies found |
| `src/normalizer.py` | 665 | Object normalization — no new discrepancies found |
| `src/solver.py` | 1382 | Legacy solver — same gaps as oracle.py (separate code path) |

## Spec Sections Reviewed

**Core spec (partial scope — excluding core/5.1–5.3 covered by other agents):**
- core/5.4.x — Admin Template (SP, Authority, C_PIN, ACE, AccessControl, Table)
- core/5.5.x — Clock Template (Clock object columns)
- core/5.6.x — Crypto Template (C_RSA, C_AES, C_EC, C_HMAC; K_AES, K_RSA, K_ECDH)
- core/5.7.x — Locking Template (LockingInfo, Locking, MBRControl, MBR, K_AES re-encryption)
- core/5.8.x — Log Template (Log table columns)
- core/6.1–6.3 — UID Tables (Admin SP, Locking SP, method UIDs)

**Opal SSC v2:**
- opal/4.2.1.1–4.2.1.8 — AdminSP table preconfiguration (SPInfo, Table, Authority, C_PIN, ACE, AccessControl)
- opal/4.2.2–4.2.9.1 — AdminSP method preconditions (StartSession, Authenticate, Random, Activate, Revert)
- opal/4.3.1.1–4.3.1.10 — LockingSP table preconfiguration (LockingInfo, Locking, MBRControl, MBR, C_PIN, K_AES, ACE, AccessControl, Authority, SecretProtect)
- opal/4.3.2–4.3.8 — LockingSP method constraints (GenKey, RevertSP, Read/Write)
- opal/5.1.1–5.1.3 — Activate, Revert, RevertSP side-effects and preconditions
- opal/5.2.1–5.2.3 — SP lifecycle states (Manufactured-Inactive, Manufactured)
- opal/5.3.x — Locking Granularity constraints

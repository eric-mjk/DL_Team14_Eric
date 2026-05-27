# Solver.py Audit — Active Code Fix Plan

## Prior Findings — Applicability to solver.py

| ID | Title | Status | solver.py location |
|---|---|---|---|
| A-001 | oracle.py StartSession — missing INVALID_PARAMETER for class authority | NOT IN solver.py | solver.py:549 (`_is_class_authority` check present) |
| A-002 | oracle.py GetACL — wrong status for wrong InvokingID | NOT IN solver.py | solver.py has no GetACL/AddACE; falls to SUCCESS default — not tested by public cases |
| A-003 | SP lifecycle states (Issued-Disabled, Issued-Frozen, Failed) not tracked | NOT IN solver.py (same gap as oracle.py but no public test coverage) | solver.py:542 uses `activated_sps` set only |
| A-004 | AUTHORITY_LOCKED_OUT condition 2 (Uses/Limit) not tracked | NOT IN solver.py (same gap, no public test coverage) | ProtocolState has no Uses/Limit tracking |
| B-001 | Authenticate — missing INVALID_PARAMETER for proof to non-Password authority | NOT IN solver.py | solver.py:609–625 always returns SUCCESS regardless of operation column (BUT solver does not track authority.operation at all, so it cannot check — see S-002) |
| B-002 | Authenticate — missing SUCCESS+False for Exchange/TPerExchange/TPerSign authority | NOT IN solver.py | solver.py has no operation-column tracking |
| B-003 | StartSession — missing error when Exchange/TPerExchange authority as HostSigningAuthority | NOT IN solver.py | solver.py:545–582 never inspects operation column |
| B-004 | GenKey — C_RSA/C_EC/C_AES wrongly rejected with INVALID_PARAMETER | NOT IN solver.py | solver.py:666–676 uses POLICIES dict which has no C_RSA/C_EC/C_AES entries; falls through to SUCCESS — correct outcome by accident |
| B-005 | C_PIN.Tries (col 6) read-only in spec_docs.py — affects oracle.py only | NOT IN solver.py | solver.py uses `_expected_cpin_set` which only checks `values keys == {"3"}` (line 960) — wrongly rejects a col-6 Set too (S-001) |
| B-006 | Authority.Limit / Authority.Uses not enforced | NOT IN solver.py | ProtocolState has no limit/uses fields; no public test coverage |
| B-007 | SetPackage on C_PIN doesn't reset Tries in state.py | NOT IN solver.py | solver.py never processes SetPackage at all (not listed in `_ingest_step`) |
| B-008 | ACE with empty BooleanExpr resolves to None | NOT IN solver.py | solver.py does not use ACE evaluation; uses POLICIES dict |
| C-001 | Random Count > 32 not validated | NOT IN solver.py | solver.py has no RANDOM case in `_expected_outcome`; falls to `ExpectedOutcome(status="SUCCESS")` default |
| C-002 | Locking RangeStart/RangeLength Set not blocked during re-encryption | NOT IN solver.py | solver.py:896–905 `_expected_locking_set` checks column membership and validity but never checks ReEncryptState |
| C-003 | Global Range re-encryption blocks all Locking objects | NOT IN solver.py | Same gap as C-002 |
| C-004 | Authority Set fallback allows Admin* in AdminSP — spec requires SID only | PARTIAL | solver.py:907–914 `_expected_authority_set` checks only column membership, doesn't distinguish AdminSP vs LockingSP authority |
| C-005 | judge_get fallback for Authority/MediaKey/ACE/etc. always requires admin | NOT IN solver.py | solver.py `_expected_get` does not handle Authority/MediaKey/ACE GET at all; falls to SUCCESS default |
| C-006 | LockingSP Authority Set ACE split not reflected | PARTIAL | solver.py:907–914 has no column-level ACE split for Authority Set |
| C-007 | RevertSP KeepGlobalRangeKey=TRUE — FAIL when Global Range both locked | APPLIES | solver.py:698–700 checks `_global_range_fully_locked()` — **present and correct in solver.py** |
| C-008 | LockingSP already-active Activate — no double-Activate guard | APPLIES | solver.py:584–607 `_expected_activate` never checks if LockingSP is already in `activated_sps` |

---

## Confirmed Bugs in solver.py

### S-001: C_PIN Set with values other than column 3 wrongly returns INVALID_PARAMETER — blocks spec-permitted col-6 (Tries) reset

- **Source**: B-005 (extended to solver.py path)
- **Spec section**: core/5.3.4.1.1.2
- **solver.py location**: solver.py:960
- **What's wrong**:
  ```python
  if set(values) != {"3"}:
      return ExpectedOutcome(status="INVALID_PARAMETER")
  ```
  The spec permits `Set C_PIN col 6 to 0` to reset the Tries counter. The check `set(values) != {"3"}` rejects any Set that doesn't write exactly column 3, including a valid `{6: 0}` Tries-reset operation. If a hidden test case has a correct Tries reset and the SSD returns SUCCESS, solver.py will predict FAIL for it.
- **Fix needed**: Change to allow column 6 as well:
  ```python
  if not set(values).issubset({"3", "6"}):
      return ExpectedOutcome(status="INVALID_PARAMETER")
  ```
  (Column 3 is the PIN, column 6 is Tries — both are host-writable on C_PIN objects per spec.)
- **Severity**: medium

---

### S-002: `_expected_authenticate` always returns SUCCESS — never predicts NOT_AUTHORIZED

- **Source**: new
- **Spec section**: core/5.3.4.1.14.1
- **solver.py location**: solver.py:609–625
- **What's wrong**: `_expected_authenticate` builds a credential check but its final branch at line 623–625 always returns `ExpectedOutcome(status="SUCCESS")` regardless of whether `proof` matches `credential`:
  ```python
  if credential is not None and self._values_equal(proof, credential):
      return ExpectedOutcome(status="SUCCESS")
  return ExpectedOutcome(status="SUCCESS")   # <-- wrong; should be NOT_AUTHORIZED
  ```
  When the credential is known and the proof doesn't match, the oracle still predicts SUCCESS. In `_compare_with_actual` (line 747–759), there is a secondary check that can catch a mis-verdict — but the `expected.status == "SUCCESS"` still passes the primary status check (line 738–741), so the secondary check at line 759 fires only when `actual_result is not None and actual_result != should_succeed`. If the SSD returns `SUCCESS` with `auth_result=False` (failed authentication), and `should_succeed=True` (we expected success), this secondary check will catch it. However if the SSD returns `NOT_AUTHORIZED` status, `actual_status == "SUCCESS"` fails at line 740–741 immediately (NOT_AUTHORIZED != SUCCESS) → returns False → verdict "fail". So a test case with wrong credentials where the SSD correctly returns NOT_AUTHORIZED will be predicted as "fail" (wrong — should be "pass"). The root issue is the final `return ExpectedOutcome(status="SUCCESS")` when credentials don't match.
- **Fix needed**:
  ```python
  def _expected_authenticate(self, step):
      if self.state.session.spid is None:
          return ExpectedOutcome(status="FAIL")
      authority = normalize_uid(get_path(step, "input", "method", "args", "required", "Authority"))
      if authority is None or not self._authority_exists(authority) or self._is_class_authority(authority):
          return ExpectedOutcome(status="INVALID_PARAMETER")
      if authority == ANYBODY_AUTHORITY:
          return ExpectedOutcome(status="SUCCESS")
      proof = get_path(step, "input", "method", "args", "optional", "Proof")
      if proof is None:
          proof = get_path(step, "input", "method", "args", "required", "Proof")
      credential = self._credential_for_authority(authority)
      if credential is None:
          # Unknown credential — SSD decides; accept any status
          return ExpectedOutcome(allowed_statuses={"SUCCESS", "NOT_AUTHORIZED"})
      if self._values_equal(proof, credential):
          return ExpectedOutcome(status="SUCCESS")
      # Known credential, wrong proof
      return ExpectedOutcome(status="NOT_AUTHORIZED")   # was: status="SUCCESS"
  ```
  The line `if authority not in self.state.enabled_authorities: return ExpectedOutcome(status="SUCCESS")` at line 617–618 is also suspicious (see S-003).
- **Severity**: critical

---

### S-003: `_expected_authenticate` returns SUCCESS (not NOT_AUTHORIZED) for disabled authority

- **Source**: new
- **Spec section**: core/5.1.5.14 ("AUTHORITY_LOCKED_OUT"), core/5.3.4.1.14.1
- **solver.py location**: solver.py:617–618
- **What's wrong**:
  ```python
  if authority not in self.state.enabled_authorities:
      return ExpectedOutcome(status="SUCCESS")
  ```
  When the authority is not in `enabled_authorities` (i.e., it has been disabled by a Set Authority.Enabled=False), the method returns SUCCESS — but a disabled authority should fail authentication with `NOT_AUTHORIZED`. The comment at this line is missing; the logic is backwards. A disabled or non-existent authority cannot authenticate.
- **Fix needed**:
  ```python
  if authority not in self.state.enabled_authorities:
      return ExpectedOutcome(status="NOT_AUTHORIZED")
  ```
- **Severity**: critical

---

### S-004: Double-Activate (LockingSP already active) not rejected — `_expected_activate` always returns SUCCESS if conditions met

- **Source**: C-008
- **Spec section**: opal/5.2.2 (SP lifecycle); Activate is only valid from Manufactured-Inactive
- **solver.py location**: solver.py:584–596
- **What's wrong**: `_expected_activate` checks only session SP, write mode, and SID authority, but never checks whether LockingSP is already in `activated_sps`. If a trajectory already activated LockingSP and then calls Activate again (which is invalid — no Manufactured→Manufactured transition), solver.py will predict SUCCESS instead of an error status.
  ```python
  def _expected_activate(self, step):
      target_uid = normalize_uid(get_path(step, "input", "invoking_id", "uid"))
      if target_uid == LOCKING_SP:
          if self.state.session.spid != ADMIN_SP:
              return ExpectedOutcome(status="NOT_AUTHORIZED")
          if not self.state.session.write:
              return ExpectedOutcome(status="NOT_AUTHORIZED")
          if not self._has_authority(SID_AUTHORITY):
              return ExpectedOutcome(status="NOT_AUTHORIZED")
          return ExpectedOutcome(status="SUCCESS")  # <-- no check for already active
  ```
- **Fix needed**:
  ```python
  if target_uid == LOCKING_SP:
      if self.state.session.spid != ADMIN_SP:
          return ExpectedOutcome(status="NOT_AUTHORIZED")
      if not self.state.session.write:
          return ExpectedOutcome(status="NOT_AUTHORIZED")
      if not self._has_authority(SID_AUTHORITY):
          return ExpectedOutcome(status="NOT_AUTHORIZED")
      if LOCKING_SP in self.state.activated_sps:
          # Already Manufactured-active; second Activate is invalid
          return ExpectedOutcome(allowed_statuses={"INVALID_PARAMETER", "NOT_AUTHORIZED", "FAIL"})
      return ExpectedOutcome(status="SUCCESS")
  ```
- **Severity**: medium

---

### S-005: `_expected_start_session` — `StartSession` for LockingSP with wrong SPID allowed if different UID format

- **Source**: new
- **Spec section**: core/5.1.5.11
- **solver.py location**: solver.py:538
- **What's wrong**: The SPID check at line 538:
  ```python
  if spid not in {ADMIN_SP, LOCKING_SP}:
      return ExpectedOutcome(status="FAIL")
  ```
  uses `normalize_uid` at line 537, which strips spaces and `0x` prefixes but does NOT zero-pad. `ADMIN_SP = "0000020500000001"` and `LOCKING_SP = "0000020500000002"` are uppercase 16-char hex strings. `normalize_uid` also calls `.upper()`. So as long as the test-case JSON SPID normalizes correctly, this is fine. However if a test case uses an abbreviated UID like `"20500000001"` (missing leading zeros), `normalize_uid` would return `"20500000001"` which doesn't match `ADMIN_SP`, and the oracle would return FAIL even if the SSD interprets it as AdminSP. This is a minor robustness issue in `normalize_uid` rather than a logic bug in `_expected_start_session` itself.
- **Fix needed**: In `normalize_uid`, add zero-padding to 16 characters for values that look like partial UIDs (optional — depends on actual test case JSON format).
- **Severity**: minor (only affects malformed test cases; public tc1–tc20 appear to use full 16-char hex UIDs)

---

### S-006: `_ingest_start_session` sets `authenticated=True` whenever `HostSigningAuthority` is present, even if it's Anybody

- **Source**: new
- **Spec section**: core/5.1.5.11; opal/4.2.2
- **solver.py location**: solver.py:303–310
- **What's wrong**:
  ```python
  self.state.session = SessionState(
      ...
      authority=normalize_uid(get_path(step, "input", "method", "args", "optional", "HostSigningAuthority")),
      authenticated=get_path(step, "input", "method", "args", "optional", "HostSigningAuthority") is not None,
      ...
  )
  ```
  If the test case passes `HostSigningAuthority = ANYBODY_AUTHORITY` (UID `0000000900000001`) in StartSession, `authenticated` is set to `True`, which would grant access to policies requiring `require_authenticated=True`. But opening a session with Anybody is not an authenticated session — no credential is verified. This state is then used by `_policy_failure` at line 869 to grant access to admin-only operations.
- **Fix needed**:
  ```python
  authenticated=normalize_uid(
      get_path(step, "input", "method", "args", "optional", "HostSigningAuthority")
  ) not in {None, ANYBODY_AUTHORITY},
  ```
- **Severity**: medium

---

### S-007: `_expected_cpin_get` — wrong SP for MSID is not caught; non-MSID C_PIN col-3 read returns NOT_AUTHORIZED in LockingSP

- **Source**: new
- **Spec section**: opal/4.2.1.4 (AdminSP C_PIN MSID readable by Anybody); opal/4.3.1.5 (LockingSP C_PIN)
- **solver.py location**: solver.py:916–935, 937–953
- **What's wrong**: `_can_read_cpin_col3` at line 950–953:
  ```python
  if object_uid == C_PIN_MSID:
      return self.state.session.spid == ADMIN_SP
  return False
  ```
  Returns `False` for all LockingSP C_PIN objects. In `_expected_cpin_get` at line 929–931:
  ```python
  if "3" in requested:
      if self._can_read_cpin_col3(object_uid):
          return ExpectedOutcome(status="SUCCESS", ...)
      return ExpectedOutcome(status="NOT_AUTHORIZED")
  ```
  If a test case GETs a LockingSP C_PIN without requesting column 3 (e.g., requesting only UID/CommonName columns), the flow falls through to line 933–935:
  ```python
  if object_uid != C_PIN_MSID and not (self._has_authority(SID_AUTHORITY) or self._has_admin_authority()):
      return ExpectedOutcome(status="NOT_AUTHORIZED")
  return ExpectedOutcome(status="SUCCESS", requires_nonempty_values=True)
  ```
  This correctly requires SID or admin authority for non-MSID C_PINs. However, `_expected_columns_for_range` is called with `{"all": ("3",)}` which is a non-standard readable_sets format — the `get((start_col, end_col))` lookup won't match it unless the Cellblock start/end are not provided. If `_cellblock_range` returns `(None, None)` (no Cellblock), then `_expected_columns_for_range` returns `()`. The `requested` set ends up empty, and the col-3 branch is not taken — which is actually correct behavior for a GET without explicit column range. The logic here is subtle but appears to work for the common case. This is a minor gap in edge cases where the Cellblock exactly requests col-3 on a LockingSP C_PIN.
- **Fix needed**: No change needed for public test cases. Document that `_can_read_cpin_col3` correctly gates LockingSP C_PIN col-3 as unreadable.
- **Severity**: minor (not expected to affect scoring)

---

### S-008: `_compare_with_actual` — `READ` result comparison when `result` is None returns False even when expected has no constraints

- **Source**: new
- **Spec section**: n/a (logic bug)
- **solver.py location**: solver.py:762–765
- **What's wrong**:
  ```python
  if self._method_name(step) == "READ":
      result = get_path(step, "output", "args", "result")
      if result is None:
          return False
  ```
  If the READ step's output has no `result` field (e.g., result is under a different key or the SSD returns an error result in a different format), the oracle unconditionally returns False (FAIL verdict). But `_expected_read` may return `ExpectedOutcome(status=None)` for cases where any result is acceptable, or `ExpectedOutcome(interface_result_should_fail=True)` where an error result would be correct. If `result` is None because of a JSON path difference, a valid FAIL response could be incorrectly classified as a FAIL verdict.

  More concretely: if an SSD returns `{"output": {"result": "FAIL"}}` for a locked read, `_interface_result` at line 860 would get it as `get_path(step, "output", "result", ...)` — but `_compare_with_actual` for READ checks `get_path(step, "output", "args", "result")` (line 763). If the result is under `output.result` rather than `output.args.result`, the comparison misses it, returning False even for a correct FAIL response. This inconsistency between `_interface_result` (which checks both paths) and `_compare_with_actual` READ (which checks only `output.args.result`) is a bug.
- **Fix needed**:
  ```python
  if self._method_name(step) == "READ":
      result = get_path(step, "output", "args", "result")
      if result is None:
          result = get_path(step, "output", "result")  # fallback path
      if result is None:
          # No result at all — only OK if we expect a fail (error may be in status)
          if expected.interface_result_should_fail:
              actual_status = self._output_status(step)
              return actual_status not in {"", "SUCCESS"}
          return False
  ```
- **Severity**: medium

---

### S-009: `_ingest_genkey` sets `genkey_effective=True` but never resets it between test cases via `_reset_state` — actually reset correctly, but `_media_key_changed_for_read` may fire for wrong ranges

- **Source**: new
- **Spec section**: core/5.7.2.1 (GenKey on K_AES changes media key for covered LBA range)
- **solver.py location**: solver.py:1251–1265
- **What's wrong**: `_media_key_changed_for_read` checks `self.state.erased_ranges` and `self.state.data_removed`. `erased_ranges` is populated by `_ingest_genkey` for the affected range. The check at line 1260–1264:
  ```python
  values = self.state.object_values.get(range_uid)
  if not values:
      return True   # <-- conservative: assume overlap if range bounds unknown
  ```
  If the GenKey happened on a range whose bounds haven't been read into `object_values` yet, the oracle assumes the GenKey affects ALL LBAs, which can incorrectly flag unrelated Read operations as "must differ" after a GenKey. This could produce false "fail" verdicts for reads at LBAs not covered by the key-regenerated range.
- **Fix needed**: Before the `if not values: return True` conservative fallback, also check if the range_uid matches what a specific K_AES key would cover (via `_range_for_key_uid` reverse mapping). If the erased range is known to be a non-global named range but its bounds are unknown, consider returning False (don't assume overlap) instead of True.
- **Severity**: medium (affects GenKey test cases where range bounds were never read)

---

### S-010: `_ingest_start_session` — `credential` learned from `HostChallenge` is not happening; solver.py doesn't learn new credentials from StartSession

- **Source**: new (compare with state.py line 192–194)
- **Spec section**: opal/4.2.2 ("StartSession" preconditions)
- **solver.py location**: solver.py:297–315 (`_ingest_start_session`)
- **What's wrong**: `state.py` `remember_successful_start_session` (line 192) does:
  ```python
  if authority and challenge is not None and state["credentials"].get(authority) is None:
      state["credentials"][authority] = challenge
  ```
  This seeds the credential from the successful StartSession's HostChallenge when the credential was previously unknown. Solver.py's `_ingest_start_session` does NOT do this — it only opens a session but never seeds the credential dict from the challenge. As a result, if a test case first uses StartSession to open an authenticated session (proving the credential implicitly), and a later step's expected outcome depends on knowing that credential (e.g., verifying a subsequent StartSession with same authority), solver.py won't have learned the credential.
- **Fix needed**: In `_ingest_start_session`, after successful session open, add:
  ```python
  authority = self.state.session.authority
  challenge = get_path(step, "input", "method", "args", "optional", "HostChallenge")
  if authority and challenge is not None and self.state.credentials.get(authority) is None:
      self.state.credentials[authority] = str(challenge)
      self._learn_credential_aliases(
          self._credential_uid_for_authority(authority), str(challenge)
      )
  ```
- **Severity**: medium

---

### S-011: `_expected_start_session` empty-PIN check compares challenge to `""` but challenge `None` is also valid for empty-PIN

- **Source**: new
- **Spec section**: opal/4.2.2; core/5.1.5.11
- **solver.py location**: solver.py:559–560
- **What's wrong**:
  ```python
  if credential == "" and (challenge is None or self._values_equal(challenge, "")):
      return ExpectedOutcome(status="SUCCESS")
  ```
  This correctly handles both None and empty-string challenge for empty-PIN authorities. This appears correct. No bug here.
- **Severity**: n/a — not a bug; noted as reviewed.

---

### S-012: `_policy_failure` for `("GET", "MBRCONTROL")` allows unauthenticated read — but `_expected_get` for MBRCONTROL (line 514–523) adds object-value check that could fail spuriously

- **Source**: new
- **Spec section**: opal/4.3.1.3 ("MBRControl"); opal ACE: ACE_MBRControl_Get = Anybody
- **solver.py location**: solver.py:514–523
- **What's wrong**: For MBRCONTROL GET, if `object_uid` is not yet tracked in `self.state.object_values`, `expected.required_values` will be empty. Then at line 517–520, it falls through to `expected_columns` from the semantic readable column sets. If the Cellblock range doesn't match a known entry, `expected_columns` is also empty. Then `requires_nonempty_values = True` is set at line 522, meaning the GET response MUST contain at least one value. If an SSD returns an empty MBRControl GET response (which is spec-valid in some cases), this would produce a false FAIL. The `requires_nonempty_values` check is too strict for the case where we have no tracked state and no explicit column request.
- **Fix needed**: Only set `requires_nonempty_values = True` if there was an explicit column range requested (i.e., `expected_columns` is non-empty from the semantic lookup):
  ```python
  if not expected.required_values:
      if expected_columns:
          expected.requires_nonempty_values = True
      # else: no specific columns requested and no tracked state — any response is OK
  ```
- **Severity**: minor

---

### S-013: `_authority_for_credential_uid` maps `0000000B0000XXXX` to `00000009000002XX` (AdminSP admin range) — but `C_PIN_ADMIN_SP_ADMIN1` = `0000000B00000201` maps to `0000000900000201` which is `ADMIN_SP_ADMIN1`; the general `0000000B0000` prefix also matches `C_PIN_SID` = `0000000B00000001`

- **Source**: new
- **Spec section**: opal/4.2.1.4 (C_PIN table, AdminSP)
- **solver.py location**: solver.py:1063–1070, 1072–1081
- **What's wrong**:
  ```python
  def _authority_for_credential_uid(self, credential_uid: str) -> str | None:
      if credential_uid == C_PIN_SID:
          return SID_AUTHORITY
      if credential_uid == C_PIN_ADMIN_SP_ADMIN1:
          return "0000000900000201"
      if credential_uid.startswith("0000000B") and len(credential_uid) == 16:
          return "00000009" + credential_uid[8:]
      return None
  ```
  The general rule `"00000009" + credential_uid[8:]` would also fire for `C_PIN_SID` = `0000000B00000001` → `0000000900000001` = ANYBODY_AUTHORITY. However, the early-exit `if credential_uid == C_PIN_SID: return SID_AUTHORITY` correctly handles this before the general rule. For `C_PIN_MSID` = `0000000B00008402`, the general rule would return `0000000900008402` — which is not a valid authority UID. This means `_learn_credential_aliases` at line 1048 would store the MSID credential under a phantom authority key `0000000900008402`, which is harmless (it won't match any real authority) but wastes memory. More importantly, `_credential_uid_for_authority` at line 1079 would convert `0000000900008402` back to `0000000B00008402` = MSID, which accidentally creates a circular alias. No verdict bug from this, but confusing.
- **Fix needed**: Add an explicit exclusion for MSID in `_authority_for_credential_uid`:
  ```python
  if credential_uid == C_PIN_MSID:
      return None  # MSID has no paired authority (Anybody-readable, not authority-keyed)
  ```
- **Severity**: minor (no wrong verdicts, but phantom key pollution)

---

## Summary

- **Total confirmed bugs in solver.py**: 11 bugs (S-001 through S-013, excluding S-005 and S-011 as non-bugs)
- **Critical**: 2 (S-002, S-003)
- **Medium**: 4 (S-001, S-004, S-008, S-009, S-010) — 5 bugs rated medium
- **Minor**: 4 (S-006, S-007, S-012, S-013)

### Priority Fixes (ordered by scoring impact)

1. **S-003** (critical): `_expected_authenticate` returns SUCCESS for disabled authority — should return NOT_AUTHORIZED. Fix: line 617–618.
2. **S-002** (critical): `_expected_authenticate` final branch always returns SUCCESS even when credential mismatch is known. Fix: line 625.
3. **S-006** (medium): `_ingest_start_session` marks session `authenticated=True` for Anybody authority — grants policy access incorrectly. Fix: line 306.
4. **S-010** (medium): StartSession HostChallenge not used to seed credentials — solver may fail to track PIN when it's only revealed via successful auth. Fix: add to `_ingest_start_session`.
5. **S-008** (medium): READ result comparison checks `output.args.result` only, but error results may be under `output.result` — can mis-verdict locked read responses. Fix: line 763.
6. **S-001** (medium): C_PIN Set rejects col-6 (Tries) writes, which are spec-permitted. Fix: line 960.
7. **S-004** (medium): Double-Activate LockingSP not rejected. Fix: `_expected_activate` line 596.
8. **S-009** (medium): GenKey erased-range overlap assumes worst case when range bounds unknown — can produce false fail verdicts on reads. Fix: line 1260.
9. **S-012** (minor): MBRControl GET `requires_nonempty_values` too strict when no columns tracked. Fix: line 522.
10. **S-013** (minor): MSID phantom authority alias pollution. Fix: `_authority_for_credential_uid`.

### Prior Report Findings NOT present in solver.py

All eight B-series findings (B-001 through B-008) primarily concern oracle.py's ACE/operation-column machinery, which solver.py does not replicate. Solver.py uses a simpler POLICIES-dict approach and does not track `authority.operation`, `authority.limit/uses`, or ACE boolean expressions. The net effect is that solver.py is **more permissive** than oracle.py for authentication edge cases (it accepts more as SUCCESS), which means test cases with valid credentials will score correctly, but test cases testing rejection of non-Password authority authentication (B-001/B-002) or StartSession with Exchange authority (B-003) may produce wrong verdicts if hidden test cases exercise those paths.

C-002/C-003 (re-encryption blocking RangeStart/RangeLength Set) do not affect solver.py scoring since re-encryption state tracking (`ReEncryptState` column) is not present in `ProtocolState` at all. No hidden test case is likely to exercise this given the Opal SSC focus of the dataset.

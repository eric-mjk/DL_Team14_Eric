# Verification Agent 4: synthetic tests audit

Scope: inspected `v6/customtest_84/generate_synthetic.py`, `synthetic_labels.jsonl`, `SYNTHETIC_TESTS.md`, and representative cases `syn_pass/fail_33` through `47`. I did not edit `v6/src` or testcase files.

Checker run:

```bash
python v6/customtest_84/generate_synthetic.py --check-only
# Synthetic dataset accuracy: 84/84 (100.0%)
```

Dataset inventory:

- `v6/customtest_84/synthetic_labels.jsonl`: 84 labels, 42 pass / 42 fail.
- `v6/customtest_84/synthetic_testcases`: 84 JSON files; no missing/extra files relative to labels.
- `v6/customtest_84/SYNTHETIC_TESTS.md` is stale: it still documents `customtest_57`, 57 cases, and `cd v5_usereference/customtest_57`.

## Top findings

1. **`syn_pass_34_createlog_duplicate_ok.json` / `syn_fail_34_createlog_duplicate.json` do not exercise duplicate-name handling.** The current oracle returns `invalid_parameter` before reaching the duplicate check because the final `CreateLog` has only `NewLogTableName` and is missing `HighSecurity` (and then `MinSize`). Labels happen to match, but the coverage claim "CreateLog uniqueness" is not valid for these files.

2. **`customtest_57` deletion plus `customtest_84` addition looks like an intended replacement, but repo hygiene is incomplete.** Git sees 60 tracked files under `v6/customtest_57` deleted and `v6/customtest_84/` untracked. Multiple docs still reference `customtest_57`, and `customtest_84/__pycache__/generate_synthetic.cpython-312.pyc` is untracked. This is likely a rename/regeneration workflow that was not fully staged/cleaned, not an intentional permanent deletion as currently represented by git status.

3. **Several new cases are narrower than their implementation-plan item names.** `syn_38` checks that Sign-authenticate with a proof returns `SUCCESS`, but it does not include the first challenge step or validate pending challenge state. `syn_40` covers `AddACE` state mutation only, not `RemoveACE` or `DeleteMethod`. `syn_43` covers AccessControl `(N)` column 4 only, not columns 1, 2, and 8. These are useful tests, but the plan coverage should be described more narrowly.

## Case-by-case audit

| Testcase | Expected label | Actual oracle behavior if run | Correctness / coverage assessment |
|---|---:|---|---|
| `syn_pass_33_addlog_default.json` | pass | pass; expected `success`, actual `success`; reason: `AddLog requires access to the Log table.` | Correct. Exercises default pre-existing Log table existence. |
| `syn_fail_33_addlog_nonexistent.json` | fail | fail; expected `error`, actual `success`; reason: target log UID `0000000100000A05` does not exist. | Correct. Exercises AddLog target existence. |
| `syn_pass_34_createlog_duplicate_ok.json` | pass | pass; expected `invalid_parameter`, actual `invalid_parameter`; reason: `CreateLog is missing required parameter HighSecurity.` | Label matches, but test does **not** exercise duplicate-name handling. It passes for malformed parameters. |
| `syn_fail_34_createlog_duplicate.json` | fail | fail; expected `invalid_parameter`, actual `success`; reason: `CreateLog is missing required parameter HighSecurity.` | Label matches, but test does **not** exercise duplicate-name handling. The fail signal is from missing required args, not duplicate `AuditLog`. |
| `syn_pass_35_reencrypt_idle_set.json` | pass | pass; expected `success`, actual `success`; reason: authenticated Admin LockingSP Set. | Correct idle baseline for geometry Set. |
| `syn_fail_35_reencrypt_set_geometry.json` | fail | fail; expected `invalid_parameter`, actual `success`; reason: `Locking RangeStart/RangeLength update is negative or overlaps another configured range.` | Correct label. It does exercise the non-IDLE geometry guard because prior `ReEncryptRequest=1` leaves Range1 in state 2, but the oracle reason is generic and does not name re-encryption. |
| `syn_fail_36_reencrypt_genkey.json` | fail | fail; expected `invalid_parameter`, actual `success`; reason: `GenKey on Range1 key is not permitted while re-encryption is in progress.` | Correct. Exercises non-IDLE media-key GenKey restriction. No matching pass case for idle GenKey; `syn_pass_35` is an idle Set baseline, not GenKey. |
| `syn_pass_37_reset_session_aborted.json` | pass | pass; expected `auth_error`, actual `auth_error`; reason: `Get requires an open session.` | Correct. Exercises Power Cycle aborting the prior session. |
| `syn_fail_37_reset_session_survives.json` | fail | fail; expected `auth_error`, actual `success`; reason: `Get requires an open session.` | Correct. Exercises same reset/session-abort rule. |
| `syn_pass_38_sign_auth_proof.json` | pass | pass; expected `success`, actual `success`; reason: Sign two-step Authenticate should return `SUCCESS`. | Label correct, but coverage is partial. It has a proof call only; it does not model/check the first challenge response or pending challenge state. |
| `syn_fail_38_sign_auth_inv_param.json` | fail | fail; expected `success`, actual `invalid_parameter`; reason: Sign Authenticate should return `SUCCESS`. | Correct for "proof Authenticate must not return INVALID_PARAMETER"; partial for the broader two-step state-machine item. |
| `syn_pass_39_disabled_sp_session.json` | pass | pass; expected `error`, actual normalized `resource_error`; reason: LockingSP lifecycle is `Issued-Disabled`. | Correct. `SP_DISABLED` normalizes into an accepted error class. |
| `syn_fail_39_disabled_sp_session.json` | fail | fail; expected `error`, actual `success`; reason: disabled LockingSP StartSession must fail. | Correct. Exercises disabled SP StartSession block. |
| `syn_pass_40_addace_anybody_set.json` | pass | pass; expected `success`, actual `success`; reason: Set matched added ACE/AccessControl policy. | Correct for AddACE mutation: prefix AddACE affects final unauthenticated Set. Does not cover RemoveACE/DeleteMethod. |
| `syn_fail_40_addace_anybody_set.json` | fail | fail; expected `success`, actual `auth_error`; reason: Set matched added ACE/AccessControl policy. | Correct for AddACE mutation negative response. Does not cover RemoveACE/DeleteMethod. |
| `syn_pass_41_tperinfo_admin1_rejected.json` | pass | pass; expected `auth_error`, actual `auth_error`; reason: Set matched ACE/AccessControl policy. | Correct. Exercises Admin1 not being allowed to write TPerInfo `ProgrammaticResetEnable` column 8. |
| `syn_fail_41_tperinfo_admin1_set.json` | fail | fail; expected `auth_error`, actual `success`; reason: Set matched ACE/AccessControl policy. | Correct. Exercises same TPerInfo SID-only write rule. |
| `syn_pass_42_datarmv_reserved_enum.json` | pass | pass; expected `invalid_parameter`, actual `invalid_parameter`; reason: reserved `ActiveDataRemovalMechanism=3`. | Correct. Exercises DataRemovalMechanism reserved enum validation. |
| `syn_fail_42_datarmv_reserved_enum.json` | fail | fail; expected `invalid_parameter`, actual `success`; reason: reserved `ActiveDataRemovalMechanism=3`. | Correct. Exercises same enum validation. |
| `syn_pass_43_ac_get_n_col.json` | pass | pass; expected `auth_error`, actual `auth_error`; reason: AccessControl column 4 has `(N)` access, not readable via Get. | Correct for ACL column 4. Does not cover other claimed `(N)` columns 1, 2, or 8. |
| `syn_fail_43_ac_get_n_col.json` | fail | fail; expected `auth_error`, actual `success`; reason: AccessControl column 4 has `(N)` access. | Correct for ACL column 4 only. |
| `syn_pass_44_getacl_unauth.json` | pass | pass; expected `success`, actual `success`; reason: `GetACLACL` defaults to `ACE_Anybody` with an open session. | Correct. Exercises unauthenticated GetACL in an open AdminSP session. |
| `syn_fail_44_getacl_unauth.json` | fail | fail; expected `success`, actual `auth_error`; reason: `GetACLACL` defaults to `ACE_Anybody`. | Correct. Exercises same GetACL rule. |
| `syn_pass_45_discovery_compliant.json` | pass | pass; expected `success`, actual `success`; reason: required Level 0 Discovery descriptors and field values are valid. | Correct. Exercises compliant Discovery baseline. |
| `syn_fail_45_discovery_missing_v2.json` | fail | fail; expected `success`, actual `discovery_missing_descriptor`; reason: missing Opal SSC V2 descriptor `0x0203`. | Correct. Exercises required Opal V2 descriptor. |
| `syn_fail_46_discovery_locking_enabled.json` | fail | fail; expected `success`, actual `discovery_locking_enabled`; reason: LockingEnabled must be 0 while LockingSP is inactive. | Correct. Exercises Discovery/lifecycle consistency before activation. |
| `syn_fail_47_discovery_few_admins.json` | fail | fail; expected `success`, actual `discovery_opal_v2`; reason: reported 2 admin authorities, fewer than required 4. | Correct. Exercises Opal SSC V2 minimum admin count. |

## Rename/delete hygiene

Current git status under `v6` shows:

- `D v6/customtest_57/...` for 60 tracked files.
- `?? v6/customtest_84/` for the new generated directory.
- `v6/customtest_84/__pycache__/generate_synthetic.cpython-312.pyc` exists and should not be committed.

This looks intentional in the sense that `customtest_84` is the 84-case successor to the 57-case dataset, but it is incomplete as a repository operation. If the intended state is replacement, the move should be staged/recorded explicitly, docs should be updated from `customtest_57`/57 cases to `customtest_84`/84 cases, and the pycache should be removed/ignored. If the intended state is additive, then deleting `customtest_57` is a hygiene issue.

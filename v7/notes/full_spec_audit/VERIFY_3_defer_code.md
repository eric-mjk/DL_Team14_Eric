# Verification Agent 3: DEFER-Code Audit

Scope: inspected `IMPLEMENTATION_PLAN.md` DEFER items marked Done and current `v6/src` only. No source or testcase files were edited.

## Summary

| Item | Verdict | Keep as Done? |
|---|---:|---:|
| D-P2 Log table / CreateLog uniqueness | Partial | No |
| D-P1 Re-encryption range/key restrictions | Partial | No |
| E-P1 Reset events abort sessions | Correct, with narrow detection caveat | Mostly |
| C-P0-1 Two-step Authenticate Sign/SymK/HMAC | Buggy | No |
| A-P1 Generic Core SP lifecycle Disabled/Frozen | Partial | No |
| C-P0-5 AddACE/RemoveACE/DeleteMethod mutations | Buggy | No |
| F-P0 DataRemovalMechanism + TPerInfo tables | Partial | No |
| F-P0 AccessControl `(N)` column/GetACL behavior | Buggy/Partial | No |
| E-P1 Level 0 Discovery normalization/judging | Partial; should remain deferred | No |

## Findings

### D-P2 Log table / CreateLog uniqueness - Partial

Implemented pieces:

- `initial_state()` now seeds `log_tables` with default Log table UID `0000000100000A01` and an empty `log_table_names` set (`v6/src/state.py:112-115`).
- `_apply_successful_create_log()` records `NewLogTableName` and, if the return columns expose UID/col 0, records that UID (`v6/src/state.py:261-270`); `apply_event()` calls it on successful `CreateLog` (`v6/src/state.py:1097-1098`).
- `judge_log_method()` rejects duplicate `NewLogTableName` and rejects `AddLog`/`ClearLog`/`FlushLog` on unknown Log table UIDs (`v6/src/oracle.py:2357-2395`).

Gaps / risk:

- Existence tracking depends on a successful `CreateLog` response exposing the new table UID through parsed return columns. If later events target a created log by UID but the prior response did not expose that UID, the oracle will false-fail the later log method.
- Name comparison is exact `str(log_name)` (`v6/src/oracle.py:2364-2365`), with no canonicalization for equivalent table-name encodings.
- This does not model the rest of `CreateLog` failure surface called out by Agent D: insufficient space, missing support rows, excessive `MinSize`, circular log behavior, or LogList row side effects (`AGENT_D_core_templates_crypto_clock_log.md:101-103`).

Spec/audit rationale: Core `5.8.3` requires `AddLog`/`ClearLog`/`FlushLog` to fail when the referenced Log table does not exist; Core `5.8.4` requires duplicate `CreateLog` names to fail. The current implementation covers the common observable case but is not robust enough to call the DEFER item fully done.

### D-P1 Re-encryption range/key restrictions - Partial

Implemented pieces:

- `invalid_locking_range_update()` now rejects RangeStart/RangeLength updates for non-IDLE target ranges and when Global Range is non-IDLE (`v6/src/oracle.py:709-727`).
- `judge_gen_key()` rejects media-key `GenKey` while the associated range is non-IDLE (`v6/src/oracle.py:2036-2057`).
- `judge_row_management()` rejects `CreateRow`/`DeleteRow` on the Locking table while Global Range is non-IDLE (`v6/src/oracle.py:2239-2258`).

Gaps / risk:

- `judge_delete()` has no Global Range non-IDLE check for `Delete` on Locking objects (`v6/src/oracle.py:2269-2279`), even though the plan explicitly listed `judge_delete`/`Delete`.
- The `GenKey` check only fires when normalization supplies `event["key_range"]` (`v6/src/oracle.py:2046-2047`). It does not validate an arbitrary credential/key object referenced by a Locking row's current ActiveKey/NextKey unless that UID normalizes to a range key.
- The status expected for non-IDLE key/range failures is mixed between `invalid_parameter` and broad `error`; that may be acceptable for current labels but is not precise.

Spec/audit rationale: Agent D states RangeStart/RangeLength, Locking row create/delete, and associated key ops fail while the relevant range or Global Range is not IDLE (`AGENT_D_core_templates_crypto_clock_log.md:32`, `78`, `127-129`). Delete remains uncovered, so this should not be marked Done.

### E-P1 Reset events abort sessions - Correct, with narrow detection caveat

Implemented pieces:

- `apply_reset_like_event()` applies LockOnReset, applies MBR DoneOnReset, then closes the session with `empty_session()`, clears `pending_clock_lag`, and clears `crypto_streams` (`v6/src/state.py:853-871`).
- `apply_event()` invokes that reset handler for successful command events recognized by `reset_like_command()` (`v6/src/state.py:1107-1108`).
- The recognition catches text containing `reset`, `reboot`, `power cycle`, or `powercycle` (`v6/src/state.py:838-840`), which covers common `TPER_RESET`, stack reset, interface reset, and hardware reset spellings.

Gaps / risk:

- Recognition is still heuristic and misses some audit-listed reset-like spellings such as `hotplug`, and likely `power_cycle` with an underscore (`AGENT_E_opal_intro_features.md:157`).
- It only runs after `success_like(event)`; that is desirable for failed commands but means interface-level TPER_RESET transport semantics are still not modeled.

Spec/audit rationale: Opal `3.2.3`/`3.3.5.1` require reset events to abort open sessions and transient protocol state. The core side effect is implemented correctly for recognized successful reset commands.

### C-P0-1 Two-step Authenticate Sign/SymK/HMAC - Buggy

Implemented pieces:

- `judge_authenticate()` recognizes authorities with Operation `Sign`, `SymK`, or `HMAC` and requires the method status to be `SUCCESS`, avoiding the old `INVALID_PARAMETER` rejection (`v6/src/oracle.py:1512-1543`).

Bug / unsafe behavior:

- There is no pending challenge state in `empty_session()` (`v6/src/state.py:48-59`) or anywhere else in state. The implementation does not store a first-call challenge, match a second-call Proof to it, or clear challenge state on session close/reset.
- The judge accepts any `SUCCESS` for both first and second calls, regardless of whether a Proof was supplied or whether the returned `Success` result is True/False (`v6/src/oracle.py:1524-1543`).
- `apply_event()` still routes successful Authenticate to `remember_successful_authenticate()` (`v6/src/state.py:1074-1078`). That function adds the authority if `auth_result is True` even without a verified challenge-response relation (`v6/src/state.py:285-301`). A successful-looking Sign/SymK/HMAC second step can therefore grant authority without modeled proof validation.

Spec/audit rationale: Core `5.3.4.1.14`/`5.3.4.1.14.1` require a two-call challenge-response flow where the second call's Proof determines `SUCCESS True` vs `SUCCESS False`. The current code is a status-shape relaxation, not a state machine. This should remain deferred until challenge state exists.

### A-P1 Generic Core SP lifecycle Disabled/Frozen - Partial

Implemented pieces:

- `initial_state()` has `sp_lifecycle` for AdminSP and LockingSP (`v6/src/state.py:89-92`).
- `apply_sp_lifecycle_columns()` tracks Set of SP columns 6/7 as Disabled/Frozen combinations, but only for `AdminSP` and `LockingSP` (`v6/src/state.py:657-690`).
- `judge_start_session()` rejects StartSession when tracked lifecycle contains `Disabled` or `Frozen` (`v6/src/oracle.py:1393-1407`).

Gaps / risk:

- This is not generic Core lifecycle. It ignores issued/non-Opal SPs because `apply_sp_lifecycle_columns()` returns unless the canonical SP is `AdminSP` or `LockingSP` (`v6/src/state.py:658-661`).
- There is no `Failed` lifecycle handling.
- Disabled-SP method preflight is absent. The plan required non-exempt methods to a disabled SP to fail while exempting `Authenticate`, `DeleteSP`, and re-enable Set; the current code only blocks session startup (`v6/src/oracle.py:1378-1494`) and does not add a method-level disabled-SP gate in `method_preflight()` (`v6/src/oracle.py:1153-1313`).
- It uses broad `"error"` expected status for disabled/frozen StartSession (`v6/src/oracle.py:1395-1405`), not distinct `SP_DISABLED`/`SP_FROZEN`. That can mask wrong status classes.

Spec/audit rationale: Agent A says disabled SPs allow only specific methods and otherwise return `SP_DISABLED`; frozen and failed SPs have distinct startup failures (`AGENT_A_core_arch_types.md:232`, `282-283`, `326-328`). Current code is an Opal-specific partial implementation.

### C-P0-5 AddACE/RemoveACE/DeleteMethod mutations - Buggy

Implemented pieces:

- Successful `AddACE`, `RemoveACE`, and `DeleteMethod` now mutate `access_control_rows` via `_apply_successful_add_ace()`, `_apply_successful_remove_ace()`, and `_apply_successful_delete_method()` (`v6/src/state.py:1001-1039`), called from `apply_event()` (`v6/src/state.py:1099-1104`).

Bug / unsafe behavior:

- `judge_meta_acl()` does not evaluate AddACEACL, RemoveACEACL, or DeleteMethodACL. For `AddACE`/`RemoveACE`/`DeleteMethod`, it only requires an open write session with any authority (`v6/src/oracle.py:2304-2323`). That is overbroad and can pass unauthorized ACL mutation methods.
- `_apply_successful_add_ace()` only appends an ACE UID/reference to a row (`v6/src/state.py:1001-1019`). It does not create or update an ACE row's BooleanExpr/Columns, so adding a new ACE whose body is supplied by the operation cannot grant access correctly.
- `_apply_successful_delete_method()` deletes matching AccessControl rows immediately (`v6/src/state.py:1031-1039`) without modeling related logs/metadata or method-specific delete authorization.

Spec/audit rationale: Core `5.3.4.3`/`5.3.4.3.1` require meta-ACL methods to satisfy the matching AddACEACL/RemoveACEACL/GetACLACL/DeleteMethodACL column, and later authorization must use the mutated ACL structure (`AGENT_C_core_methods.md:417-419`, `467`, `506`, `538`). Current mutation is thin and its authorization gate is unsafe.

### F-P0 DataRemovalMechanism + TPerInfo tables - Partial

Implemented pieces:

- `normalizer.py` recognizes table UIDs and row UID prefixes for `TPerInfo` and `DataRemovalMechanism` (`v6/src/normalizer.py:19-42`, `294-297`, `379-383`).
- `spec_docs.py` has column schemas and read-only sets for both tables (`v6/src/spec_docs.py:222-230`, `279-280`).
- `invalid_data_removal_enum()` rejects ActiveDataRemovalMechanism values outside `{0,1,2,5}` (`v6/src/oracle.py:795-802`), and `judge_set()` invokes it (`v6/src/oracle.py:1862-1870`).

Gaps / risk:

- `ProgrammaticResetEnable` boolean value validation is missing. `method_preflight()` only validates method parameters such as `Write`, `KeepGlobalRangeKey`, and `DeletePattern` (`v6/src/oracle.py:1185-1191`), not TPerInfo column 8 values.
- `object_sp()` does not map `TPerInfo`, `DataRemovalMechanism`, or `AccessControl` to AdminSP (`v6/src/oracle.py:621-636`). When no ACE row matches, protected Set fallback can treat the current session SP as the target, allowing wrong-SP authorization paths.
- `judge_set()` has no family-specific fallback for `TPerInfo` or `DataRemovalMechanism`; after policy matching, it falls through to any authenticated write session (`v6/src/oracle.py:1872-1878`, `1945-1951`). This is overbroad if the extracted AccessControl rows do not match the event shape.
- It does not validate TPerInfo fixed contents such as SSC containing Opal, nor conditional DataRemovalMechanism table existence based on feature descriptor support (`AGENT_F_opal_adminsp.md:97-98`).

Spec/audit rationale: Agent F requires TPerInfo `ProgrammaticResetEnable` to be boolean, readable by Anybody and settable only by SID, and DataRemovalMechanism ActiveDataRemovalMechanism to reject reserved/unsupported enum values (`AGENT_F_opal_adminsp.md:55-56`, `82-83`, `116-117`). Current support is schema plus one enum check, not full table behavior.

### F-P0 AccessControl `(N)` column / GetACL behavior - Buggy/Partial

Implemented pieces:

- `NOT_READABLE_VIA_GET["AccessControl"] = {1,2,4,8}` lists InvokingID, MethodID, ACL, and GetACLACL (`v6/src/spec_docs.py:283-287`).
- `judge_get()` rejects explicit Get cellblocks that request these columns (`v6/src/oracle.py:1643-1655`).

Bug / unsafe behavior:

- A Get with no explicit cellblock columns can still reach policy/fallback behavior because `requested_cols` is empty and the `(N)` check does not treat whole-row/default-column Gets as including the forbidden columns (`v6/src/oracle.py:1643-1655`).
- `judge_meta_acl()` handles `GetACL` by requiring only an open session and assuming GetACLACL defaults to `ACE_Anybody` (`v6/src/oracle.py:2310-2315`). It does not evaluate the target row's actual GetACLACL column. This may allow GetACL when GetACLACL is empty/denied and may reject/accept for the wrong reason.
- The same `judge_meta_acl()` weakness affects AddACE/RemoveACE/DeleteMethod because it does not use the row-specific meta-ACL columns (`v6/src/oracle.py:2315-2317`).

Spec/audit rationale: Agent F states AccessControl InvokingID, MethodID, and GetACLACL have `(N)` Get access, ACL is readable only through GetACL, and GetACL must evaluate GetACLACL (`AGENT_F_opal_adminsp.md:52`, `68-69`, `81`, `114-115`). Current code covers only explicit-column Get denial.

### E-P1 Level 0 Discovery normalization + judging - Partial; should remain deferred

Implemented pieces:

- `normalize_record()` recognizes IF_RECV records only when output includes a structured `discovery` or `descriptors` payload (`v6/src/normalizer.py:708-714`).
- `_normalize_discovery()` builds a `features` dict keyed by parsed feature code (`v6/src/normalizer.py:587-620`).
- `judge_discovery()` checks for TPer, Locking, and Opal SSC V2 descriptors and validates a few fields when present (`v6/src/oracle.py:2661-2766`).

Gaps / risk:

- Normalization does not parse raw Level 0 Discovery buffers, security protocol `0x01`, ComID `0x0001`, descriptor lengths, or header fields. It only handles an already-decoded synthetic shape.
- Several mandatory fields are treated as optional: TPer sync/streaming pass when missing because the check is `is not False` (`v6/src/oracle.py:2678-2693`); LockingSupported and MediaEncryption only fail when explicitly False (`v6/src/oracle.py:2695-2717`); Opal admin/user/ComID counts only fail when present and too low (`v6/src/oracle.py:2738-2760`).
- It does not judge many Agent E/A executable requirements: descriptor feature-code/length correctness, geometry fields, crypto erase support, MBREnabled/MBRDone/Locked dynamic bits, range crossing behavior, or malformed descriptor payloads (`AGENT_E_opal_intro_features.md:98-110`, `140`, `162-170`; `AGENT_A_core_arch_types.md:234`, `311-313`).

Spec/audit rationale: Opal `3.1.1.*` Level 0 Discovery has mandatory descriptors and normative field values. The current implementation is useful for a narrow structured synthetic test, but over-lenient for real discovery responses and should remain deferred until raw parsing and complete field checks are added.

## Top Issues

1. Two-step Authenticate is unsafe: it accepts any SUCCESS for Sign/SymK/HMAC and can grant authority without a modeled pending challenge or proof verification (`v6/src/oracle.py:1524-1543`; `v6/src/state.py:285-301`).
2. Meta-ACL methods are overbroad: AddACE/RemoveACE/DeleteMethod/GetACL do not evaluate the row-specific meta-ACL columns (`v6/src/oracle.py:2304-2323`).
3. AccessControl `(N)` and GetACL are only partially implemented: explicit forbidden columns are blocked, but whole-row Gets and row-specific GetACLACL are not handled (`v6/src/oracle.py:1643-1655`, `2310-2315`).
4. Generic SP lifecycle is not generic: only AdminSP/LockingSP Disabled/Frozen startup is tracked, with no Failed state or disabled-SP method preflight (`v6/src/state.py:657-690`; `v6/src/oracle.py:1393-1407`).
5. Level 0 Discovery should not be considered Done: it handles only pre-decoded descriptors and treats many mandatory fields as optional (`v6/src/normalizer.py:708-714`; `v6/src/oracle.py:2661-2766`).

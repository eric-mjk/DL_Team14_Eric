# Agent H Audit: Opal 5.* Lifecycle, Revert, RevertSP, PSID-Adjacent Behavior

## Documents Read

Read all 35 assigned files under `documents/opal/5.*`:

1. `documents/opal/5.1.txt`
2. `documents/opal/5.1.1.txt`
3. `documents/opal/5.1.1.1.txt`
4. `documents/opal/5.1.1.2.txt`
5. `documents/opal/5.1.2.txt`
6. `documents/opal/5.1.2.1.txt`
7. `documents/opal/5.1.2.2.txt`
8. `documents/opal/5.1.2.2.1.txt`
9. `documents/opal/5.1.2.3.txt`
10. `documents/opal/5.1.3.txt`
11. `documents/opal/5.1.3.1.txt`
12. `documents/opal/5.1.3.2.txt`
13. `documents/opal/5.1.3.3.txt`
14. `documents/opal/5.1.3.4.txt`
15. `documents/opal/5.2.txt`
16. `documents/opal/5.2.1.txt`
17. `documents/opal/5.2.1.1.txt`
18. `documents/opal/5.2.1.2.txt`
19. `documents/opal/5.2.2.txt`
20. `documents/opal/5.2.2.1.txt`
21. `documents/opal/5.2.2.2.txt`
22. `documents/opal/5.2.2.2.1.txt`
23. `documents/opal/5.2.2.2.2.txt`
24. `documents/opal/5.2.2.3.txt`
25. `documents/opal/5.2.2.3.1.txt`
26. `documents/opal/5.2.2.3.2.txt`
27. `documents/opal/5.2.3.txt`
28. `documents/opal/5.3.txt`
29. `documents/opal/5.3.1.txt`
30. `documents/opal/5.3.1.1.txt`
31. `documents/opal/5.3.1.1.1.txt`
32. `documents/opal/5.3.1.1.2.txt`
33. `documents/opal/5.3.1.2.txt`
34. `documents/opal/5.3.1.2.1.txt`
35. `documents/opal/5.3.1.2.2.txt`

The full on-disk count is 35 files.

## Key Normative Requirements Relevant To Final-Response Judging

- `Activate` is an Admin SP SP-object method. It operates in a read-write Admin SP session. The TPer shall not permit invocation on issued SP objects. Invocation on a `Manufactured-Inactive` SP transitions it to `Manufactured`; invocation on an SP in any other lifecycle state shall complete successfully if access control is satisfied and have no effect. An Activate Error fails with `FAIL`. MethodID is `0000000600000203`.
- Successful `Activate` changes the Admin SP SP-table `LifeCycleState` to `Manufactured`, copies current `C_PIN_SID.PIN` into activated-SP `C_PIN_Admin1.PIN`, activates template functionality, and shall not destroy user data when transitioning the LockingSP from inactive to manufactured.
- `Revert` is an Admin SP SP-object method. It operates in a read-write Admin SP session. The TPer shall not permit it on issued SP objects. It is permitted for manufactured SPs in any lifecycle state. Successful Revert on a manufactured SP in `Manufactured-Inactive` has no effect on that SP.
- Successful `Revert` on LockingSP or AdminSP causes user data removal and media-key eradication only if the LockingSP is not `Manufactured-Inactive`; if LockingSP is inactive, Revert on LockingSP shall not cause user data removal. Revert on AdminSP reverts the whole TPer to original factory state, except `C_PIN_SID.PIN` follows the special rule in `5.1.2.2.1`; manufactured SPs already in `Manufactured-Inactive` are not affected.
- On successful AdminSP Revert, if SID has never authenticated, `C_PIN_SID.PIN` remains current. If SID has authenticated, then the descriptor field `Behavior of C_PIN_SID PIN upon TPer Revert` controls whether SID becomes `C_PIN_MSID.PIN` or a vendor-unique value.
- `RevertSP` is an SP method. It operates in a read-write session to the target SP, reverts the SP to OFS, reports status, then aborts the session.
- `KeepGlobalRangeKey=True` is Locking Template-specific. For LockingSP RevertSP, if the Global Range is either read-unlocked or write-unlocked, the TPer shall keep the Global Range user data and media key. If the Global Range is both read-locked and write-locked, RevertSP with `KeepGlobalRangeKey=True` shall fail with `FAIL` and not change lifecycle state.
- Manufactured lifecycle: AdminSP OFS is `Manufactured`; manufactured LockingSP OFS is `Manufactured-Inactive`, and both `Manufactured` and `Manufactured-Inactive` are mandatory for manufactured LockingSP. Sessions cannot be opened to SPs in `Manufactured-Inactive`; LockingSP locking/media-encryption management is disabled while inactive and enabled while manufactured.
- `life_cycle_state` valid values are extended: `8 = manufactured-inactive`, `9 = manufactured`, `10-13 = manufactured disabled/frozen/failed variants`, `14-15 = reserved`.
- Byte-table granularity: `Table.MandatoryWriteGranularity` and `Table.RecommendedAccessGranularity` are not host-modifiable. For object-table rows both are zero. For byte-table rows, mandatory granularity applies to Set `Where` and byte length; invalid mandatory alignment shall fail with `INVALID_PARAMETER`. Recommended granularity only affects performance and is not a pass/fail condition.

## Implementation Coverage Assessment

- `Solver.predict_one` returns the lowercase `RuleResult.verdict` from `judge_final`, so the project goal's lowercase `pass`/`fail` output contract is covered (`v6/src/solver.py:62-80`). No source edit needed.
- Method name/UID normalization covers `Activate`, `Revert`, and `RevertSP` (`v6/src/spec_docs.py:60-81`, `v6/src/normalizer.py:593-643`). `KeepGlobalRangeKey`, `Where`, and byte payload length are normalized for later checks (`v6/src/normalizer.py:619-625`). No source edit needed for basic parsing.
- Initial lifecycle state matches the mandatory Opal assumption for this project: AdminSP `Manufactured`, LockingSP `Manufactured-Inactive`, and `locking_sp_active=False` (`v6/src/state.py:81-85`). No source edit needed.
- `Activate` side effects are tracked: LockingSP becomes active/manufactured and current SID is copied to Admin1 (`v6/src/state.py:651-658`). No source edit needed for a successful inactive-to-manufactured activation.
- `Activate` final judging requires target `LockingSP`, AdminSP write session, and SID authority (`v6/src/oracle.py:1875-1888`). The access-control requirement is stricter than the 5.* text alone, but consistent with the broader AdminSP ownership model. No source edit needed for ordinary first activation.
- Gap: `judge_activate` treats an already active LockingSP as `INVALID_PARAMETER` (`v6/src/oracle.py:1879-1880`), but `5.1.1` says invocation in any non-inactive lifecycle state shall complete successfully if access control is satisfied and have no effect. This can misjudge final `Activate` responses after a previous successful activation.
- `StartSession` to inactive LockingSP is rejected (`v6/src/oracle.py:1372-1378`), matching `5.2.2.1` / `5.2.2.3.1`. No source edit needed.
- `Revert` final judging requires an SP object, an AdminSP write session, and SID or PSID authority (`v6/src/oracle.py:1891-1905`). The SID/PSID decision is broader than the 5.* files; PSID is not normatively defined in the assigned 5.* set. Current source should keep PSID only if backed by the separate PSID Feature Set.
- Gap: `judge_revert` permits any normalized `SP` object, including unknown `SP_xxxx` objects that may represent issued SPs (`v6/src/oracle.py:1891-1905`). `5.1.2` says Revert shall not be permitted on issued SP objects. In this Opal model, only AdminSP and manufactured LockingSP are known manufactured SPs.
- `Revert` state transitions mostly exist: successful LockingSP Revert calls `reset_locking_sp`; AdminSP Revert resets LockingSP, AdminSP credentials/policy, tables, lockout state, sessions, writes, and named key tracking (`v6/src/state.py:688-739`). Session abort is covered by resetting `state["session"]`. No source edit needed for normal active LockingSP or AdminSP Revert side effects.
- Gap: `reset_locking_sp` always bumps key generations for all affected ranges (`v6/src/state.py:688-695`), and AdminSP/LockingSP Revert always calls it (`v6/src/state.py:722-729`). `5.1.2.2` says Revert on a `Manufactured-Inactive` LockingSP has no user-data removal and manufactured SPs already inactive are not affected by AdminSP Revert. Prior successful Revert steps while inactive can therefore poison later final read/key-generation judgments.
- `C_PIN_SID.PIN` handling after successful AdminSP Revert is partially covered. If SID has authenticated, the code sets SID to tracked MSID; otherwise it leaves SID unchanged (`v6/src/state.py:710-718`). This matches descriptor behavior `0x00`. The vendor-unique branch is not executable because the normalized state does not track the Opal SSC V2 descriptor field. No source edit needed unless descriptor fields appear in traces.
- `RevertSP` final judging handles inactive LockingSP rejection, `KeepGlobalRangeKey=True` failure when Global is both read-locked and write-locked, and admin/owner write-session authorization (`v6/src/oracle.py:1908-1930`). No source edit needed for the locked-global failure case.
- Gap: `KeepGlobalRangeKey` logic is not scoped to LockingSP. `judge_revert_sp` checks the Global Range for any current SP (`v6/src/oracle.py:1913-1922`), and `apply_successful_revert_sp` lets AdminSP RevertSP preserve the Global key (`v6/src/state.py:742-754`). `5.1.3.2` and `5.1.3.3` define this behavior only for LockingSP.
- `RevertSP` successful LockingSP side effects are mostly covered by `reset_locking_sp(preserve_global_key=...)` (`v6/src/state.py:688-707`, `v6/src/state.py:742-747`). No source edit needed for ordinary LockingSP RevertSP with `KeepGlobalRangeKey=False` or allowed `True`.
- Gap: SP-table lifecycle values are tracked in `state["sp_lifecycle"]` but not validated on final `Get` of the AdminSP `SP` table. `judge_get` has no `family == "SP"` branch and falls through to generic success (`v6/src/oracle.py:1573-1709`). A final response that returns stale `LifeCycleState` after Activate/Revert would be passed.
- Type-table lifecycle enum values are represented in column metadata (`v6/src/spec_docs.py:222-224`) but there is no final-response check that returned lifecycle values avoid reserved values or match tracked state. This matters only when traces expose SP table column 6 values.
- Mandatory byte-table write granularity is implemented when a prior Table row provides `MandatoryWriteGranularity`: `byte_table_granularity` and `invalid_byte_table_granularity` check byte-table Set `Where` and byte length, returning `INVALID_PARAMETER` on violations (`v6/src/oracle.py:784-815`, `v6/src/oracle.py:1236-1256`). No source edit needed for mandatory alignment once table metadata is known.
- Recommended byte-table granularity is intentionally not enforced, because `5.3.1.2.2` only says performance may be reduced. No source edit needed.
- Table granularity columns are marked in the generic table schema (`v6/src/spec_docs.py:224`) and Set rule refs include Opal 5.3 sections (`v6/src/spec_docs.py:268-269`). No source edit needed for traceability.
- Static `spec_tables.POLICIES` lists Revert as SID-only (`v6/src/spec_tables.py:359-368`), while `judge_revert` allows SID or PSID (`v6/src/oracle.py:1894-1904`). This is not currently a final-judge bug because Revert has a dedicated judge path, but it is a source-of-truth inconsistency.

## Required Edits

1. P0: Fix repeated `Activate` final judging. In `judge_activate`, if LockingSP is already `Manufactured`/active and AdminSP write-session access control is satisfied, expect `success`, not `invalid_parameter`; state mutation for prior successful repeated Activate should be no-op. Keep target validation for non-LockingSP/issued targets.
2. P0: Validate SP lifecycle values on final `Get`. Add a `family == "SP"` branch in `judge_get` for `LifeCycleState`/column 6 returned from the AdminSP SP table. Compare returned values against `state["sp_lifecycle"]` for AdminSP/LockingSP, accepting the documented numeric/string forms (`8`/`manufactured-inactive`, `9`/`manufactured`) and failing stale or reserved values.
3. P1: Restrict `Revert` to known manufactured SP objects in this Opal model. `judge_revert` should accept only AdminSP and LockingSP unless the state model explicitly tracks an SP as manufactured. Unknown `SP_xxxx`/issued objects should expect an error, per `5.1.2`.
4. P1: Make Revert side effects conditional on LockingSP lifecycle. `reset_locking_sp` or its callers should avoid key-generation bumps/data-erasure modeling when the LockingSP is already `Manufactured-Inactive`, both for LockingSP Revert and AdminSP Revert. AdminSP Revert should still reset AdminSP personalization, SID per `5.1.2.2.1`, sessions, policy, etc.
5. P1: Scope `KeepGlobalRangeKey` to LockingSP RevertSP. The locked-global failure check and preserved Global key side effect should run only when the current SP is LockingSP. For AdminSP RevertSP, decide whether the parameter is invalid or ignored; do not preserve Global key based on the assigned 5.* text.
6. P2: Add explicit traceability for interrupted Revert/RevertSP sections. `RULE_REFERENCES["revert"]` should include `opal/5.1.2.3`, and `RULE_REFERENCES["revert_sp"]` should include `opal/5.1.3.4`. If no raw reset/interruption signal is exposed, classify these as transport/background-operation constraints rather than executable status rules.
7. P2: Align PSID source-of-truth. Either add PSID Feature Set refs to the audit/coverage source and `spec_tables.POLICIES`, or document that PSID is handled only by `judge_revert` and not by static policy. Do not infer PSID behavior from the assigned 5.* documents alone.

## Ambiguities And Intentionally Non-Executable Sections

- Transaction support for Activate/Revert/RevertSP is `(N)` and explicitly out of scope in `5.1.1.1`, `5.1.2.1`, and `5.1.3.1`; normalized traces do not expose transaction containment here.
- "Activate Error" is defined by an external reference. Without an exposed activate-error condition, the solver can only judge ordinary access/target/lifecycle status.
- Interrupted Revert/RevertSP behavior depends on TCG reset/power-loss timing and Level 0 discovery bits. Unless traces expose interruption and discovery fields, it should not alter final method status beyond normal reset-like events.
- The statement that a Revert/RevertSP return status does not mean all background data removal is complete is not directly executable for command-response judging unless later data/discovery observations expose completion state.
- Issued SP lifecycle management is delegated to the base architecture reference in `5.2.1.1`; this audit only found the Opal-specific prohibition against Activate/Revert on issued SP objects.
- Vendor-unique SID reset behavior after AdminSP Revert depends on the Opal SSC V2 descriptor field. Current state does not track that field, so deterministic judging can only implement the default/MSID branch or remain conservative when descriptor data is absent.
- Recommended byte-table granularity is advisory/performance-only. It should not cause `fail` for final-response compliance.
- PSID is not normatively defined in the assigned `documents/opal/5.*` files. Existing PSID behavior appears to come from a separate PSID Feature Set and should be audited against that source, not inferred from this section set.

## Synthetic Tests Recommended

- Prior successful Activate, then final `Activate` on LockingSP with valid SID AdminSP write session returns `SUCCESS`: expect `pass`; final `INVALID_PARAMETER` should be `fail`.
- Prior successful Activate, then final `Get` of LockingSP SP-table `LifeCycleState` returns `manufactured-inactive`/`8`: expect `fail`; `manufactured`/`9`: expect `pass`.
- Final `Revert` on unknown issued-like `SP_1234` in AdminSP write session with SID returns `SUCCESS`: expect `fail`.
- Write data while LockingSP is inactive, perform successful LockingSP Revert while still inactive, then final read of that LBA returns the original pattern: expect `pass`.
- LockingSP active with data written, successful AdminSP Revert, then final LockingSP StartSession fails because inactive and final read behavior reflects key/data removal only when LockingSP had not been inactive.
- LockingSP active, Global read-locked and write-unlocked, final RevertSP with `KeepGlobalRangeKey=True` succeeds and later Global data/key generation is preserved.
- LockingSP active, Global read-locked and write-locked, final RevertSP with `KeepGlobalRangeKey=True` returns `FAIL`: expect `pass`; `SUCCESS` should be `fail`.
- AdminSP RevertSP with `KeepGlobalRangeKey=True` while LockingSP Global is locked should not fail solely due to Global lock state; expected behavior should be fixed as either invalid parameter or normal AdminSP RevertSP without Global preservation.
- Learned Table row sets `MandatoryWriteGranularity=4` for DataStore/MBR; final byte-table Set with `Where=2`, length 4 returns `INVALID_PARAMETER`: expect `pass`; `SUCCESS` should be `fail`.
- Learned Table row sets only `RecommendedAccessGranularity=4`; misaligned final Get/Set returns `SUCCESS`: expect `pass` because recommendation is not mandatory.

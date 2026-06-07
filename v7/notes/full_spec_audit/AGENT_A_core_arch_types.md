# Agent A Core Architecture and Types Spec Audit

Scope: `documents/core/1.*`, `documents/core/2.*`, `documents/core/3.*`, and `documents/core/4.*` compared against `v6/src/solver.py`, `v6/src/normalizer.py`, `v6/src/state.py`, `v6/src/oracle.py`, `v6/src/spec_docs.py`, and `v6/src/spec_tables.py`.

Constraint observed: no source files under `v6/src` were edited. This note is the only file written for this audit.

## Document Files Read

Exact count: 200 document files.

```text
documents/core/1.1.txt
documents/core/1.2.txt
documents/core/1.3.txt
documents/core/1.4.1.txt
documents/core/1.4.txt
documents/core/2.1.txt
documents/core/2.2.1.txt
documents/core/2.2.2.1.txt
documents/core/2.2.2.txt
documents/core/2.2.3.txt
documents/core/2.2.4.txt
documents/core/2.2.txt
documents/core/2.3.1.txt
documents/core/2.3.2.txt
documents/core/2.3.3.txt
documents/core/2.3.4.txt
documents/core/2.3.txt
documents/core/3.1.txt
documents/core/3.2.1.1.txt
documents/core/3.2.1.2.txt
documents/core/3.2.1.3.txt
documents/core/3.2.1.4.txt
documents/core/3.2.1.txt
documents/core/3.2.2.1.txt
documents/core/3.2.2.2.txt
documents/core/3.2.2.3.1.1.txt
documents/core/3.2.2.3.1.2.txt
documents/core/3.2.2.3.1.3.txt
documents/core/3.2.2.3.1.4.txt
documents/core/3.2.2.3.1.5.txt
documents/core/3.2.2.3.1.txt
documents/core/3.2.2.3.2.1.txt
documents/core/3.2.2.3.2.2.txt
documents/core/3.2.2.3.2.txt
documents/core/3.2.2.3.3.1.txt
documents/core/3.2.2.3.3.2.txt
documents/core/3.2.2.3.3.3.txt
documents/core/3.2.2.3.3.4.txt
documents/core/3.2.2.3.3.5.txt
documents/core/3.2.2.3.3.txt
documents/core/3.2.2.3.4.txt
documents/core/3.2.2.3.txt
documents/core/3.2.2.4.1.txt
documents/core/3.2.2.4.2.txt
documents/core/3.2.2.4.txt
documents/core/3.2.2.txt
documents/core/3.2.3.1.txt
documents/core/3.2.3.2.1.1.txt
documents/core/3.2.3.2.1.2.txt
documents/core/3.2.3.2.1.3.txt
documents/core/3.2.3.2.1.4.txt
documents/core/3.2.3.2.1.5.txt
documents/core/3.2.3.2.1.6.txt
documents/core/3.2.3.2.1.txt
documents/core/3.2.3.2.2.1.txt
documents/core/3.2.3.2.2.txt
documents/core/3.2.3.2.txt
documents/core/3.2.3.3.1.1.txt
documents/core/3.2.3.3.1.2.txt
documents/core/3.2.3.3.1.3.txt
documents/core/3.2.3.3.1.4.txt
documents/core/3.2.3.3.1.5.txt
documents/core/3.2.3.3.1.6.txt
documents/core/3.2.3.3.1.txt
documents/core/3.2.3.3.2.1.txt
documents/core/3.2.3.3.2.txt
documents/core/3.2.3.3.txt
documents/core/3.2.3.4.1.1.1.txt
documents/core/3.2.3.4.1.1.2.txt
documents/core/3.2.3.4.1.1.3.txt
documents/core/3.2.3.4.1.1.txt
documents/core/3.2.3.4.1.2.1.txt
documents/core/3.2.3.4.1.2.2.txt
documents/core/3.2.3.4.1.2.txt
documents/core/3.2.3.4.1.txt
documents/core/3.2.3.4.2.1.1.txt
documents/core/3.2.3.4.2.1.2.txt
documents/core/3.2.3.4.2.1.3.txt
documents/core/3.2.3.4.2.1.txt
documents/core/3.2.3.4.2.2.1.txt
documents/core/3.2.3.4.2.2.txt
documents/core/3.2.3.4.2.txt
documents/core/3.2.3.4.txt
documents/core/3.2.3.5.1.1.txt
documents/core/3.2.3.5.1.2.txt
documents/core/3.2.3.5.1.3.txt
documents/core/3.2.3.5.1.4.txt
documents/core/3.2.3.5.1.5.txt
documents/core/3.2.3.5.1.6.txt
documents/core/3.2.3.5.1.txt
documents/core/3.2.3.5.2.1.txt
documents/core/3.2.3.5.2.2.1.txt
documents/core/3.2.3.5.2.2.2.txt
documents/core/3.2.3.5.2.2.3.txt
documents/core/3.2.3.5.2.2.txt
documents/core/3.2.3.5.2.3.txt
documents/core/3.2.3.5.2.txt
documents/core/3.2.3.5.txt
documents/core/3.2.3.txt
documents/core/3.2.4.1.txt
documents/core/3.2.4.2.txt
documents/core/3.2.4.3.txt
documents/core/3.2.4.txt
documents/core/3.2.5.1.txt
documents/core/3.2.5.2.txt
documents/core/3.2.5.3.txt
documents/core/3.2.5.4.txt
documents/core/3.2.5.txt
documents/core/3.2.6.txt
documents/core/3.2.txt
documents/core/3.3.1.txt
documents/core/3.3.10.txt
documents/core/3.3.2.txt
documents/core/3.3.3.1.txt
documents/core/3.3.3.2.txt
documents/core/3.3.3.3.txt
documents/core/3.3.3.txt
documents/core/3.3.4.1.txt
documents/core/3.3.4.2.txt
documents/core/3.3.4.3.1.txt
documents/core/3.3.4.3.txt
documents/core/3.3.4.4.1.txt
documents/core/3.3.4.4.txt
documents/core/3.3.4.5.txt
documents/core/3.3.4.6.txt
documents/core/3.3.4.7.1.txt
documents/core/3.3.4.7.2.txt
documents/core/3.3.4.7.3.txt
documents/core/3.3.4.7.4.txt
documents/core/3.3.4.7.5.txt
documents/core/3.3.4.7.txt
documents/core/3.3.4.txt
documents/core/3.3.5.txt
documents/core/3.3.6.1.txt
documents/core/3.3.6.2.1.txt
documents/core/3.3.6.2.2.txt
documents/core/3.3.6.2.3.txt
documents/core/3.3.6.2.4.txt
documents/core/3.3.6.2.txt
documents/core/3.3.6.3.1.1.txt
documents/core/3.3.6.3.1.2.txt
documents/core/3.3.6.3.1.3.txt
documents/core/3.3.6.3.txt
documents/core/3.3.6.4.1.txt
documents/core/3.3.6.4.2.txt
documents/core/3.3.6.4.3.txt
documents/core/3.3.6.4.4.txt
documents/core/3.3.6.4.5.txt
documents/core/3.3.6.4.6.txt
documents/core/3.3.6.4.txt
documents/core/3.3.6.5.1.txt
documents/core/3.3.6.5.2.txt
documents/core/3.3.6.5.3.txt
documents/core/3.3.6.5.4.txt
documents/core/3.3.6.5.5.txt
documents/core/3.3.6.5.6.txt
documents/core/3.3.6.5.txt
documents/core/3.3.6.6.txt
documents/core/3.3.6.txt
documents/core/3.3.7.1.1.txt
documents/core/3.3.7.1.2.txt
documents/core/3.3.7.1.3.txt
documents/core/3.3.7.1.4.txt
documents/core/3.3.7.1.5.txt
documents/core/3.3.7.1.6.txt
documents/core/3.3.7.1.txt
documents/core/3.3.7.2.txt
documents/core/3.3.7.3.1.txt
documents/core/3.3.7.3.txt
documents/core/3.3.7.txt
documents/core/3.3.8.1.txt
documents/core/3.3.8.2.txt
documents/core/3.3.8.txt
documents/core/3.3.9.1.txt
documents/core/3.3.9.2.txt
documents/core/3.3.9.3.txt
documents/core/3.3.9.4.txt
documents/core/3.3.9.5.txt
documents/core/3.3.9.txt
documents/core/3.3.txt
documents/core/3.4.1.1.txt
documents/core/3.4.1.2.txt
documents/core/3.4.1.txt
documents/core/3.4.2.1.txt
documents/core/3.4.2.2.txt
documents/core/3.4.2.3.txt
documents/core/3.4.2.txt
documents/core/3.4.3.1.txt
documents/core/3.4.3.txt
documents/core/3.4.txt
documents/core/4.1.txt
documents/core/4.2.txt
documents/core/4.3.txt
documents/core/4.4.txt
documents/core/4.5.1.txt
documents/core/4.5.2.txt
documents/core/4.5.3.txt
documents/core/4.5.4.txt
documents/core/4.5.5.txt
documents/core/4.5.txt
```

## Key Normative Requirements Relevant To Final-Response Judging

1. Normative keywords and reserved values (`1.2`): `SHALL`/`SHALL NOT` etc. define conformance. Reserved fields must be zero where applicable, but communicators must not check reserved fields. For this solver, this is only executable where normalized traces expose reserved fields; most traces do not.

2. SP/session architecture (`2.2.4`, `2.3.1`, `3.3.7.1`): each SP has separate storage/security domain; the only way to communicate with an SP is via a session; methods are invoked within sessions; read-only sessions may be simultaneous, while a read-write session to an SP cannot run simultaneously with any other session to that SP; read-only session changes normally do not persist.

3. Method syntax and response status (`3.2.4.1`, `3.2.4.2`, `3.3.7.2`): a method call has an invoking object, method ID, required parameters, optional parameters, result list, and status list. Required parameters precede optional parameters; optional parameter names are ordinal uintegers. Each non-Session-Manager method call has a response; the first status-list value is the method status unless the host sent a nonzero abort status, in which case that nonzero value is echoed. A method that cannot be processed completely fails and makes no direct changes.

4. Table/object addressing (`3.2.5`, `3.2.5.1`, `3.2.5.3`, `3.2.5.4`): table contents are SP persistent state and are not user-addressable LBA space. Byte tables are addressed by row number and cannot have rows allocated/freed. Object tables are addressed by UID, always have a UID column, and generated UIDs must be SP-unique and never reused. Unique column combinations must remain unique.

5. Access control and authority semantics (`3.4.2.1`, `3.4.2.2`, `3.4.2.3`): authenticated authorities evaluate to True in ACE Boolean expressions; unauthenticated authorities evaluate to False. Class authorities are authenticated when any member is authenticated, but class authorities must not be directly authenticated and must not refer directly to credentials. Authentication applies only to the current session.

6. Session startup/ending (`3.3.7.1.4`, `3.3.7.1.5`, `3.3.7.1.6`): successful session startup depends on resources, key exchange where required, and authentication. All authorities participating in successful session startup are authenticated for that session. Session end releases resources; aborted sessions abort transactions and currently executing methods. Hardware resets and power cycles abort open sessions. Session timeouts can make startup invalid or abort later sessions, but elapsed time is not exposed in current normalized traces.

7. Transactions (`3.2.2.3.3.4`, `3.2.2.3.3.5`, `3.3.7.3`, `3.3.7.3.1`): start/end transaction tokens control commit/abort. Direct SP changes commit immediately outside transactions, commit at top-level transaction commit inside transactions, and roll back on abort. Lock/key/hardware-affecting changes must not take effect until commit. Failed methods inside a transaction do not change SP state unless specified.

8. Admin SP invariants (`3.4.1.1`): a TPer with SPs has exactly one Admin SP; the Admin SP cannot be deleted, disabled, or frozen and must have name `Admin`.

9. SP lifecycle (`4.1`-`4.5.5`): SP lifecycle is recorded in AdminSP SP table `LifeCycleState`; AdminSP object's lifecycle state is only `Issued`; SP lifecycle state must change when the SP state changes; SP table/lifecycle information is readable by Anybody on AdminSP. Disabled SPs allow only `Authenticate`, `Set` on `SPInfo.Enabled`, and `DeleteSP`; other methods to the disabled SP must return `SP_DISABLED`. Frozen SP session startup must return `SP_FROZEN`. Failed SP session startup must return `SP_FAIL` and cannot complete.

10. Level 0 Locking feature (`3.3.6.5.3`, `3.3.6.5.5`, `3.3.6.5.6`): `Locked`, `MBREnabled`, and `MBRDone` feature bits derive from locking-range and MBRControl state. This is executable only if final responses expose Level 0 Discovery/feature descriptors, which current normalizer does not parse as structured events.

## Implementation Coverage Assessment

`v6/src/solver.py`

- `Solver.predict` and `Solver.predict_one` (`solver.py:52`, `solver.py:63`) satisfy the project-level output contract: they return lowercase `"pass"` or `"fail"` via `RuleResult.verdict`. Empty trajectories return `"fail"`.
- `predict_one` correctly judges only the final event against state inferred from `events[:-1]` (`solver.py:67`-`solver.py:69`). No source edit is needed for the lowercase pass/fail return contract.

`v6/src/normalizer.py`

- Status normalization covers most Core status classes used by the oracle (`normalizer.py:47`, `normalizer.py:84`, `normalizer.py:96`), including `sp_disabled`, `sp_frozen`, and `sp_failed`. Gap: Core `4.5.5` names `SP_FAIL`; `sp_fail` is not currently aliased to `sp_failed`.
- Object/SP/authority/column normalization is strong enough for final-response judging when traces are high-level JSON method records (`normalizer.py:165`, `normalizer.py:176`, `normalizer.py:234`, `normalizer.py:332`, `normalizer.py:431`, `normalizer.py:466`, `normalizer.py:564`).
- Not covered because not exposed at this abstraction: token ordering, raw CALL/EOD/EOS/ST/ET tokens, packet/subpacket headers, reserved bits, ACK/NAK, ComID state, IV/MAC/padding. No source edit is needed unless future trajectories include raw transport/token fields.

`v6/src/state.py`

- Core session/auth persistence is partially modeled: one current session, session authority set, write flag, host/SP session IDs, trusted flag, failed auth counts, and successful `StartSession`/`Authenticate` effects (`state.py:48`, `state.py:66`, `state.py:172`, `state.py:199`, `state.py:249`, `state.py:889`).
- Access-control metadata learned from successful `Get`/`Set` of ACE, AccessControl, Authority, and C_PIN rows is modeled (`state.py:479`, `state.py:500`, `state.py:539`, `state.py:575`, `state.py:582`, `state.py:594`, `state.py:621`).
- Locking/data state is modeled for LBA read/write judging: range columns, MBRControl, resets, selected range, locked state, writes, reads, and key generations (`state.py:334`, `state.py:351`, `state.py:772`, `state.py:789`, `state.py:837`, `state.py:875`, `state.py:889`).
- Lifecycle coverage is Opal-specific and incomplete for Core 4.x. `locking_sp_active` and some `sp_lifecycle` side effects are tracked for `Activate`, `Revert`, and `RevertSP` (`state.py:651`, `state.py:688`, `state.py:722`, `state.py:742`), but generic Core `Issued-Disabled`, `Issued-Frozen`, `Issued-Disabled-Frozen`, `Failed`, `DeleteSP`, and AdminSP non-deletable/non-freezable invariants are not fully modeled.
- `state.py` does not track multiple simultaneous sessions. This is acceptable for a single active high-level session trace, but conflicts with Core's allowance for simultaneous read-only sessions and only one read-write session per SP.
- `state.py` has no transaction stack. This is acceptable while normalized events omit ST/ET tokens. It becomes incorrect if traces expose transaction boundaries and final responses depend on commit/abort visibility.

`v6/src/oracle.py`

- Status classes and the `RuleResult` verdict mechanism are clear and compatible with final pass/fail judging (`oracle.py:23`, `oracle.py:45`, `oracle.py:107`, `oracle.py:145`).
- Method preflight covers many executable Core method constraints: known methods, required parameters, malformed booleans/uintegers, malformed `Where`, byte-table/object-table `Set` shape, invalid columns, read-only columns, and basic session/write-session requirements (`oracle.py:818`, `oracle.py:878`-`oracle.py:1132`).
- Session startup/authentication is partially covered: open session requirement, LockingSP activation, class authority rejection, disabled authority, lockout, credential matching, `Authenticate` result handling, secure messaging requirement from Authority metadata, and successful StartSession ID validation (`oracle.py:1295`, `oracle.py:1357`, `oracle.py:1460`).
- ACE/ACL Boolean expression evaluation and AccessControl matching implement the core authenticated-authority model well enough for high-level traces (`oracle.py:303`, `oracle.py:350`, `oracle.py:507`, `oracle.py:557`).
- Table/data behavior is partially covered: byte-table row restrictions, Set/Get cellblock shape, read-only/write-only columns, locking range bounds, read/write locked LBA behavior, and GenKey read-after-key-change behavior (`oracle.py:645`, `oracle.py:662`, `oracle.py:708`, `oracle.py:1573`, `oracle.py:1712`, `oracle.py:2308`, `oracle.py:2359`).
- Core lifecycle is the largest gap: `judge_start_session` only checks a bespoke `locking_sp_active` flag and open-session conflict (`oracle.py:1357`), not generic `SP_DISABLED`, `SP_FROZEN`, or `SP_FAIL`. `judge_set`, `judge_delete`, and `judge_delete_sp` do not block disabling/freezing/deleting AdminSP (`oracle.py:1712`, `oracle.py:2141`, `oracle.py:2154`). `DeleteSP` is judged but not tracked as a state transition in `state.apply_event`.
- `judge_start_session` rejects any `StartSession` while another session is open (`oracle.py:1364`), which is overstrict for Core read-only session concurrency and under-modeled for one read-write session per SP.
- Host nonzero status-list abort/echo semantics from `3.2.4.2` are not checked: `normalizer.status_from` prefers output status and does not compare `input_status` with `output_status`; `oracle.method_preflight` does not enforce echo or non-effect semantics for final responses.

`v6/src/spec_docs.py`

- Builds schema, default rows, access policy, rule references, and coverage reports from `v6/artifacts/documents` and `v6/artifacts/spec_index.json` (`spec_docs.py:493`, `spec_docs.py:597`, `spec_docs.py:746`, `spec_docs.py:953`, `spec_docs.py:1195`, `spec_docs.py:1297`). This supports source behavior but is not itself a runtime judge except through exported helpers.
- It includes Core 3.x/4.x rule references but most implemented references point into Core 5.x and Opal sections. For this audit's 1.x-4.x scope, `spec_docs.py` is a useful schema/index bridge, not complete executable coverage.

`v6/src/spec_tables.py`

- This file appears unused by the active v6 source (`rg "spec_tables" v6/src` only finds the file itself). It is a legacy/static policy file labeled "for v5 solver" and should not be treated as active coverage.

## Required Edits

Priority P1: implement generic Core SP lifecycle judging.

- Add lifecycle state to `state.py` for every known SP, not just `locking_sp_active`. Track `SPInfo.Enabled`, AdminSP `SP.Frozen`, `SP.LifeCycleState`, `DeleteSP`, and `Delete` on SP rows when prior successful responses show those updates.
- In `oracle.py`, before ordinary method-specific judging, reject final session startup to `Issued-Frozen` or `Issued-Disabled-Frozen` SPs with `sp_frozen`, final startup to `Failed` SPs with `sp_failed`/`sp_fail`, and in-session methods to disabled SPs with `sp_disabled` except `Authenticate`, `Set` on `SPInfo.Enabled`, and `DeleteSP`.
- Add `sp_fail` as a status alias in `normalizer.py` so Core `SP_FAIL` is classified consistently with the existing `sp_failed` resource-error class.

Priority P1: enforce AdminSP invariants.

- In `judge_set`, reject attempts to disable or freeze AdminSP by setting SPInfo/AdminSP SP-table lifecycle columns.
- In `judge_delete` and `judge_delete_sp`, reject deleting AdminSP. Core `3.4.1.1` is explicit: AdminSP cannot be deleted, disabled, or frozen.
- No edit is needed for "exactly one AdminSP" unless traces expose SP issuance/deletion across multiple AdminSP-like rows; existing normalizer canonicalizes the AdminSP UID.

Priority P2: refine session concurrency.

- Replace the blanket "StartSession while another session is open should be rejected" rule with per-SP session tracking. Allow multiple read-only sessions when resources are not known to be exhausted; reject a read-write session if any session to that SP is open, and reject any other session if a read-write session to that SP is open.
- If the benchmark only presents one logical current session, document that assumption in code comments and avoid asserting a Core violation for a second read-only `StartSession`.

Priority P2: enforce status-list abort echo semantics when exposed.

- If `input.status_codes` carries a non-success/nonzero first method status, final output should echo that status rather than independently succeeding. Add an oracle preflight check comparing `event["input_status"]` and `event["output_status"]` for this case.
- In state tracking, prior host-aborted method events should not apply direct state changes even if output parsing is ambiguous.

Priority P2: model SP deletion and UID/unique-column constraints for object-table row operations.

- Apply successful `DeleteSP` and AdminSP `Delete` of an SP row to lifecycle state so later final sessions/methods against that SP fail as nonexistent/unavailable.
- For `CreateRow`, track generated row UIDs and reject known duplicates or reuse as `uniqueness_conflict`/appropriate error. For tables with unique columns, reject known duplicate combinations. This implements Core `3.2.5.3` and `3.2.5.4` where high-level row data is visible.

Priority P3: transaction support if ST/ET tokens become visible.

- Add a transaction stack in `state.py`; buffer direct state changes inside transactions; commit only on top-level successful ET; roll back on abort/session abort. This is not required for current high-level method-only traces that do not expose transaction control tokens.

Priority P3: Level 0 Discovery feature-bit judging if discovery responses become structured.

- Add normalizer support for Level 0 Discovery/feature descriptors, then judge `Locked`, `MBREnabled`, and `MBRDone` against `state.locking_ranges` and `state.mbr`.

## Ambiguities And Intentionally Non-Executable Sections

- `1.1`, `1.3`, `1.4`, and most of `2.1`-`2.3.4` are architectural, terminology, reference, or capability-scoping material. They guide interpretation but do not directly determine a final response unless a trace exposes a corresponding method/status.
- Raw token and packet constraints in `3.2.2`, `3.2.3`, `3.3.2`-`3.3.6`, `3.3.8`, `3.3.9`, and `3.3.10` are mostly non-executable for the current solver because `normalize_record` receives already-decoded method/read/write records. Reserved bits, packet lengths, ComID assignment, ACK/NAK, flow-control credit, IV/MAC/padding, IF-SEND/IF-RECV state, and sequence numbers are not present in the normalized event model.
- Method parameter ordering from `3.2.4.1` is not executable when trace parameters arrive as dictionaries. The implementation can validate required names and value types, but cannot infer original token order.
- Session timeout behavior in `3.3.7.1.6` is not executable without timestamps or elapsed-time fields.
- Transaction rollback is not executable unless traces expose ST/ET control tokens or explicit transaction events.
- Core permits SSCs to define support levels, resource limits, method sets, and additional authorities. Where the trace lacks SSC/resource evidence, the oracle should avoid overconfident failure and prefer "not contradicted by state" behavior.

## Synthetic Tests Recommended

1. `StartSession` to an SP after setting its `SPInfo.Enabled` to False: final non-allowed method should pass only with `SP_DISABLED`; final `Authenticate`, `Set SPInfo.Enabled`, and `DeleteSP` should remain eligible subject to access control.

2. `StartSession` to an SP after setting its AdminSP SP-table `Frozen` column True: final response with `SP_FROZEN` should pass; success should fail.

3. `StartSession` to an SP with lifecycle `Failed`: final response with `SP_FAIL`/`SP_FAILED` should pass; success should fail; confirm `sp_fail` normalization.

4. Attempt `DeleteSP` on AdminSP and `Delete` on the AdminSP row in the AdminSP SP table: final success should fail.

5. Attempt to set AdminSP `Enabled=False` or `Frozen=True`: final success should fail.

6. Open a read-only session, then final `StartSession` for another read-only session to the same SP with resources unspecified: final success should not be rejected solely because a session is open.

7. Open a read-write session, then final `StartSession` to the same SP, read-only or read-write: final success should fail; resource/auth error should pass.

8. Host sends final method invocation with nonzero `input.status_codes`; output status must echo that first status. A mismatched output status should fail.

9. Prior successful `DeleteSP` on a non-Admin SP, then final `StartSession` to that SP: final success should fail.

10. Object-table `CreateRow` returning a UID already observed for the same SP/table: final success should fail with uniqueness conflict or an accepted error class.

11. Byte-table `CreateRow` and `DeleteRow` final responses: success should fail because byte-table rows are not allocated/freed.

12. If ST/ET tokens are added to the event model: set a lock inside a transaction, abort, then final write to that LBA should pass as unlocked; repeat with commit and final write should fail if write-locked.


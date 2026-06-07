# Agent D Core Templates/Crypto/Clock/Log Audit

Scope honored: read-only audit of `documents/core/5.4*`, `5.5*`, `5.6*`, `5.7*`, `5.8*`, and `6.*`; compared against `v6/src/{solver.py,normalizer.py,state.py,oracle.py,spec_docs.py,spec_tables.py}`. No source files were edited.

## 1. Document Files Read

Count: 403 document files, 3013 total lines.

Counts by assigned prefix:

- `5.4*`: 55 files
- `5.5*`: 68 files
- `5.6*`: 146 files
- `5.7*`: 69 files
- `5.8*`: 62 files
- `6.*`: 3 files

Exact inventory notation: `a.[m-n].txt` means every integer file in the inclusive range, preserving the dotted prefix.

- `5.4`: `5.4.txt`, `5.4.1.txt`, `5.4.2.txt`, `5.4.2.1.txt`, `5.4.2.1.[1-8].txt`, `5.4.2.2.txt`, `5.4.2.3.txt`, `5.4.2.3.[1-12].txt`, `5.4.2.4.txt`, `5.4.2.4.[1-8].txt`, `5.4.3.txt`, `5.4.3.1.txt`, `5.4.3.1.[1-5].txt`, `5.4.3.1.6.txt`, `5.4.3.1.6.[1-2].txt`, `5.4.3.1.7.txt`, `5.4.4.txt`, `5.4.4.[1-2].txt`, `5.4.4.3.txt`, `5.4.4.3.1.txt`, `5.4.4.[4-5].txt`, `5.4.5.txt`, `5.4.5.1.txt`.
- `5.5`: `5.5.txt`, `5.5.[1-2].txt`, `5.5.3.txt`, `5.5.3.1.txt`, `5.5.3.1.[1-14].txt`, `5.5.4.txt`, `5.5.4.1.txt`, `5.5.4.1.1.txt`, `5.5.4.1.1.[1-4].txt`, `5.5.4.1.2.txt`, `5.5.4.2.txt`, `5.5.4.2.1.txt`, `5.5.4.2.1.1.txt`, `5.5.4.2.2.txt`, `5.5.4.3.txt`, `5.5.4.3.[1-2].txt`, `5.5.4.3.2.1.txt`, `5.5.4.3.3.txt`, `5.5.4.4.txt`, `5.5.4.4.[1-2].txt`, `5.5.4.4.2.1.txt`, `5.5.4.5.txt`, `5.5.4.5.[1-2].txt`, `5.5.4.5.2.1.txt`, `5.5.4.5.3.txt`, `5.5.4.6.txt`, `5.5.4.6.[1-2].txt`, `5.5.4.6.2.1.txt`, `5.5.4.7.txt`, `5.5.4.7.1.txt`, `5.5.4.7.1.1.txt`, `5.5.4.7.2.txt`, `5.5.5.txt`, `5.5.5.1.txt`, `5.5.5.1.[1-3].txt`, `5.5.5.[2-9].txt`, `5.5.6.txt`, `5.5.6.1.txt`.
- `5.6`: `5.6.txt`, `5.6.[1-2].txt`, `5.6.3.txt`, `5.6.3.[1-4].txt`, `5.6.3.1.[1-6].txt`, `5.6.3.2.[1-6].txt`, `5.6.3.3.[1-6].txt`, `5.6.3.4.[1-6].txt`, `5.6.4.txt`, `5.6.4.1.txt`, `5.6.4.1.[1-3].txt`, `5.6.4.1.3.1.txt`, `5.6.4.2.txt`, `5.6.4.2.[1-3].txt`, `5.6.4.2.1.[1-2].txt`, `5.6.4.2.3.1.txt`, `5.6.4.3.txt`, `5.6.4.3.[1-3].txt`, `5.6.4.3.2.1.txt`, `5.6.4.4.txt`, `5.6.4.4.[1-4].txt`, `5.6.4.4.1.[1-2].txt`, `5.6.4.4.3.1.txt`, `5.6.4.5.txt`, `5.6.4.5.[1-2].txt`, `5.6.4.5.1.1.txt`, `5.6.4.6.txt`, `5.6.4.6.[1-3].txt`, `5.6.4.6.2.1.txt`, `5.6.4.7.txt`, `5.6.4.7.[1-4].txt`, `5.6.4.7.1.[1-2].txt`, `5.6.4.7.3.1.txt`, `5.6.4.8.txt`, `5.6.4.8.[1-2].txt`, `5.6.4.8.1.1.txt`, `5.6.4.9.txt`, `5.6.4.9.[1-4].txt`, `5.6.4.9.1.[1-2].txt`, `5.6.4.9.3.1.txt`, `5.6.4.10.txt`, `5.6.4.11.txt`, `5.6.4.11.[1-3].txt`, `5.6.4.11.2.1.txt`, `5.6.4.12.txt`, `5.6.4.12.[1-3].txt`, `5.6.4.12.1.[1-2].txt`, `5.6.4.12.2.1.txt`, `5.6.4.13.txt`, `5.6.4.13.[1-2].txt`, `5.6.4.13.1.1.txt`, `5.6.4.14.txt`, `5.6.4.14.[1-3].txt`, `5.6.4.14.2.1.txt`, `5.6.4.15.txt`, `5.6.4.15.[1-3].txt`, `5.6.4.15.1.[1-2].txt`, `5.6.4.15.2.1.txt`, `5.6.4.16.txt`, `5.6.4.16.[1-2].txt`, `5.6.4.16.1.1.txt`, `5.6.4.17.txt`, `5.6.4.17.[1-6].txt`, `5.6.4.17.3.[1-2].txt`, `5.6.4.17.5.1.txt`, `5.6.5.txt`, `5.6.5.[1-9].txt`, `5.6.5.5.[1-2].txt`, `5.6.5.6.[1-2].txt`, `5.6.6.txt`, `5.6.6.1.txt`.
- `5.7`: `5.7.txt`, `5.7.1.txt`, `5.7.1.1.txt`, `5.7.2.txt`, `5.7.2.1.txt`, `5.7.2.1.[1-7].txt`, `5.7.2.2.txt`, `5.7.2.2.[1-20].txt`, `5.7.2.3.txt`, `5.7.2.3.[1-5].txt`, `5.7.2.4.txt`, `5.7.2.4.[1-5].txt`, `5.7.2.5.txt`, `5.7.2.5.[1-4].txt`, `5.7.2.6.txt`, `5.7.3.txt`, `5.7.3.1.txt`, `5.7.3.1.[1-2].txt`, `5.7.3.[2-6].txt`, `5.7.3.7.txt`, `5.7.3.7.[1-5].txt`, `5.7.3.8.txt`, `5.7.4.txt`, `5.7.4.1.txt`.
- `5.8`: `5.8.txt`, `5.8.1.txt`, `5.8.1.1.txt`, `5.8.2.txt`, `5.8.2.1.txt`, `5.8.2.1.[1-14].txt`, `5.8.2.2.txt`, `5.8.2.2.[1-6].txt`, `5.8.3.txt`, `5.8.3.1.txt`, `5.8.3.1.[1-4].txt`, `5.8.3.1.3.1.txt`, `5.8.3.2.txt`, `5.8.3.2.[1-8].txt`, `5.8.3.2.7.[1-3].txt`, `5.8.3.3.txt`, `5.8.3.3.[1-2].txt`, `5.8.3.3.1.1.txt`, `5.8.3.4.txt`, `5.8.3.4.[1-2].txt`, `5.8.3.4.1.1.txt`, `5.8.4.txt`, `5.8.4.[1-6].txt`, `5.8.5.txt`, `5.8.5.1.txt`.
- `6`: `6.1.txt`, `6.2.txt`, `6.3.2.txt`.

## 2. Key Normative Requirements Relevant To Final-Response Judging

- Admin Template (`5.4`): TPerInfo, CryptoSuite, Template, and most SP object metadata columns are read-only. `IssueSP` is an Admin Template method with name/space/template failure cases. Deleting an SP is via `Delete` on the SP object in a read-write AdminSP session and is not completed until successful session close. Read-write AdminSP sessions must not be combined with other open SP sessions. An SP with `Frozen=True` must reject session opens; AdminSP itself must not be disabled, frozen, or deleted.
- Clock Template (`5.5`): ClockTime has one row; most columns are method-maintained and not directly host-modifiable. `GetClock`, `ResetClock`, `SetClockHigh`, `SetLagHigh`, `SetClockLow`, `SetLagLow`, and `IncrementCounter` must target ClockTime. `SetClockHigh`/`SetLagHigh` and `SetClockLow`/`SetLagLow` are immediate method pairs; intervening methods prevent the time update. `IncrementCounter` and `GetClock` advance monotonic time and are allowed in read-only sessions; later counter values must be greater. ResetClock returns the clock to Timer mode.
- Crypto Template (`5.6`): Hash/HMAC/Encrypt/Decrypt require an Init before data/finalize, reject duplicate Init on the same object/operation, and close on Finalize. Cellblock inputs require Get authorization; output buffers require Set authorization and adequate size; buffer-output methods return empty method results where specified. Sign/Verify targets must be valid public-key credential or hash objects; Verify returns a boolean success result. XOR requires PatternInput to be a byte-table UID, adequate pattern size, Get ACL on input/pattern, Set ACL when deleting the pattern or using BufferOut, and empty method result when BufferOut is used.
- Locking Template (`5.7`): LockingInfo is read-only. Locking rows define read/write lock state and media encryption state. Non-global ranges must not overlap; zero-length non-global ranges control no LBAs. Global Range is mandatory and non-deletable. Read/write commands must follow Table 230/231, including MBR shadowing when MBRControl Enable is true and Done is false. `ReEncryptRequest` is valid only for the current `ReEncryptState`; RangeStart/RangeLength modification and row create/delete have additional failure rules while a range or the Global Range is not IDLE. `NextKey` and associated key operations are valid only in IDLE. `ActiveKey` is described as host-directly writable in `5.7.3.7.2`, while `ReEncryptState`, LastReEncryptLBA, LastReEncStat, and GeneralStatus are not host-writable.
- Log Template (`5.8`): Log rows are only accessible through table-level methods; individual rows have no AccessControl rows. `AddLog` may persist even in read-only sessions and is not transaction-rolled-back. `CreateLog` creates LogList and Log table rows and fails on duplicate name, insufficient space, metadata row creation failure, or excessive MinSize. `ClearLog` and `FlushLog` require existing Log tables. Most Log row columns and LogList UID/Name/CommonName/Log/Serial columns are not host-modifiable; HighSecurity is host-controlled.
- Required UIDs (`6`): UID ranges reserve method/table/template assignment bands. `6.3.2` describes secure messaging ECDH/KDF/key-confirmation details, relevant only where a trace exposes trusted-session cryptographic proof; otherwise it is not executable from final method status alone.

## 3. Implementation Coverage Assessment

- Final-response plumbing is correct in shape: `Solver.predict_one` normalizes the full trajectory, tracks state on all prior events, judges only the last event, and returns lowercase `pass`/`fail` (`v6/src/solver.py:63`, `v6/src/solver.py:67`, `v6/src/solver.py:69`, `v6/src/solver.py:83`).
- Normalization covers core UIDs for SPs, Locking, MBR, Log, LogList, DataStore, C_PIN, Authority, MethodID, AccessControl, and ACE (`v6/src/normalizer.py:19`, `v6/src/normalizer.py:234`, `v6/src/normalizer.py:332`). It normalizes method parameters, values, cellblocks, statuses, LBAs, and command results (`v6/src/normalizer.py:564`).
- Status-class judging is intentionally coarse but usable for protocol compliance: success, auth error, invalid-parameter-like, resource error, generic error, and data command success/error (`v6/src/oracle.py:23`, `v6/src/oracle.py:107`, `v6/src/oracle.py:121`).
- ACE/AccessControl evaluation exists and supports BooleanExpr, scoped policy rows, method/object matching, and column subsets for Get/Set (`v6/src/oracle.py:303`, `v6/src/oracle.py:411`, `v6/src/oracle.py:507`, `v6/src/oracle.py:557`). This is a real coverage point for Admin/Locking template access control, although only when defaults or observed rows are available.
- Table-schema enforcement covers many Core/Opal families through `COLUMN_NAME_NUMBERS`, `READ_ONLY_COLUMNS`, and `WRITE_ONLY_COLUMNS` (`v6/src/spec_docs.py:100`, `v6/src/spec_docs.py:237`, `v6/src/spec_docs.py:255`), plus Set/Get cellblock and Set value shape checks (`v6/src/oracle.py:645`, `v6/src/oracle.py:662`, `v6/src/oracle.py:1070`, `v6/src/oracle.py:1234`).
- Locking state is the strongest implemented area in this assignment: prior successful Set/Get merge Locking columns (`v6/src/state.py:334`, `v6/src/state.py:594`, `v6/src/state.py:621`), resets apply LockOnReset and MBR DoneOnReset (`v6/src/state.py:772`), LBA range selection and mixed-range detection exist (`v6/src/state.py:789`, `v6/src/state.py:837`), and final read/write commands are judged against lock state (`v6/src/oracle.py:2308`, `v6/src/oracle.py:2359`).
- Re-encryption request validity and state transitions for successful `ReEncryptRequest` are partially modeled (`v6/src/oracle.py:736`, `v6/src/oracle.py:745`, `v6/src/state.py:290`). `NextKey` non-IDLE writes are rejected (`v6/src/oracle.py:760`).
- Crypto stream sequencing is partially modeled: successful Init opens per-object/per-operation state and Finalize closes it (`v6/src/state.py:213`, `v6/src/state.py:934`); final crypto stream methods reject duplicate Init and data/finalize without an open stream (`v6/src/oracle.py:2046`).
- Clock method-pair ordering is partially modeled: successful `SetClockHigh`/`SetClockLow` creates pending lag state and final lag methods must immediately match (`v6/src/state.py:237`, `v6/src/state.py:910`, `v6/src/oracle.py:2203`).
- Log methods are recognized and checked for basic target/session/write requirements (`v6/src/oracle.py:867`, `v6/src/oracle.py:2222`), but no log table existence, circular log state, or CreateLog uniqueness/space tracking exists.

## 4. Required Edits

P0 - Implement MBR shadowing in data-command judging.

- Requirement: `5.7.2.5.2`, `5.7.2.5.3`, and Tables 230/231 require reads/writes touching the MBR-shadow LBA region to use MBR table behavior when `MBRControl.Enable=True` and `Done=False`. Writes to the MBR-shadowed region must be rejected; reads fully within MBR return MBR table data; mixed MBR/user reads must return Data Protection Error.
- Current behavior: `judge_read`/`judge_write` only inspect Locking range lock state (`v6/src/oracle.py:2308`, `v6/src/oracle.py:2359`). `state["mbr"]` is tracked (`v6/src/state.py:351`, `v6/src/state.py:647`, `v6/src/state.py:780`) but not used for data commands.
- Concrete edit: add MBR region metadata from the MBR table/Table table size where available, default conservatively to LBA 0 when size is unknown, and branch before normal lock-state judgment. Do not accept a successful write to the active MBR region. Do not accept user-data read for mixed MBR/user spans.

P1 - Add Admin Template `IssueSP` and SP deletion/frozen session behavior.

- Requirement: `5.4.3.1` defines `IssueSP`; `5.4.3.1.7` gives name/template/space failures. `5.4.4.2` requires SP deletion by `Delete` on an SP object in a read-write AdminSP session, completed only at successful close. `5.4.2.4.8` and lifecycle sections require frozen SP session opens to fail.
- Current behavior: `IssueSP` is absent from `METHOD_NAMES` (`v6/src/spec_docs.py:13`), so final `IssueSP` is classified as unsupported/invalid (`v6/src/oracle.py:1132`). `judge_delete` is generic (`v6/src/oracle.py:2141`) and state does not track pending deleted SPs. `judge_start_session` checks active LockingSP but not SP Frozen (`v6/src/oracle.py:1357`).
- Concrete edit: add `IssueSP` to normalization/method matrix; judge AdminSP read-write session plus issuer authority evidence and obvious parameter failures. Track SP table column 7/Frozen and pending SP deletions from prior successful `Delete`, applying deletion only on successful close.

P1 - Add ClockTime table schema and direct Set immutability.

- Requirement: `5.5.3.1.[1-13]` marks ClockTime columns UID, HaveHigh, HighByWhom, HighInitialTimer, HighLag, HaveLow, LowByWhom, LowSetTime, LowInitialTimer, LowLag, MonotonicBase, and MonotonicReserve as host non-modifiable. Clock methods, not table Set, update the clock.
- Current behavior: `ClockTime` has no `COLUMN_NAME_NUMBERS`/`READ_ONLY_COLUMNS` entry in `spec_docs.py`, so `Set` on ClockTime can fall through to generic authenticated-write success (`v6/src/spec_docs.py:100`, `v6/src/spec_docs.py:237`, `v6/src/oracle.py:1866`).
- Concrete edit: add ClockTime column mapping 0..13 and read-only set for all method-maintained columns. If TrustMode is treated as directly writable, document why; otherwise mark it read-only too and rely on Reset/SetClock methods.

P1 - Track and validate Clock result state where final response exposes return values.

- Requirement: `5.5.4.7` says later `IncrementCounter` returns a greater value; `5.5.5.7` defines `GetClock` Kind/ExactTime/Lag/Monotonic return behavior; `5.5.5.8` defines ResetClock state.
- Current behavior: `judge_increment_counter` only checks target/open session (`v6/src/oracle.py:2191`) and `apply_successful_clock_method` tracks only pending lag, not TrustMode, HaveHigh/HaveLow, or monotonic values (`v6/src/state.py:237`).
- Concrete edit: capture successful GetClock/IncrementCounter return MonotonicTime and fail later non-increasing successful returns when observable. Track ResetClock as Timer mode. For SetClockHigh/Low, track enough pending ExactTime/Lag to validate a final GetClock where prior steps make the expected Kind obvious.

P1 - Enforce re-encryption restrictions on range geometry, row create/delete, and key operations.

- Requirement: `5.7.3.7` says RangeStart/RangeLength modifications fail when that row is not IDLE; if Global Range is not IDLE, modifying any range geometry, deleting any Locking object, or creating a Locking object fails. `5.7.2.2.12` also extends non-IDLE restrictions to Set/Delete/DeleteRow/GenKey on the associated credential object.
- Current behavior: invalid `ReEncryptRequest` and non-IDLE `NextKey` are covered (`v6/src/oracle.py:745`, `v6/src/oracle.py:760`), but `invalid_locking_range_update` only checks Global/faulty/overlap geometry (`v6/src/oracle.py:708`), row management is generic (`v6/src/oracle.py:2122`), and `judge_gen_key` does not check the range's current re-encryption state (`v6/src/oracle.py:1933`).
- Concrete edit: add `range_reencrypt_state != IDLE` checks for geometry Set; add global non-IDLE checks for `CreateRow`, `DeleteRow`, and `Delete` on Locking rows; reject `GenKey` on a MediaKey associated with a non-IDLE range.

P1 - Resolve `ActiveKey` host-writability conflict from Core Locking docs.

- Requirement: `5.7.3.7.2` explicitly lists "Host Application directly writes ActiveKey column value"; `5.7.2.2.11` does not mark ActiveKey host non-modifiable. By contrast, `5.7.2.2.13` marks ReEncryptState non-modifiable and progress/status columns are non-modifiable.
- Current behavior: `READ_ONLY_COLUMNS["Locking"]` includes column 10 ActiveKey (`v6/src/spec_docs.py:242`), so final Set of ActiveKey is expected to fail.
- Concrete edit: either remove column 10 from read-only for Core Locking or gate it behind SSC-specific policy if Opal prohibits direct ActiveKey writes. The audit source here is Core 5.7, so this should not be left as unconditional read-only in a Core audit.

P2 - Improve crypto cellblock/output-buffer/access-control checks.

- Requirement: `5.6.5.1` and method sections require Get ACL for input cellblocks, Set ACL for BufferOut/DeletePattern, valid cellblocks, and adequate output/pattern sizes; BufferOut often makes method result empty.
- Current behavior: `judge_crypto_stream_method`, `judge_crypto_sign_method`, and `judge_xor` check target, stream state, session, and PatternInput UID only (`v6/src/oracle.py:2046`, `v6/src/oracle.py:2068`, `v6/src/oracle.py:2082`).
- Concrete edit: normalize method-specific `Input`, `BufferIn`, `BufferOut`, `ProofBuffer`, and `PatternInput` parameters, reuse ACE decisions for Get/Set on referenced cellblocks when the referenced object/table is identifiable, and fail obvious malformed or too-small buffers when byte lengths are observable.

P2 - Add crypto/hash table schemas and target recognition.

- Requirement: H_SHA_* tables have UID/Name/CommonName non-modifiable for issuance rows and Proof/Accumulator/Signer semantics (`5.6.3`). Crypto methods target hash objects or public/symmetric credential objects.
- Current behavior: `hash_object_target` is name-only (`v6/src/oracle.py:1999`), `credential_object_target` misses `MediaKey` family unless object names look like `C_AES_*` (`v6/src/oracle.py:1993`), and no H_SHA_* column schema exists.
- Concrete edit: add canonical object/family handling for H_SHA_* and credential-key UIDs/names, plus schema/read-only handling for H_SHA_* support tables where the trace exposes them.

P2 - Tighten Log method existence/uniqueness and table-level behavior.

- Requirement: `AddLog`, `ClearLog`, and `FlushLog` fail if the referenced log table does not exist; `CreateLog` fails on duplicate name, insufficient space, missing support rows, or excessive MinSize. Log rows are table-method-only, not row ACL objects.
- Current behavior: `judge_log_method` checks method target family/table-level shape and session/write requirements only (`v6/src/oracle.py:2222`).
- Concrete edit: track successful `CreateLog` names/table UIDs, fail duplicate `CreateLog` names, and fail final Add/Clear/Flush when the target Log table is not known and the UID/name is not the default Log table.

P2 - Expand method UID mappings from required UID assignments.

- Requirement: section `6` reserves and categorizes required UID assignments; final-response judging depends on method normalization when traces provide method UID without method name.
- Current behavior: `METHOD_UID_NAMES` has a small subset (`v6/src/spec_docs.py:72`; duplicated concepts in `normalizer.py` via `method_name_from_value`). Missing assigned Core method UIDs can normalize as `None` and fail as unsupported.
- Concrete edit: add all Core method UIDs available from the artifacts/index or required UID tables. Synthetic tests should include UID-only method records for Clock/Crypto/Log methods.

## 5. Ambiguities / Intentionally Non-Executable Sections

- Informative overview and terminology sections in `5.4.1`, `5.5.1`, `5.5.2`, `5.6.1`, `5.6.2`, `5.7.1`, `5.7.1.1`, `5.8.1`, and `5.8.1.1` do not create direct final-response rules except where terms define later executable behavior.
- Crypto algorithm correctness, key sizes, IV use by cipher mode, signing proof mathematics, HMAC/hash bytes, ECDH KDF/key confirmation (`6.3.2`) are not executable unless the trace exposes enough cryptographic material and expected outputs. The solver should judge protocol status/shape, not recompute cryptography, unless a future dataset supplies deterministic test vectors.
- Default logging settings in `5.4.4.5`, `5.5.5.9`, `5.6.5.9`, `5.7.3.8`, and `5.8.4.6` are mostly not final-response executable unless a final `Get`/`Next`/log read exposes log content after a prior method.
- Clock trust bracketing has a spec tension: `5.5.4.3.3` says SetClockHigh fails if TrustMode is not Low, while `5.5.5.1.2`/`5.5.5.1.1` describe accepting High Trust time with or without Low Trust values and possibly discarding Low values. This should be implemented conservatively only when prior state makes TrustMode and bracketing values observable.
- `IssueSP` certificate-chain authorities and AdminExch/SPSigning details are not fully executable from ordinary status traces unless certificate/authority inputs are present. Basic target/session/parameter/failure cases are still executable.
- Log circular ordering, atomicity across multiple read-only sessions, and persistent-storage commit timing are generally not executable from a single final response unless the dataset exposes log rows before/after.

## 6. Synthetic Tests Recommended

- `ClockTime_Set_ReadOnlyColumn_Fails`: open authenticated write session to an SP with Clock Template; final `Set` on ClockTime `HaveHigh` or `MonotonicBase` returns success. Expected solver verdict: fail.
- `SetClockHigh_Then_Get_Then_SetLagHigh_Fails`: successful `SetClockHigh`, intervening `GetClock`, final `SetLagHigh` success. Expected: fail because lag method did not immediately follow.
- `IncrementCounter_NonIncreasingReturn_Fails`: prior successful IncrementCounter returns N; final successful IncrementCounter returns N or lower. Expected: fail.
- `MBRShadow_WriteLBA0_Success_Fails`: MBRControl Enable=True and Done=False in prior state; final write to LBA 0 succeeds. Expected: fail.
- `MBRShadow_MixedRead_UserData_Fails`: MBR shadow active; final read spans MBR and non-MBR LBA and returns user data. Expected: fail.
- `ReencryptActive_SetRangeStart_Success_Fails`: prior Locking range ReEncryptState=ACTIVE; final `Set` RangeStart succeeds. Expected: fail.
- `GlobalReencrypt_CreateRow_Success_Fails`: prior Global Range ReEncryptState=PENDING; final `CreateRow` on Locking table succeeds. Expected: fail.
- `AssociatedMediaKey_GenKey_NonIdle_Fails`: prior range has NextKey/ActiveKey pointing to media key and ReEncryptState=ACTIVE; final `GenKey` on that media key succeeds. Expected: fail.
- `ActiveKey_Set_CoreAllowed`: final `Set` ActiveKey in an authorized LockingSP write session should be accepted under Core 5.7 unless an SSC-specific override is active.
- `IssueSP_UnsupportedRegression`: valid-looking final `IssueSP` in authenticated AdminSP read-write session should not be rejected as unknown method.
- `DeleteSP_DeferUntilClose`: successful `Delete` on an SP object followed by failed close should not make later StartSession fail; successful close should.
- `FrozenSP_StartSession_Fails`: prior successful Set of SP Frozen=True; final StartSession to that SP succeeds. Expected: fail.
- `Hash_WithoutInit_Fails`, `HashInit_Duplicate_Fails`, `Hash_AfterFinalize_Fails`: cover current stream tracking and prevent regression.
- `Hash_BufferOut_ReturnsData_Fails`: successful Hash/HashFinalize with BufferOut specified returns non-empty result. Expected: fail when BufferOut is observable.
- `XOR_DeletePattern_RequiresSetACL`: final XOR with DeletePattern=True and no Set authority over PatternInput succeeds. Expected: fail when referenced ACL is known.
- `CreateLog_DuplicateName_Fails`: prior successful `CreateLog` name X; final successful `CreateLog` name X. Expected: fail.
- `AddLog_UnknownLogTable_Fails`: final AddLog on a non-default unknown Log UID succeeds. Expected: fail.


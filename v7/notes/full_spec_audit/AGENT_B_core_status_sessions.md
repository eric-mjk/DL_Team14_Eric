# Agent B Core Status/Sessions Audit

Scope: `documents/core/5.1*` and `documents/core/5.2*` only, compared against `v6/src/{solver.py,normalizer.py,state.py,oracle.py,spec_docs.py,spec_tables.py}`. No source code was edited.

## 1. Documents Read

Count: 209 document files.

Exact files:

```text
documents/core/5.1.1.txt
documents/core/5.1.2.txt
documents/core/5.1.3.1.txt
documents/core/5.1.3.10.txt
documents/core/5.1.3.100.txt
documents/core/5.1.3.11.txt
documents/core/5.1.3.12.txt
documents/core/5.1.3.13.txt
documents/core/5.1.3.14.txt
documents/core/5.1.3.15.txt
documents/core/5.1.3.16.txt
documents/core/5.1.3.17.txt
documents/core/5.1.3.18.txt
documents/core/5.1.3.19.txt
documents/core/5.1.3.2.txt
documents/core/5.1.3.20.txt
documents/core/5.1.3.21.txt
documents/core/5.1.3.22.txt
documents/core/5.1.3.23.txt
documents/core/5.1.3.24.txt
documents/core/5.1.3.25.txt
documents/core/5.1.3.26.txt
documents/core/5.1.3.27.txt
documents/core/5.1.3.28.txt
documents/core/5.1.3.29.txt
documents/core/5.1.3.3.txt
documents/core/5.1.3.30.txt
documents/core/5.1.3.31.txt
documents/core/5.1.3.32.txt
documents/core/5.1.3.33.txt
documents/core/5.1.3.34.txt
documents/core/5.1.3.35.txt
documents/core/5.1.3.36.txt
documents/core/5.1.3.37.txt
documents/core/5.1.3.38.txt
documents/core/5.1.3.39.txt
documents/core/5.1.3.4.txt
documents/core/5.1.3.40.txt
documents/core/5.1.3.41.txt
documents/core/5.1.3.42.txt
documents/core/5.1.3.43.txt
documents/core/5.1.3.44.txt
documents/core/5.1.3.45.txt
documents/core/5.1.3.46.txt
documents/core/5.1.3.47.txt
documents/core/5.1.3.48.txt
documents/core/5.1.3.49.txt
documents/core/5.1.3.5.txt
documents/core/5.1.3.50.txt
documents/core/5.1.3.51.txt
documents/core/5.1.3.52.txt
documents/core/5.1.3.53.txt
documents/core/5.1.3.54.txt
documents/core/5.1.3.55.txt
documents/core/5.1.3.56.txt
documents/core/5.1.3.57.txt
documents/core/5.1.3.58.txt
documents/core/5.1.3.59.txt
documents/core/5.1.3.6.txt
documents/core/5.1.3.60.txt
documents/core/5.1.3.61.txt
documents/core/5.1.3.62.txt
documents/core/5.1.3.63.txt
documents/core/5.1.3.64.txt
documents/core/5.1.3.65.txt
documents/core/5.1.3.66.txt
documents/core/5.1.3.67.txt
documents/core/5.1.3.68.txt
documents/core/5.1.3.69.txt
documents/core/5.1.3.7.txt
documents/core/5.1.3.70.txt
documents/core/5.1.3.71.txt
documents/core/5.1.3.72.txt
documents/core/5.1.3.73.txt
documents/core/5.1.3.74.txt
documents/core/5.1.3.75.txt
documents/core/5.1.3.76.txt
documents/core/5.1.3.77.txt
documents/core/5.1.3.78.txt
documents/core/5.1.3.79.txt
documents/core/5.1.3.8.txt
documents/core/5.1.3.80.txt
documents/core/5.1.3.81.txt
documents/core/5.1.3.82.txt
documents/core/5.1.3.83.txt
documents/core/5.1.3.84.txt
documents/core/5.1.3.85.txt
documents/core/5.1.3.86.txt
documents/core/5.1.3.87.txt
documents/core/5.1.3.88.txt
documents/core/5.1.3.89.txt
documents/core/5.1.3.9.txt
documents/core/5.1.3.90.txt
documents/core/5.1.3.91.txt
documents/core/5.1.3.92.txt
documents/core/5.1.3.93.txt
documents/core/5.1.3.94.txt
documents/core/5.1.3.95.txt
documents/core/5.1.3.96.txt
documents/core/5.1.3.97.txt
documents/core/5.1.3.98.txt
documents/core/5.1.3.99.txt
documents/core/5.1.3.txt
documents/core/5.1.4.1.txt
documents/core/5.1.4.2.1.txt
documents/core/5.1.4.2.10.txt
documents/core/5.1.4.2.11.txt
documents/core/5.1.4.2.12.txt
documents/core/5.1.4.2.13.txt
documents/core/5.1.4.2.14.txt
documents/core/5.1.4.2.15.txt
documents/core/5.1.4.2.16.txt
documents/core/5.1.4.2.17.txt
documents/core/5.1.4.2.18.txt
documents/core/5.1.4.2.2.txt
documents/core/5.1.4.2.3.txt
documents/core/5.1.4.2.4.txt
documents/core/5.1.4.2.5.txt
documents/core/5.1.4.2.6.txt
documents/core/5.1.4.2.7.txt
documents/core/5.1.4.2.8.txt
documents/core/5.1.4.2.9.txt
documents/core/5.1.4.2.txt
documents/core/5.1.4.txt
documents/core/5.1.5.1.txt
documents/core/5.1.5.10.txt
documents/core/5.1.5.11.txt
documents/core/5.1.5.12.txt
documents/core/5.1.5.13.txt
documents/core/5.1.5.14.txt
documents/core/5.1.5.15.txt
documents/core/5.1.5.16.txt
documents/core/5.1.5.2.txt
documents/core/5.1.5.3.txt
documents/core/5.1.5.4.txt
documents/core/5.1.5.5.txt
documents/core/5.1.5.6.txt
documents/core/5.1.5.7.txt
documents/core/5.1.5.8.txt
documents/core/5.1.5.9.txt
documents/core/5.1.5.txt
documents/core/5.1.txt
documents/core/5.2.1.txt
documents/core/5.2.2.1.1.txt
documents/core/5.2.2.1.2.1.txt
documents/core/5.2.2.1.2.2.txt
documents/core/5.2.2.1.2.txt
documents/core/5.2.2.1.txt
documents/core/5.2.2.2.txt
documents/core/5.2.2.3.txt
documents/core/5.2.2.4.1.1.txt
documents/core/5.2.2.4.1.10.txt
documents/core/5.2.2.4.1.11.txt
documents/core/5.2.2.4.1.2.txt
documents/core/5.2.2.4.1.3.txt
documents/core/5.2.2.4.1.4.txt
documents/core/5.2.2.4.1.5.txt
documents/core/5.2.2.4.1.6.txt
documents/core/5.2.2.4.1.7.txt
documents/core/5.2.2.4.1.8.txt
documents/core/5.2.2.4.1.9.txt
documents/core/5.2.2.4.1.txt
documents/core/5.2.2.4.2.txt
documents/core/5.2.2.4.3.txt
documents/core/5.2.2.4.4.txt
documents/core/5.2.2.4.5.txt
documents/core/5.2.2.4.txt
documents/core/5.2.2.txt
documents/core/5.2.3.1.1.txt
documents/core/5.2.3.1.10.txt
documents/core/5.2.3.1.11.txt
documents/core/5.2.3.1.12.txt
documents/core/5.2.3.1.2.txt
documents/core/5.2.3.1.3.txt
documents/core/5.2.3.1.4.txt
documents/core/5.2.3.1.5.txt
documents/core/5.2.3.1.6.txt
documents/core/5.2.3.1.7.txt
documents/core/5.2.3.1.8.txt
documents/core/5.2.3.1.9.txt
documents/core/5.2.3.1.txt
documents/core/5.2.3.2.1.txt
documents/core/5.2.3.2.2.txt
documents/core/5.2.3.2.3.txt
documents/core/5.2.3.2.4.txt
documents/core/5.2.3.2.5.txt
documents/core/5.2.3.2.6.txt
documents/core/5.2.3.2.7.txt
documents/core/5.2.3.2.8.txt
documents/core/5.2.3.2.txt
documents/core/5.2.3.3.1.txt
documents/core/5.2.3.3.2.txt
documents/core/5.2.3.3.3.txt
documents/core/5.2.3.3.4.txt
documents/core/5.2.3.3.5.txt
documents/core/5.2.3.3.6.txt
documents/core/5.2.3.3.txt
documents/core/5.2.3.4.1.txt
documents/core/5.2.3.4.2.txt
documents/core/5.2.3.4.3.txt
documents/core/5.2.3.4.4.txt
documents/core/5.2.3.4.5.txt
documents/core/5.2.3.4.6.txt
documents/core/5.2.3.4.txt
documents/core/5.2.3.5.1.txt
documents/core/5.2.3.5.2.txt
documents/core/5.2.3.5.txt
documents/core/5.2.3.txt
documents/core/5.2.txt
```

## 2. Key Normative Requirements Relevant To Final-Response Judging

- Status codes in `core/5.1.5*`: `SUCCESS` is required when a method completes without error. `NOT_AUTHORIZED` is the default required status when an AccessControl row is missing or its ACL is not satisfied, and is also required for a password `StartSession` challenge mismatch. `SP_BUSY`, `SP_FAILED`, `SP_DISABLED`, `SP_FROZEN`, `NO_SESSIONS_AVAILABLE`, `UNIQUENESS_CONFLICT`, `INSUFFICIENT_SPACE`, `INSUFFICIENT_ROWS`, `INVALID_PARAMETER`, `TPER_MALFUNCTION`, `TRANSACTION_FAILURE`, `RESPONSE_OVERFLOW`, `AUTHORITY_LOCKED_OUT`, and `FAIL` are distinct status names with numeric values in Table 166. `INVALID_PARAMETER` is the catch-all for malformed method parameters unless another status is directly applicable. `AUTHORITY_LOCKED_OUT` may be returned for `SyncSession` or `Authenticate` when TryLimit/Limit has been reached.
- Session Manager invocation in `core/5.2.1`: Session Manager methods must be invoked using SMUID (`00...FF`). This applies to `Properties`, `StartSession`, `SyncSession`, trusted-session methods, and `CloseSession`.
- `Properties` in `core/5.2.2.1` through `5.2.2.4`: `Properties` is session-less. `HostProperties` is optional. The response is formatted as a `Properties` method response and must return supported TPer property name/value pairs. If the host supplies `HostProperties`, the response `HostProperties` portion must include the communications limitations/capabilities the TPer will use. Unsupported host properties are ignored and omitted. Values below required minimum assumptions are clamped/reported at the minimum.
- `StartSession` in `core/5.2.3.1`: required parameters are `HostSessionID`, `SPID`, and `Write`. `Write` is boolean. `SPID` is a UID reference to an SP object. `SessionTimeout` and `TransTimeout` are unsigned millisecond values and out-of-range values must make the method fail. `HostSigningAuthority` identifies the authority and `HostChallenge` is the password for Password authorities.
- `SyncSession` in `core/5.2.3.2`: this is returned by the TPer in response to `StartSession`. Its `HostSessionID` must be the same as the `StartSession` invocation. `SPSessionID` is assigned by the TPer and is reused in further invocations. `TransTimeout`, when present, must be within TPer limits and must be greater than or equal to the requested `StartSession` value unless the requested value exceeded the maximum.
- Trusted session startup in `core/5.2.3.3` and `5.2.3.4`: `StartTrustedSession`/`SyncTrustedSession`, if needed, must occur after `StartSession`/`SyncSession`; otherwise the invocation returns an error. Both trusted-session methods carry the same `HostSessionID`; the supplied `SPSessionID` is the one assigned in `SyncSession`. Optional challenge/response, keyset, and signed-hash fields are cryptographic/session-integrity material.
- `CloseSession` in `core/5.2.3.5`: `CloseSession` is transmitted only by the TPer to notify the host that the TPer is aborting a session. Its remote/local session numbers identify the host and TPer portions of the session number.
- Abstract/types in `core/5.1.1` through `5.1.4`: most type definitions are encoding/schema context, but final judging can execute some checks when normalized traces expose values: booleans must be `0/1` or equivalent; `uidref` is exactly 8 bytes; `cell_block` object/table/byte-table context restrictions can make methods fail; named components must appear in specified order; `row_data` values must use valid column numbers and column value types; reserved enum values should be invalid where the method/table declares a bounded enum.

## 3. Implementation Coverage Assessment

- `Solver.predict` and `predict_one` return lowercase `"pass"`/`"fail"` and judge only the final response against state inferred from previous events. This meets the project output contract (`v6/src/solver.py:52`, `v6/src/solver.py:63`).
- Status name normalization covers the non-obsolete status names from `core/5.1.5` as strings and aliases them into oracle classes (`v6/src/normalizer.py:47`, `v6/src/oracle.py:23`, `v6/src/oracle.py:107`). Coverage is incomplete for numeric Table 166 encodings such as `0x00`, `0x01`, and `0x3F`.
- `INVALID_PARAMETER` parameter-shape coverage is substantial: malformed unsigned integers, booleans, `HostProperties` shape, `Where`, `Next` UID references, `Set` values shape, duplicate/unknown columns, byte-table granularity, row-list shape, and some `CreateTable`/meta-ACL restrictions are covered (`v6/src/oracle.py:902`, `v6/src/oracle.py:1132`, `v6/src/oracle.py:1234`). Coverage is partial for `uidref` length/type constraints and full `cell_block` row/table context.
- Session tracking models a single active session with SP, write/read mode, authorities, trusted flag, host session ID, and SP session ID (`v6/src/state.py:48`). Successful `StartSession` opens state and records the input `HostSessionID` (`v6/src/state.py:172`). `SyncSession` and trusted-session methods can update host/SP IDs (`v6/src/state.py:199`). This is adequate for single-session traces but not the `SP_BUSY` same-SP concurrency matrix.
- `StartSession` final judging handles missing SPID, already-open session, inactive LockingSP, class authority invalidity, disabled/locked authority, credential match/mismatch, and successful response ID presence (`v6/src/oracle.py:1295`, `v6/src/oracle.py:1357`). It does not compare returned `HostSessionID` to the requested one and does not persist `SPSessionID` from a successful `StartSession`/`SyncSession` response when the response is represented as a `StartSession` event.
- Trusted session judging checks that a session is open and validates provided IDs against tracked IDs when available (`v6/src/oracle.py:1116`, `v6/src/oracle.py:2381`, `v6/src/oracle.py:2391`). It does not distinguish the `StartTrustedSession` step from the `SyncTrustedSession` step or require a prior trusted-session half-exchange.
- `Properties` has a direct SessionManager target check and a basic `HostProperties` shape check (`v6/src/oracle.py:926`, `v6/src/oracle.py:2446`). It does not judge returned property lists or minimum/clamping requirements from `core/5.2.2.2` through `5.2.2.4`.
- SMUID target enforcement is inconsistent. `Properties`, `StartSession`, `StartTrustedSession`, and `SyncTrustedSession` have explicit `target: SessionManager` entries in the preflight matrix (`v6/src/oracle.py:818`). `SyncSession`, `CloseSession`, and `EndSession` do not.
- `CloseSession`/`EndSession` are modeled as host-callable close methods that succeed if a session is open (`v6/src/oracle.py:2401`) and previous successful occurrences clear state (`v6/src/state.py:916`). This is broader than `core/5.2.3.5`, which says `CloseSession` is transmitted only by the TPer.
- `spec_docs.py` imports many status/session references into `RULE_REFERENCES` and classifies type-definition sections as non-executable except for selected executable pieces (`v6/src/spec_docs.py:260`, `v6/src/spec_docs.py:1071`). This is a reasonable indexing strategy, but several executable `5.1.4`/`5.2` rules above need direct oracle coverage.
- `spec_tables.py` contains older/static table and policy constants for status/session-adjacent authority names, but the active oracle mainly uses `spec_docs.py` generated policy and `normalizer.py` UID canonicalization. No required edits are specific to `spec_tables.py` for this assigned scope.

## 4. Required Edits

Priority P1:

- Normalize numeric status encodings from Table 166. Add mappings in `normalize_status` for integer values and strings like `0x00`, `00`, `0`, `0x01`, `0x0C`, `0x12`, and `0x3F` to the existing canonical names. Without this, a protocol-compliant final response carrying numeric status can be judged as generic error. Source: `v6/src/normalizer.py:47`, `v6/src/normalizer.py:84`; docs: `documents/core/5.1.5.txt`, `documents/core/5.1.5.1.txt`.
- Persist `SPSessionID` and validate echoed `HostSessionID` from a successful `StartSession`/`SyncSession` response when represented as a `StartSession` event. `remember_successful_start_session` records only the input host ID, and `_check_sync_session_ids` checks presence/zero but not equality. Concrete behavior: on successful `StartSession`, find `HostSessionID`/`SPSessionID` in output `return_values`; fail if output host ID differs from input; fail if `SPSessionID` is missing/zero; store `sp_session_id` for later trusted-session validation. Source: `v6/src/state.py:172`, `v6/src/oracle.py:1295`; docs: `documents/core/5.2.3.2.1.txt`, `documents/core/5.2.3.2.2.txt`.
- Validate UID lengths for `SPID` and authority UID parameters in session-start methods. Concrete behavior: `SPID`, `HostSigningAuthority`, `HostExchangeAuthority`, `SPExchangeAuthority`, and related UID parameters should be exact 8-byte UID references when present; malformed values should expect `INVALID_PARAMETER`. Source: `v6/src/normalizer.py:77`, `v6/src/oracle.py:1132`; docs: `documents/core/5.1.4.2.18.txt`, `documents/core/5.2.3.1.2.txt`, `documents/core/5.2.3.1.5.txt`, `documents/core/5.2.3.1.7.txt`.

Priority P2:

- Enforce SMUID/SessionManager target consistently for all Session Manager methods in `core/5.2`, especially `SyncSession`, `CloseSession`, and any modeled `EndSession` equivalent. Concrete behavior: if normalized `object` is not `SessionManager`, expect `INVALID_PARAMETER` for host-invoked Session Manager method records. Source: `v6/src/oracle.py:818`; docs: `documents/core/5.2.1.txt`.
- Improve `Properties` response judging when final response includes structured return values. Concrete behavior: if `HostProperties` is present in the request and status is `SUCCESS`, require response `HostProperties`; validate returned property value types for known properties, boolean fields, and documented minimums when visible. Unsupported host properties should be absent rather than cause failure. Source: `v6/src/oracle.py:926`, `v6/src/oracle.py:2446`; docs: `documents/core/5.2.2.1.2.2.txt`, `documents/core/5.2.2.2.txt`, `documents/core/5.2.2.3.txt`, `documents/core/5.2.2.4.txt`.
- Model the same-SP session concurrency rule more precisely if hidden traces include multiple sessions. Concrete behavior: distinguish RW-vs-RO open sessions by SP and expect `SP_BUSY` for the exact cases in `core/5.1.5.3` rather than any generic resource/error for any already-open session. This requires multi-session state or an explicit single-session assumption. Source: `v6/src/state.py:48`, `v6/src/oracle.py:1364`; docs: `documents/core/5.1.5.3.txt`.
- Split trusted-session phase state. Concrete behavior: `StartTrustedSession` should require the preceding normal session IDs, then a later `SyncTrustedSession` should require a pending trusted-session start and matching IDs; both should reject wrong order with an error result. Source: `v6/src/state.py:918`, `v6/src/oracle.py:2391`; docs: `documents/core/5.2.3.3.txt`, `documents/core/5.2.3.4.txt`.
- Add executable `cell_block` context checks for Get/table invocation where normalized input exposes rows/table fields. Concrete behavior: on object invocation, `Table`, `startRow`, and `endRow` in Cellblock should fail; on object-table invocation, missing `startRow` or wrong-table UID should fail; on byte-table invocation, `startColumn`/`endColumn` should fail. Some byte-table column checks already exist, but row/table constraints are not modeled. Source: `v6/src/normalizer.py:466`, `v6/src/oracle.py:645`; docs: `documents/core/5.1.4.2.3.txt`.
- Reassess `CloseSession` final judging semantics. Concrete behavior: if traces encode host invocations, `CloseSession` should not be accepted as a normal host-invoked success path; if traces encode TPer-to-host methods in `output`, the normalizer should distinguish direction. Source: `v6/src/oracle.py:2401`, `v6/src/state.py:916`; docs: `documents/core/5.2.3.5.txt`.

Priority P3:

- Add bounded enum/range checks for visible abstract type parameters such as `package_purpose`, `hash_protocol`, `date`, `clock_time`, and `lag` where those values appear in final method arguments. These are useful but depend on whether normalized traces expose the nested values. Source: `v6/src/oracle.py:1132`; docs: `documents/core/5.1.4.2.5.txt`, `documents/core/5.1.4.2.7.txt`, `documents/core/5.1.4.2.8.txt`, `documents/core/5.1.4.2.10.txt`, `documents/core/5.1.4.2.13.txt`.

No source edit needed:

- Lowercase `pass`/`fail` output is already satisfied by `RuleResult` constructors and `Solver.predict_one`.
- Most `5.1.1`, `5.1.2`, and `5.1.3.*` primitive/type table sections are schema/encoding background, not directly executable after traces have already been normalized to Python values.
- Transport packet/subpacket/ComPacket limits in `5.2.2.4.1.*` are not executable unless input exposes raw packet counts, token sizes, continued-token flags, sequence numbers, ACK/NAK fields, or asynchronous credit-control state.

## 5. Ambiguities Or Intentionally Non-Executable Sections

- `core/5.1.1` and most `core/5.1.3.*` sections define column/type table rows, base types, fixed byte sizes, reference type categories, and enumeration names. They matter for parsing and schema generation, but final-response judging should not invent failures unless the final method arguments expose a concrete malformed value.
- Named/list token ordering rules in `core/5.1.2` and `core/5.1.4.1` are mostly lost after normalization. They are non-executable unless the raw token stream or ordered grouped structure is preserved.
- `core/5.2.2.4.1.*` protocol violations are raw communications behavior. Normalized command-response records do not appear to expose packet/subpacket counts, aggregate token size, sequence number, ACK/NAK, or credit-control details.
- `core/5.2.3.1.12`, `5.2.3.2.8`, `5.2.3.3.6`, and `5.2.3.4.6` signed-hash requirements refer to cryptographic integrity and control authority policy from other sections. Without cryptographic material and 5.3 authority context, deterministic final judging should only validate presence/shape when visible, not signature correctness.
- `CloseSession` direction is ambiguous in normalized records: the spec says it is TPer-transmitted, while the current normalizer treats every method record as an input invocation. This needs a trace-format decision before enforcing a hard fail.

## 6. Synthetic Tests Recommended

- Status numeric acceptance: final `Get` with `output.status_codes="0x00"` should pass when the same case with `"SUCCESS"` passes; final unauthorized `Set` with `"0x01"` should pass as not authorized; malformed final method with `"0x0C"` should pass as invalid parameter.
- StartSession success response validation: final `StartSession` with matching credential and `SUCCESS` but missing `SPSessionID` should fail; `SPSessionID=0` should fail; output `HostSessionID` different from input `HostSessionID` should fail.
- Trusted session ID carry-forward: prior successful `StartSession` response with `HostSessionID=7`, `SPSessionID=11`; final `StartTrustedSession` with `SPSessionID=12` should fail, and with `11` should pass if status is success.
- Malformed UID references: final `StartSession` with `SPID` shorter than 8 bytes should expect invalid parameter; final `StartSession` with class authority should continue expecting invalid parameter.
- SMUID target enforcement: final `SyncSession` or `CloseSession` invoked on a non-SMUID object should expect invalid parameter.
- Properties response: final `Properties` with request `HostProperties` and `SUCCESS` but no response `HostProperties` should fail; unsupported host property should be omitted without failure; boolean property returned as non-boolean should fail.
- Cellblock context: final `Get` on an object with Cellblock `startRow` present should fail; final `Get` on a byte table with `startColumn`/`endColumn` present should fail; final `Get` on an object table with missing start-row UID should fail if normalized traces expose table-level invocation.
- Same-SP concurrency: prior open RW session to AdminSP; final RO/RW `StartSession` to AdminSP should expect `SP_BUSY`; prior RO session and final RO session should not be collapsed into the same failure unless the implementation intentionally supports only one session.

# Agent E Full Spec Audit - Opal 1.*, 2.*, 3.*

Scope constraints followed: read only `documents/opal/1.*.txt`, `documents/opal/2.*.txt`, and `documents/opal/3.*.txt` for normative document analysis. No source files were edited. This note is the only owned output.

## Documents Read

Count: 69 document files.

Files read:

1. `documents/opal/1.1.txt`
2. `documents/opal/1.2.txt`
3. `documents/opal/1.3.txt`
4. `documents/opal/1.3.1.txt`
5. `documents/opal/1.3.2.txt`
6. `documents/opal/1.3.3.txt`
7. `documents/opal/1.3.4.txt`
8. `documents/opal/1.3.5.txt`
9. `documents/opal/1.3.5.1.txt`
10. `documents/opal/1.3.5.2.txt`
11. `documents/opal/1.3.5.3.txt`
12. `documents/opal/1.3.6.txt`
13. `documents/opal/1.3.7.txt`
14. `documents/opal/1.3.8.txt`
15. `documents/opal/1.3.9.txt`
16. `documents/opal/1.4.txt`
17. `documents/opal/1.4.1.txt`
18. `documents/opal/1.4.2.txt`
19. `documents/opal/1.4.3.txt`
20. `documents/opal/1.5.txt`
21. `documents/opal/1.6.txt`
22. `documents/opal/1.7.txt`
23. `documents/opal/2.1.txt`
24. `documents/opal/2.2.txt`
25. `documents/opal/2.3.txt`
26. `documents/opal/2.4.txt`
27. `documents/opal/2.5.txt`
28. `documents/opal/2.6.txt`
29. `documents/opal/2.7.txt`
30. `documents/opal/2.8.txt`
31. `documents/opal/2.9.txt`
32. `documents/opal/2.10.txt`
33. `documents/opal/3.1.txt`
34. `documents/opal/3.1.1.txt`
35. `documents/opal/3.1.1.1.txt`
36. `documents/opal/3.1.1.2.txt`
37. `documents/opal/3.1.1.3.txt`
38. `documents/opal/3.1.1.3.1.txt`
39. `documents/opal/3.1.1.4.txt`
40. `documents/opal/3.1.1.4.1.txt`
41. `documents/opal/3.1.1.4.2.txt`
42. `documents/opal/3.1.1.4.3.txt`
43. `documents/opal/3.1.1.4.4.txt`
44. `documents/opal/3.1.1.4.5.txt`
45. `documents/opal/3.1.1.5.txt`
46. `documents/opal/3.1.1.5.1.txt`
47. `documents/opal/3.1.1.5.2.txt`
48. `documents/opal/3.1.1.6.txt`
49. `documents/opal/3.1.1.6.1.txt`
50. `documents/opal/3.1.1.6.2.txt`
51. `documents/opal/3.1.1.6.3.txt`
52. `documents/opal/3.1.1.6.4.txt`
53. `documents/opal/3.2.txt`
54. `documents/opal/3.2.1.txt`
55. `documents/opal/3.2.2.txt`
56. `documents/opal/3.2.3.txt`
57. `documents/opal/3.3.txt`
58. `documents/opal/3.3.1.txt`
59. `documents/opal/3.3.2.txt`
60. `documents/opal/3.3.3.txt`
61. `documents/opal/3.3.4.txt`
62. `documents/opal/3.3.4.1.txt`
63. `documents/opal/3.3.4.1.1.txt`
64. `documents/opal/3.3.4.1.2.txt`
65. `documents/opal/3.3.4.1.3.txt`
66. `documents/opal/3.3.5.txt`
67. `documents/opal/3.3.5.1.txt`
68. `documents/opal/3.3.5.2.txt`
69. `documents/opal/3.3.6.txt`

## Normative Requirements Relevant To Final-Response Judging

1. Opal compliance scope and precedence:
   - Opal SSC compliant devices must conform to this spec (`1.2`).
   - Opal text is normative unless explicitly marked informative (`1.3.3`).
   - Preconfiguration table cell content is normative even where cell shading is informative (`1.3.4`).
   - Opal has precedence over Interface Interactions and Core for conflicting requirements (`1.4.1`, `1.6`).

2. Basic Opal feature obligations:
   - Device must support at least Admin SP and Locking SP (`2.2`).
   - Device must implement the synchronous communication protocol (`2.3`, `3.3.4`).
   - Device must implement full-disk encryption for host-accessible user data and support AES-128 or AES-256 (`2.4`).
   - Device must support password authorities and authentication (`2.5`).
   - Manufactured mandatory tables and rows are defined by spec; post-manufacturing table/row creation or deletion is outside this spec (`2.6`).
   - Initial access controls are manufacturer-preconfigured and certain Locking SP ACEs must be personalizable (`2.7`).
   - Additional DataStore, PSID, and Block SID feature sets are mandatory (`2.10`).

3. Level 0 Discovery:
   - A compliant Level 0 response must include Discovery Header, TPer descriptor, Locking descriptor, and Opal SSC V2 descriptor (`3.1.1`).
   - TPer descriptor must report Feature Code `0x0001`, Length `0x0C`, Streaming Supported `1`, Sync Supported `1`, and allowed VU values for several flags (`3.1.1.2`).
   - Locking descriptor must report Feature Code `0x0002`, Length `0x0C`, MBR Shadowing Not Supported `0`, Media Encryption `1`, Locking Supported `1`, and live state bits for MBR Done, MBR Enabled, Locked, and Locking Enabled (`3.1.1.3`).
   - LockingEnabled must be `1` when a Locking-template SP is in any state other than Nonexistent or Manufactured-Inactive, otherwise `0` (`3.1.1.3.1`).
   - Optional Geometry descriptor, if returned, must use Feature Code `0x0003`, Version `0x01`, Length `0x1C`, and its ALIGN, LogicalBlockSize, AlignmentGranularity, and LowestAlignedLBA fields must mirror LockingInfo columns (`3.1.1.4.1` through `3.1.1.4.5`).
   - Opal SSC V2 descriptor must use Feature Code `0x0203`, Length `0x10`, at least one ComID, at least 4 Locking SP admin authorities, at least 8 Locking SP user authorities, and only defined/reserved values for SID PIN indicator and revert behavior (`3.1.1.5`).
   - Optional data-removal descriptor, if returned, must use Feature Code `0x0404`, Version `0x02`, Length `0x20`; crypto erase must be supported; Processing/Interrupted bits must track Revert, RevertSP, GenKey progress and interruption state (`3.1.1.6` through `3.1.1.6.4`).

4. Security Protocol 2 and reset behavior:
   - Stack Protocol Reset and Protocol Stack Reset commands must be supported (`3.2.2`, `3.3.6`).
   - If TPER_RESET is enabled, before the next IF-SEND/IF-RECV the device must abort all open sessions, abort uncommitted transactions, reset protocol stacks, invalidate buffers, abort method processing, reset communication assumptions, apply Programmatic LockOnReset to ReadLocked/WriteLocked, and apply Programmatic DoneOnReset to MBRControl.Done (`3.2.3`).
   - TPER_RESET has no IF-RECV response, must accept and acknowledge at interface level if enabled, and transfer length must be non-zero (`3.2.3`).
   - Interface reset TCG events must abort all open sessions, abort transactions and pending startup, invalidate buffers, reset sync stacks, and send no notification (`3.3.5.1`).

5. Communication and payload behavior:
   - Properties must report physical buffer size per ComID; IF-SEND transfer length larger than MaxComPacketSize must terminate at interface level (`3.3.1`).
   - Method responses plus protocol overhead must fit in the response buffer; if not, sync protocol returns no method response body and status `RESPONSE_OVERFLOW` (`3.3.1`).
   - Security Protocol values are constrained for IF-RECV and IF-SEND (`3.3.2`).
   - At least one static active synchronous ComID must be supported; inactive or unsupported ComID handling must follow specified invalid-parameter behavior or Core requirements (`3.3.3`).
   - Supported stream tokens are enumerated; unsupported tokens are streaming protocol violations (`3.3.4.1.1`).
   - The required minimum packet shape is one ComPacket containing one Packet containing one Subpacket; ack, credit, and sequence behavior may be ignored depending on discovery support (`3.3.4.1.2`).
   - Streaming protocol violation before valid session ID resolution discards payload and returns to Awaiting IF-SEND; violation after session resolution aborts the session and may prepare CloseSession (`3.3.4.1.3`).

## Implementation Coverage Assessment

Overall solver flow is appropriate for final-response judging: `Solver.predict_one` normalizes the whole trajectory, tracks state on all prior events, then judges only the final event (`v6/src/solver.py:41` to `v6/src/solver.py:64`). It returns lowercase `pass` or `fail` via `RuleResult.verdict` (`v6/src/oracle.py:44` to `v6/src/oracle.py:104`).

Covered or adequately represented:

- Status normalization includes `response_overflow`, invalid command/parameter classes, resource errors, auth errors, and success aliases (`v6/src/normalizer.py:47` to `v6/src/normalizer.py:74`; `v6/src/oracle.py:23` to `v6/src/oracle.py:42`). This supports section 3 status class comparisons once the relevant condition is modeled.
- AdminSP and LockingSP UIDs are recognized (`v6/src/normalizer.py:6` to `v6/src/normalizer.py:7`, `v6/src/normalizer.py:165` to `v6/src/normalizer.py:173`), and initial state includes both SP lifecycles (`v6/src/state.py:81` to `v6/src/state.py:85`).
- Password authorities and credentials are modeled through canonical authority/C_PIN mapping and tracked credentials (`v6/src/normalizer.py:176` to `v6/src/normalizer.py:207`; `v6/src/state.py:71` to `v6/src/state.py:80`; `v6/src/oracle.py:581` to `v6/src/oracle.py:594`).
- Access control personalization is partially modeled through default and learned ACE/AccessControl/Authority rows (`v6/src/spec_docs.py:930` to `v6/src/spec_docs.py:1005`; `v6/src/state.py:582` to `v6/src/state.py:591`; `v6/src/oracle.py:507` to `v6/src/oracle.py:579`).
- Table/schema metadata from spec artifacts is used to normalize column names and enforce read-only/write-only and max-column constraints (`v6/src/spec_docs.py:100` to `v6/src/spec_docs.py:220`, `v6/src/spec_docs.py:746` to `v6/src/spec_docs.py:828`; `v6/src/oracle.py:720` to `v6/src/oracle.py:810`).
- Full-disk encryption/key-change behavior is executable for user-data reads and writes: prior writes record key generation, GenKey bumps key generation, and reads after key change must not return old plaintext (`v6/src/state.py:661` to `v6/src/state.py:685`; `v6/src/oracle.py:2307` to `v6/src/oracle.py:2399`). This is a reasonable final-response proxy for `2.4` in normalized traces.
- LockOnReset/DoneOnReset side effects are partially modeled for reset-like command events (`v6/src/state.py:757` to `v6/src/state.py:786`).
- Properties exists as a method and is constrained to SessionManager (`v6/src/oracle.py:2411` to `v6/src/oracle.py:2418`; `v6/src/oracle.py:2446` to `v6/src/oracle.py:2453`).
- PSID support is partially represented by canonical PSID authority and Revert authorization (`v6/src/normalizer.py:42` to `v6/src/normalizer.py:44`, `v6/src/normalizer.py:184` to `v6/src/normalizer.py:187`; `v6/src/oracle.py:1932` to `v6/src/oracle.py:1944`). This addresses the `2.10` PSID reference at a coarse level, though not the full feature-set spec.

Gaps or weak coverage:

- Level 0 Discovery is not normalized as a first-class event and has no judge path. A final IF-RECV/Level 0 Discovery response with missing mandatory descriptors, wrong feature code/length, wrong LockingEnabled bit, bad geometry values, missing crypto erase bit, or invalid authority counts would fall through as a generic command or data result (`v6/src/normalizer.py:547` to `v6/src/normalizer.py:569`; `v6/src/oracle.py:2411` to `v6/src/oracle.py:2430`). This misses most executable requirements in `3.1.1.*`.
- Reset semantics are incomplete. `apply_reset_like_event` applies LockOnReset and MBR DoneOnReset, but it does not abort the open session, clear trusted/session IDs, clear pending clock-lag state, or close crypto streams (`v6/src/state.py:757` to `v6/src/state.py:786`). This contradicts `3.2.3` and `3.3.5.1` and can produce false `pass` results for post-reset methods that should require a new session.
- TPER_RESET command transport requirements are not modeled: no explicit recognition of ComID `0x0004`, Security Protocol `0x02`, non-zero transfer length, interface-level ack/no IF-RECV response, enabled/disabled behavior, or invalid transfer length handling. Current command normalization keeps only `command`, `args`, `result`, and status (`v6/src/normalizer.py:547` to `v6/src/normalizer.py:569`).
- Communication buffer behavior is not executable. The solver can classify `response_overflow` as a resource error, but it does not learn Properties buffer sizes or compare response payload size plus protocol overhead to MaxComPacketSize/response buffer. A legitimate `RESPONSE_OVERFLOW` final response may be marked `fail` by method-specific success expectations, and an oversized successful response may not be rejected (`v6/src/oracle.py:107` to `v6/src/oracle.py:158`, `v6/src/oracle.py:1132` to `v6/src/oracle.py:1279`).
- Streaming protocol violations and packet-token support are not visible to the normalizer. Unsupported token, malformed stream, bad packet shape, and session-abort-after-streaming-error behavior are not checked (`3.3.4.1.1` to `3.3.4.1.3`).
- The mandatory Block SID feature-set reference in `2.10` has no obvious implementation hook in the reviewed source. The referenced feature-set details are outside assigned Opal 1-3 files, so this audit cannot define concrete Block SID behavior, but hidden final responses that expose Block SID state would not be covered by this source surface.

## Required Edits

No source edits were made in this audit. Recommended edits:

### P1 - Reset events must abort sessions and transient protocol state

Concrete behavior:

- In `state.apply_reset_like_event`, after applying LockOnReset and DoneOnReset effects, set `state["session"] = empty_session()`.
- Clear transient state that belongs to an open protocol/session context: `pending_clock_lag = None`, `crypto_streams = {}`. If future transaction state is added, clear it here too.
- Make reset-like command detection more explicit for `TPER_RESET`, `Protocol Stack Reset`, `Stack Protocol Reset`, `interface reset`, `TCG reset`, `hardware reset`, `hotplug`, and `power cycle`.
- If a prior reset command/event succeeds, a final protected `Get`, `Set`, `Authenticate`, `SyncSession`, `CloseSession`, or data access must be judged against a closed session and reset lock state.

Why source edit is needed: section `3.2.3` and `3.3.5.1` directly require open sessions to be aborted. Current state tracking leaves the session open, so later final-response judgments can be wrong.

### P1 - Add Level 0 Discovery normalization and judging when traces expose discovery responses

Concrete behavior:

- Extend `normalizer.normalize_record` to recognize IF-RECV/Level 0 Discovery responses, likely by `command`, Security Protocol `0x01`, ComID `0x0001`, or structured descriptor output.
- Normalize descriptors into a stable shape: feature code, version, length, and named fields for TPer, Locking, Geometry, Opal SSC V2, and Data Removal.
- Add an oracle judge for final discovery responses:
  - Required descriptors must be present: header, TPer, Locking, Opal SSC V2.
  - TPer descriptor: code `0x0001`, length `0x0C`, streaming `1`, sync `1`.
  - Locking descriptor: code `0x0002`, length `0x0C`, MBR shadowing not-supported bit `0`, media encryption `1`, locking supported `1`, dynamic bits consistent with tracked Locking/MBR state.
  - LockingEnabled: `0` while LockingSP is Manufactured-Inactive, `1` after activation or any state other than Nonexistent/Manufactured-Inactive.
  - Optional Geometry descriptor, if present, must match tracked/known `LockingInfo` columns.
  - Opal SSC V2: code `0x0203`, length `0x10`, ComIDs >= 1, admin authorities >= 4, user authorities >= 8, reserved PIN indicator values rejected.
  - Optional Data Removal descriptor, if present, must have code `0x0404`, version `0x02`, length `0x20`, crypto erase bit set, and processing/interrupted bits consistent with known operation state.

Why source edit is needed: these are mandatory response-shape requirements in section `3.1.1.*`. Current fallback cannot distinguish a compliant descriptor from an invalid one.

### P2 - Model TPER_RESET interface-specific validation if traces expose raw command fields

Concrete behavior:

- Preserve Security Protocol, ComID, and transfer length in normalized command events.
- For final TPER_RESET:
  - enabled devices should accept/acknowledge interface-level command with non-zero transfer length;
  - disabled devices should abort with the Interface Interactions invalid command parameter status;
  - zero transfer length should fail/invalid;
  - no IF-RECV response should be expected.

Why source edit may be conditional: current public-style normalized traces may not expose raw IF-SEND fields. If future traces include them, this is executable under `3.2.3`.

### P2 - Properties and response-overflow checking

Concrete behavior:

- Track relevant communication properties returned by successful `Properties`: MaxComPacketSize, MaxResponseComPacketSize, and any response buffer fields present in the normalized data.
- If a final method response is explicitly too large or status is `response_overflow`, judge it as compliant only when the modeled response would not fit; otherwise reject `response_overflow` for normal-sized responses.
- If a final response succeeds while explicit size metadata shows it exceeds the response buffer, return `fail`.

Why source edit is needed if size fields are available: section `3.3.1` gives deterministic behavior for oversized method responses. Without size metadata this remains non-executable.

### P3 - Streaming protocol violation event support

Concrete behavior:

- If normalized input exposes malformed tokens, unsupported tokens, malformed ComPacket/Packet/Subpacket structure, or a `streaming_protocol_violation` marker, judge final response per `3.3.4.1.3`.
- If violation occurs before valid session ID resolution, discard payload and leave/return to no pending response.
- If violation occurs after session ID resolution, abort the session; later final session-bound methods must fail until a new session is opened.

Why source edit is conditional: raw token and packet streams are not currently normalized. If the dataset never exposes them, this is intentionally non-executable.

### P3 - Block SID feature-set hook

Concrete behavior:

- Add a placeholder or explicit rule mapping only after reading the Block SID feature-set document referenced by `2.10`.
- Do not infer details from `2.10` alone; it only says the feature set is mandatory.

Why source edit is not concrete from this scope: assigned documents identify the mandatory feature set but do not define its executable behavior.

## Ambiguities Or Intentionally Non-Executable Sections

- Sections `1.1`, `1.2`, `1.3.*`, `1.4.*`, `1.5`, `1.6`, and `1.7` mostly define scope, precedence, terms, and conventions. They affect interpretation and spec indexing, but do not by themselves determine a final TCG method status.
- Section `2.1` is explicitly informative use-case text. It should not drive pass/fail directly.
- Section `2.4` full-disk encryption is not directly measurable from command-response status unless traces include user-data read/write content around key changes. Current key-generation readback logic is an acceptable executable proxy; no additional edit is required from `2.4` alone.
- Section `2.6` says post-manufacturing table/row creation/deletion is outside this specification, not that every CreateTable/CreateRow/DeleteRow must fail. The solver may still model Core table-management methods for broader TCG behavior; no Opal 1-3 edit is required unless another Opal section says these methods are prohibited.
- Geometry Reporting and Supported Data Removal descriptors are optional Level 0 descriptors. Absence is compliant; if present, field contents are normative and should be checked.
- VU fields in discovery descriptors are intentionally not deterministic. The judge should accept any value unless the spec reserves or constrains a value.
- Security Protocol, ComID, token, ack/nak, packet sequence, packet shape, and IF-SEND transfer-length requirements are transport-layer requirements. They are non-executable unless the input trajectory exposes raw transport metadata or explicit violation markers.
- Data Removal Processing/Interrupted bits are only directly executable if discovery responses are present and prior operations can be known to be in progress or interrupted. For synchronous completed method traces, these bits should usually be zero after success.

## Synthetic Tests Recommended

1. `reset_aborts_session`: Open a successful LockingSP or AdminSP session, insert a successful `TPER_RESET`/`TCG reset` command, then final `Get` or `Set` that would have succeeded only with the old session. Expected prediction: `pass` only if final response is auth/error, not success.

2. `reset_applies_lor_dor_and_closes`: Configure a Locking range with `LockOnReset=Programmatic`, read/write locks enabled, and MBRControl `DoneOnReset=Programmatic`; issue reset; final read/write in the locked range should be protected and final MBRControl Get should reflect `Done=False`.

3. `level0_missing_required_descriptor`: Final Level 0 Discovery response omits the Opal SSC V2 descriptor. Expected final compliance: fail.

4. `level0_locking_enabled_state`: Before LockingSP activation, final discovery reports LockingEnabled `1`; after activation, final discovery reports LockingEnabled `0`. Both should fail.

5. `level0_geometry_mismatch`: Prior successful Get of `LockingInfo` records `LogicalBlockSize`, `AlignmentGranularity`, `LowestAlignedLBA`; final optional Geometry descriptor reports a different value. Expected: fail.

6. `level0_opal_v2_authority_counts`: Final Opal SSC V2 descriptor reports fewer than 4 admin authorities or fewer than 8 user authorities. Expected: fail.

7. `level0_data_removal_crypto_erase_required`: Final Supported Data Removal descriptor is present but crypto erase bit is zero. Expected: fail.

8. `response_overflow_allowed_only_when_oversized`: Learn small response buffer via `Properties`; final large `Get` returns `response_overflow` and empty response list. Expected: pass. Repeat with a small response returning `response_overflow`. Expected: fail.

9. `stream_violation_aborts_session`: After a valid session, inject a normalized streaming violation after session ID resolution, then final `Get` requiring that session. Expected: pass only if final response is auth/error.

10. `tper_reset_zero_transfer_length`: Final TPER_RESET with transfer length zero should be invalid/fail if reported accepted.


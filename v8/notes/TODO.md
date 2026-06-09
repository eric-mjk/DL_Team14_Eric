# v8 TODO

Current validation status:

- `PYTHONPATH=v8 python3 v8/evaluate.py`: `score=100.00`
- `core_gap_cases`: `355/355`
- `cross_gap_cases`: `30/30`
- `opal_gap_cases`: `172/172`
- Full sweep: `customtest_84` is `84/84`, `default_20_dataset` is `20/20`, and `myeongseok_cases` is `278/278`.

Already handled:

- AdminSP and LockingSP MethodID support filtering.
- StartSession timeout bounds from learned `Properties` and `SPInfo.SPSessionTimeout`.
- SyncSession session ID and `TransTimeout` consistency checks.
- SyncSession now also compares the explicit `SPSessionID` parameter with the TPer-assigned session ID learned from the successful `StartSession` response, with generated pass/fail coverage.
- SP lifecycle basics: disabled, frozen, failed startup behavior; disabled-SP method exemptions; `DeleteSP`; concrete `IssueSP` tracking.
- `IssueSP` duplicate known-name rejection, including names learned from successful issuance even when no concrete SP UID is returned.
- `IssueSP` template-list UID validation, Admin-template exclusion, concrete Template `MaxInstances` rejection, known Template `Instances` replay, and optional success-result validation for returned UID shape and allocated Size.
- `IssueSP` issuance-space first slice: successful `TPerInfo.Get` of `SpaceForIssuance` records concrete free issuance space; successful `IssueSP` decrements it by returned `Size` or requested `Size`, and later `IssueSP` cannot succeed once learned space is exhausted or report an allocated size larger than available space.
- `IssueSP` template inventory slice: Template table UIDs are normalized, Template columns map `Instances`/`MaxInstances`, learned table capacity now applies to concrete table UIDs, successful Template-table `Next` can mark a complete template inventory only after a concrete row count is known, and `IssueSP` rejects templates absent from that complete learned inventory.
- `IssueSP` issued-SP side-effect slice: successful `IssueSP` with a concrete returned SP UID records an issued-SP registry entry, rejects later successful duplicate returned SP UIDs, and applies `Enabled=False` to the issued SP lifecycle so later `StartSession` returns `SP_DISABLED`.
- `IssueSP` issued-SP deletion/template slice: `DeleteSP` and deferred AdminSP `Delete` mark concrete issued SPs deleted, bound issued-SP `GetFreeSpace.FreeSpace` by issued `Size`, and release concrete Template `Instances` counts on delete when the issued SP entry records concrete template UIDs.
- `CreateTable` basic parameter shape, byte-table restrictions, size ordering, and duplicate preconfigured table-name checks.
- Package key parameter shape checks.
- Meta-ACL `GetACLACL` and explicit `(N)` AccessControl columns.
- Direct row/delete bans for TPer-managed tables.
- Dynamic table registry first slice: successful `CreateTable` records concrete returned table UIDs, table names, SP scope, kind, schema parameter, basic size fields, and learned names.
- Dynamic table registry usage first slice: `Next` now uses learned dynamic table kind and rejects learned dynamic byte tables.
- Dynamic table registry usage second slice: `Set` now uses learned dynamic byte-table kind for `Where` row-vs-UID checks and `Values` Bytes-vs-RowValues shape checks.
- Dynamic row `Get`/`Set` first slice: learned dynamic row UIDs use parsed table schema for named/numeric column validation, successful row `Get`/`Set` updates tracked row values, and `Set` rejects known unique-column conflicts.
- Dynamic row `Get` value consistency: returned dynamic row columns must match tracked row values when both are concrete.
- Dynamic table-level `Get`/`Set` first slice: learned dynamic table rows validate returned `Rows`/`RowsFree`/size metadata; object-table `Set Where=<row UID>` validates known row existence, schema columns, updates targeted row state, and rejects unique-column conflicts.
- Dynamic table ACL first slice: successful `CreateTable` records `GetSetACL`; dynamic table/row `Get`/`Set` evaluate known ACE refs; arbitrary returned dynamic table UIDs are accepted as table-level `Set` targets; generated pass/fail coverage covers `ACE_Anybody` and `ACE_Admin` behavior.
- Dynamic table meta-ACL bridge first slice: successful dynamic `CreateTable` synthesizes mutable AccessControl rows for table `Get`/`Set`, and dynamic ACL evaluation observes `AddACE` mutations on those rows; generated coverage covers `AddACE(ACE_Anybody)` granting a later dynamic `Get`.
- Dynamic ACL revocation slice: dynamic synthetic AccessControl rows now distinguish explicit empty ACLs from unknown ACLs, `RemoveACE` and `DeleteMethod` revoke dynamic `Get` authorization without falling back to the original `CreateTable.GetSetACL`, and generated pass/fail coverage covers both revocation paths.
- Dynamic meta-ACL write-authorization slice: concrete dynamic AccessControl rows now enforce `AddACEACL`, `RemoveACEACL`, and `DeleteMethodACL` refs for `AddACE`, `RemoveACE`, and `DeleteMethod`, with generated unauthenticated-success fail coverage.
- Dynamic `GetACL` content slice: successful `GetACL` on concrete synthetic dynamic AccessControl rows validates returned ACL refs when the response exposes an `ACL`/`ACE`/`ACEList` field, scoped away from static AccessControl behavior.
- Dynamic row inventory first slice: successful `CreateRow` records concrete returned row UIDs for known dynamic tables; successful `DeleteRow`/`Delete` removes known dynamic rows; `DeleteRow` on unknown rows in a known dynamic table cannot succeed while row inventory is complete.
- Dynamic `CreateRow` first enforcement slice: known dynamic tables require row UID results, reject duplicate returned row UIDs, reject numeric schema mismatches when parseable, and reject row creation beyond known `MaxSize`.
- Dynamic `CreateRow` learned-capacity slice: `CreateRow` cannot succeed when concrete tracked dynamic `RowsFree` is already zero, even if `MaxSize` has not yet been reached.
- Dynamic `CreateRow` unique-column slice: parsed `IsUnique`/`Unique` metadata from learned `CreateTable.Columns`, stores column-name aliases, rejects known unique-value conflicts, and accepts explicit uniqueness-conflict errors.
- Dynamic schema-from-Column slice: successful concrete `Column` row `Get` responses that expose a concrete `TableUID` and `ColumnNumber` now merge column numbers, names/common names, `IsUnique`, and visible type metadata into existing learned dynamic table schemas; generated coverage checks supplied learned columns, missing learned columns, and learned unique-column conflicts.
- Dynamic `DeleteRow` all-or-fail replay: a non-compliant successful multi-row delete that includes any unknown row no longer partially removes known rows from local dynamic inventory.
- Dynamic capacity first slice: `GetFreeRows` on learned dynamic tables validates returned `FreeRows` against tracked `rows_free` while row inventory is complete.
- Dynamic `GetFreeSpace` first slice: explicitly returned `FreeSpace` must be non-negative, and returned `TableRows` entries for learned dynamic tables with complete inventory must match tracked `rows_free`.
- Learned table capacity first slice: successful `Table.Get` of concrete `Rows`/`RowsFree`/`MaxSize` records typed capacity, and `GetFreeRows` plus `GetFreeSpace.TableRows` must match learned `RowsFree` when returned.
- Learned table capacity `CreateRow` slice: `CreateRow` cannot succeed on a preconfigured table once concrete `Table.RowsFree=0` has been learned for that table.
- Learned Table-table capacity `CreateTable` slice: successful `CreateTable` decrements learned Table table capacity when known, and `CreateTable` cannot succeed once concrete Table table `RowsFree=0` has been learned.
- Dynamic table deletion capacity slice: deleting a known dynamic table removes its table/row/ACL inventory tombstones and restores learned Table-table `Rows`/`RowsFree` counters when those counters are concrete.
- Table capacity consistency slice: successful table metadata `Get` responses that expose concrete `Rows`, `RowsFree`, and `MaxSize` must be internally consistent; `Rows` and `Rows + RowsFree` cannot exceed `MaxSize`.
- Generated core regression cases for dynamic unique-column conflicts, dynamic byte-table `Next`/`Set`, dynamic `GetFreeSpace.TableRows`, mixed known/unknown dynamic `DeleteRow`, dynamic table metadata `Get`, and dynamic row `Set`/`Get`.
- Two-step `Authenticate` challenge-response state for `Sign`, `SymK`, and `HMAC` authorities, including pending challenge tracking, boolean response enforcement, and SymK 32-byte nonce validation when byte length is visible.
- `Authenticate` `MaxAuthentications` first slice: learned `Properties.MaxAuthentications`, enforced the per-session cap for new distinct authorities with `Anybody` counted, validated reported values against the Opal minimum, and added generated pass/fail coverage.
- Explicit `Properties` first slice: when a response includes a `Properties`/`TPerProperties` map, validate the mandatory Opal Table 17 fields and numeric minima, with generated pass/fail coverage.
- Empty-result return-shape first slice: `Activate`, `EndSession`/`CloseSession`, `GenKey`, and a broader set of unambiguous no-result methods now reject non-empty success return lists; generated fail cases and `myeongseok_cases` sweep coverage improved.
- Concrete `Get` return-value first slice: successful `Get` for `C_PIN_MSID`, C_PIN readable metadata, Authority `Enabled`, AccessControl `CommonName`, SP `LifeCycleState`, Locking range core columns, `LockingInfo.MaxRanges`, and `MBRControl` must include requested authorized columns and match tracked/default state/minimums; generated pass/fail coverage added.
- Object identity validation first slice: final successful methods now reject incompatible concrete invoking object name/UID families and non-singleton `MBRControl` row UIDs; generated pass/fail coverage added. This handled the remaining deterministic `myeongseok_cases` rule gaps without changing parser-obfuscation behavior.
- Level 0 Discovery descriptor length validation when length fields are present: generic multiple-of-4 rule plus TPer/Locking/Opal SSC V2 required lengths.
- Level 0 Discovery descriptor-list/header validation first slice: raw feature order and duplicate feature codes are preserved; duplicate/out-of-order feature descriptors are rejected; optional Geometry and Data Removal descriptor exact lengths are checked when present; explicit header MajorVersion/MinorVersion must be `0x0000/0x0001`; Opal V2 reserved C_PIN_SID indicator values `0x01..0xFE` are rejected when present.
- Level 0 Discovery reserved-field slice: explicit header reserved bytes, TPer descriptor reserved fields, Locking descriptor reserved fields, and Opal V2 future-common reserved fields must be zero when traces expose them; absent reserved evidence remains unjudged.
- Level 0 Discovery total-length slice: explicit `LengthOfParameterData` must cover returned descriptor bytes; complete/non-truncated evidence must match the concrete descriptor byte count, while explicit truncation allows a larger total length.
- Level 0 Discovery Geometry descriptor validation when optional feature `0x0003` is present and `LockingInfo` geometry columns have been observed.
- Exact SP lifecycle status matching for disabled/frozen/failed `StartSession` and disabled-SP in-session method failures.
- Exact resource status matching for concrete `INSUFFICIENT_ROWS`/`INSUFFICIENT_SPACE` paths: dynamic/preconfigured `CreateRow`, Table-table `CreateTable`, and issuance-space `IssueSP` now reject generic wrong error classes when the exhausted resource state is concrete and authorization is satisfied.
- Conditional return-shape/value slice: `Random.Count` visible output length must match `Count`, and `Hash`/`HMAC`/`Encrypt`/`Decrypt` plus finalize variants and `XOR` must not return more visible output bytes than explicit `BufferOut`.
- MBR/DataStore minimum sizes, MBR shadowing behavior, Locking range alignment/overlap, and related Opal locking rules.

Remaining work:

Myeongseok/adversarial-case policy:

- Treat `myeongseok_cases` as adversarial hard cases, not as direct implementation targets.
- It is appropriate to change the deterministic state machine/oracle only when all of these hold:
  - the behavior is a clear spec-backed rule gap,
  - v8 already tracks, or can generally track, the required protocol evidence,
  - the rule generalizes to public/core/cross/opal/custom traces,
  - the implementation is expressed as protocol/state validation, not filename or generator-pattern logic.
- Good deterministic candidates: missing requested authorized columns, unexpected return payloads for empty-result methods, concrete tracked state/value mismatches, session ID mismatches, and malformed UID/status evidence.
- Do not force parser-obfuscation cases into the state machine. Stripped method names, stripped UID names, ambiguous raw evidence, and semantic recovery from damaged traces belong in parser fallback/RAG/LLM repair or should remain unresolved until evidence is concrete.
- Triage adversarial misses into:
  - `rule_gap`: deterministic state/oracle implementation,
  - `parser_recovery`: normalizer/fallback/RAG/LLM repair,
  - `ambiguous_or_dataset_specific`: leave as-is until reconciled with spec and non-adversarial suites.
- Preserve the selected-suite baseline after every deterministic change:
  - `PYTHONPATH=v8 python3 v8/evaluate.py`
  - `PYTHONPATH=v8 python3 new_datasets/run_all_tests.py new_datasets core_gap_cases cross_gap_cases opal_gap_cases`
- Current `myeongseok_cases` triage after deterministic state/value fixes:
  - `rule_gap`: 0 remaining.
  - `parser_recovery`: 0 current misses.
  - `ambiguous_or_dataset_specific`: 0 current misses under this policy.
- Do not implement a blanket "C_PIN Set only writes PIN column" rule: selected core/cross/opal suites intentionally use successful admin writes to C_PIN `TryLimit` column 5, and v8 tracks that state for lockout validation.

1. Dynamic table registry usage
   - Extend dynamic table/row ACL modeling beyond the current synthetic row slice only where additional concrete meta-ACL fields are exposed; current `GetSetACL`, `AddACEACL`, `RemoveACEACL`, `DeleteMethodACL`, `AddACE`, `RemoveACE`, `DeleteMethod`, and dynamic `GetACL` content checks are implemented.
   - Extend schema extraction beyond the current concrete `Column.Get(TableUID, ColumnNumber, Name/CommonName, IsUnique, Type)` path only where traces expose unambiguous table/column associations rather than partial or inferred metadata.
   - Track dynamic table deletion side effects beyond current table/row/ACL inventory removal, tombstones, and learned Table-table capacity restoration only when more concrete dependent state is exposed.

2. CreateRow schema enforcement
   - Improve schema parsing for row encodings beyond numeric keys and known column-name aliases.
   - Add broader generated regression cases if new row encodings or compound unique-column groups are introduced.
   - Expand all-or-fail delete checks beyond the current complete-inventory dynamic-table replay protection.

3. Capacity semantics
   - Model `GetFreeSpace.FreeSpace` from observed/default SP byte-space state beyond the current non-negative check.
   - Extend learned capacity into byte-space enforcement only when current SP/table capacity is concrete; current `CreateRow` exhaustion and Table-table `CreateTable` exhaustion from concrete `RowsFree=0` are implemented.

4. Full IssueSP semantics
   - Extend template-specific/default-SP side effects only when concrete issued-SP template state is available beyond current Template `Instances` increment/release and concrete issued-SP lifecycle/size tracking.
   - Extend issuance-space modeling to additional default-SP side effects only where the spec and datasets agree.
   - Seed default SP authority/ACL state only when template evidence is concrete.

5. Full Level 0 Discovery validation
   - Extend total-length arithmetic only if traces expose additional raw payload length/transfer length evidence beyond the current descriptor-sum and truncation/complete markers.
   - Extend additional Opal V2 enumerated validation only where local spec evidence names a non-VU field and valid range.
   - Add dynamic Locking/MBR bits where state provides enough evidence beyond the current LockingEnabled and Geometry checks.

6. Exact lifecycle/resource status matching
   - Extend exact status checks beyond implemented SP lifecycle and concrete resource-exhaustion cases only where the spec mandates a specific status and generated labels use that normalized status.

7. Remaining Authenticate refinements
   - Verify cryptographic proof correctness for `Sign`, `SymK`, and `HMAC` only when credential/key material is known.
   - Consider strict rejection of proof-without-pending for challenge-response authorities after datasets and spec policy are reconciled; current behavior accepts it as an externally-started response step if the result is boolean.
   - Reconcile `customtest_84/syn_pass_38_sign_auth_proof.json`: current miss is caused by `User1` Sign auth inside an AdminSP session, while `User1` is a LockingSP authority. Do not loosen SP-authority scoping to fit this case without a corrected spec-backed trace.

8. Return-shape/value validation backlog
   - Extend empty-success return-shape checks only where conditional-result methods become concretely modelable beyond the current `Random.Count` and `BufferOut` output-bound checks, such as `SetLagHigh` `LowPreserved` semantics.
   - Validate mandatory returned columns for known object `Get` calls when the request asks for those cells and state/default data is concrete.
   - Extend concrete `Get` value checks to additional state-backed metadata where the normalizer exposes enough requested/returned structure.
   - Continue reconciling this backlog against `myeongseok_cases`, which intentionally includes many missing/wrong-return-value mutations not yet part of the main selected validation suites.

9. Parser recovery backlog
   - Add deterministic parser/normalizer recovery only where raw evidence is unambiguous and general, not based on adversarial filenames.
   - For stripped method names and stripped UID dictionary names, prefer LLM/RAG parser repair or a narrowly justified parser fallback. Keep ambiguous semantic recovery out of the state machine.

Advanced TODO for next implementation loop:

1. Capacity and byte-space accounting
   - Goal: extend resource enforcement beyond row counts into byte-space only when concrete evidence exists.
   - Current status: row-count exhaustion, Table metadata consistency, dynamic table delete Table-capacity restoration, and exact resource-exhaustion statuses are implemented; byte-space accounting remains open.
   - Concrete evidence sources:
     - `TPerInfo.SpaceForIssuance` for `IssueSP` allocation space.
     - `SPInfo.Size` / `SPInfo.SizeInUse` for current SP byte budget if exposed.
     - Table row metadata such as `RowBytes`, `Rows`, `RowsFree`, `MinSize`, `MaxSize`, and dynamic table `HintSize`/`MinSize`.
     - `GetFreeSpace.FreeSpace` only after a state source can compute or bound it; keep current non-negative-only rule until then.
   - Candidate rules:
     - `CreateTable` cannot succeed if concrete SP/table free byte budget is insufficient for requested table size.
     - `CreateRow` cannot succeed if concrete table byte budget or row byte capacity is exhausted.
     - Successful byte-space-affecting `CreateTable`, `Delete`, `CreateRow`, and `DeleteRow` update learned byte counters when all needed counters are concrete.
     - `GetFreeSpace.FreeSpace` must not contradict concrete tracked byte-space state once that state is modeled.
   - Acceptance checks:
     - Add generated pass/fail cases where `RowsFree`/byte-space is explicitly learned before the mutating method.
     - Keep `PYTHONPATH=v8 python3 v8/evaluate.py` at `100.00`.
     - Keep selected sweep at `core_gap_cases`, `cross_gap_cases`, and `opal_gap_cases` all `100%`.
   - Defer if:
     - Required byte accounting depends on unobserved implementation-specific row encoding or compression.
     - Only adversarial labels imply the expected resource state.

2. IssueSP template-specific side effects
   - Goal: model issued-SP side effects only when template evidence is concrete enough to avoid inventing state.
   - Current status: concrete returned issued-SP UIDs are tracked, duplicate successful returned SP UIDs are rejected, `Enabled=False` issued SP lifecycle is enforced for later `StartSession`, issued-SP `FreeSpace` is bounded by concrete issued `Size`, and concrete Template `Instances` counts increment on `IssueSP` and release on concrete issued-SP delete.
   - Concrete evidence sources:
     - Complete Template-table inventory learned from concrete `Rows` plus `Next`.
     - Concrete Template row values (`Instances`, `MaxInstances`, template UID/name).
     - Concrete `IssueSP` success result with issued SP UID/name/Size/Templates.
     - Subsequent observed `SPInfo`, `SP`, `Table`, `MethodID`, `Authority`, or `AccessControl` rows for the issued SP.
   - Candidate rules:
     - Extend issued-SP lifecycle/resource side effects into additional observed `SPInfo`, `SP`, `Table`, `MethodID`, `Authority`, or `AccessControl` rows.
     - Seed default authority/ACL rows only for issued SPs whose template evidence is complete enough to identify the table source; do not seed from template name alone.
   - Acceptance checks:
     - Generated pass/fail cases for any newly seeded default tables/authorities/ACLs.
     - No loosening of AdminSP/LockingSP authority scoping.
   - Defer if:
     - The requested template is unknown but inventory is incomplete.
     - The effect requires assuming vendor-template defaults.

3. Discovery raw-payload length refinement
   - Goal: extend Level 0 Discovery length validation only if future traces expose raw transfer/payload byte counts beyond descriptor `LengthOfParameterData`.
   - Current status: descriptor-sum arithmetic, complete/non-truncated exact matching, short-length rejection, and explicit truncated-long acceptance are implemented.
   - Candidate rules:
     - Compare raw payload/transfer byte count with `LengthOfParameterData` only when the trace exposes both values unambiguously.
     - Preserve current reserved-field, descriptor-order, descriptor-length, and truncation-marker behavior.
   - Defer if:
     - The trace cannot distinguish padding, truncation, or vendor-specific tail bytes.

4. Exact lifecycle/resource status matching
   - Goal: tighten status expectations only where the spec mandates a specific status and datasets normalize that status consistently.
   - Candidate exact-status targets:
     - Disabled/frozen/failed SP lifecycle paths and concrete `INSUFFICIENT_ROWS`/`INSUFFICIENT_SPACE` resource exhaustion are handled.
     - Invalid parameter shape statuses where the parameter defect is unambiguous and not ACL-dependent.
   - Acceptance checks:
     - Every exact-status rule gets paired pass/fail generated cases where the wrong non-success class is rejected.
     - Exact status must not regress public/core/cross/opal/custom traces.
   - Defer if:
     - Existing datasets use multiple normalized error classes for the same spec condition.
     - The rule would convert a broad non-success expectation into a brittle label-specific check.

5. Authenticate proof correctness
   - Goal: verify `Sign`, `SymK`, and `HMAC` proof correctness only when credential/key material and nonce/challenge bytes are concrete.
   - Concrete evidence sources:
     - Known PIN/secret/key material from successful `Set`, `GenKey`, or fixture state.
     - Pending challenge nonce tracked in the current session.
     - Visible proof bytes and algorithm mode.
   - Candidate rules:
     - Proof response must correspond to the pending challenge and selected mechanism when all cryptographic inputs are known.
     - Replayed proof for an old challenge must fail when challenge freshness is concrete.
     - SymK nonce length and response-shape checks stay as currently implemented when cryptographic material is unavailable.
   - Acceptance checks:
     - Add generated crypto-proof cases only if the local generator can produce deterministic proof bytes.
     - Do not reject proof-without-pending globally until datasets/spec policy are reconciled.
   - Defer if:
     - The trace omits key material, algorithm details, or exact proof bytes.
     - The expected behavior depends on an external authenticator not represented in state.

6. Conditional return-shape/value validation
   - Goal: extend return-value validation to methods whose result shape depends on parameters or streamed state.
   - Current status: `Random.Count` exact visible output length and `BufferOut` upper bounds for crypto stream/finalize methods plus `XOR` are implemented.
   - Candidate methods:
     - `SetLagHigh` / `SetLagLow` `LowPreserved` semantics when clock state is concrete.
     - Missing required output fields for methods where success must expose output and the output field is deterministically identifiable.
   - Acceptance checks:
     - Only enforce result-shape fields tied to explicit input parameters or tracked stream state.
     - Add pass/fail cases for missing output, unexpected output, and wrong output length/value where deterministic.
   - Defer if:
     - The method result can legally be empty or non-empty depending on hidden stream state.

7. Dynamic schema and table deletion side effects
   - Goal: finish dynamic table modeling beyond inline `CreateTable.Columns`.
   - Candidate rules:
     - Extend schema learning beyond the current concrete Column-row path only when traces expose full table/column associations instead of ambiguous nested metadata.
     - Track dynamic table `Delete` side effects on generated `Column` rows or other concrete dependent rows beyond current table/row/ACL removal, tombstones, and Table-capacity restoration.
     - Extend unique-column checks to compound unique constraints only if the trace exposes the grouping explicitly.
   - Acceptance checks:
     - Add generated cases for nested Column schema, deleted dynamic table reuse, and post-delete stale row/table access.
     - Keep dynamic table rules protocol-generic; no filename or synthetic-pattern special cases.
   - Defer if:
     - Column metadata is partial or ambiguous enough that schema inference would be a guess.

8. Parser recovery and adversarial cases
   - Goal: keep parser repair separate from deterministic protocol rules.
   - Candidate work:
     - Add parser/normalizer recovery only for raw evidence that is unambiguous and general.
     - Use LLM/RAG repair for stripped method names or stripped UID dictionary names if future datasets require it.
     - Maintain a triage report separating `rule_gap`, `parser_recovery`, and `ambiguous_or_dataset_specific`.
   - Acceptance checks:
     - Parser recovery must improve damaged traces without changing already-normalized public/core/cross/opal/custom behavior.
     - Deterministic state/oracle code must not special-case adversarial filenames or generator patterns.

Recommended next implementation order:

1. Capacity and byte-space accounting, only when byte counters are concrete.
2. IssueSP default-SP/table/authority side effects from concrete template evidence.
3. Exact invalid-parameter status matching for unambiguous non-ACL defects.
4. Conditional return-shape/value validation beyond current `Random`/`BufferOut` checks.
5. Discovery raw-payload length refinement if raw transfer length evidence appears.
6. Authenticate proof correctness.
7. Parser recovery and adversarial cases.

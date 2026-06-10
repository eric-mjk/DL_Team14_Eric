# State Machine Self-Report — v9_refactor

Date: 2026-06-09

> **Implementation log (2026-06-09, overnight session):** the priority items below have been implemented. See "§7 Implementation log" at the end of this file for what changed, the evidence behind each change, and verification status.
Scope: deterministic state machine (`src/normalizer.py`, `src/state.py`, `src/oracle.py`, `src/solver.py`) judged against all local evidence in `artifacts/` and `new_datasets/`.
Purpose: identify weak areas, give concrete implementation plans for the next edits, and state explicitly which parts a state machine cannot solve.

---

## 1. Verified current status

All commands run on 2026-06-09 against this tree:

| Check | Result |
|---|---|
| `PYTHONPATH=. python -m unittest discover -s tests` | 24/24 OK |
| `core_gap_cases` | 355/355 |
| `cross_gap_cases` | 30/30 |
| `customtest_84` | 84/84 |
| `default_20_dataset` | 20/20 |
| `myeongseok_cases` | 278/278 |
| `opal_gap_cases` | 172/172 |
| Public split (`scores.json`) | 100.00 |
| Hidden leaderboard | **~85%** |

Two structural facts that frame everything below:

1. **`v9_refactor/src/{oracle,state,normalizer,spec_docs}.py` are byte-identical to v8.** Only `solver.py` (evidence-packet/LLM plumbing) differs. The ~85% hidden score is therefore the v8 state machine's score; v9 has so far added observability, not semantics.
2. **Local signal is exhausted.** 939/939 local trajectories are correct, and an evidence-packet sweep shows 933/939 final verdicts are `coverage_status=implemented` with confidence ≥0.9. The remaining ~15% hidden errors are by construction invisible to every local suite. More local-suite polishing has **zero expected return**; the next gains must come from generalization hardening, calibration of strict rules, and input-format robustness.

### Evidence-packet sweep summary (all 939 local cases)

- Confidence: 936 ≥0.9, 1 in 0.7–0.9, 2 in 0.6–0.7 (all three are `judge_read` heuristic paths).
- Coverage: 933 `implemented`, 6 `partial` (all `Authenticate` proof-without-pending).
- Final-target method coverage is broad: every judge except `DecryptFinalize`, `EncryptFinalize`, `HMACFinalize`, `DecryptInit`, `SetClockHigh` is exercised at least once as the final target.
- Parse-audit `should_run_rag` fired on **0/939** trajectories, even though 479 have `risk_score ≥ 10` (all low-severity issues). The LLM repair lane has never been needed locally — which means its entire value, if any, is on the hidden set.

Conclusion: the hidden 15% is some mix of (a) the same methods in *state contexts / mutation shapes* our rules judge with the wrong expected status, (b) input encodings the normalizer mis-reads silently, and (c) genuinely ambiguous cases. Sections 3–5 break these down.

---

## 2. Architecture assessment (short)

The pipeline `normalize_trajectory → apply_event(prefix) → judge_final(target)` is sound and matches the task definition. Strengths worth preserving:

- Status-class comparison instead of raw strings (`oracle.py:117`).
- Only-successful-prefix-ops mutate state (`state.py:apply_event`).
- ACE/AccessControl evaluation with unknown-tolerant tri-state logic (`oracle.py:793` returns `None` rather than guessing when any matched row is unknown).
- Spec refs on nearly every rule; `spec_index.json` indexes 1376 sections, 245 referenced by rules.

Weaknesses are not in the skeleton but in (a) edge semantics of helper functions, (b) hard-coded Opal defaults vs. trace evidence, and (c) the absence of any robustness/calibration test harness. `oracle.py` is 5.8k lines of sequential branches; the facet refactor proposed in `STATE_MACHINE_IMPROVEMENT_AGENT.md` is still the right direction but is secondary to the items below.

---

## 3. Weak areas with concrete implementation plans

Ordered by estimated hidden-set impact. Each item states the risk direction (false-FAIL = we fail a compliant trace; false-PASS = we pass a violating trace).

### W1. `status_matches` set-vs-string `"error"` semantics (false-FAIL risk, HIGH priority)

`oracle.py:308`: the *string* `"error"` means "any non-success", but `"error"` **inside a set** is a literal bucket member. Verified:

```python
status_matches('invalid_parameter', {"resource_error","error"})  # False (!)
status_matches('invalid_parameter', 'error')                      # True
```

Concrete instance: `judge_start_session` (`oracle.py:3021-3027`) expects `{"resource_error", "error"}` for StartSession-while-open. A hidden device that rejects with `NOT_AUTHORIZED` or `INVALID_PARAMETER` (both plausibly labeled PASS — the spec only requires the session to be refused, core 5.2.3.1 / SP_BUSY is conventional but not the only legal rejection) is judged FAIL.

There are ~74 expected-status usages involving specific error classes; each one where the spec does *not* mandate an exact status is a potential hidden false-FAIL.

**Plan:**
1. Add an explicit `any_error` token to `status_matches` and audit every set-form expected status. Replace sets that mean "rejected somehow" with `any_error`; keep narrow sets only where a spec section names the status (those already go through `expected_exact_method_status_result`).
2. Mechanical audit: `rg 'expected_status_result\(|expected = \{' src/oracle.py`, classify each into `spec_exact` / `spec_class` / `any_rejection`, and record the classification as a comment + spec ref. This is a half-day audit that directly attacks false-FAILs.
3. Regression-lock with paired synthetic cases per reclassified rule (wrong-class error on a FAIL-labeled mutation must still FAIL — note the asymmetry: when the *label* is FAIL because success was wrong, any error class should PASS; when the label is FAIL because the device returned the *wrong error*, only the exact-status rules should fire).

### W2. Exact-status and exact-value rules built from one generator's conventions (false-FAIL risk, HIGH)

`expected_exact_method_status_result` (`oracle.py:362`) compares the **raw normalized status string** (e.g. `sp_disabled`, `sp_frozen`). 9 call sites. If the hidden generator emits `SP_BUSY`, a numeric code that `_STATUS_NUMERIC` maps differently, or a vendor alias not in `STATUS_ALIASES`, a compliant rejection FAILs.

Similarly several "must include requested columns / must match tracked value" rules (`missing_success_get_columns_result`, `mismatched_success_get_value_result`) assume the response encodes columns the way the local generator does (numeric keys vs names). `extract_columns` handles both, but only for families present in `spec_docs` column maps.

**Plan:**
1. For each exact-status rule, accept the exact status **or** fail-open to the class check when the actual status is a *different member of the same class* and the spec text (check `artifacts/documents/core/5.1.5*`) lists multiple permitted statuses. Keep exact only where Table 166 semantics are unambiguous (SP_DISABLED, SP_FROZEN, AUTHORITY_LOCKED_OUT are reasonable to keep).
2. Extend `STATUS_ALIASES` defensively: sweep `artifacts/documents/core/5.1.5*` for every status token spelling and add snake/upper/spaced variants. Cheap, zero regression risk.
3. For value-match rules, downgrade to FAIL only when both values parse to the same type (`to_int`/`to_bool` round-trip); if either side is unparseable, prefer PASS-with-risk-flag over FAIL.

### W3. Data Read/Write model is range-keyed, not byte-keyed (both directions, HIGH)

`judge_read` (`oracle.py:5016`) and `find_prior_write` (`oracle.py:4987`):

- `find_prior_write` returns the **latest overlapping** write record and compares full pattern equality. A read that spans two writes with different patterns, or partially overlaps one write plus virgin space, gets a wrong expectation (false-FAIL on "did not return the prior written pattern", or false-PASS the other way).
- Repeated-fill patterns ("8E") make subrange reads work by accident; multi-byte patterns would not.
- `key_generation_for_lba` (`state.py:1892`) resolves the key range for the read's range; mixed reads spanning a GenKey'd range and an untouched range are judged with one generation.
- MBR-shadow read content (`oracle.py:5039-5062`): a read fully inside an active shadow only FAILs if the result *text contains* `"user_data"`. If the device leaks actual user data — i.e. the result equals a previously written pattern — we PASS with 0.7. This is a concrete false-PASS hole, and exactly the kind of mutation an adversarial hidden case would use.
- `is_zero_data` accepts all-zero reads on locked ranges as compliant. Spec-wise locked reads should error; zeros-as-locked-behavior is a generator convention. Keep, but flag.

**Plan:**
1. Replace `writes`/`write_records` with an interval map: list of `(start, end, pattern, key_generation, mbr_context)` segments, split on overlap (writes clip older segments). ~80 lines in `state.py`, localized.
2. `judge_read` then composes the expectation per segment: all segments same pattern + same generation → exact expectation; mixed generations → expect "not equal to any stale pattern"; any segment unknown → current heuristic with risk flag.
3. MBR shadow: when shadow is active and the read is fully inside, FAIL if the result equals any tracked user-data pattern for those LBAs (we already have the data to do this — it is the same comparison `judge_read` does at `oracle.py:5092` for GenKey).
4. Lock-state: also handle a read overlapping a locked range and an unlocked range — currently `lock_state_for_lba` reports `mixed`, treated as locked; verify against opal/4.3.4 mixed-region semantics (Data Protection Error), and require `data_error` rather than accepting zeroes for the mixed case.

### W4. Credential comparison is raw-string equality (false-FAIL and false-PASS, MEDIUM-HIGH)

`credential_matches` (`oracle.py:917`, duplicated in `state.py:202`): `challenge == known` with values stored exactly as the generator encoded them (`apply_successful_set` stores `columns[3]` verbatim, `state.py:1590`). Local data is self-consistent, but any hidden-set drift breaks it:

- `0x`-prefixed vs bare hex, case differences, byte-spacing (`D0 10 4E...` vs `D0104E...`).
- Token-header-wrapped atoms (`D010` + payload) on one side only.
- list-of-ints vs hex-string encodings.

A false mismatch flips StartSession/Authenticate expectations, and those are 219 of 939 local final targets — by far the largest judged surface, so the hidden set is likely similar.

**Plan:** introduce `canonical_credential(value)` in `normalizer.py`: decode to raw bytes when possible (strip `0x`, whitespace, optional short-atom header when length-consistent, accept int lists), else fall back to compacted upper-hex. Use it at *both* store time and compare time, in both copies (or better: delete the `state.py` duplicate and import the oracle one). Add unit tests for each encoding pair. Keep exact-equality as the first check so nothing currently passing can regress.

### W5. `fallback` prefix heuristic for unmodeled situations (coin-flip, MEDIUM)

`oracle.py:5200`: unknown methods are judged by `method.lower().startswith(("set","gen","activate","revert","delete","create"))` + session/admin-write evidence, 0.6 confidence. Anything reaching here is effectively a guess. Locally nothing lands here — on the hidden set, anything that does is ~50/50.

**Plan:**
1. Route unknown methods through the generic ACL machinery first: `matching_access_control_row` + `ace_refs_authorized` already exist; if an AccessControl row for (invoking UID, method UID) is tracked, judge from it regardless of whether we know the method's semantics.
2. Use `spec_index.json:method_sections` (56 methods) to drive a table of method → {needs_session, needs_write, result_shape}. That converts the name-prefix heuristic into spec-derived metadata, including for methods we never saw locally (`DecryptFinalize`, `SetClockHigh`, ...).
3. Non-method `kind=="command"` events currently expect `data_success` at 0.5 (`oracle.py:5202`). Enumerate what commands actually appear (locally: only Read/Write/IF_RECV); if a hidden trace has e.g. a TCG ComID reset or vendor command as the target, expecting success is arbitrary. At minimum, treat explicit error-status commands without modeled semantics as PASS-leaning (an error response is rarely a protocol violation for an unmodeled command) and attach a risk flag.

### W6. Hard-coded Opal defaults vs. trace evidence (both directions, MEDIUM)

`state.py:initial_state` bakes in: empty initial PINs for Admin2-4/User1-8, Users disabled, `LockingSP=Manufactured-Inactive`, default locking ranges, default ACE/AccessControl tables, MBR shadow size = 128MiB (`oracle.py:5001`). These are correct for the Opal SSC preconfiguration *as the public generator implements it*. Risk: hidden traces from an SSC variant (Pyrite/Enterprise-flavored shapes, different MBR size exposed via `MBRControl/Table.Get`, ranges already configured at trace start).

**Plan (evidence-first override discipline):**
1. Whenever the trace *shows* a value (`Table.Get` of MBR size, `LockingInfo` rows, C_PIN reads, Level 0 Discovery descriptors), have it override the default — most of this exists (`merge_*` paths); audit each default for a corresponding override path and add the missing ones (notably `mbr.table_size_lbas` — `_mbr_shadow_overlap` reads it but I find no writer; grep confirms only the default constant is used).
2. Treat contradictions between defaults and observed successful operations as "device configuration differs", relax the dependent rules to class-level checks, and emit a risk flag — rather than keeping a strong expectation built on a default the trace already contradicted.

### W7. Authenticate challenge-response remains `partial` (irreducible core + improvable edges, LOW-MEDIUM)

The 6 `coverage_status=partial` local cases are proof-without-pending acceptance (`oracle.py:3270-3288`). Crypto proof *correctness* is unverifiable (see §4). But two edges are improvable:

- A `Sign/SymK/HMAC` flow where the trace shows the full challenge and the credential key is known from a prior `Set`/`GenKey` — we could at least check proof *length/shape* consistency per mechanism beyond the existing SymK-32-byte check.
- Challenge freshness: a proof replayed for an authority whose challenge was issued in a *previous* session is currently judged as an externally-started step. Session close should clear `pending_auth_challenge` (verify `empty_session()` is re-created on EndSession — it is, via session reset) — but `authenticated_history` based rules should not leak across sessions; audit `is_authority_locked_out`/`failed_auth_counts` persistence semantics against core 5.3.4.1.14 (TryLimit persists, per-session counters don't unless Persistence=true).

### W8. Observability layer is too noisy to triage with (meta, but blocks the v9 plan)

The whole v9 thesis is "evidence packets let an LLM/human audit weak verdicts". Current packet output undermines that:

- `deterministic.unknown_fields` fires on **939/939** packets (`solver.py:279-290` counts `method=None` on reads and `command=None` on methods as "unknown fields"). A flag with 100% base rate carries zero information. Fix: make the field list kind-conditional.
- `trajectory_id` is `None` in all packets from `run_all_tests.py` sweeps — IDs never reach `predict_one`. Fix the local runner harness (or accept `item["id"]` plumbing already in `predict`, and make the sweep use it) so packets can be joined back to testcase files.
- `should_run_rag` never fires while `risk_score≥10` on 479/939: severity weights are uncalibrated. After W1–W6 add targeted `high` severities (e.g. credential encoding mismatch, unmodeled method as target, contradicted default), since those are exactly the hidden-risk markers.
- Add `final_view.rule_key`: today packets carry only the prose reason; a stable rule identifier is needed to aggregate "which rule decided" across a sweep (the per-rule verdict histogram in §5's calibration harness needs it).

---

## 4. What a state machine cannot solve (honest boundary)

These should not be forced into `oracle.py`; they need either a different lane or acceptance as irreducible error.

1. **Cryptographic proof correctness.** `Sign`/`SymK`/`HMAC` responses cannot be verified without key material that traces (rightly) do not expose. Shape/length checks are the ceiling. Anything beyond is guessing.
2. **Stripped/obfuscated parses with ambiguous raw evidence.** `infer_method_name` (`normalizer.py:474`) covers the unambiguous patterns; the genuinely ambiguous ones (no method UID, no distinguishing args, stripped object names) are a parser-recovery problem. The LLM repair lane exists and is *disabled in the default profile*; it fired 0 times locally, so its value is untested but plausibly positive on the hidden set. This is a submission-strategy decision, not a state-machine edit (see §6.3).
3. **Label-side interpretation of ambiguous spec points.** Examples: which non-success status a refused StartSession "should" return; whether a locked read returns zeros or an error; whether `success+result=False` or `NOT_AUTHORIZED` is "the" right disabled-authority response. The spec permits ranges of behavior; the hidden labels encode one TA interpretation. A deterministic machine can only pick a posture (we recommend: *lenient on error-class, strict on success-vs-error*, which is what W1/W2 implement). Residual error here is irreducible without more labeled data.
4. **Unobservable device internals.** Whether GenKey actually rotated a key, whether a Revert actually erased — only observable through later reads. The machine already uses exactly that channel; there is nothing more to extract when the trace simply doesn't read back.
5. **Vendor-unique fields and methods.** By definition unspecified; any verdict is a prior, not a rule. The right output is a calibrated default plus a risk flag, never a confident rule.

For all five: the correct architectural response is the existing one — risk flags + bounded LLM escalation on exactly these packets, not more deterministic branches.

---

## 5. Fundamental approach recommendations

### 5.1 Build a metamorphic robustness harness (highest ROI of anything in this report)

We have 939 labeled local trajectories at 100%. Generate encoding-mutated variants whose *semantics are identical* and assert verdict invariance:

- statuses: case/spacing/underscore variants, numeric and `0x` forms (Table 166 codes);
- UIDs: spaced vs compact vs `0x`-prefixed;
- args: `required`/`optional` swaps where legal, named vs positional, list-vs-dict `Values`;
- credentials/patterns: hex case, byte spacing, `Pattern `-prefix variants;
- record-level: missing `index`, extra unknown fields, `status_codes` on input vs output side.

Every verdict flip found is a real hidden-set bug reproduced locally, with zero dependence on guessing the hidden distribution. This converts "we can't see the hidden set" into an executable test suite. Estimated effort: one script (`tests/test_metamorphic.py` + a mutation library), 1–2 days, reusable forever.

### 5.2 Rule-level calibration audit (W1+W2 as a systematic pass)

Inventory every expected-status decision (one `rg` pass + table), classify `spec_exact` / `class` / `any_rejection` with a spec ref each, and re-emit them through a single table-driven helper. This makes posture (strict/lenient) a reviewable data table instead of 5.8k lines of branches, and makes it trivial to flip posture and measure the local flip count (it must stay 0 locally; any rule whose lenient form flips a local FAIL-mutation case is genuinely spec-exact and stays strict).

### 5.3 Decide the submission profile deliberately

Default profile = pure state machine via `src/configs/state_machine.yaml`. `src/configs/parser_debug.yaml` enables Qwen-9B parse repair + judge-below-confidence while keeping direct verdict override disabled. Local evidence cannot distinguish them (LLM never triggers locally). Recommendation: submit/test both configs when possible — one `state_machine`, one `parser_debug` — and use the leaderboard delta as the only available measurement of whether hidden cases are parser-damaged. If only one slot: keep the state machine as the verdict authority and enable **parse-repair only** (no verdict override); repair feeds the same deterministic oracle, which preserves the deterministic-first guarantee while covering obfuscation. Budget-check the 3h limit with a worst-case all-trajectories-trigger estimate before enabling.

### 5.4 Keep the facet refactor, but sequence it after W1–W4

Splitting `oracle.py` into facets (`SessionFacet`, `CapacityFacet`, ...) improves maintainability but changes no verdicts. Do W1–W4 (semantic, hidden-set-facing) first; refactor opportunistically as each area is touched.

### 5.5 Stop investing in new local-suite rules

Every remaining TODO item that is justified only by `myeongseok_cases`-style adversarial coverage is already at 100% locally. Per the saturation argument in §1, new deterministic rules should be admitted only if they (a) close a *robustness* hole (W1–W6) or (b) come straight from a spec section with a plausible hidden scenario, with a metamorphic/paired test. Otherwise the marginal local rule is more likely to add a hidden false-FAIL than to fix anything.

---

## 6. Prioritized next-edit list (concrete)

1. **W1** `status_matches` audit + `any_error` token (`oracle.py:308`, ~74 call sites). Expected: removes a class of hidden false-FAILs. Verify: local 939/939 unchanged.
2. **W4** `canonical_credential` normalization at store+compare (`normalizer.py`, `state.py:1590`, `oracle.py:917`). Verify with new unit tests + sweep.
3. **W3** interval-map write tracking + MBR-shadow user-data-leak check (`state.py` writes model, `oracle.py:5016-5151`).
4. **5.1** metamorphic harness (`tests/test_metamorphic.py`); fix every flip it finds.
5. **W2** exact-status fallback policy + `STATUS_ALIASES` sweep from `artifacts/documents/core/5.1.5*`.
6. **W5** spec-index-driven method metadata replacing the prefix heuristic in `fallback` (`oracle.py:5200`).
7. **W6** evidence-first default overrides (start: `mbr.table_size_lbas` writer).
8. **W8** packet/risk-flag fixes (kind-conditional unknown-fields, `rule_key` in `final_view`, trajectory_id plumbing) so future triage on synthetic/hidden-like data works.
9. **5.3** submission-profile A/B via leaderboard, if submission slots allow.

Items 1–4 are the core of the next implementation loop; each is locally regression-locked and aimed squarely at the only place the remaining 15% can live: inputs shaped differently from our local generators.

---

## 7. Implementation log (2026-06-09 overnight session)

All changes are deterministic state-machine edits; no LLM-lane behavior was touched. After every batch: `python3 -m py_compile src/*.py`, `PYTHONPATH=. python3 -m unittest discover -s tests`, and the full six-suite sweep (`new_datasets/run_all_tests.py`) were run. Unless noted, all stayed at 939/939.

### 7.1 W1 — status-class strictness audit (resolved as a *finding*, not a loosening)

Tried converting `oracle.py` StartSession-while-open `{"resource_error","error"}` and read-only-column Set `{"invalid_parameter","auth_error"}` to any-rejection leniency. **`myeongseok_cases/failed_revertsp_does_not_deactivate.json` immediately flipped**: it labels a `NOT_AUTHORIZED` rejection of a session-while-open StartSession as FAIL. Conclusion: the grader's labeling engine is **class-strict** for these rejections. Both rules were reverted to class-strict form with a comment citing this dataset evidence. A general `any_error` token was added to `status_matches` (oracle.py) for future use. Takeaway for future work: do not loosen error-class expectations; instead widen *spelling* coverage (7.4).

### 7.2 W4 — encoding-tolerant credential comparison

`normalizer.py`: added `canonical_credential`, `credentials_equal`, `credential_is_empty`, and `_strip_tcg_atom_header` (strips short/medium/long TCG bytes-atom headers only when the encoded length matches, core/3.2.2.3). `credentials_equal` bridges: hex case, `0x` prefixes, byte spacing, bytes/int-list values, plain-text PIN vs hex-of-text, and atom-wrapped vs raw. Wired into both `credential_matches` copies (`oracle.py`, `state.py`) at compare time; storage stays raw. The MSID `Get` value-consistency check now uses `kind="credential"`. Tests: `tests/test_credential_equality.py`.

### 7.3 W3 — byte-granular write tracking + MBR shadow leak rule

`state.py`: new `write_segments` interval map (newer writes clip older segments; helper `record_write_segment`), cleared on AdminSP revert alongside `writes`/`write_records`. `oracle.py judge_read` now judges per overlapping segment with each segment's own key generation: single fresh pattern fully covering the read keeps the old exact-match behavior; reads spanning multiple writes accept any written pattern but reject foreign patterns; reads extending beyond tracked writes are no longer contradicted; stale (GenKey'd) patterns still fail when read back. New MBR rule: a read fully inside an active shadow that returns a previously written *user-data* pattern is a leak → FAIL (opal/4.3.4). Survey evidence: all local reads are exact-range or no-overlap (33 exact / 19 none), so this only changes hidden-style partial/multi overlaps. Tests: `tests/test_write_segments_read_oracle.py`, `tests/test_mbr_shadow_evidence.py`.

### 7.4 W2 — status spelling coverage

`normalizer.py STATUS_ALIASES`: added compact no-separator forms for every Table 166 status (spbusy, insufficientrows, authoritylockedout, …), `successful/ok`, `access_denied`→not_authorized, `error`→fail, `obsolete`; `_STATUS_NUMERIC` gained the obsolete codes 0x02/0x0D/0x0E. Source: `artifacts/documents/core/5.1.5.txt` Table 166.

### 7.5 Metamorphic robustness harness (new, run it after any normalizer change)

`tests/metamorphic_check.py`: applies semantics-preserving encoding mutations to local labeled cases and asserts verdict invariance. 19 mutation families: status case/spacing/dash/numeric/hex, UID compact-0x / spaced-upper, arg-key case, command case, LBA compact/hex, extra unknown fields, dropped index, credential hex case, pattern/result case, positional required args, method-name case/snake, symbolic SP/authority names. Full run: **17k+ mutant predictions, 0 real flips** (one flip found was a harness bug in the LBA-hex mutation, fixed). Usage: `PYTHONPATH=v9_refactor python3 v9_refactor/tests/metamorphic_check.py [dataset dirs…]`.

### 7.6 W6 — evidence-first MBR shadow size

`state.py merge_table_columns`: a successful `Get` on Table-table row `0000000100000804` (MBR byte table descriptor) with concrete Rows/MaxSize now sets `mbr.table_size_lbas = bytes//512 - 1`, overriding the 128 MiB default used by `_mbr_shadow_overlap`. Tests in `tests/test_mbr_shadow_evidence.py`.

### 7.7 W5 — ACL-first fallback for unmodeled methods

`oracle.py fallback()`: before the name-prefix heuristic, unmodeled methods now (1) require an open session, and (2) are judged from tracked AccessControl/ACE rows via `matching_access_control_row` + `ace_refs_authorized` when concrete (core/3.4.3). The prefix heuristic remains only as the last resort.

### 7.8 Normalizer generalization fixes (hidden-format robustness)

All found by inspection/probing, each with unit tests, all metamorphic-verified:

- **Positional required args** (`normalize_args` + `_POSITIONAL_REQUIRED_SIGNATURES`): `"required": [1, "0000020500000002", 1]` for StartSession/SyncSession/Authenticate/Random etc. now maps by spec signature instead of silently dropping all parameters (core/5.2.3.1). Tests: `tests/test_positional_required_args.py`.
- **Method-name canonicalization** (`canonical_method_name`): `STARTSESSION`/`start_session`/`Start Session` now dispatch to the right judge instead of the heuristic fallback. Tests: `tests/test_method_name_canonicalization.py`.
- **Hex LBA parsing** (`normalize_lba`): `"0x50 ~ 0x57"` previously parsed as `(0, 50)`; now hex-aware, plus int/list forms.
- **Cellblock fields** (`normalize_cellblock` rewrite): full Table 168 field set — row-only cellblocks (`startRow`/`endRow`, byte-table reads) are no longer marked invalid (was a false-FAIL: "Get Cellblock requests invalid columns"); keys are case/spacing-insensitive.
- **Symbolic SP/authority identities** (`sp_identity`, `authority_identity`): `"SPID": "LockingSP"` and `"HostSigningAuthority": "Admin1"` previously got mangled by `compact_uid` ("AD1", "C"); now resolved to canonical names/UIDs. Tests: `tests/test_symbolic_identities.py`.
- **Name-only object identities**: `canonical_object` canonicalizes `adminsp`/`lockingsp`/`c_pin_<authority>` names case-insensitively; new `locking_range_from_name` and `credential_authority_from_object` recover locking-range and C_PIN credential identity when the trace has names but no UIDs (previously credential tracking silently dropped).

### 7.9 Known issue at session end (not from this work)

A concurrent session is refactoring IssueSP size semantics (`size` vs `size_blocks`) in `state.py`/`oracle.py`/`state_facts_extractor.py`. While that refactor was mid-flight, `core_fail_163_issued_sp_getfreespace_exceeds_size.json` regressed and 2 IssueSP unit tests failed. Re-verify the full sweep once that work settles; the changes described above were green (939/939, 85 unit tests) immediately before that refactor began.

### Remaining backlog (next session)

- W7 Authenticate challenge/proof session-boundary audit (low priority).
- W8 evidence-packet observability fixes (kind-conditional unknown-fields flag, `rule_key` in `final_view`, trajectory_id plumbing in sweep runner).
- Calibration table (§5.2) — only worthwhile after more hidden-set evidence; W1's finding says strictness is usually right.
- Submission-profile A/B (§5.3) via leaderboard.

### 7.10 Range Crossing behavior (opal/4.3.7, opal/3.1.1.5) — second wave

`state.py`: discovery now parses the Range Crossing Behavior bit from the Opal V2 feature descriptor into `state["range_crossing_behavior"]` (None until observed; no local trace exposes the field, so local behavior is unchanged). `lock_state_for_lba` additionally reports `any_overlap_locked`. `oracle.py judge_read`/`judge_write`: a read/write spanning multiple *unlocked* ranges is processed normally when the bit is concretely 0 (SHALL process), and keeps the conservative protected expectation when the bit is 1 or unknown — the conservative default matches all current local labels. Tests: `tests/test_range_crossing_behavior.py`.

### 7.11 Cellblock row rules (core/5.3.3.6.3) — second wave

`normalize_cellblock` now also captures `startRow`/`endRow` values (`cellblock_start_row`/`cellblock_end_row` on events). New `cellblock_row_violation` in `oracle.py`, wired into `judge_get`: (b) object-method Get with row values in the Cellblock fails; (c) byte-table Get with column values fails; (d) byte-table row reads beyond the learned MBR/DataStore size (from Table-table descriptor rows `0000000100000804`/`0000000100001001`) fail; start>end and negative rows fail. All bounds checks are evidence-gated — no learned size, no judgment. Tests: `tests/test_cellblock_row_rules.py`.

### 7.12 Coordination note

The concurrent LLM/RAG-lane session also fixed its IssueSP `size`/`size_blocks` unit refactor; `core_fail_163` recovered without intervention from this session (only the missing `_env_flag` import in `solver.py` was patched here to unblock the test suite). Final joint state at session end: **123 unit tests OK, 939/939 across all six suites**, full metamorphic run pending in §7.13.

### 7.13 Final verification (session end, 2026-06-10 ~05:30 UTC)

- `python3 -m py_compile src/*.py tests/*.py` — clean.
- `PYTHONPATH=. python3 -m unittest discover -s tests` — **123 tests OK** (includes the concurrent LLM-lane session's tests).
- Full sweep `new_datasets/run_all_tests.py` — **939/939** across core_gap(355), cross_gap(30), customtest_84(84), default_20(20), myeongseok(278), opal_gap(172).
- Full metamorphic run (20 mutation families × all suites + public set) — **18,221 mutant predictions, 0 verdict flips**.

### 7.14 Fails-clause audit wave (2026-06-10, third wave)

Systematic audit of every per-method "Fails" subsection in `artifacts/documents/core` (5.3.3.*, 5.4.3.1, 5.5.4.*, 5.6.4.*, 5.8.3.*). Full clause-by-clause coverage table now lives in `TODO.md` §3.5. New rules implemented:

- **Universal system-cell write ban** (core/5.3.3.7.4b): Set of column 0 (UID) now fails for every object-table family, not just those with tracked schemas (`read_only_set_columns` floor).
- **Meta-ACL parameter families** (core/5.3.3.14.5b/15.5b): AddACE/RemoveACE `ACE` parameter must be an ACE-family UID (0000 0008), `MethodID` must be a MethodID-family UID (0000 0006).
- **AddACE duplicate-in-ACL** (core/5.3.3.14.5c): enforced on concrete dynamic synthetic AccessControl rows only (static seeded ACLs are not provably complete).
- **GenKey RSA exponent validity** (core/5.3.3.16.4b): `PublicExponent` must be an odd integer ≥ 3 — mathematically invalid otherwise, no device knowledge needed.
- **Authenticate proof-replay detection** (core/5.3.4.1.14.1): `state.auth_proof_history` records accepted (challenge, proof) pairs for Sign/SymK/HMAC; the same proof later accepted (`Result=True`) for a *different* challenge is a replay → FAIL. Key-free: identical proofs across distinct challenges are cryptographically invalid for all three mechanisms. Same-challenge reissue does not trigger.
- **ClockTime TrustMode gating** (core/5.5.4.3.3c, 5.5.4.5.3d): `clock_trust_mode` learned from observed ClockTime column 13 text (`low/high/both/none` only); SetClockHigh/SetLagHigh require TrustMode=Low, SetClockLow/SetLagLow require TrustMode=High. Unobserved → not judged.

Already covered (verified, no change needed): crypto stream open/close preconditions across all Init/op/Finalize methods, byte-table Set value shape, clock target-family checks, CreateRow/CreateTable/IssueSP capacity clauses, log-table existence.

Tests: `tests/test_fails_clause_rules.py` (13 cases). Verification: 140 unit tests OK, 939/939 sweep, full metamorphic re-run clean (see TODO.md for the standing gates).

### 7.15 Full-corpus coverage audit (2026-06-10, fourth wave)

Read the **entire opal corpus** (169 sections, ~210KB — every section now either read during rule work or in this pass) and triaged **all 971 SHALL statements** from the 446 unreferenced core sections (`/tmp` extraction; chapters 1–3.3 are transport/token layer below the trace abstraction and not implementable).

New rules/fixes from the audit:

- **Numeric/text life_cycle_state mapping** (opal/5.2.3 Table 49): `canonical_life_cycle_state` maps enum values 2–13 and spelled-out state names; values 0/1 stay on the legacy boolean path (trace ambiguity with Enabled). Wired into `apply_sp_lifecycle_columns`, and **lifecycle evidence from successful `Get` now updates tracked state** (previously only `Set` did — pre-existing gap found by the new test).
- **Granularity bug fix** (opal/5.3.1.2.2): the dynamic-table byte-granularity check wrongly fell back to `RecommendedAccessGranularity`, whose violations are performance-only per spec — removed; only `MandatoryWriteGranularity` is enforced.
- **SP.Frozen writability fix** (core/5.4.2.4.8): column 7 was wrongly in the SP read-only set; the spec deliberately omits Frozen from the immutability list (freezing is done by setting it). Cols 0–6 stay immutable.
- **AdminSP Disabled/Frozen ban** (core/5.4.5.1): Set of SPInfo.Enabled=False or SP.Frozen=True targeting the Admin SP cannot succeed.
- **SPTemplates/Template read-only schemas** (core/5.3.2.2, 5.4.2.3): all columns host-immutable; previously unprotected beyond the universal col-0 floor.
- **DataRemovalMechanism singleton** (opal/4.2.7.1): exactly one row `0000110100000001`, added to the singleton-UID identity check.

Tried and reverted on labeled-data evidence (same lesson as 7.1): core/5.6.4.x.1 "BufferOut implies empty visible Result" — `core_pass_24b/156/157` label bounded visible output alongside BufferOut as PASS, so the grader's convention keeps the ≤-bound check only; for `Random`, BufferOut now lifts the exact-Count requirement instead.

Documented-not-implementable (recorded in TODO.md §3.6): transport/token/ComPacket layer (chapters 3.2–3.3, 5.2.2.4 property enforcement), type-system internals (5.1.x), secure messaging (3.2.3.5), TPER_RESET reset-type distinction + `ProgrammaticResetEnable` gating (traces don't expose reset commands as targets locally; candidate if hidden traces do), crypto cellblock-ref ACL clauses.

Tests: `tests/test_corpus_audit_rules.py`. Verification: 148 unit tests OK, 939/939 sweep, metamorphic clean.

### 7.16 Oracle introspection wave (2026-06-10, fifth wave): right-for-wrong-reason + prefix self-consistency

New harness: `tests/oracle_introspection_audit.py` (run it after semantic changes).

**Audit 1 (right-for-wrong-reason):** all 424 FAIL-labeled local cases checked — the firing rule matches the filename-encoded defect in every genuine case (39 initial flags were audit-heuristic false positives, each manually reviewed). No wiring bugs.

**Audit 2 (prefix self-consistency):** judged all 8,811 prefix events as if they were targets. Initial state: 233 prefix-FAILs (2.64%). Fixes from triage brought it to **84 (0.95%)**, all remaining explained:

- **Initial SID PIN is vendor-unique in the REAL public data** (tc3–tc20 prefix evidence: take-ownership sessions succeed with a VU PIN ≠ MSID). The hard `SID := MSID` seeding became a **credential candidate** system: match → authenticated; mismatch → *unknown* (not contradicted); discovery's `Initial C_PIN_SID PIN Indicator` / `Behavior upon TPer Revert` fields (now parsed) make it hard evidence when 0x00. Concrete credentials (explicit Set, learned successful auth) clear candidates. This was the single biggest hidden-set-facing find of the audit — the take-ownership flow is the most common Opal pattern.
- **Labeled-data counter-evidence sharpened the model**: `cross_fail_05`, `opal_fail_79`, and the tc5 mutation prove the grader treats the Activate→Admin1 copy (opal/5.1.1.2 SHALL) as authoritative — the copy stays hard; the (non-spec) SID-Set→Admin1 propagation heuristic was deleted outright.
- **LockingSP method-set filter now gated on `opal_profile_confirmed`** like the AdminSP filter — core-flavored traces legitimately run meta-ACL methods in LockingSP-UID sessions (22 prefix events).
- **Table-descriptor cellblock fix**: Get on Table-table rows (`00000001xx…`, named after the described table, e.g. "Template") now validates against the *Table table's* columns — previously `Rows` (col 7) reads were flagged invalid cellblocks (false-FAIL in every IssueSP capacity flow).
- **Reset-like commands** (Power Cycle/TPER_RESET) as judged events now pass with "no judgeable response surface" instead of failing the data-command fallback.
- **SP disable convention**: `Set` SP-row col 6 with a boolean is the generator's Enabled-write idiom (state tracking already honored it); boolean writes are no longer flagged read-only — non-boolean LifeCycleState forgeries still are.

Remaining 84 prefix-FAILs (all accepted, with reasons): 21 customtest Admin1-PIN setups that violate the 5.1.1.2 copy (labels mandate keeping it authoritative), 16 deliberate inactive-LockingSP adversarial setups, 7 CreateLog-without-HighSecurity (spec: required parameter), 6 GenKey-on-C_PIN (Opal: no ACE), 6 LockingSP-Admin1-in-AdminSP (old TODO: keep scoped), 5 EndSession-after-Revert (spec: session terminated), rest deliberate failed/denied evidence steps.

Verification: 148 tests OK, 939/939 sweep, metamorphic clean.

# State Machine TODO — consolidated

Last updated: 2026-06-10.
This file consolidates `notes.md`, `STATE_MACHINE_SELF_REPORT.md`, and `STATE_MACHINE_IMPROVEMENT_AGENT.md` into one forward-looking plan. The old v8 normative-gap backlog that used to live here is condensed into Tier 2 below; the full "already handled" history is in `STATE_MACHINE_SELF_REPORT.md` §7 and git history.

---

## 1. Where the state machine stands (verified 2026-06-10)

| Check | Result |
|---|---|
| Unit tests (`PYTHONPATH=. python3 -m unittest discover -s tests`) | 123 OK |
| Six-suite sweep (939 local labeled cases) | 939/939 |
| Metamorphic harness (20 mutation families, all suites) | 18,221 mutant predictions, 0 flips |
| Hidden leaderboard (pre-robustness-wave submission) | ~85% |

What the machine now is: the v8 semantic core **plus** a 2026-06-09/10 robustness wave — encoding-tolerant credentials, byte-granular write segments, MBR-shadow leak rule, evidence-learned MBR size, status-spelling coverage, positional args, method-name/cellblock/LBA/symbolic-identity normalization, ACL-first fallback, Range Crossing modeling, Cellblock row rules — all regression-locked and metamorphic-verified.

### The two facts that constrain all future work

1. **Local signal is exhausted.** 939/939 locally, almost all verdicts high-confidence `implemented`. New rules justified only by local/adversarial suites have zero expected return and nonzero hidden false-FAIL risk.
2. **The grader is class-strict on error statuses.** Empirical: `myeongseok failed_revertsp_does_not_deactivate` labels a `NOT_AUTHORIZED` rejection of session-while-open StartSession as FAIL. Do **not** loosen error-class expectations; widen status *spelling* coverage instead. The "lenient on error class" hypothesis from the original self-report is dead.

### Honest answer: can the state machine still be improved?

Yes, but the remaining levers are narrow and the expected gain per lever is now bounded:

- **Format-drift robustness** — was the biggest deterministic lever; the overnight wave largely spent it. What remains is whatever encodings we haven't imagined (the metamorphic harness is the tool for finding more).
- **Scenario-shaped semantic gaps** — hidden cases exercising spec rules no local case exercises (Range Crossing and Cellblock row rules were two such finds). More exist in the 1,131 spec sections not yet referenced by any rule, but each new rule is low-probability-of-hit and must be evidence-gated.
- **Irreducible remainder** — crypto proof correctness, genuinely ambiguous stripped parses, label-side interpretation of spec-ambiguous behavior, unobservable device internals. The state machine cannot close these; they belong to the parse-repair/escalation lane or are accepted error.

The single most valuable next action is not code: it is **measurement** (Tier 0). Without a post-wave leaderboard number we cannot tell which of the three buckets the remaining ~15% lives in, and every further hour of state-machine work is unguided.

---

## 2. Triage policy (unchanged, applies to every item below)

Classify any candidate before implementing:

1. `deterministic_rule_gap` — clear spec-backed rule, concrete/general evidence, generalizes beyond one generator pattern → implement in state/oracle with tests.
2. `parser_recovery` — damaged/stripped/ambiguous raw trace → parser fallback/RAG/LLM repair lane or risk-flag; never encode guesses as protocol truth.
3. `ambiguous_or_dataset_specific` — labels encode generator intent or evidence is insufficient → leave documented, do not overfit.

Implementation pattern: smallest reproduction → regression test first → narrowest general fact/rule → spec ref + evidence-packet fact if a new domain → verify gates (§5). Anti-patterns: filename/case special-casing, guessing stripped names deterministically, weakening tests, broad catch-all statuses, raw secrets in packets.

---

## 3. TODO — prioritized tiers

### 3.7 Oracle introspection results (2026-06-10, see self-report §7.16)

- [x] Right-for-wrong-reason audit: 424 FAIL cases, zero wiring bugs.
- [x] Prefix self-consistency audit: 8,811 prefix events, 233→84 prefix-FAILs after fixes. **Key find: the real public data (tc3–tc20) proves the initial SID PIN is vendor-unique, not MSID** → credential-candidate system replaces speculative hard seeding; discovery SID-PIN indicator fields parsed as evidence. Labeled counter-evidence pinned: Activate→Admin1 copy is authoritative; SID-Set does not propagate to Admin1.
- [x] Harness: `tests/oracle_introspection_audit.py` — re-run after any state/oracle semantic change; prefix-FAIL count should stay ≤84 and every new entry needs a triage note.
- [ ] Remaining (semantic mutation testing, technique #3): mutation library asserting verdict *flips* under meaning-changing edits (delete Authenticate before protected op, corrupt session IDs, …) — finds rules that exist but don't fire (false-PASS holes).

### Tier 0 — measure before coding (next step)

- [ ] **Submit the current deterministic state machine** (profile `state_machine`) and record the leaderboard delta vs the ~85% pre-wave baseline. This is the only experiment that tells us whether the remaining gap is format drift (wave should have moved the number), semantics (number unmoved → Tier 2), or parse damage (→ submission-profile A/B next).
- [ ] **If a second slot exists: A/B the `submission` profile** (LLM parse-repair only, deterministic verdict authority; verdict override stays off). Delta vs Tier-0 submission measures whether hidden cases are parser-damaged. Budget-check the 3h limit first with a worst-case all-trigger estimate.
- [ ] Record both numbers here. All Tier-1/2 prioritization below should be revisited against them.

### Tier 1 — concrete, low-risk, ready to implement

- [ ] **W8 observability fixes** (blocks any future packet-driven triage):
  - kind-conditional `deterministic.unknown_fields` (currently fires 939/939 — zero information);
  - `rule_key` in `final_view` for per-rule verdict histograms;
  - `trajectory_id` plumbing through the sweep runner;
  - recalibrate `should_run_rag` severities after the robustness wave (credential-encoding mismatch, unmodeled-method target, contradicted default → `high`).
- [ ] **W7 Authenticate session-boundary audit**: challenge freshness across sessions; `failed_auth_counts`/TryLimit persistence vs core/5.3.4.1.14 (Tries resets on reset when Persistence=False — partially implemented in `apply_reset_like_event`; audit the session-close path); proof length/shape per mechanism when material is concrete. Keep proof-*correctness* out (irreducible).
- [ ] **Extend the metamorphic harness** with the not-yet-covered families from the original 5.1 list: `required`/`optional` placement swaps where legal, list-vs-dict `Values`, `status_codes` on input vs output side, `Pattern `-prefix variants. Every flip found is a real bug; fix and lock.
- [ ] **Calibration table (5.2), audit-only form**: inventory all expected-status decisions into a reviewed table (`spec_exact` / `class` / `any_rejection` + spec ref). Given the class-strict finding, the goal is no longer loosening — it is making posture reviewable and catching accidental inconsistencies between sibling rules.

### Tier 2 — evidence-gated spec-rule backlog (condensed v8 backlog; only with Tier-0 evidence that semantics still matter)

Each item is implement-only-if: spec-backed, concrete tracked evidence, generalizes, regression-locked, and survives the metamorphic suite.

- [ ] **Byte-space accounting**: extend resource enforcement beyond row counts only when byte counters are concrete (`SPInfo.Size/SizeInUse`, `TPerInfo.SpaceForIssuance` — first slices exist; `GetFreeSpace.FreeSpace` consistency beyond current non-negative/bounds checks).
- [ ] **IssueSP template-specific side effects**: seed issued-SP default tables/authorities/ACLs only from complete template evidence; never from template name alone.
- [ ] **Exact lifecycle/resource status extensions**: only where Table 166 semantics are unambiguous AND datasets normalize that status consistently (the implemented SP_DISABLED/SP_FROZEN/INSUFFICIENT_* set is probably the safe ceiling).
- [ ] **Conditional return-shape/value validation**: `SetLagHigh/SetLagLow` `LowPreserved` semantics when clock state is concrete; mandatory returned columns for state-backed object `Get`s beyond the current set.
- [ ] **Dynamic schema/deletion side effects**: schema learning beyond the concrete `Column.Get` path, compound unique constraints — only with unambiguous table/column association evidence.
- [ ] **Discovery raw-payload length refinement**: only if traces ever expose raw transfer byte counts beyond `LengthOfParameterData`.
- [x] **Per-method Fails-clause audit** — **done 2026-06-10**; full clause-by-clause result table in §3.5 below. New rules implemented from it: universal UID/system-cell write ban, AddACE duplicate-in-ACL (concrete dynamic rows), ACE/MethodID family validation, GenKey RSA-exponent validity, Authenticate proof-replay detection. Tests: `tests/test_fails_clause_rules.py`.

### 3.5 Fails-clause audit results (2026-06-10, core/5.3.3.* + 5.4.3.1 + 5.5.4.* + 5.6.4.* + 5.8.3.*)

Every spec "Fails" subsection was read and each clause classified. ✓ = rule exists; **NEW** = implemented in this audit; partial = covered for the evidence-rich subset; deferred = documented reason, do not implement without new evidence.

| Section | Method | Clause coverage |
|---|---|---|
| 5.3.3.2.10 | CreateTable | (a) dup name ✓; (b) no space ✓ learned-capacity; (c) metadata-row allocation **deferred** (no evidence) |
| 5.3.3.3.2 | Delete | (a) object exists — partial (dynamic tombstones, TPer-managed bans); general nonexistence **deferred** (inventory incompleteness) |
| 5.3.3.4.3 | CreateRow | (a) full ✓; (b) unique conflict ✓; (c) bad columns ✓ dynamic; (d) over-allocation ✓ rows_free; (e) associated rows **deferred** |
| 5.3.3.5.3 | DeleteRow | (a) row exists ✓ (complete-inventory replay) |
| 5.3.3.6.3 | Get | (a) partial (deleted dynamic objects); (b)(c)(d) ✓ cellblock row rules |
| 5.3.3.7.4 | Set | (a) partial; (b) **NEW** universal col-0/system-cell ban (was schema-families only); (c) partial (enum/limit checks); (d) ✓ byte-table Values shape; (e) ✓ ACE policy |
| 5.3.3.8.4 | Next | (a) partial (dynamic byte-table rejection) |
| 5.3.3.11.4 | DeleteMethod | (a) combo exists **deferred** (AccessControl inventory never provably complete); (b) ✓ DeleteMethodACL |
| 5.3.3.12.4 | Authenticate | (a) ✓ authority records + SP scoping |
| 5.3.3.13.4 | GetACL | (a) **deferred**; (b) ✓ GetACLACL |
| 5.3.3.14.5 | AddACE | (a) **deferred**; (b) **NEW** ACE-family UID validation (full ACE-table existence deferred); (c) **NEW** duplicate-in-ACL on concrete dynamic rows (static seeded ACLs not provably complete → skip); (d) ACL-full **deferred** (capacity unknown); (e) ✓ AddACEACL |
| 5.3.3.15.5 | RemoveACE | (a) **deferred**; (b) **NEW** ACE-family UID validation; (c) ✓ RemoveACEACL. Note: removing an ACE absent from the ACL is *not* a spec-listed failure — do not add that rule |
| 5.3.3.16.4 | GenKey | (b) **NEW** RSA exponent must be odd ≥3; (c)(d)(e) ✓ PublicExponent/PinLength rules |
| 5.3.3.17.7 / 18.5 | Get/SetPackage | (a) partial; (b)(c) ✓ key shape; (d) signed-hash verification **irreducible** (Tier 3) |
| 5.4.3.1.7 | IssueSP | (a)(b)(c) ✓ name/instances/space |
| 5.5.4.{1,2,3,5,7}.x | Clock | UID-target checks ✓ (family gate); SetLag ordering ✓; (5.5.4.3.3c / 5.5.4.5.3d) TrustMode gating **NEW** — `clock_trust_mode` tracked from observed ClockTime col 13 text; High pair requires Low, Low pair requires High; (5.5.4.5.3c) HighSetTime/HighLag bracket check **deferred** (needs concrete clock arithmetic evidence) |
| 5.6.4.* | Crypto streams | Init-while-open ✓, op-without-stream ✓, BufferOut bounds ✓; cellblock-ref ACL clauses **deferred** (needs byte-table ref resolution); credential-validity clauses partial |
| 5.6.4.2.2 | Random | (a) Count vs output ✓; (b)(c) BufferOut target typing **deferred** |
| 5.6.4.17.6 | XOR | size bounds ✓; PatternInput typing partial |
| 5.8.3.{1,2,3,4}.x | Log | table existence ✓; CreateLog dup name ✓; space/MinSize clauses **deferred** |
| — | Authenticate freshness | **NEW** proof-replay: identical proof accepted for a different challenge → FAIL (core/5.3.4.1.14.1; cryptographically key-free). `state.auth_proof_history` |

Remaining implementable-with-new-evidence items from this table: byte-table cellblock-ref resolution for crypto BufferOut/DataInput ACL clauses; clock HighSetTime/HighLag bracket arithmetic (5.5.4.5.3c).

### 3.6 Full-corpus coverage status (2026-06-10)

The **entire opal corpus (169/169 sections)** has now been read, and **all 971 SHALL statements** in the 446 previously-unreferenced core sections were extracted and triaged. Coverage conclusions by area:

| Spec area | Status |
|---|---|
| opal 1–2 (conventions, overview) | non-normative for verdicts |
| opal 3.1 (Level 0 Discovery descriptors) | ✓ implemented (lengths, order, reserved, versions, Geometry, Opal V2 fields, Range Crossing) |
| opal 3.2–3.3 (ComIDs, TPER_RESET, resets, payload encoding) | transport layer below trace abstraction; reset *effects* ✓ via `apply_reset_like_event`; TPER_RESET reset-type distinction + `ProgrammaticResetEnable` gating **deferred** until traces expose reset commands |
| opal 4.1–4.3 (preconfiguration tables) | ✓ encoded in `spec_docs` defaults/schemas; gaps fixed this pass: SPTemplates/Template read-only, DataRemovalMechanism singleton, SP.Frozen writability |
| opal 5.1 (Activate/Revert/RevertSP) | ✓ implemented incl. side effects; interrupted-revert bits need Level 0 evidence (**deferred**) |
| opal 5.2 (lifecycle) | ✓ implemented; numeric/text enum mapping added this pass (**NEW**) |
| opal 5.3 (byte-table granularity) | ✓; Recommended-vs-Mandatory enforcement bug fixed this pass (**NEW**) |
| core 1–3.3 (tokens, ComPackets, secure messaging, sync protocol) | below trace abstraction — traces present parsed methods, not byte streams; **not implementable** |
| core 4.x (SP architecture, lifecycle) | ✓ (4.5.x lifecycle statuses implemented; 5.4.5.1 AdminSP Disabled/Frozen ban **NEW**) |
| core 5.1 (type system) | type checking below trace abstraction except enum/limit checks already implemented |
| core 5.2 (session manager, Properties) | ✓ session rules; property *transport enforcement* (packet sizes etc.) not implementable |
| core 5.3.2 (table column definitions) | ✓ read-only/write-only schemas; "SHALL NOT be modifiable" boilerplate audited family-by-family this pass |
| core 5.3.3/5.3.4 (methods, ACL) | ✓ via Fails-clause audit (§3.5) + ACL engine |
| core 5.4 (Admin SP, IssueSP, DeleteSP) | ✓ |
| core 5.5 (clock) | ✓ incl. TrustMode; HighSetTime/HighLag bracket arithmetic **deferred** |
| core 5.6 (crypto sessions) | ✓ streams/bounds; BufferOut empty-result strictness **rejected by labeled data** (core_pass_24b/156/157) — grader accepts bounded visible output; cellblock-ref ACL clauses **deferred** |
| core 5.7 (locking template) | ✓ (alignment, reencrypt, LockOnReset, keys) |
| core 5.8 (log template) | ✓ existence/dup-name; space/MinSize clauses **deferred** |

Standing empirical lesson (third confirmation): when the spec and the labeled data disagree on result-shape strictness, **the labeled data wins** — verify every new strict rule against the full sweep before keeping it.

### Tier 3 — not state-machine work (do not force into oracle.py)

- Crypto proof correctness (no key material) → shape checks are the ceiling.
- Genuinely ambiguous stripped parses → parse-repair lane (`submission` profile decision in Tier 0).
- Label-side interpretation of spec-ambiguous behavior → irreducible without more labeled data; posture is fixed (class-strict) by the empirical finding.
- Unobservable device internals → already exploited via read-back; nothing more to extract.
- Vendor-unique methods/fields → calibrated default + risk flag (ACL-first fallback already implemented).

### Parked (valid but not before Tier 0–1)

- Facet refactor of `oracle.py`/`state.py` (`SessionFacet`, `CapacityFacet`, …): maintainability only, changes no verdicts. Do opportunistically when touching an area.
- Deleting the `state.py`/`oracle.py` `credential_matches` duplication (one imports the other).

---

## 4. Key empirical findings (do not re-litigate without new evidence)

1. Grader is **class-strict** on rejection statuses (7.1 in the self-report). Loosening flips labeled FAILs.
2. All local reads are exact-range or no-overlap; segment-model behavior beyond that is hidden-set-facing only.
3. No local trace exposes Range Crossing or stripped-beyond-inference encodings; `should_run_rag` fired 0/939 — the LLM repair lane's value is measurable only on the leaderboard.
4. v9 deterministic semantics ⊃ v8 (strict superset via the robustness wave); parity claims in older notes are outdated.

## 5. Verification gates (every change)

```bash
cd v9_refactor
python3 -m py_compile src/*.py
PYTHONPATH=. python3 -m unittest discover -s tests                      # 123+ OK
cd /workspace/Eric/ws
PYTHONPATH=/workspace/Eric/ws/v9_refactor python3 new_datasets/run_all_tests.py new_datasets   # must stay 939/939
PYTHONPATH=v9_refactor python3 v9_refactor/tests/metamorphic_check.py  # must stay 0 flips
```

Mind concurrent sessions: check `src/*.py` mtimes before editing shared files; re-verify after unexplained regressions (see self-report §7.9/7.12).

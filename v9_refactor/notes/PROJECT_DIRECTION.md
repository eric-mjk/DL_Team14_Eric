# Project Direction — how we work from here (2026-06-10)

Companion to `SESSION_LEARNINGS.md` (the evidence). This is the forward plan.

## The one-line strategy

The deterministic state machine is **done and frozen as the verdict authority**; all improvement effort goes into **LLM parse repair** feeding that same authority, validated against `rag_validation_cases`, measured one experiment per submission slot.

## Why this allocation

84.5% is flat under every deterministic improvement we could construct, and the low-confidence inversion probe was flat too. The only hypothesis left standing with positive evidence is parse damage: the deterministic solver scores **64% on deliberately damaged traces** (`rag_validation_cases`) while scoring 100% on clean ones. If the hidden set contains a damaged slice, repairing parses is the only lever that touches the score. The residual after that is label ambiguity + crypto-unverifiable — accept it as the floor.

## Lane 1 — LLM parse repair (active development, with the other agent)

Architecture contract (already implemented in skeleton; keep it):

1. **Deterministic-first**: normalizer → state replay → oracle stays the verdict authority.
2. **Repair, don't override**: the LLM fixes *events* (stripped method names, stripped UID dictionary names, damaged fields, ambiguous parses); repaired events feed the *same* oracle. `LLM_ALLOW_VERDICT_OVERRIDE` stays off — flipping verdicts directly forfeits every guarantee the deterministic lane earned.
3. **Routed, not blanket**: invoke the model only for trajectories the parse audit flags; clean traces never pay model latency. Budget-check the 3h evaluation limit against a worst-case all-trigger estimate before submitting any LLM config.
4. **Dev set**: `rag_validation_cases`. **Deterministic baseline raised 64% → 92%** (2026-06-10, see SESSION_LEARNINGS §7): unambiguous damage (alias names, stringified args, prose statuses, bare IF_RECV) is now recovered deterministically. The LLM's remaining job is the genuinely ambiguous residue — starting with name/UID conflict arbitration (the 2 remaining misses; note myeongseok labels that shape FAIL while rag_validation labels it PASS, so repair must decide from context, not a fixed rule). Gates: rag_validation ≥ 23/25 deterministic, clean suites 939/939.
5. The deterministic side exposes everything the repair lane needs: per-verdict confidence/reason, parse-audit risk scores, evidence packets (`EVIDENCE_PACKET_AUDIT_PATH`), and the canonicalization helpers in `normalizer.py` (reuse them — don't re-implement UID/status/credential normalization in prompts).

## Lane 2 — deterministic machine (maintenance mode)

- **No new rules.** Marginal deterministic rule value is measured at zero. A change is justified only by (a) a falsifying labeled case, (b) a crash, or (c) support the repair lane explicitly needs (new fact exposure, normalization helper).
- Every change still passes the full gates: `py_compile` → 173+ unit tests → seven-suite sweep (939/939 clean + ≥23/25 rag_validation) → metamorphic (0 flips) → prefix audit (≤85, new entries triaged) → `tests/sensitivity_check.py` (no new non-flips).
- The grader conventions in `SESSION_LEARNINGS.md` §3 are binding constraints on any edit.

## Submission protocol (slots are the scarcest resource)

1. One variable per slot; record every score in this file, next to what was submitted.
2. **Next slot: LLM parse-repair config** (deterministic authority + repair lane on). The delta vs 84.5 is the direct measurement of the parse-damage hypothesis.
3. Optional calibration slot: `src/configs/probe_all_pass.yaml` measures the hidden pass-label base rate exactly (costs one ~50% slot, informs the crash-default verdict and bounds every later estimate).
4. Before any submit: confirm what a clean environment actually loads (`src/configs/submission.yaml` is the default; simulate with env vars cleared) — the tree is edited by multiple agents and the default config has changed under us before.

### Score log

| Date | Config submitted | Score | Conclusion |
|---|---|---|---|
| (long-running baseline) | deterministic (v8-era) | ~84.5 | baseline |
| (earlier) | low-confidence inversion probe | ~84.5 | heuristic-path hypothesis dead |
| 2026-06-10 | deterministic + all five waves | 84.5 | format/spec/credential hypotheses dead |
| | deterministic + two-step-auth fix + unknown-status posture | | ← submit this BEFORE the LLM config: it tests the spec-Example-1 hypothesis alone |
| | LLM parse repair | | ← after the above |
| 2026-06-10 | **myeongseok replica** (staged in `submission.yaml`, user-directed): legacy LLM fallback + verdict override ON, no trust gate, RAG off | 84.5 | his +7.5 did NOT transfer: his thresholds are identical (verified vs `v10_88copy`), but his oracle abstains often and ours never does, so the judge never fires. |
| 2026-06-10 | (local only, not submitted) blanket LLM judge experiments, 9B + 27B-FP8, two prompts | n/a | **dead**: 0/37 disagreement precision incl. 5 external public labels; every flip-producing operating point is net-negative. See TODO_LLM_PIPELINE.md. Next slots: `probe_all_pass` calibration, then two-step-auth fix. |

## Expectations, honestly

If repair recovers most of a damaged slice the size of the local one (~36% of damaged cases currently lost), the plausible ceiling is roughly high-80s to low-90s; the remainder is interpretation ambiguity and crypto-unverifiable behavior that no amount of engineering on our side resolves without more labeled signal. Plan the report (4-page deliverable) around that narrative: deterministic core + measured falsifications + targeted LLM repair — it is a defensible and complete methodology story regardless of the final number.

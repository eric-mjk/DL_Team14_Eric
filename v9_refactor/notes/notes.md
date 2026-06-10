# v9_refactor notes

Last updated: 2026-06-09

> See `STATE_MACHINE_SELF_REPORT.md` (2026-06-09) for the current weak-area analysis of the deterministic state machine, the prioritized next-edit list, and the explicit boundary of what the state machine cannot solve. Key conclusion: all 939 local cases pass while the hidden leaderboard is ~85%, so local-suite rule additions are saturated; the next gains must come from robustness/calibration hardening (status-class strictness, credential encoding, byte-granular read/write model, metamorphic testing).

## Current direction

`v9_refactor` should treat the v8 state machine as the green deterministic baseline, not as something to rewrite from scratch. The immediate goal is to make state-machine reasoning more interpretable and useful for later LLM-in-the-loop audit/debug workflows while preserving deterministic scoring behavior.

The first v9 milestone is implemented: an evidence-packet audit layer exists for debug/audit use. It is intentionally not a verdict-changing LLM pipeline.

The first LLM/RAG refactor slice is also implemented enough to use for
observability: `src/llm_pipeline.py` defines a model-free routing boundary, and
`src/llm_workflow_trace.py` defines the unified bounded JSONL trace writer for
the parser/LLM/RAG workflow. Trace emission is opt-in and does not call an LLM by
itself.

Direct LLM target-verdict replacement is now blocked by default. The legacy
override path is still available only with explicit `LLM_ALLOW_VERDICT_OVERRIDE=1`.

## Editable runtime configs

The canonical submitted config files now live under `src/configs/`. The solver defaults to `src/configs/submission.yaml`; the repo-owned configs are YAML:

```bash
PYTHONPATH=/workspace/Eric/ws/v9_refactor \
SOLVER_CONFIG_PATH=/workspace/Eric/ws/v9_refactor/src/configs/parser_debug.yaml \
uv run python /workspace/Eric/ws/new_datasets/run_all_tests.py /workspace/Eric/ws/new_datasets
```

Available configs:

- `src/configs/submission.yaml` — canonical default loaded by the solver; edit this for submitted behavior.
- `src/configs/state_machine.yaml` — deterministic state machine only.
- `src/configs/trace_debug.yaml` — deterministic state machine plus safe workflow/evidence JSONL artifacts; no LLM calls.
- `src/configs/parser_debug.yaml` — legacy parser fallback + RAG context for parser-damaged traces; direct verdict override remains disabled.
- `src/configs/rag_repair_experiment.yaml` — experimental RAG repair path that patches events, then re-runs the deterministic oracle.

`SOLVER_PROFILE=trace_debug` also works for config names under `src/configs/`.
Caller-set environment variables take precedence over values from these files.

## State-machine output contract

The state machine should not only return `pass`/`fail`. It should also leave behind enough interpretable evidence for a later human or LLM audit pass to understand the deterministic decision.

Required direction for future state-machine work:

- Every substantial rule/facet should expose compact, named facts rather than relying only on hidden mutable dict state.
- Facts should distinguish concrete, inferred, partial, unknown, and abstained evidence where practical.
- Rule results should carry useful reasons and local spec/document references.
- State-machine uncertainty should become risk flags or abstains, not guessed protocol truth.
- Evidence packets should remain safe to feed to an LLM later:
  - include normalized events, state facts, rule traces, spec references, risk flags, and provenance;
  - exclude raw payload blobs, credentials, secrets, and wholesale mutable state snapshots;
  - keep packet emission debug/audit-only unless a future task explicitly changes runtime policy.

This is the bridge between deterministic state-machine improvement and later LLM-assisted debugging: the state machine predicts the SSD state deterministically, and the evidence packet makes that prediction inspectable.

## Current implemented v9 layer

Evidence packets are emitted when `EVIDENCE_PACKET_AUDIT_PATH` is set.

Implemented properties:

- JSONL evidence packet writer independent from `PARSE_RAG_AUDIT_PATH`.
- Packet schema version: `v2`.
- Normalized-event policy version: `normalized_events_v1`.
- Risk-flag taxonomy version: `risk_flags_v1`.
- Optional `trajectory_id` is preserved from dataset item IDs when available.
- Packets include bounded/sanitized:
  - normalized events,
  - strict state facts,
  - rule trace,
  - spec references,
  - risk flags,
  - parse/repair/override provenance,
  - subsystem flags.
- Credential-like values are redacted.
- Raw payload blobs and wholesale `_state_snapshot` dumps are intentionally excluded.
- LLM prompt contract is unchanged.
- Enabling packet writing must not add LLM calls or change verdicts.

Validation evidence from the implementation pass:

```bash
cd v9_refactor
PYTHONPATH=. python -m unittest discover -s tests
# 106 tests OK after adding the LLM workflow trace, override guard, and IssueSP byte-space tests

PYTHONPATH=. USE_LLM_PARSE_FALLBACK=0 ENABLE_RAG_REPAIR=0 LLM_WORKFLOW_TRACE_PATH= python evaluate.py
# score=100.00

PYTHONPATH=/workspace/Eric/ws/v9_refactor \
USE_LLM_PARSE_FALLBACK=0 ENABLE_RAG_REPAIR=0 LLM_WORKFLOW_TRACE_PATH= \
uv run python /workspace/Eric/ws/new_datasets/run_all_tests.py /workspace/Eric/ws/new_datasets
# core_gap_cases 355/355, cross_gap_cases 30/30, customtest_84 84/84,
# default_20_dataset 20/20, myeongseok_cases 278/278, opal_gap_cases 172/172
```

Trace-enabled parity was also checked with `LLM_WORKFLOW_TRACE_PATH=$tmp/trace.jsonl`:
all six dataset suites stayed 100%, 939 `llm_workflow_trace_v1` records were
written, and the generated JSONL contained no `raw_step`, `_state_snapshot`,
`state_snapshot`, `prompt`, `response`, `SECRET`, `PIN_MARKER`, or
`CHALLENGE_MARKER` markers.

## LLM workflow trace

Enable the unified process trace with:

```bash
LLM_WORKFLOW_TRACE_PATH=/tmp/llm-workflow.jsonl
```

This writes one bounded JSONL record per trajectory. It is meant to answer:

- what route the deterministic LLM/RAG policy selected;
- what parser-audit risks were seen;
- whether RAG parser repair was attempted;
- what constrained repair decision/evidence was returned;
- whether the repair was applied and re-judged;
- what deterministic result existed before and after repair;
- whether legacy LLM verdict override was considered and why it was blocked or
  applied.

The workflow trace is not a raw debug dump. `src/llm_workflow_trace.py` centrally
owns field allowlists, redaction, and bounding. It intentionally excludes raw
steps, raw prompts, raw model responses, wholesale state snapshots, credentials,
PINs, proofs, challenges, tokens, and secrets.

Relationship to existing artifacts:

- `EVIDENCE_PACKET_AUDIT_PATH` remains the deterministic evidence/fact packet.
- `PARSE_RAG_AUDIT_PATH` remains the parse/RAG audit record path.
- Legacy parser-fallback raw audits remain separate opt-in debug artifacts and
  should only be cross-referenced/summarized by the unified workflow trace.

## Relationship to v8

- v8 remains the semantic/scoring baseline until v9 passes equivalent full sweeps.
- v9 currently improves observability and downstream audit readiness; it should not be assumed semantically stronger than v8 merely because the packet layer exists.
- When changing deterministic protocol behavior, preserve v8 parity unless the change is a deliberate, spec-backed rule improvement with tests.

## How to use `TODO.md`

`v9_refactor/notes/TODO.md` is inherited from the v8 normative-gap backlog. Treat it as a candidate-rule backlog, not as an instruction to implement every item directly in the current state machine.

Before implementing an item, classify it as one of:

1. `deterministic_rule_gap`
   - Clear spec-backed rule.
   - Concrete evidence is available in normalized events/state facts or can be added generally.
   - Rule generalizes beyond one dataset or adversarial generator pattern.
   - Good candidate for state/oracle implementation.
2. `parser_recovery`
   - Raw trace is damaged, stripped, or semantically ambiguous.
   - Better handled by parser fallback/RAG/LLM repair or by an explicit abstain/risk flag.
   - Do not encode this as protocol truth in the deterministic state machine.
3. `ambiguous_or_dataset_specific`
   - Evidence is insufficient, labels may encode generator intent, or the rule would require filename/pattern special-casing.
   - Leave as TODO with rationale instead of overfitting.

## Recommended next state-machine architecture work

Prefer modular, interpretable state facets over more monolithic growth in `oracle.py` and `state.py`.

High-value areas:

1. Dynamic table and ACL facets
   - Separate dynamic table schema, row inventory, synthetic AccessControl rows, and meta-ACL mutation behavior.
   - Keep exact fact provenance so an LLM/debugger can see why an ACL conclusion was made.
2. Capacity/byte-space facts
   - Extend beyond row counts only when byte-space evidence is concrete.
   - Track known/unknown/partial capacity instead of guessing.
3. IssueSP side effects
   - Model issued-SP lifecycle, template instances, default tables, authorities, and ACLs only when template evidence is concrete.
4. Exact status matching
   - Add only where the spec mandates a specific status and current state proves the precondition.
5. Conditional return shape/value validation
   - Implement when request parameters bound the response shape or when tracked state makes a returned value concrete.
6. Authenticate proof correctness
   - Validate cryptographic proof material only when the credential/key evidence is available and safe to use.
7. Parser recovery as a separate lane
   - Keep stripped/damaged method or UID recovery out of deterministic state unless raw evidence is unambiguous.

## Evidence-packet workflow for future work

Use the packet layer to decide whether a trajectory needs LLM/debug attention:

1. Run with `EVIDENCE_PACKET_AUDIT_PATH=/tmp/packets.jsonl`.
2. Inspect the packet for:
   - missing normalized evidence,
   - weak/absent state facts,
   - rule conflicts,
   - parser/repair provenance,
   - low-quality or missing spec references,
   - oracle abstains.
3. If the packet lacks a fact needed for deterministic validation, extend the fact schema deliberately and test it.
4. Do not dump raw state wholesale just to help the LLM; add a bounded, named fact with provenance and redaction.

## Verification expectations

Minimum local check after documentation-only changes:

```bash
ls v9_refactor/notes
```

Minimum code check after packet/state-machine changes:

```bash
cd v9_refactor
PYTHONPATH=. python -m unittest discover -s tests
```

When dataset paths and time are available, run targeted and full sweeps with packet on/off parity. A typical command shape is:

```bash
PYTHONPATH=/workspace/Eric/ws/v9_refactor \
uv run python /workspace/Eric/ws/new_datasets/run_all_tests.py /workspace/Eric/ws/new_datasets
```

Confirm the exact dataset command before relying on it for submission evidence.

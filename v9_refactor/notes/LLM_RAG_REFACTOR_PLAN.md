# v9 LLM/RAG refactor plan

Last updated: 2026-06-09

## Current assessment

`v9_refactor` already has several LLM/RAG-related surfaces, but they are not yet governed by one explicit process contract.

Current surfaces:

1. `llm_parse_fallback.py`
   - Repairs normalized events.
   - Can apply constrained state patches for pre-target history.
   - Can ask the LLM to judge the target and currently has a path that may replace a deterministic `RuleResult` when the deterministic result is not trusted.
2. `rag_parser_repair.py`
   - Retrieves local spec evidence.
   - Builds a parser-repair prompt.
   - Validates constrained JSON repair decisions.
   - Can run in dry-run/no-LLM mode.
3. `llm_judge.py`
   - Older direct verdict-judge surface.
   - Builds a separate prompt from raw trajectory/state/rule reason.
   - Not currently the best fit for the v9 evidence-packet-first direction.
4. `parse_audit.py`
   - Scores parser risk and decides whether RAG repair should run.
5. Evidence packet modules
   - `state_facts_extractor.py`
   - `packet_serializer.py`
   - `evidence_packet_writer.py`
   - These now provide the safer substrate for later LLM audit/debug.

## Desired LLM policy

The preferred v9 direction is:

1. Deterministic state machine first.
2. Evidence packet always available for audit/debug when enabled.
3. LLM is selectively invoked only for routed high-risk trajectories.
4. LLM should primarily produce:
   - parser repair suggestions,
   - evidence summaries,
   - rule-gap classifications,
   - debug/audit recommendations.
5. LLM should not directly flip final verdicts by default.

This matches the current strategic constraints:

- no heavy runtime LLM by default,
- no LLM for every trajectory,
- no direct verdict changes in the normal path,
- preserve prompt contract unless intentionally versioned,
- keep raw/secrets out of LLM-facing packets.

## Main refactor target

Create a single LLM/RAG orchestration boundary instead of spreading routing and model calls across solver, parse fallback, and RAG repair code.

Initial module now added:

```text
v9_refactor/src/llm_pipeline.py
v9_refactor/src/llm_workflow_trace.py
```

Current implemented slice:

- Pure dataclasses/functions for LLM/RAG route decisions.
- Model-free classification of:
  - `parser_damage`,
  - `oracle_abstains`,
  - `rule_conflict`,
  - `low_explanation_quality`.
- Explicit route labels:
  - `none`,
  - `parse_repair_dry_run`,
  - `parse_repair_llm`,
  - `audit_only_llm`,
  - `needs_rule_patch`.
- Explicit no-verdict-override default in route decisions.
- Unified workflow trace JSONL writer/serializer for bounded observability.
- Solver wiring for route/parse/RAG/merge/deterministic before-after trace emission.
- Direct LLM verdict changes are blocked by default unless `LLM_ALLOW_VERDICT_OVERRIDE=1`.
- Unit coverage in `v9_refactor/tests/test_llm_pipeline.py`.
- Workflow trace coverage in `v9_refactor/tests/test_llm_workflow_trace.py` and
  `v9_refactor/tests/test_solver_llm_workflow_trace.py`.

Future responsibilities:

- Load LLM/RAG-related runtime policy.
- Decide whether a trajectory needs LLM/RAG handling.
- Use evidence packets, parse audit, and deterministic rule metadata as the routing input.
- Route to one of:
  - `none`
  - `parse_repair_dry_run`
  - `parse_repair_llm`
  - `audit_only_llm`
  - `needs_rule_patch`
- Return a typed decision/provenance object.
- Never mutate state or verdict directly; return proposed patches/classifications to solver-owned code.

## Unified workflow trace

The new opt-in process trace is enabled with:

```text
LLM_WORKFLOW_TRACE_PATH=/tmp/llm-workflow.jsonl
```

It is separate from both:

- `EVIDENCE_PACKET_AUDIT_PATH` — deterministic state/rule evidence packet;
- `LLM_PARSE_AUDIT_PATH` / legacy parser fallback audit paths — deeper raw debug
  artifacts that may contain prompt/raw payload material when explicitly enabled.

The workflow trace is a bounded summary/index only. Its central owner is
`src/llm_workflow_trace.py`; solver code should assemble objects and let that
module handle schema, field allowlists, bounding, and redaction.

Trace sections:

- `identity` — trajectory/task/profile/source and record id.
- `route` — model-free `LLMRouteDecision`.
- `parse_audit` — issue kinds/severity/risk summary, not raw values.
- `legacy_parse_fallback` — bounded provenance/cross-reference only.
- `rag` — retrieval/evidence metadata and model-called status.
- `repair` — action/confidence/safe event patch/application metadata.
- `rag_repair` — compatibility alias for the combined repair summary.
- `deterministic_before` / `deterministic_after` — `RuleResult` summaries around
  the repair application boundary.
- `merge` — whether a repair was attempted/applied and whether the re-judged
  deterministic verdict changed.
- `verdict_policy` — deterministic-first policy plus blocked/applied override
  provenance.

Forbidden in the workflow trace:

- full `raw_step` / raw trajectory payloads;
- raw prompt or raw model response text;
- wholesale `_state_snapshot` / mutable `state` dumps;
- credentials, PINs, proofs, challenges, tokens, or secrets.

Sensitive repair fields such as `values`, `where`, and parameter dictionaries
are summarized by shape rather than copied into the trace.

Baseline ordering rule:

- `deterministic_before` is the `RuleResult` immediately before the repair
  application being traced.
- `deterministic_after` is the re-judged `RuleResult` after an applied repair.
- If no repair is applied, before/after are the same deterministic result.

## Suggested decision object

```python
@dataclass(frozen=True)
class LLMRouteDecision:
    route: str
    reason: str
    confidence: float
    risk_codes: tuple[str, ...]
    allowed_actions: tuple[str, ...]
    invoke_model: bool
```

```python
@dataclass(frozen=True)
class LLMProcessResult:
    route: str
    attempted: bool
    model_called: bool
    usable: bool
    action: str
    event_patch: dict | None
    state_effect: str | None
    needs_rule_patch: bool
    audit_summary: str | None
    provenance: dict
```

## Confidence/routing formula

Use a cheap deterministic routing score before any model call.

Inputs:

- `ParseAuditReport.risk_score`
- parse issue kinds/severity
- deterministic `RuleResult.confidence`
- `RuleResult.coverage_status`
- `RuleResult.policy_source`
- evidence-packet risk flags
- terminal normalized event unknown fields
- missing/weak spec references
- repair/override provenance

Recommended initial routing:

| Condition | Route |
| --- | --- |
| implemented deterministic rule, confidence >= 0.95, no high parser issues | `none` |
| parser damage or unknown terminal fields | `parse_repair_dry_run` or `parse_repair_llm` depending profile |
| deterministic fallback/partial coverage with good parse | `audit_only_llm` or `needs_rule_patch` |
| parse and rule both understood but spec refs conflict/missing | `needs_rule_patch` |
| packet/rule explanation quality low | `audit_only_llm` |

Runtime profiles should decide whether a route is allowed to invoke the model.

## Runtime profile direction

Keep profiles explicit:

- `state_machine` / `deterministic`
  - no LLM calls,
  - parse audit allowed,
  - evidence packets allowed.
- `submission`
  - ideally still deterministic-first,
  - if LLM is enabled, route only high-risk parser-damage cases,
  - no direct verdict override.
- `aggressive`
  - experiment-only,
  - can call parse repair LLM more often,
  - still should record provenance and avoid direct verdict flips unless explicitly enabled.

Add explicit env names rather than relying on ambiguous legacy toggles:

```text
LLM_PIPELINE_MODE=off|audit|repair|aggressive
LLM_ALLOW_VERDICT_OVERRIDE=0
LLM_MAX_TRAJECTORY_FRACTION=...
LLM_MAX_CALLS=...
LLM_ROUTE_MIN_RISK=...
```

## Refactor steps

### Phase 1: Policy isolation

- Add `llm_pipeline.py`. **Done: initial pure routing boundary exists.**
- Move route decision logic out of `Solver.predict_one`. **Done for route computation/tracing.**
- Keep behavior unchanged initially except for the intentional default no-verdict-override guard.
- Unit-test route decisions with synthetic parse reports/rule results. **Done.**

### Phase 2: Disable direct verdict changes by default

- Keep the existing override code available behind an explicit opt-in env flag.
- Default `LLM_ALLOW_VERDICT_OVERRIDE=0`. **Done.**
- If the LLM disagrees, record that disagreement as provenance/risk, not as the final verdict. **Done.**

### Phase 3: Packet-first LLM input

- Build audit prompts from evidence packets or packet-like objects.
- Do not pass broad `_state_snapshot` to new LLM prompts.
- Preserve the existing `llm_parse_user_template.txt` contract until a versioned prompt migration is added.

### Phase 4: Unify RAG repair and parse fallback

- Keep `rag_parser_repair.py` as the constrained repair engine.
- Make `llm_parse_fallback.py` thinner or split it into:
  - event patch schema/merge,
  - state patch schema/apply,
  - model backend,
  - audit writer.
- Prefer the validated `RepairDecision` schema from `rag_schema.py` over the looser `LLMParseDecision` for new repair work.

### Phase 5: LLM audit output

Add a non-verdict-changing LLM audit output:

```json
{
  "classification": "parser_damage|oracle_abstain|rule_conflict|low_explanation_quality|no_action",
  "confidence": 0.0,
  "evidence_refs": [],
  "suggested_next_step": "parser_recovery|state_rule_patch|leave_ambiguous",
  "reason": "brief"
}
```

This can help prioritize future deterministic edits without making runtime scoring depend on broad LLM judgment.

## Specific code risks to address

1. Direct verdict override path
   - `solver.py` can replace `RuleResult` with `policy_source=\"llm_parse_fallback\"`.
   - This conflicts with the current preferred `no_verdict_changes` direction unless strictly opt-in.
2. Duplicate LLM concepts
   - `llm_judge.py` and `llm_parse_fallback.py` both include verdict-judging concepts.
   - Prefer one packet-first audit/judge interface; keep old direct judge disabled or legacy.
3. Loose state patching
   - `apply_state_patch` can mutate several state domains from LLM output.
   - Keep this only for constrained, high-confidence parser recovery, not semantic invention.
4. Prompt/input mismatch
   - Current parse-fallback prompt uses `_state_snapshot`, while the new v9 direction prefers evidence packets/state facts.
   - Migrate carefully with prompt-contract tests.
5. RAG repair state effects are validated but not broadly applied
   - `RepairDecision.state_effect` exists, but solver currently applies only `repair_event` from RAG repair.
   - Decide whether state effects are debug-only or implement a constrained applier with tests.

## Near-term recommendation

Do not rewrite the LLM stack immediately. First add the orchestration boundary and tests:

1. `llm_pipeline.py` route decision dataclasses/functions.
2. Unit tests for routing without model calls.
3. Solver wiring that records route/provenance but preserves current default verdict behavior.
4. Explicit env flag to prevent LLM verdict override by default. **Done.**
5. New prompt/audit path that consumes evidence packets for debug-only review.

This gives later agents a safe place to improve LLM usage without entangling parser repair, RAG retrieval, state mutation, and final verdict selection inside `solver.py`.

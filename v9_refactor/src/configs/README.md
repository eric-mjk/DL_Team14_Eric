# v9 solver configs

These files are intentionally under `src/configs/` because the submission
package includes `src/` and may not include an arbitrary top-level `configs/`
directory.

The default file is `submission.yaml`. The solver loads it when you do not set `SOLVER_PROFILE` or `SOLVER_CONFIG_PATH`.

```bash
PYTHONPATH=/workspace/Eric/ws/v9_refactor \
uv run python /workspace/Eric/ws/new_datasets/run_all_tests.py /workspace/Eric/ws/new_datasets
```

You can still use another config by explicit path:

```bash
PYTHONPATH=/workspace/Eric/ws/v9_refactor \
SOLVER_CONFIG_PATH=/workspace/Eric/ws/v9_refactor/src/configs/parser_debug.yaml \
uv run python /workspace/Eric/ws/new_datasets/run_all_tests.py /workspace/Eric/ws/new_datasets
```

## Which config should I edit?

- `submission.yaml` — the one default file the solver points to. Edit this for the behavior you want to submit.
- `state_machine.yaml` — deterministic state machine only. Use/copy this for fast, stable scoring.
- `trace_debug.yaml` — deterministic state machine plus safe JSONL traces. Use
  this when you want to understand a decision without invoking an LLM.
- `parser_debug.yaml` — legacy LLM parser fallback plus RAG context. Use this
  only for parser-damaged/adversarial cases.
- `rag_repair_experiment.yaml` — newer RAG repair experiment. It tries to repair
  normalized events and then re-runs the deterministic oracle.

## YAML vs JSON

Use YAML here. It supports comments and is easier to read/edit:

```yaml
settings:
  USE_LLM_PARSE_FALLBACK: true  # comments are allowed
```

JSON is stricter and cannot have comments:

```json
{"settings": {"USE_LLM_PARSE_FALLBACK": true}}
```

The loader still supports JSON for custom files, but the repo keeps YAML as the
canonical format to reduce duplicate config surfaces.

## Important parameter meanings

### `USE_LLM_PARSE_FALLBACK`

Turns on the legacy LLM parser-repair path.

- `false`: do not use the legacy parser LLM.
- `true`: when the normalized event looks suspicious, ask the LLM to repair the
  parser interpretation.

This is about repairing **what event the trace means**, not directly replacing
the final pass/fail verdict.

### `ENABLE_RAG_REPAIR`

Turns on the newer RAG repair path in `solver.py`.

- `false`: do not run this separate RAG repair engine.
- `true`: if parse audit says the trace is damaged, retrieve relevant spec
  context, ask for a constrained `RepairDecision`, patch the event if confident,
  then re-run the deterministic state machine.

Usually keep this off unless you are specifically experimenting with
`rag_repair_experiment.yaml`.

### `ENABLE_PARSE_AUDIT`

Runs a cheap parser-audit pass.

- It does not call an LLM by itself.
- It detects risks like missing/unknown methods, UID/name disagreement, malformed
  fields, and other parser-damage signals.
- The workflow trace uses this to explain whether a trajectory looks risky.

Recommended: `true`.

### `LLM_PIPELINE_MODE`

Controls the model-free routing decision recorded in the workflow trace.

Allowed values:

- `off`: never route to LLM/RAG lanes; deterministic only.
- `audit`: record when an LLM audit would be useful, but do not repair events.
- `repair`: parser-damage risks are repair candidates.
- `aggressive`: broader experimental routing; riskier/slower.

This flag by itself mostly affects routing/provenance. Actual LLM calls still
require the relevant engine flags such as `USE_LLM_PARSE_FALLBACK` or
`ENABLE_RAG_REPAIR`.

### `LLM_ALLOW_VERDICT_OVERRIDE`

Controls the dangerous legacy behavior where an LLM can directly change the
final `pass`/`fail` verdict.

Recommended: always `false`.

- `false`: LLM can help repair parser events, but the deterministic oracle still
  decides the final verdict.
- `true`: legacy LLM fallback may directly replace the deterministic verdict in
  low-confidence cases.

Only enable this for controlled experiments.

### `LLM_WORKFLOW_TRACE_PATH`

Path to a safe, bounded JSONL workflow trace.

This tells you:

- parser audit risks;
- route decision;
- whether repair was attempted/applied;
- deterministic verdict before/after repair;
- whether verdict override was blocked.

This is the best first debug artifact.

### `EVIDENCE_PACKET_AUDIT_PATH`

Path to deterministic state/rule evidence packets.

This is the best artifact to give a human/LLM later because it contains compact
facts, state evidence, rule traces, spec refs, risk flags, and provenance.

### `PARSE_RAG_AUDIT_PATH`

Path to parse-audit/RAG-repair records.

Use it when debugging the RAG repair engine specifically.

### `LLM_PARSE_AUDIT_PATH`

Path to raw legacy LLM parse-fallback call audits.

This can include raw steps, prompts, and model responses depending on
`LLM_PARSE_AUDIT_INCLUDE_PROMPT` / `LLM_PARSE_AUDIT_INCLUDE_RESPONSE`.
Do not treat it as a safe compact artifact.

## Model/threshold parameters

### `MODEL_NAME`

Local model used by parser/RAG LLM paths, currently usually:

```yaml
MODEL_NAME: Qwen/Qwen3.5-9B
```

### `LLM_PARSE_MIN_CONFIDENCE`

Minimum confidence required before accepting a legacy parser repair decision.
Higher is safer but may apply fewer repairs.

### `LLM_PARSE_TRUST_MIN_CONFIDENCE`

If the deterministic oracle confidence is at least this high and the rule is
implemented, LLM verdict override is ignored even if fallback is enabled.

### `LLM_PARSE_RAG_TOP_K` / `LLM_PARSE_RAG_MAX_CHARS`

How much spec/document context the legacy parser fallback can retrieve and feed
to the model.

- larger values: potentially better context, slower/more tokens;
- smaller values: faster, but less context.

## Recommended workflow

1. Submit/debug baseline with `state_machine.yaml`.
2. If you need explanations, use `trace_debug.yaml`.
3. If failures look parser-damaged, try `parser_debug.yaml`.
4. Only use `rag_repair_experiment.yaml` for focused experiments.
5. Avoid `LLM_ALLOW_VERDICT_OVERRIDE: true` unless you are explicitly testing
   whether direct LLM verdict changes improve hidden score.

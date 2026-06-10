# LLM/RAG Prompt Files

These files are the human-editable prompt surface for the optional LLM parser fallback.
The normal submission default (`SOLVER_PROFILE=state_machine`, loaded from `src/configs/state_machine.yaml`) does **not** use these prompts because it disables `USE_LLM_PARSE_FALLBACK`.

## Main LLM parse fallback

Used by `src/llm_parse_fallback.py` when `src/configs/parser_debug.yaml` or another config sets `USE_LLM_PARSE_FALLBACK: true`.

- `llm_parse_system.txt` — system message sent to the model.
- `llm_parse_user_template.txt` — user prompt template. `$payload_json` is replaced at runtime.

The `$payload_json` object contains:

- `task` — `pre_target`, `target`, or `judge_target`.
- `raw_step` — compact raw JSON step from the dataset.
- `current_normalized_event` — event dict produced by `normalizer.py` and consumed by the state machine.
- `state_before_step` — compact state snapshot before this step.
- `retrieved_spec_context` — RAG text retrieved from `artifacts/documents`.
- `rule_result` — deterministic oracle verdict/reason when target judging is asking for an override.

The LLM must return JSON only:

```json
{
  "usable": true,
  "confidence": 0.0,
  "reason": "brief reason",
  "normalized_event": null,
  "state_patch": null,
  "verdict": null
}
```

## RAG parser repair prompt

Used by `src/rag_parser_repair.py` when `src/configs/rag_repair_experiment.yaml` or another config sets `ENABLE_RAG_REPAIR: true`.

- `rag_parser_repair_system.txt` — system message.
- `rag_parser_repair_few_shot.txt` — examples.
- `rag_parser_repair_user_template.txt` — final prompt template.

## How to see actual inputs and outputs

Run with the LLM profile and audit enabled:

```bash
PYTHONPATH=/workspace/Eric/ws/v9_refactor \
SOLVER_CONFIG_PATH=/workspace/Eric/ws/v9_refactor/src/configs/parser_debug.yaml \
LLM_PARSE_AUDIT_PATH=/workspace/Eric/ws/tmp/llm_parse.jsonl \
LLM_PARSE_AUDIT_INCLUDE_PROMPT=1 \
LLM_PARSE_AUDIT_INCLUDE_RESPONSE=1 \
LLM_PARSE_AUDIT_PRETTY=1 \
LLM_PARSE_AUDIT_DIR=/workspace/Eric/ws/tmp/llm_parse_calls \
uv run python /workspace/Eric/ws/new_datasets/run_all_tests.py /workspace/Eric/ws/new_datasets myeongseok_cases
```

Then inspect:

- `/workspace/Eric/ws/tmp/llm_parse.jsonl` — one JSONL record per call.
- `/workspace/Eric/ws/tmp/llm_parse_calls/*.json` — pretty per-call files containing prompt, RAG context, response, and parsed decision.

This gives most of the observability benefit you wanted from LangChain tracing without adding a dependency or changing the grader runtime.

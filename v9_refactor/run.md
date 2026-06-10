# v9_refactor run guide

## Recommended: edit one config file, then run it

Editable configs live in:

```text
v9_refactor/src/configs/submission.yaml   # default loaded by solver
v9_refactor/src/configs/state_machine.yaml
v9_refactor/src/configs/trace_debug.yaml
v9_refactor/src/configs/parser_debug.yaml
v9_refactor/src/configs/rag_repair_experiment.yaml
```

By default, edit `src/configs/submission.yaml` and run without extra config flags:

```bash
PYTHONPATH=/workspace/Eric/ws/v9_refactor \
uv run python /workspace/Eric/ws/new_datasets/run_all_tests.py /workspace/Eric/ws/new_datasets
```

Or select another named YAML config:

```bash
PYTHONPATH=/workspace/Eric/ws/v9_refactor \
SOLVER_PROFILE=trace_debug \
uv run python /workspace/Eric/ws/new_datasets/run_all_tests.py /workspace/Eric/ws/new_datasets
```

Important configs:

- `submission.yaml`: canonical default; edit this for the submitted behavior.
- `state_machine.yaml`: deterministic state machine only.
- `trace_debug.yaml`: deterministic state machine plus workflow/evidence JSONL files; no LLM calls.
- `parser_debug.yaml`: legacy parser fallback + RAG context for damaged parser cases; direct verdict override remains off.
- `rag_repair_experiment.yaml`: experimental RAG repair path; repaired events are re-judged by deterministic oracle.

Direct LLM verdict override is off unless you explicitly set:

```bash
LLM_ALLOW_VERDICT_OVERRIDE=1
```

## default submission run, using src/configs/submission.yaml:
```
PYTHONPATH=/workspace/Eric/ws/v9_refactor \
uv run python /workspace/Eric/ws/new_datasets/run_all_tests.py /workspace/Eric/ws/new_datasets
```
## explicit LLM/RAG profile if you want parser fallback:
```
PYTHONPATH=/workspace/Eric/ws/v9_refactor \
SOLVER_CONFIG_PATH=/workspace/Eric/ws/v9_refactor/src/configs/parser_debug.yaml \
uv run python /workspace/Eric/ws/new_datasets/run_all_tests.py /workspace/Eric/ws/new_datasets
```
## llm parse audits
```
PYTHONPATH=/workspace/Eric/ws/v9_refactor \
SOLVER_CONFIG_PATH=/workspace/Eric/ws/v9_refactor/src/configs/parser_debug.yaml \
LLM_PARSE_AUDIT_PATH=/workspace/Eric/ws/tmp/llm_parse.jsonl \
uv run python /workspace/Eric/ws/new_datasets/run_all_tests.py /workspace/Eric/ws/new_datasets 
```

myeongseok_cases

LLM_PARSE_AUDIT_INCLUDE_PROMPT=0
LLM_PARSE_AUDIT_INCLUDE_RESPONSE=1
LLM_PARSE_AUDIT_PROMPT_CHARS=12000
LLM_PARSE_AUDIT_RESPONSE_CHARS=3000
LLM_PARSE_AUDIT_RAG_CHARS=6000
## inspect actual LLM/RAG calls:
```
PYTHONPATH=/workspace/Eric/ws/v9_refactor \
SOLVER_CONFIG_PATH=/workspace/Eric/ws/v9_refactor/src/configs/parser_debug.yaml \
LLM_PARSE_AUDIT_PATH=/workspace/Eric/ws/tmp/llm_parse.jsonl \
LLM_PARSE_AUDIT_INCLUDE_PROMPT=1 \
LLM_PARSE_AUDIT_INCLUDE_RESPONSE=1 \
LLM_PARSE_AUDIT_PRETTY=1 \
LLM_PARSE_AUDIT_DIR=/workspace/Eric/ws/tmp/llm_parse_calls \
uv run python /workspace/Eric/ws/new_datasets/run_all_tests.py /workspace/Eric/ws/new_datasets myeongseok_cases
```

Open `/workspace/Eric/ws/tmp/llm_parse_calls/*.json` to see the exact prompt, retrieved RAG context, raw model response, and parsed decision for each LLM fallback call.

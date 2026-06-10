## default submission-safe deterministic state machine (no LLM fallback):
```
PYTHONPATH=/workspace/Eric/ws/v8 \
uv run python /workspace/Eric/ws/new_datasets/run_all_tests.py /workspace/Eric/ws/new_datasets
```
## explicit LLM/RAG profile if you want parser fallback:
```
PYTHONPATH=/workspace/Eric/ws/v8 \
SOLVER_PROFILE=submission \
uv run python /workspace/Eric/ws/new_datasets/run_all_tests.py /workspace/Eric/ws/new_datasets
```
## llm parse audits
```
PYTHONPATH=/workspace/Eric/ws/v8 \
SOLVER_PROFILE=submission \
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
PYTHONPATH=/workspace/Eric/ws/v8 \
SOLVER_PROFILE=submission \
LLM_PARSE_AUDIT_PATH=/workspace/Eric/ws/tmp/llm_parse.jsonl \
LLM_PARSE_AUDIT_INCLUDE_PROMPT=1 \
LLM_PARSE_AUDIT_INCLUDE_RESPONSE=1 \
LLM_PARSE_AUDIT_PRETTY=1 \
LLM_PARSE_AUDIT_DIR=/workspace/Eric/ws/tmp/llm_parse_calls \
uv run python /workspace/Eric/ws/new_datasets/run_all_tests.py /workspace/Eric/ws/new_datasets myeongseok_cases
```

Open `/workspace/Eric/ws/tmp/llm_parse_calls/*.json` to see the exact prompt, retrieved RAG context, raw model response, and parsed decision for each LLM fallback call.

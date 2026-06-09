# Runtime Profiles

The solver loads `state_machine.env` by default. That profile disables the LLM parser fallback so submission runs on the deterministic state machine unless the caller explicitly selects another profile. Runtime environment variables set
by the caller always take precedence over profile values.

Use a profile:

```bash
uv run python evaluate.py                         # default: state_machine, no LLM fallback
SOLVER_PROFILE=state_machine uv run python evaluate.py
SOLVER_PROFILE=deterministic uv run python evaluate.py
SOLVER_PROFILE=submission uv run python evaluate.py   # LLM parser fallback + RAG
SOLVER_PROFILE=aggressive uv run python evaluate.py
```

Use an explicit config file:

```bash
SOLVER_CONFIG_PATH=/path/to/custom.env uv run python evaluate.py
```

Do not use `aggressive.env` for timed submission unless you have measured the
hidden-sized runtime budget; it can trigger many LLM calls.

Audit LLM fallback calls:

```bash
LLM_PARSE_AUDIT_PATH=/tmp/llm_parse.jsonl SOLVER_PROFILE=submission uv run python evaluate.py
```

Optional audit size controls:

```text
LLM_PARSE_AUDIT_INCLUDE_PROMPT=1
LLM_PARSE_AUDIT_INCLUDE_RESPONSE=1
LLM_PARSE_AUDIT_PRETTY=1
LLM_PARSE_AUDIT_DIR=/workspace/Eric/ws/tmp/llm_parse_calls
LLM_PARSE_AUDIT_PROMPT_CHARS=30000
LLM_PARSE_AUDIT_RESPONSE_CHARS=5000
LLM_PARSE_AUDIT_RAW_CHARS=3000
LLM_PARSE_AUDIT_RAG_CHARS=12000
```

When pretty audit is enabled, each LLM call is also written as separate
`*.json` files under `LLM_PARSE_AUDIT_DIR`. If that directory is not set, files
are written under `<LLM_PARSE_AUDIT_PATH>.d/`.

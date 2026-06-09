# Myeongseok Cases

Imported from `/workspace/myeongseok/skeleton/artifacts`.

This dataset contains the deduplicated labeled implementation/regression cases
from Myeongseok's artifacts:

- `adversarial_cases`
- `failing_before_fix`
- `failing_before_fix_round2`
- `failing_before_fix_round3`

The `failing_before_fix*` cases duplicate filenames already present in
`adversarial_cases`; `manifest.json` preserves the original source groups for
each case. The `failing_after_fix*` artifact directories had no labeled JSON
cases to add.

Layout matches the other `new_datasets` corpora:

- `testcases/`: JSON trajectories.
- `label.jsonl`: evaluator labels.
- `manifest.json`: source group and rationale metadata.

Run from the v8 solver directory with:

```bash
PYTHONPATH=/workspace/Eric/ws/v8 \
ENABLE_RAG_REPAIR=0 USE_LLM_PARSE_FALLBACK=0 \
python /workspace/Eric/ws/new_datasets/run_all_tests.py \
  /workspace/Eric/ws/new_datasets myeongseok_cases
```


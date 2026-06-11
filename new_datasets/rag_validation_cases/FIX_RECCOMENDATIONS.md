# Fix Recommendations

Use `validate_debug.py` reports to decide where to improve the RAG workflow:

1. **Low hit@5**: improve lexical anchors or split `rag_targets` into more precise document sections.
2. **Repair-positive classified as no_repair**: inspect parse-audit issues; the drift may not be severe enough to route to RAG.
3. **No-repair false positives**: add more clean controls/decoys and tighten routing prompts/thresholds.
4. **Correct classification but no repair application**: treat as solver/RAG integration debt, not dataset failure.
5. **state_effect sentinels visible**: keep out-of-band until the solver applies `state_effect` decisions; do not include them in primary thresholds.

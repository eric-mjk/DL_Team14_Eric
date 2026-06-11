# RAG Validation Cases

This dataset validates the state-machine + RAG pipeline without mixing metrics.
It is intentionally separate from the saturated generated suites.

## Contents

- `generate_rag_validation.py` — deterministic generator and structural `--check` mode.
- `validate_debug.py` — profile-separated validator/report writer.
- `manifest.json` — case metadata, including `family`, `probe_class`, `drift_pattern`, `rag_targets`, `expected_repair_action`, `metric_scope`, and `base_case`.
- `label.jsonl` and `testcases/*.json` — evaluator-compatible dataset files.
- `debug_audit.json` / `debug_audit.md` — latest single-profile validator report.
- `debug_audit_summary.json` / `debug_audit_summary.md` — combined headline metrics from the latest profile sweep.


## Current generated mix

`generate_rag_validation.py` currently writes 81 cases:

- 19 `control` cases for the deterministic `state_machine` hard gate.
- 35 `repair_positive` parser-drift probes for retrieval/action routing.
- 11 `no_repair` clean decoys for false-positive checks.
- 9 `needs_rule_patch` semantic-rule sentinels, reported as review-only action rows.
- 7 `state_effect_sentinel` out-of-band cases, excluded from primary thresholds.

## Metric ownership

- `state_machine`: hard gate on `probe_class=control` and `metric_scope=primary` only.
- `parser_debug`: offline retrieval hit@1/3/5 and parser/action-routing classification only. Action classification is derived from parse-audit behavior (`should_run_rag` plus actionable issue kinds), not from the dataset's expected label. `needs_rule_patch` and `state_effect_sentinel` rows are review-only for action routing.
- `rag_repair_experiment`: repair-event application and before/after verdict visibility only. Offline dry mode is a wiring smoke test; it is not evidence that the LLM applied repairs.
- `state_effect_sentinel`: out-of-band appendix; excluded from primary thresholds.

## Commands

```bash
python3 new_datasets/rag_validation_cases/generate_rag_validation.py
python3 new_datasets/rag_validation_cases/generate_rag_validation.py --check
python3 new_datasets/rag_validation_cases/validate_debug.py --profile state_machine --scope controls --strict
python3 new_datasets/rag_validation_cases/validate_debug.py --profile state_machine --scope primary --non-gating-smoke
python3 new_datasets/rag_validation_cases/validate_debug.py --profile parser_debug --scope primary --strict
python3 new_datasets/rag_validation_cases/validate_debug.py --profile rag_repair_experiment --scope repair_positive --strict
python3 new_datasets/rag_validation_cases/validate_debug.py --profile rag_repair_experiment --scope controls --strict
```

`parser_debug` retrieval uses `section_prefix_tolerant` matching: a retrieved chunk is a hit when its file/section exactly matches a target or is in the same immediate section-prefix neighborhood. Treat hit@k as approximate retrieval-neighborhood coverage, not exact citation accuracy. The validator emits this policy in `debug_audit.json` and fails strict mode if any repair-positive family falls below the family hit@5 review threshold.

By default, `rag_repair_experiment` runs in offline dry mode and will not load/call a local LLM. In dry mode, repair application is reported but not enforced; when a scope contains no controls, control regressions are reported as `null` / `not_evaluated` rather than a vacuous zero.

For an actual model-backed repair gate, run both repair and control scopes with the local LLM backend available:

```bash
python3 new_datasets/rag_validation_cases/validate_debug.py --profile rag_repair_experiment --scope repair_positive --invoke-llm --require-llm-repair --strict
python3 new_datasets/rag_validation_cases/validate_debug.py --profile rag_repair_experiment --scope controls --invoke-llm --strict
```

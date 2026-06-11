# RAG Validation Debug Audit Summary

## dataset_size

- total_cases: `81`

## py_compile

- status: `passed`
```

```

## generator_check

- status: `passed`
```
generation check passed
```

## state_machine

- scope: `controls`
- gating: `True`
```
wrote /workspace/Eric/ws/new_datasets/rag_validation_cases/debug_audit.json
wrote /workspace/Eric/ws/new_datasets/rag_validation_cases/debug_audit.md
state_machine controls: 19/19 accuracy=1.000 gating=True
```

## state_machine_non_gating

- scope: `primary/all`
```
state_machine primary non-gating: 62/74 accuracy=0.838
state_machine all non-gating: 69/81 accuracy=0.852
```

## parser_debug

- scope: `primary`
- match_policy: `section_prefix_tolerant`
```
wrote /workspace/Eric/ws/new_datasets/rag_validation_cases/debug_audit.json
wrote /workspace/Eric/ws/new_datasets/rag_validation_cases/debug_audit.md
parser_debug primary: hit@1=0.543 hit@3=0.829 hit@5=1.000 action_accuracy=1.000 no_repair_fp=0.000
```

## out_of_band_sentinel

- scope: `out_of_band`
- thresholded: `False`
```
wrote /workspace/Eric/ws/new_datasets/rag_validation_cases/debug_audit.json
wrote /workspace/Eric/ws/new_datasets/rag_validation_cases/debug_audit.md
parser_debug out_of_band: hit@1=0.000 hit@3=0.000 hit@5=0.000 action_accuracy=0.000 no_repair_fp=0.000
```

## rag_repair_experiment

- scope: `repair_positive`
- offline_dry_mode: `True`
```
wrote /workspace/Eric/ws/new_datasets/rag_validation_cases/debug_audit.json
wrote /workspace/Eric/ws/new_datasets/rag_validation_cases/debug_audit.md
rag_repair_experiment repair_positive (offline-dry): repair_application=0.000 control_regressions=None (not_evaluated)
```

## rag_repair_controls

- scope: `controls`
- offline_dry_mode: `True`
```
wrote /workspace/Eric/ws/new_datasets/rag_validation_cases/debug_audit.json
wrote /workspace/Eric/ws/new_datasets/rag_validation_cases/debug_audit.md
rag_repair_experiment controls (offline-dry): repair_application=0.000 control_regressions=0 (evaluated)
```

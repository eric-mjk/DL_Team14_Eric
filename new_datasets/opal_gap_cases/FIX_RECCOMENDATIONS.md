# Fix Recommendations

Latest `opal_gap_cases` audit:

- Dataset size: 142 cases
- Labels: 70 pass, 72 fail
- v7 label accuracy: 142/142
- Debug-state classifications:
  - `sound_debug_reason`: 142
  - `miss`: 0
  - `right_label_weak_reason`: 0

## Current Result

No Opal misses or weak debug reasons were found in this first generated round.

The generated cases cover activation, Revert/RevertSP, manufactured lifecycle, locking ranges, MBR/MBRControl, C_PIN and Authority behavior, AccessControl/ACE mutation, DataRemovalMechanism, byte-table Set forms, storage data locking, reset behavior, GenKey data effects, and Level 0 Discovery.

## Maintenance Rule

Re-run these commands after any generator or solver change:

```bash
python3 new_datasets/opal_gap_cases/generate_opal_gap.py
python3 new_datasets/opal_gap_cases/generate_opal_gap.py --check
python3 new_datasets/opal_gap_cases/validate_debug.py
python3 new_datasets/opal_gap_cases/validate_debug.py --strict
```

Treat any future `miss` or `right_label_weak_reason` classification as a development failure until the generator expectation or v7 rule is corrected.

# Opal Gap Cases

This package generates Opal SSC-focused stateful oracle cases for v7.

## Files

- `generate_opal_gap.py`: deterministic generator for testcases, labels, and manifest.
- `validate_debug.py`: runs v7 with `SOLVER_DEBUG=1` and writes debug audit reports.
- `label.jsonl`: generated labels.
- `manifest.json`: generated case metadata with concepts and spec refs.
- `testcases/*.json`: generated trajectories.
- `debug_audit.json` and `debug_audit.md`: generated debug-reason audit.
- `FIX_RECCOMENDATIONS.md`: current solver/dataset follow-up notes from the latest audit.

## Generate and Validate

```bash
python3 new_datasets/opal_gap_cases/generate_opal_gap.py
python3 new_datasets/opal_gap_cases/generate_opal_gap.py --check
python3 new_datasets/opal_gap_cases/validate_debug.py
```

Use strict mode when fixing the solver:

```bash
python3 new_datasets/opal_gap_cases/validate_debug.py --strict
```

## Coverage

The first round targets these Opal clusters:

- LockingSP activation and SID-to-Admin1 PIN copy.
- Revert and RevertSP reset behavior.
- Manufactured SP lifecycle and StartSession behavior.
- Locking range authorization, geometry, lock flags, and reset side effects.
- MBRControl and MBR shadow read/write behavior.
- C_PIN and Authority defaults, class-vs-instance authorities, and authentication.
- AccessControl and ACE policy mutations.
- DataRemovalMechanism writable and read-only columns.
- Byte-table access shape and granularity-sensitive Set forms.
- Level 0 Discovery feature descriptors.

Every generated manifest row includes at least one `opal/...` reference.

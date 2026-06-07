# Fix Recommendations

Latest `core_gap_cases` audit:

- Dataset size: 189 cases
- Labels: 100 pass, 89 fail
- v7 label accuracy: 189/189
- Debug-state classifications:
  - `sound_debug_reason`: 185
  - `miss`: 0
  - `right_label_weak_reason`: 4

## Priority 1: Strengthen `GetFreeSpace` / `GetFreeRows` Debug Coverage

No current Core gap case is a label miss. Strict debug validation still fails because four table free-space/free-row cases are classified as `right_label_weak_reason` with `coverage=partial`.

Affected cases:

- `core_pass_48_get_free_space_readonly.json`
- `core_fail_48_get_free_space_readonly_rejected.json`
- `core_pass_49_get_free_rows_table.json`
- `core_fail_49_get_free_rows_table_rejected.json`

Recommended fix:

- Treat `GetFreeSpace` as a fully modeled SP method when invoked on an SP object in an open session.
- Treat `GetFreeRows` as a fully modeled table method when invoked on an object table in an open session.
- Keep the existing read-only positive behavior: these methods should not require a read-write session.
- Keep rejecting incompatible targets, such as `GetFreeRows` on an object row or `GetFreeSpace` on a non-SP object.
- Once the debug reason no longer uses `coverage=partial`, rerun:

```bash
python3 new_datasets/core_gap_cases/validate_debug.py --strict
```

## Debug Rule

Accuracy alone is not enough. A case can be labeled correctly while the solver uses the wrong reason.

Use:

```bash
python3 new_datasets/core_gap_cases/validate_debug.py
python3 new_datasets/core_gap_cases/validate_debug.py --strict
```

Treat `right_label_weak_reason` as a failure during development.

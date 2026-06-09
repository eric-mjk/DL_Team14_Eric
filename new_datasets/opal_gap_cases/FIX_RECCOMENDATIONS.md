# Fix Recommendations

Latest `opal_gap_cases` audit:

- Dataset size: 172 cases
- Labels: 85 pass, 87 fail
- v7 label accuracy: 172/172
- Debug-state classifications:
  - `sound_debug_reason`: 172
  - `miss`: 0
  - `right_label_weak_reason`: 0

## Current Result

No Opal misses or weak debug reasons. All 172 cases pass strict audit.

Round 1 (cases 01–72) covers: activation, Revert/RevertSP, manufactured lifecycle, locking ranges, MBR/MBRControl, C_PIN and Authority behavior, AccessControl/ACE mutation, DataRemovalMechanism, byte-table Set forms, storage data locking, reset behavior, GenKey data effects, and Level 0 Discovery.

Round 2 (cases 73–87) adds: lock-flag-without-enable semantics, RevertSP write-session requirement, Activate no-op on already-active SP, User1 TryLimit lockout, Admin1→Admin2 PIN delegation, authority disable mid-trajectory, MBRControl DoneOnReset power-cycle effect, MBR byte Get in read-only session, repeated GenKey counter increment, LockingSP reactivate after Revert, and RevertSP KeepGlobalRangeKey behavior under locked/unlocked Global range.

## Maintenance Rule

Re-run these commands after any generator or solver change:

```bash
python3 new_datasets/opal_gap_cases/generate_opal_gap.py
python3 new_datasets/opal_gap_cases/generate_opal_gap.py --check
python3 new_datasets/opal_gap_cases/validate_debug.py
python3 new_datasets/opal_gap_cases/validate_debug.py --strict
```

Treat any future `miss` or `right_label_weak_reason` classification as a development failure until the generator expectation or v7 rule is corrected.

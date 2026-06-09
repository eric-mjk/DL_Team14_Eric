# Fix Recommendations

Latest `cross_gap_cases` audit:

- Dataset size: 30 cases
- Labels: 15 pass, 15 fail
- v7 label accuracy: 30/30
- Debug-state classifications:
  - `sound_debug_reason`: 30
  - `miss`: 0
  - `right_label_weak_reason`: 0

## Current Result

No misses or weak debug reasons. All 30 cases pass with sound reasoning.

## V7 Fixes Applied During Generation

Two oracle rules were added to address gaps found by these cases:

### SP-scoped Authority Lookup (StartSession)

**File**: `v7/src/oracle.py`, `judge_start_session`

**Added**: Before `credential_matches`, check whether all authority records with SP-discriminating sources (`opal/4.2.1.7` = AdminSP, `opal/4.3.1.8` = LockingSP) match the target SP. If not, return `auth_error`.

**Rationale**: SID_UID (opal/4.2.1.7) is an AdminSP-only authority. Previously, v7 tracked credentials globally and allowed SID to authenticate in LockingSP sessions (wrong).

**Refs**: `opal/4.2.1.7`, `opal/4.3.1.8`, `core/5.2.3.1`

### SP-scoped Authority Lookup (Authenticate)

**File**: `v7/src/oracle.py`, `judge_authenticate`

**Added**: Before `credential_matches`, check whether all sourced authority records match the current session SP. If not, expect `SUCCESS with result=False` (Core/5.3.4.1.14.1 semantics for non-existent authority).

**Rationale**: Authenticate with SID_UID in a LockingSP session must return `result=False`, not `result=True`. Previously, v7 matched the SID credential globally and returned `result=True` (wrong).

**Refs**: `core/5.3.4.1.14.1`, `opal/4.2`, `opal/4.3.1`

## Maintenance Rule

Re-run these commands after any generator or solver change:

```bash
python3 new_datasets/cross_gap_cases/generate_cross_gap.py
python3 new_datasets/cross_gap_cases/generate_cross_gap.py --check
python3 /workspace/Eric/ws/new_datasets/cross_gap_cases/validate_debug.py
python3 /workspace/Eric/ws/new_datasets/cross_gap_cases/validate_debug.py --strict
```

Treat any future `miss` or `right_label_weak_reason` classification as a development failure until the generator expectation or v7 rule is corrected.

# cross_gap_cases — Agent Start

## Current Status

- Dataset size: **30 cases** (15 pass, 15 fail)
- v7 label accuracy: **30/30 (100%)**
- Debug-state classifications:
  - `sound_debug_reason`: 30
  - `miss`: 0
  - `right_label_weak_reason`: 0

## What This Package Tests

Core-Opal **crossover** behaviors: rules that require knowledge of BOTH specs simultaneously.
These are orthogonal to `opal_gap_cases` (Opal-only) and `core_gap_cases` (Core-only).

## Case Coverage (15 pairs, 30 cases)

| # | Concept | Key Rule |
|---|---------|----------|
| 01 | TryLimit cross-SP isolation | SID auth failure in AdminSP must not affect Admin1 TryLimit in LockingSP |
| 02 | SID authority AdminSP-only | StartSession to LockingSP with SID_UID must return NOT_AUTHORIZED |
| 03 | Activate requires SID auth | Activate(LockingSP) from unauthenticated AdminSP session must fail |
| 04 | Revert requires SID auth | Revert(LockingSP) without SID auth must fail |
| 05 | SID PIN change no Admin1 update | Opal copies SID→Admin1 PIN only at initial Activate, never again |
| 06 | TryLimit=0 means unlimited | AUTHORITY_LOCKED_OUT cannot occur when TryLimit=0 |
| 07 | Auth success resets Tries | Single failure with TryLimit=2 cannot cause lockout |
| 08 | GenKey in LockingSP session | GenKey on LockingSP media key requires LockingSP session (not AdminSP) |
| 09 | RevertSP Admin1 KeepGlobal | RevertSP(LockingSP, KeepGlobalRangeKey) valid from authenticated Admin1 |
| 10 | Revert vs RevertSP path | Revert(LockingSP) from LockingSP session is wrong path |
| 11 | Users class not authenticatable | Authenticate targeting Users class must return INVALID_PARAMETER |
| 12 | SID Authenticate in LockingSP → False | Authenticate with SID_UID in LockingSP session must return result=False |
| 13 | DataRemovalMechanism Set needs write | Set DataRemovalMechanism col 1 (writable) vs read-only session |
| 14 | C_PIN.PIN column returns NOT_AUTHORIZED | No read ACE for PIN column; ACE_C_PIN_Admins_Get_All_NOPIN excludes col 3 |
| 15 | Revert returns LockingSP inactive | After Revert(LockingSP), new LockingSP sessions must fail |

## V7 Improvements Made During Generation

Two oracle rules were added to v7/src/oracle.py during this package's creation:

1. **SP-authority scoping for StartSession** (case 02): SID_UID is AdminSP-only per opal/4.2.1.7. `judge_start_session` now checks that all SP-discriminating authority records match the target SP; if not, returns `auth_error`.

2. **SP-authority scoping for Authenticate** (case 12): SID_UID in a LockingSP session has no matching authority record. `judge_authenticate` now returns `result=False` for authorities whose source records don't match the session SP, per core/5.3.4.1.14.1.

## Reproduction Commands

```bash
# Regenerate testcases
python3 new_datasets/cross_gap_cases/generate_cross_gap.py

# Check v7 label accuracy
python3 new_datasets/cross_gap_cases/generate_cross_gap.py --check

# Full debug audit
python3 /workspace/Eric/ws/new_datasets/cross_gap_cases/validate_debug.py

# Strict mode (fails on any miss or weak reason)
python3 /workspace/Eric/ws/new_datasets/cross_gap_cases/validate_debug.py --strict
```

## Next Cases (when expanding)

Potential case 16+:

- `PSID can only invoke Revert` — PSID used for Activate or Set must fail (cross: Core method ACL + Opal PSID definition)
- `Clock/Log only via AdminSP` — Core clock/log objects exist in AdminSP; LockingSP Get must fail
- `Next on Locking table` — Core Next semantics on Opal-defined Locking table; row ordering constraints
- `CreateTable uniqueness` — Core table-creation rule applied to Opal SP's table namespace
- `LockingRange and MBR combined` — Core write-session gate applies to both Locking Set and MBRControl Set in same trajectory
- `RevertSP from wrong SP session` — RevertSP(LockingSP) from AdminSP session uses wrong path; should use Revert
- `GenKey then read stale data` — Core key-generation invalidates Opal locking range data; subsequent Read returns new key data
- `User1 enable + ACE grant` — Admin1 enables User1 (Authority.Enabled) and grants ACE before User1 can access ranges

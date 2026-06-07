# Core Gap Cases

This dataset targets Core-spec behavior that is mostly absent from `dataset/` and thinly covered in `v7/customtest_84`.

Files:

- `testcases/*.json`: trajectories in the same format as `dataset/testcases/tc*.json`
- `label.jsonl`: expected `pass` / `fail` labels
- `manifest.json`: concept and spec refs for each case
- `generate_core_gap.py`: regenerates the dataset and can run the v7 solver check
- `validate_debug.py`: runs v7 with `SOLVER_DEBUG=1` and classifies sound vs weak reasoning
- `debug_audit.json` / `debug_audit.md`: latest debug-state audit output

Run:

```bash
python3 new_datasets/core_gap_cases/generate_core_gap.py
python3 new_datasets/core_gap_cases/generate_core_gap.py --check
python3 new_datasets/core_gap_cases/validate_debug.py
python3 new_datasets/core_gap_cases/validate_debug.py --strict
```

Covered Core concepts:

- Session exchange: malformed `StartSession`, `SyncSession`, `SyncTrustedSession`, `CloseSession`, `EndSession`, nested `StartSession`, trusted-session ordering
- Authority constraints: class authorities, TryLimit lockout/reset, disabled authority `Authenticate`, authority `Operation`, secure-messaging failure status
- Table management: `CreateTable`, `CreateRow`, `DeleteRow`, `Delete`, `Next`, `GetFreeSpace`, `GetFreeRows`, duplicate `Set` columns, Set `Where`/`Values` shape rules for object tables, objects, and byte tables, invalid `Get` cellblocks
- Package and crypto methods: `GetPackage`, `SetPackage`, hash/HMAC/encrypt/decrypt stream sequencing, `Sign`, `Verify`, `XOR`, `Random`, `Stir`, `GenKey` parameter restrictions
- Clock template: direct `ClockTime.Set` rejection, immediate high/low `SetClock*` / `SetLag*` pairing, `ResetClock`, monotonic `IncrementCounter` return values
- Log template: `ClearLog`, `FlushLog`, `CreateLog` followed by methods on the new log table
- Meta-ACL mutation: `RemoveACE` and `DeleteMethod` revocation effects
- Lifecycle and locking-template edges: frozen SP session rejection, invalid re-encryption requests, Global Range re-encryption row creation block
- SP lifecycle/deletion: `IssueSP`, `DeleteSP`, AdminSP `Delete` of an SP with deletion after close
- Admin Template/Core-only gap: `ActiveKey` direct write behavior
- Additional method-shape probes: direct `StartSession` SyncSession return ID validation, malformed `GetACL`, malformed `Next Where`, and missing `CreateTable MinSize`

Current v7 note:

- Current local audit: 189 cases, 189/189 correct, 185 sound debug reasons, 0 misses, 4 weak reasons.
- `validate_debug.py --strict` currently exits non-zero only because `GetFreeSpace` / `GetFreeRows` cases 48-49 are labeled correctly with `coverage=partial`.
- The appended case batch is `core_pass_96...` through `core_fail_99...`; existing case names and labels were preserved.
- `ActiveKey` is a Core/Opal tension: Core `5.7.3.7.2` says the host directly writes `ActiveKey`, while Opal AccessControl rows may still constrain whether a particular Opal authority can perform that `Set`. The pair is kept because this dataset is scoped to Core-gap exploration.

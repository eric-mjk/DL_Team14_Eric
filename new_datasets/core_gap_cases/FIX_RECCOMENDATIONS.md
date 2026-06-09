# Fix Recommendations

Latest `core_gap_cases` audit:

- Dataset size: 219 cases
- Labels: 115 pass, 104 fail
- v7 label accuracy: 219/219
- Debug-state classifications:
  - `sound_debug_reason`: 219
  - `miss`: 0
  - `right_label_weak_reason`: 0

## Current Result

No Core misses or weak debug reasons. All 219 cases pass strict audit.

Round 1 (cases 01–95) covers: Session lifecycle (StartSession, SyncSession, CloseSession, EndSession, Trusted sessions), table operations (CreateTable, CreateRow, DeleteRow, Next, GetFreeRows, GetFreeSpace), crypto streams (Hash, HMAC, Encrypt, Decrypt, XOR, Stir, Random, Sign, Verify), clock methods (GetClock, SetClock, SetLag, ResetClock, IncrementCounter), log methods (CreateLog, AddLog, FlushLog, ClearLog), credential operations (GetPackage, SetPackage), ACL mutation (AddACE, RemoveACE, DeleteMethod), authority authentication (Authenticate, TryLimit, disabled authorities), Set shape rules (Where, Bytes, RowValues, duplicate columns), GenKey parameter validation, and IssueSP/DeleteSP lifecycle.

Round 2 (cases 96–99) adds: StartSession SyncSession ID presence, GetACL missing MethodID, Next malformed Where, CreateTable missing MinSize.

Round 3 (cases 100–114) adds: GetClock in read-only session, IncrementCounter on non-ClockTime target, AddLog to newly created log, AddLog to non-Log target (INVALID_PARAMETER), GetACL with empty InvokingID, HMAC after HMACInit positive path, Next with Count=0 valid, SetPackage authorized success, IssueSP missing required Size, GenKey on C_PIN NOT_AUTHORIZED (no Opal SSC ACE), AddLog missing LogEntryName, Hash after HashInit positive path, ClearLog on newly created log, Decrypt after DecryptInit positive path, Verify with non-matching proof returns Result=False.

Previously weak cases 48-49 (GetFreeSpace/GetFreeRows, `coverage=partial`) are now `sound_debug_reason` with `coverage=implemented` following oracle improvements in v7.

## Maintenance Rule

Re-run these commands after any generator or solver change:

```bash
python3 new_datasets/core_gap_cases/generate_core_gap.py
python3 new_datasets/core_gap_cases/generate_core_gap.py --check
python3 new_datasets/core_gap_cases/validate_debug.py
python3 new_datasets/core_gap_cases/validate_debug.py --strict
```

Treat any future `miss` or `right_label_weak_reason` classification as a development failure until the generator expectation or v7 rule is corrected.

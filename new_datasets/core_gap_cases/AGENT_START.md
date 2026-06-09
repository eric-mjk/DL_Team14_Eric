# AGENT_START: Core Gap Cases

Continue the existing Core dataset package in `new_datasets/core_gap_cases`. The current package already has the generator, validator, manifest, labels, testcases, debug audit, and fix recommendations. Treat generated files as outputs of `generate_core_gap.py`; do not manually edit testcase JSON except for emergency diagnosis.

## Living Handoff Protocol

Treat this file as a recursive handoff document. Any agent working in `new_datasets/core_gap_cases` must update this Markdown as part of its process:

- At start, add a short entry under `Progress Log` with the date/time, task scope, and intended write set.
- After each material discovery, update `Current Status`, `Decisions`, `Blockers`, or `Next Steps` in this file.
- Before finishing, update `Current Status`, append a final `Progress Log` entry, and list exact files changed.
- If implementation choices differ from this brief, record the reason under `Decisions`.
- If validation fails, record exact commands, failure summaries, and the next concrete fix under `Blockers` or `Next Steps`.
- Keep this file concise: preserve the durable instructions below and add only high-signal operational notes.

## Current Status

- 2026-06-06 17:52 UTC: Core gap dataset at 189 cases: 100 pass, 89 fail. Debug audit 185/189 sound (4 weak for GetFreeSpace/GetFreeRows).
- 2026-06-07: Round 3 expansion added 30 cases (pairs 100-114). Now 219 cases: 115 pass, 104 fail. v7 label check 219/219. Debug strict audit 219/219 sound_debug_reason (0 miss, 0 weak). Previously weak cases 48-49 now also sound (coverage=implemented). New topics: GetClock readonly, IncrementCounter wrong target, AddLog to new log / non-Log target, GetACL bad InvokingID, HMAC+Hash+Decrypt positive paths, Next Count=0, SetPackage authorized, IssueSP missing Size, GenKey C_PIN NOT_AUTHORIZED, AddLog missing LogEntryName, ClearLog new log, Verify wrong proof Result=False.

## Progress Log

- 2026-06-06: Initial continuation handoff created with baseline counts, remaining topic areas, validation workflow, and acceptance criteria.
- 2026-06-06 17:43 UTC: Core worker started. Intended write set: `AGENT_START.md`, `generate_core_gap.py`, generated `testcases/*.json`, `label.jsonl`, `manifest.json`, `README.md`, `debug_audit.json`, `debug_audit.md`, and `FIX_RECCOMENDATIONS.md` if validation findings shift.
- 2026-06-06 17:44 UTC: Baseline workflow rerun after fixing helper import path. Generation and `--check` pass; non-strict debug audit is 181/181 with 4 weak reasons; strict mode fails on weak reasons as designed.
- 2026-06-06 17:45 UTC: Chose four paired append-only cases (`core_pass_96` through `core_fail_99`) from representable Core method parameter/response-shape rules.
- 2026-06-06 17:52 UTC: Completed Core worker round 2. Final counts: 189 cases, 100 pass, 89 fail, 189/189 label accuracy, 185 sound debug reasons, 0 misses, 4 weak reasons.
- 2026-06-07: Round 3 — 30 new cases (pairs 100-114). Files changed: `AGENT_START.md`, `generate_core_gap.py`, `FIX_RECCOMENDATIONS.md`, `label.jsonl`, `manifest.json`, `debug_audit.json`, `debug_audit.md`, and 30 new `testcases/*.json`. Final: 219/219 label accuracy, 219/219 sound_debug_reason. 3 generator fixes required after initial --check run (cases 103/109/114 status or concept adjustments).

## Decisions

- Preserve existing Core case names and labels unless a documented mistake is found.
- Use `new_datasets/customtest_84/generate_synthetic.py` for trajectory helper functions because `v7/customtest_84/generate_synthetic.py` is not present in this checkout.
- Updated `generate_core_gap.py` to import helpers from `new_datasets/customtest_84` so the documented workflow can run in this checkout.
- New cases will stay in method-shape/session-response territory because the solver has explicit implemented rules there and the behavior is directly justified by Core sections 5.2.3.2, 5.3.3.13, 5.3.3.8, and 5.3.3.2.

## Blockers

- Strict debug validation is blocked by existing weak debug reasons for `core_pass_48_get_free_space_readonly.json`, `core_fail_48_get_free_space_readonly_rejected.json`, `core_pass_49_get_free_rows_table.json`, and `core_fail_49_get_free_rows_table_rejected.json`. No solver edits are allowed in this worker task.

## Next Steps

- For solver work, strengthen `GetFreeSpace` / `GetFreeRows` debug coverage so cases 48-49 no longer emit `coverage=partial`.
- After solver changes, rerun `python3 new_datasets/core_gap_cases/validate_debug.py --strict`.
- For dataset continuation, append future Core cases after `core_pass_99...` / `core_fail_99...`.

## Current Baseline

Known baseline:

- 189 cases
- 100 pass, 89 fail
- v7 local accuracy: 189/189 after this run
- debug classifications:
  - `sound_debug_reason`: 185
  - `miss`: 0
  - `right_label_weak_reason`: 4

Core package files to use:

- `new_datasets/core_gap_cases/generate_core_gap.py`
- `new_datasets/core_gap_cases/validate_debug.py`
- `new_datasets/core_gap_cases/README.md`
- `new_datasets/core_gap_cases/manifest.json`
- `new_datasets/core_gap_cases/label.jsonl`
- `new_datasets/core_gap_cases/debug_audit.json`
- `new_datasets/core_gap_cases/debug_audit.md`
- `new_datasets/core_gap_cases/FIX_RECCOMENDATIONS.md`

## Files To Read First

Before adding or changing cases, read:

- `project_specification.md`
- `new_datasets/core_gap_cases/generate_core_gap.py`
- `new_datasets/core_gap_cases/validate_debug.py`
- `new_datasets/core_gap_cases/FIX_RECCOMENDATIONS.md`
- `new_datasets/customtest_84/generate_synthetic.py`
- `v7/src/normalizer.py`
- `v7/src/state.py`
- `v7/src/oracle.py`
- `v7/src/spec_docs.py`
- relevant `documents/core/*.txt` sections for each new rule

Note: older notes may mention `v7/customtest_84/generate_synthetic.py`; that path is not present in this checkout. The equivalent helper file is `new_datasets/customtest_84/generate_synthetic.py`.

## Continuation Rules

When adding more Core cases:

- preserve existing case names and labels unless a documented mistake is found
- append new case numbers after `core_pass_95...`
- keep paired pass/fail probes
- use the existing `Scenario` dataclass and `scen(...)` helper pattern
- update `README.md`, `manifest.json`, `label.jsonl`, and debug audit through the generator
- keep deterministic JSON output with stable filenames
- do not manually edit generated testcase JSON except for emergency diagnosis

Every new case must have:

- a Core spec reference
- a label of exactly `pass` or `fail`
- a matching `label.jsonl` row
- a matching `manifest.json` row
- contiguous `index` values starting at 1
- a concept string explaining the intended state-machine rule

Each new stateful rule should have at least one positive control and one negative/fail variant. The debug reason must match the intended state-machine rule, not merely predict the right label.

## High-Value Remaining Core Topics

Add new cases from these areas when they can be represented in the project JSON trajectory format:

- deeper `Properties` and HostProperties communication minimums
- session timeout and transaction timeout behavior if representable
- `CloseSession` vs `EndSession` vs EOS edge cases
- transaction tokens: start/end transaction, nested transaction failures
- invalid/unexpected token behavior only if the JSON format can represent it
- `GetACL`, `AddACE`, `RemoveACE`, `DeleteMethod` malformed parameter variants
- richer `IssueSP` cases after implementing solver support
- `CreateTable` uniqueness, insufficient space, insufficient rows
- `Get`/`Set` return shape and cellblock edge cases
- `Next` ordering, missing `Count`, and invalid `Where`
- `DeleteSP` and AdminSP SP deletion across session close
- crypto stream controls for all hash/HMAC/encrypt/decrypt/sign/verify combinations
- Clock `GetClock`, `ResetClock`, monotonic counter, timer mode, and trust-mode edge cases
- Log table deletion, high-security logs, `CreateLog` invalid parameter combinations

## Current Solver Fix Priorities

Keep `FIX_RECCOMENDATIONS.md` synchronized whenever misses shift. Current priority areas are:

- implement `IssueSP`
- fix Core `Authenticate` failure status semantics
- enforce prohibited table row operations
- enforce `GenKey` parameter restrictions
- implement SP deletion state
- track trusted-session pending state
- validate byte-table `Set` `Where` shape
- track Clock monotonic returns

## Validation Workflow

Run after every generator edit:

```bash
python3 new_datasets/core_gap_cases/generate_core_gap.py
python3 new_datasets/core_gap_cases/generate_core_gap.py --check
python3 new_datasets/core_gap_cases/validate_debug.py
python3 new_datasets/core_gap_cases/validate_debug.py --strict
```

Use strict mode during solver fixes. Treat `right_label_weak_reason` as a bug, not a success.

Also run a structural check that verifies:

- every `label.jsonl` filename exists
- every `manifest.json` filename exists
- every testcase has contiguous `index` values starting at 1
- labels are only `pass` or `fail`
- testcase count equals label count equals manifest count

## Acceptance Criteria For Future Rounds

- every new case has a Core spec ref
- each new stateful rule has at least one positive control and one negative/fail variant
- debug reason matches the intended state-machine rule
- `FIX_RECCOMENDATIONS.md` is updated whenever misses shift
- structural validation passes after every generator edit

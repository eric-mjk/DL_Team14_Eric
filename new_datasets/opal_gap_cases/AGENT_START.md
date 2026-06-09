# AGENT_START: Opal Gap Cases

Build a new Opal-focused dataset package in this folder. Mirror the structure and workflow of `new_datasets/core_gap_cases`, but use Opal SSC behavior as the source of truth.

## Living Handoff Protocol

Treat this file as a recursive handoff document. Any agent working in `new_datasets/opal_gap_cases` must update this Markdown as part of its process:

- At start, add a short entry under `Progress Log` with the date/time, task scope, and intended write set.
- After each material discovery, update `Current Status`, `Decisions`, `Blockers`, or `Next Steps` in this file.
- Before finishing, update `Current Status`, append a final `Progress Log` entry, and list exact files changed.
- If implementation choices differ from this brief, record the reason under `Decisions`.
- If validation fails, record exact commands, failure summaries, and the next concrete fix under `Blockers` or `Next Steps`.
- Keep this file concise: preserve the durable instructions below and add only high-signal operational notes.

## Current Status

- 2026-06-06 17:54 UTC: First Opal dataset package implemented and validated. Generated 142 cases: 70 pass, 72 fail, 74 distinct concepts. v7 label check passed 142/142. Debug strict audit passed with 142 `sound_debug_reason`, 0 `miss`, and 0 `right_label_weak_reason`.
- 2026-06-07: Round 2 expansion added 30 cases (cases 73–87, 15 pairs). Now 172 cases: 85 pass, 87 fail. v7 label check 172/172. Debug strict audit 172/172 sound_debug_reason. New topics: lock flags without enable, RevertSP session requirements, Activate no-op, TryLimit lockout, Admin1→Admin2 PIN, authority disable, DoneOnReset, MBR byte Get in read-only session, repeated GenKey, LockingSP reactivate after Revert, RevertSP KeepGlobalRangeKey rules.

## Progress Log

- 2026-06-06: Initial handoff created with target package, scenario clusters, validation workflow, and acceptance criteria.
- 2026-06-06 17:43 UTC: Started Opal worker run. Scope is end-to-end first package implementation, generation, debug audit, structural check, and recursive handoff updates. No v7 solver edits planned.
- 2026-06-06 17:54 UTC: Finished first Opal package. Files changed: `AGENT_START.md`, `generate_opal_gap.py`, `validate_debug.py`, `README.md`, `FIX_RECCOMENDATIONS.md`, `label.jsonl`, `manifest.json`, `debug_audit.json`, `debug_audit.md`, and 142 generated testcase JSON files under `testcases/` matching `manifest.json`.

## Decisions

- Use `new_datasets/core_gap_cases/generate_core_gap.py` as the primary implementation template.
- Use `new_datasets/customtest_84/generate_synthetic.py` for trajectory helper functions because `v7/customtest_84/generate_synthetic.py` is not present in this checkout.
- Implemented the generator as a data-driven list of paired scenario builders to keep pass/fail variants stable and deterministic.
- Included six singleton discovery cases where the compliance signal is the descriptor payload rather than a method-status pair.
- Did not edit v7 solver code; all cases were shaped to documented Opal behavior already representable in the project trajectory format.

## Blockers

- None. Generation, v7 label check, debug strict audit, and structural validation all passed.

## Next Steps

- Future rounds can expand Opal coverage beyond the current modeled surfaces, especially deeper `DoneOnReset` return-value checking, additional byte-table granularity rows if table metadata mutation is modeled, and interrupted Revert/RevertSP only if the command-response JSON shape can represent those states.
- Re-run the documented validation workflow after any generator or solver change.

## Target Package

Create and maintain these files:

- `new_datasets/opal_gap_cases/generate_opal_gap.py`
- `new_datasets/opal_gap_cases/validate_debug.py`
- `new_datasets/opal_gap_cases/README.md`
- `new_datasets/opal_gap_cases/FIX_RECCOMENDATIONS.md`
- `new_datasets/opal_gap_cases/label.jsonl`
- `new_datasets/opal_gap_cases/manifest.json`
- `new_datasets/opal_gap_cases/debug_audit.json`
- `new_datasets/opal_gap_cases/debug_audit.md`
- `new_datasets/opal_gap_cases/testcases/*.json`

Use `new_datasets/core_gap_cases/generate_core_gap.py` as the implementation template. Reuse helpers from `new_datasets/customtest_84/generate_synthetic.py`, especially:

- `make_step`
- `start_session`
- `end_session`
- `setup_tper`
- `activate_locking_sp`
- `setup_user`
- `authenticate_step`
- `set_locking`
- `set_authority`

Note: older notes may mention `v7/customtest_84/generate_synthetic.py`; that path is not present in this checkout. The equivalent helper file is `new_datasets/customtest_84/generate_synthetic.py`.

## Files To Read First

Before implementing the generator or validator, read:

- `project_specification.md`
- `new_datasets/core_gap_cases/generate_core_gap.py`
- `new_datasets/core_gap_cases/validate_debug.py`
- `new_datasets/core_gap_cases/FIX_RECCOMENDATIONS.md`
- `new_datasets/customtest_84/generate_synthetic.py`
- `v7/src/normalizer.py`
- `v7/src/state.py`
- `v7/src/oracle.py`
- `v7/src/spec_docs.py`
- `documents/opal/section_title.json`
- `documents/opal/4.1*.txt`
- `documents/opal/4.2*.txt`
- `documents/opal/4.3*.txt`
- `documents/opal/5.1*.txt`
- `documents/opal/5.2*.txt`
- `documents/opal/5.3*.txt`
- `documents/opal/3.1.1*.txt`

## Generator Requirements

`generate_opal_gap.py` must include:

- a `Scenario` dataclass with `name`, `label`, `steps`, `concept`, and `refs`
- a `scen(...)` helper that deep-copies steps and renumbers `index` values from 1
- `write_dataset()`
- `check_with_v7()`
- CLI flags `--check` and `--check-only`
- deterministic JSON output with stable filenames
- pass/fail paired cases for every important rule where possible

Use the naming convention:

- `opal_pass_XX_short_concept.json`
- `opal_fail_XX_short_concept.json`
- paired pass/fail variants should use the same number
- start at `opal_pass_01...`
- keep concepts concise and refs precise, such as `opal/5.1.1.2`

Every generated case must have:

- a `label` of exactly `pass` or `fail`
- a matching row in `label.jsonl`
- a matching row in `manifest.json`
- contiguous `index` values starting at 1
- at least one `documents/opal` spec reference in `manifest.json`

Do not include a case unless its expected behavior can be justified from Opal/Core docs or existing project trajectory conventions.

## Validator Requirements

`validate_debug.py` must mirror `new_datasets/core_gap_cases/validate_debug.py`:

- run v7 with `SOLVER_DEBUG=1`
- write `debug_audit.json`
- write `debug_audit.md`
- classify cases as `sound_debug_reason`, `miss`, or `right_label_weak_reason`

Treat these weak debug markers as development failures:

- `coverage=partial`
- `not a supported modeled method`
- `success_or_auth_error`
- `not contradicted by state`
- `fallback`

Use strict mode during solver fixes. A correct label with a weak reason is still a bug.

## High-Priority Scenario Clusters

### LockingSP Activation

- `Activate` succeeds only from an authenticated SID AdminSP write session.
- `Activate` copies SID PIN to LockingSP Admin1 only on the first transition out of Manufactured-Inactive.
- `StartSession(LockingSP)` fails before activation and succeeds after activation.
- Repeated `Activate` does not re-copy SID after Admin1 has already been initialized.

Primary refs:

- `opal/4.1`
- `opal/4.2`
- `opal/4.3`
- `opal/5.1.1`
- `opal/5.1.1.1`
- `opal/5.1.1.2`
- `opal/5.2.2.2.1`
- `opal/5.2.2.3.1`
- `opal/5.2.2.3.2`

### Revert and RevertSP

- `Revert` on LockingSP returns LockingSP to Manufactured-Inactive.
- After `Revert`, LockingSP sessions fail until reactivation.
- `Revert` resets LockingSP Admin/User C_PIN values to factory defaults.
- `RevertSP` on LockingSP resets LockingSP state but respects `KeepGlobalRangeKey`.
- `KeepGlobalRangeKey` is meaningful only for LockingSP `RevertSP`; reject or ignore malformed use elsewhere according to docs.
- Add interrupted `Revert` / `RevertSP` cases only if the docs expose representable status/state in trajectory JSON.

Primary refs:

- `opal/5.1.2`
- `opal/5.1.2.1`
- `opal/5.1.2.2`
- `opal/5.1.2.2.1`
- `opal/5.1.2.3`
- `opal/5.1.3`
- `opal/5.1.3.1`
- `opal/5.1.3.2`
- `opal/5.1.3.3`
- `opal/5.1.3.4`

### Manufactured Lifecycle

- Manufactured-Inactive permits AdminSP session but not LockingSP session.
- Manufactured allows LockingSP sessions.
- Factory reset returns Manufactured SPs to original factory state.
- Add lifecycle behavior after `TPER_RESET` or stack reset only if representable by the existing method log shape.

Primary refs:

- `opal/5.2.1`
- `opal/5.2.1.1`
- `opal/5.2.1.2`
- `opal/5.2.2`
- `opal/5.2.2.1`
- `opal/5.2.2.2`
- `opal/5.2.2.2.1`
- `opal/5.2.2.2.2`
- `opal/5.2.2.3`
- `opal/5.2.2.3.1`
- `opal/5.2.2.3.2`

### Locking Ranges

- Admin can set `RangeStart`, `RangeLength`, `ReadLockEnabled`, `WriteLockEnabled`, `ReadLocked`, and `WriteLocked`.
- Unauthenticated users cannot mutate locking range columns.
- Read/write data access should depend on `ReadLockEnabled`, `WriteLockEnabled`, `ReadLocked`, and `WriteLocked` when the trajectory format has corresponding method representations.
- Include zero-length range semantics.
- Include changing `RangeStart` / `RangeLength` restrictions.
- Include `LockOnReset` restrictions and reset side effects.

Primary refs:

- `opal/4.3.5.1`
- `opal/4.3.5.2`
- `opal/4.3.5.2.1`
- `opal/4.3.5.2.1.1`
- `opal/4.3.5.2.1.2`
- `opal/4.3.5.2.2`
- `opal/4.3.7`

### MBR and MBRControl

- `MBRControl.Enable`, `MBRControl.Done`, and `MBRControl.DoneOnReset` are Admin-controlled.
- `DoneOnReset` causes `Done` reset on power-cycle style reset.
- MBR byte-table read/write authorization differs from MBRControl object access.
- MBR byte-table access must respect byte-table shape and granularity from Opal `5.3`.

Primary refs:

- `opal/4.3.5.3`
- `opal/4.3.5.3.1`
- `opal/4.3.5.4`
- `opal/5.3`
- `opal/5.3.1.1.2`
- `opal/5.3.1.2.2`

### C_PIN and Authorities

- LockingSP Admin2-Admin4 and User1-User8 default empty PIN behavior.
- User authority enable/disable affects `StartSession` and `Authenticate`.
- User1 is not necessarily equivalent to the Users class; test class-vs-instance authority behavior.
- Admin1 can enable users and set their PINs; users can authenticate only after enabled if required by table policy.

Primary refs:

- `opal/4.2.1.7`
- `opal/4.2.1.8`
- `opal/4.3.1.8`
- `opal/4.3.1.9`
- `core/5.3.4.1.2`
- `core/5.3.4.1.14`

### AccessControl and ACE Policy

- AdminSP and LockingSP preconfigured ACE rows differ.
- `ACE_Anybody` allows CommonName-style reads but not protected columns.
- `AddACE` and `RemoveACE` controls should be tested with positive control, mutation, then negative control.
- CommonName write permissions for Authority/Locking objects should be tested because v7 has explicit comments around these Opal ACE rows.

Primary refs:

- `opal/4.2.1.5`
- `opal/4.2.1.6`
- `opal/4.3.1.6`
- `opal/4.3.1.7`
- `core/5.3.3.11`
- `core/5.3.3.14`
- `core/5.3.3.15`
- `core/5.3.4.3.1`

### DataRemovalMechanism

- `DataRemovalMechanism.ActiveDataRemovalMechanism` is writable.
- `DataRemovalMechanism.UID` is not writable.
- Invalid data-removal mechanism values are rejected.
- Data-removal state should interact with `Revert` only if representable and supported by docs.

Primary refs:

- `opal/3.1.1.6`
- `opal/3.1.1.6.1`
- `opal/3.1.1.6.2`
- `opal/3.1.1.6.3`
- `opal/3.1.1.6.4`
- `opal/4.2.6.1`
- `opal/4.2.6.1.1`
- `opal/4.2.6.1.2`
- `opal/4.2.7.1`

### Geometry and Byte-Table Granularity

- Object-table `MandatoryWriteGranularity` and `RecommendedAccessGranularity` cases.
- Byte-table granularity cases for MBR/DataStore where possible.
- Unaligned byte-table writes should fail if Opal docs require alignment.

Primary refs:

- `opal/3.1.1.4`
- `opal/3.1.1.4.1`
- `opal/3.1.1.4.2`
- `opal/3.1.1.4.3`
- `opal/3.1.1.4.4`
- `opal/3.1.1.4.5`
- `opal/4.3.8.1`
- `opal/5.3`
- `opal/5.3.1`
- `opal/5.3.1.1`
- `opal/5.3.1.1.1`
- `opal/5.3.1.1.2`
- `opal/5.3.1.2`
- `opal/5.3.1.2.1`
- `opal/5.3.1.2.2`

### Discovery and Reset

- Generate only cases that can be expressed in existing command-response JSON.
- Avoid raw IF-SEND/IF-RECV binary packet cases unless the project format already supports them.
- Use `TPER_RESET`, stack reset, and discovery feature behavior only where an existing command or method representation is available.

Primary refs:

- `opal/3.1.1`
- `opal/3.1.1.1`
- `opal/3.1.1.2`
- `opal/3.1.1.3`
- `opal/3.1.1.3.1`
- `opal/3.1.1.4`
- `opal/3.2.2`
- `opal/3.2.3`
- `opal/3.3.5`
- `opal/3.3.5.1`
- `opal/3.3.5.2`

## Validation Workflow

Run:

```bash
python3 new_datasets/opal_gap_cases/generate_opal_gap.py
python3 new_datasets/opal_gap_cases/generate_opal_gap.py --check
python3 new_datasets/opal_gap_cases/validate_debug.py
```

After generation, run a structural check that verifies:

- every `label.jsonl` filename exists
- every `manifest.json` filename exists
- every testcase has contiguous `index` values starting at 1
- labels are only `pass` or `fail`
- testcase count equals label count equals manifest count

## First-Round Acceptance Criteria

- At least 80 Opal-focused cases.
- Every case has a spec ref from `documents/opal`.
- At least 10 distinct Opal concept clusters.
- `debug_audit.json` and `debug_audit.md` are generated.
- Misses and weak reasons are summarized in `FIX_RECCOMENDATIONS.md`.
- No case is included unless the expected behavior is justified from Opal/Core docs or existing project trajectory conventions.

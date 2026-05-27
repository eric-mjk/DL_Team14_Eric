# CLAUDE.md
Session brief for `/workspace/Eric/ws` and the DL2026 SSD protocol oracle project.

## Goal
Build a verifier for SSD / TCG Storage command-response trajectories.
Input is a full testcase trajectory; only the final response is judged.
Output must be exactly lowercase `"pass"` or `"fail"`.
A verdict judges protocol compliance, not whether the SSD returned `SUCCESS`.

## Active Version
Work is currently on `v6/`.
`v6/src` is derived from `v5_usereference/src` and is the active edit target.
Older folders (`skeleton/`, `v1_0520/`, `v4_ter_/`, `v5_usereference/`) are references only unless asked.
The public dataset is in `dataset/testcases/`; labels are in `dataset/label.jsonl`.
Parsed TCG Core / Opal documents live under root `documents/`.

## Submission Contract
The grader expects `src/`, `setup.sh`, `pyproject.toml`, `uv.lock`, and optional `artifacts/`.
`src/solver.py` exposes `Solver.predict(dataset)` returning `{id: "pass"|"fail"}`.
`Solver.predict_one(steps)` handles one trajectory.
Do not rely on network during evaluation.
Anchor artifacts with `Path(__file__).resolve().parents[1] / "artifacts"`.
Do not commit `.venv/`, `__pycache__/`, `predictions.jsonl`, or `scores.json`.

## v6 Layout
`v6/src/solver.py`: grader-facing entrypoint and debug summary.
`v6/src/normalizer.py`: raw JSON record to canonical event dict.
`v6/src/state.py`: replays prefix events and mutates protocol state.
`v6/src/oracle.py`: judges the final event against tracked state.
`v6/src/spec_docs.py`: spec metadata, column maps, refs, coverage helpers.
`v6/src/spec_tables.py`: older/static Opal table and policy constants.
`v6/artifacts/`: `spec_index.json` and `spec_coverage_report.json`.
`v6/customtest_57/`: synthetic regression suite and generator.
`v6/notes/`: audit notes, solver explanation, coverage notes, changelogs.

## Runtime Flow
`Solver.predict_one` calls `normalize_trajectory(steps)`.
It tracks state over `events[:-1]` with `track_state`.
It judges `events[-1]` with `judge_final`.
The final `RuleResult.verdict` is returned directly.
`SOLVER_DEBUG=1` prints event, expected/actual status, refs, state, and reason.

## State Model
State includes session, authenticated authorities, credentials, SP lifecycle, and LockingSP activity.
It also tracks locking ranges, MBRControl, ACE/AccessControl rows, authority rows, TryLimit failures, key generations, writes, and reads.
Only successful prefix operations mutate state.
Failed StartSession does not open a session.
Failed Set does not update tables or credentials.
Failed GenKey does not change key generation.
Failed Revert / RevertSP does not reset state.

## Oracle Surface
`oracle.py` handles StartSession, Authenticate, Get, Set, Activate, Revert, RevertSP, GenKey, Random, crypto, clock, log, table methods, Next, Read, and Write.
It compares status classes rather than raw strings where appropriate.
Data `Read` and `Write` use lock state and key-generation history.
Important hidden-test surfaces include C_PIN PIN reads, Locking range access, MBRControl access, Authority state, and ACE policy evaluation.
Spec refs are attached through `spec_refs_for(...)` and `RULE_REFERENCES`.

## Checks
Compile Python with `python3 -m py_compile v6/src/*.py`.
Run public evaluation with `python3 v6/evaluate.py`.
Run synthetic checks with `cd v6/customtest_57 && python3 generate_synthetic.py --check-only`.
Current baseline before v6 edits: public `score=100.00`, synthetic `57/57`.

## Hygiene
The worktree may contain unrelated user changes; do not revert them.
At v6 startup, `v6/` was untracked and `v5_usereference/artifacts/documents` showed as deleted.
Leave unrelated changes alone.
Use `rg` for search and `git diff` before handing back substantial edits.

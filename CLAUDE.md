# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a term project (SNU Deep Learning M2177.0043, due June 8 2026) to build a **stateful test oracle** for SSD security protocol compliance. Given a trajectory of SSD command-response records, the system must predict whether the **final response** is `"pass"` or `"fail"` (lowercase required). The verdict judges protocol compliance, not whether the SSD returned SUCCESS or an error.

## Repository Layout

```
/workspace/Eric/ws/
├── project_specification.md   # Full task spec
├── idea.md                    # Design document (Korean) — read this first
├── dataset/
│   ├── label.jsonl            # Ground-truth labels for public 20 cases
│   └── testcases/tc1.json … tc20.json
├── skeleton/                  # Original template (reference only)
└── 0520/                      # Active working experiment (the one to modify)
    ├── src/
    │   ├── solver.py          # Entry point: Solver.predict(dataset) / predict_one(steps)
    │   ├── normalizer.py      # JSON -> canonical event dicts
    │   ├── state.py           # Stateful tracker across trajectory prefix
    │   └── oracle.py          # Deterministic rule oracle -> RuleResult(verdict, confidence, reason)
    ├── artifacts/documents/   # Parsed TCG spec texts (core/, opal/)
    ├── evaluate.py            # Local evaluator: writes predictions.jsonl + scores.json
    ├── setup.sh               # Just runs: uv sync
    ├── pyproject.toml         # Python 3.12.3, vllm, torch, transformers, accelerate
    └── scores.json / predictions.jsonl  # Output from last local run
```

## Common Commands

All commands run from inside the project directory (`0520/` or whichever experiment dir):

```bash
# Install dependencies (Phase 1 equivalent)
cd /workspace/Eric/ws/0520
uv sync

# Run local evaluation against public dataset
python evaluate.py
# or with custom dataset path:
DATASET_DIR=/workspace/dataset/testcases LABEL_PATH=/workspace/dataset/label.jsonl python evaluate.py

# Enable debug output per test case
SOLVER_DEBUG=1 python evaluate.py

# Use a different model
MODEL_NAME=Qwen/Qwen3.5-0.8B python evaluate.py

# Submit current directory
submit
submit --job-name <name>
submit --dir /workspace/Eric/ws/0520 --job-name v2
submit --list
```

## Architecture

The pipeline is: `JSON steps → normalize → track state → oracle → "pass"/"fail"`

### `normalizer.py`
Converts raw JSON records into canonical event dicts. Key output fields:
- `kind`: `"method"` | `"read"` | `"write"` | `"command"`
- `method`: `"StartSession"`, `"EndSession"`, `"Get"`, `"Set"`, `"Activate"`, `"GenKey"`, etc.
- `object`: symbolic name (`"C_PIN_SID"`, `"LockingSP"`, `"Range1_Key"`, etc.)
- `sp`: `"AdminSP"` | `"LockingSP"`
- `authority`: `"SID"` | `"Admin1"` | etc.
- `status`: normalized lowercase: `"success"`, `"not_authorized"`, `"invalid_parameter"`, `"fail"`
- `challenge`: the HostChallenge value from StartSession (raw bytes, used for credential comparison)

UID mapping is centralized here (e.g., `C_PIN_SID_UID = "0000000B00000001"`).

### `state.py`
Tracks mutable protocol state using only the trajectory prefix (all events except the last). **Only successful operations mutate state.**

Key state fields:
- `session`: `{open, sp, authority, write}`
- `credentials`: `{SID, MSID, Admin1}` — credential values (raw bytes from HostChallenge / C_PIN column 3)
- `locking_sp_active`: bool
- `locking_ranges`: per-range config dict
- `key_generations`: `{"Range1_Key": count}` — incremented on successful GenKey
- `writes`: `{lba_tuple: {pattern, key_generations_snapshot}}` — LBA write memory
- `reads`: list of read events

### `oracle.py`
Takes `(state, final_event)` and returns `RuleResult(verdict, confidence, reason)`.

Decision logic (checked in order):
1. `read` kind → `judge_read`: compares key generation snapshot at write time vs. now
2. `write` kind → always `pass`
3. `method` kind → dispatched by `method` name: Properties, StartSession, Get, Set, Activate, GenKey, EndSession
4. fallback → accepts success-like response (confidence 0.50)

The `Solver.predict_one` in `solver.py` currently returns `result.verdict` directly (no LLM fallback yet). The `idea.md` describes adding an LLM fallback for `confidence < 0.90` cases.

## Critical Constraints

- **Output format**: must be exactly `"pass"` or `"fail"` (lowercase). The grader rejects `"PASS"`, `"True"`, etc.
- **No network during evaluation phase**: all weights or resources must be in `artifacts/` or downloaded in `setup.sh`.
- **Archive limit**: 12 GB compressed. Use shared HuggingFace cache (`HF_HOME=/workspace/cache/hf_cache`) for base models; put only fine-tuned adapters in `artifacts/`.
- **Evaluation time limit**: 3 hours.
- **Path anchoring**: use `Path(__file__).resolve().parents[1] / "artifacts"` not absolute paths (grading container uses `/workspace/submission/`).
- **Failed commands do not mutate state**: a failed StartSession does not open a session; a failed Set does not update credentials.

## Public Dataset Taxonomy (tc1–tc20)

tc1–tc10 are PASS, tc11–tc20 are FAIL, and many are intentional pairs:

| Pair | Concept tested |
|---|---|
| tc1/tc11 | Properties method response status |
| tc2/tc12 | C_PIN Get authorization |
| tc3/tc13 | SID credential update via C_PIN Set |
| tc4/tc14 | Repeated credential updates (latest PIN wins) |
| tc5/tc15 | LockingSP activation with correct object UID |
| tc6/tc16 | Authority object Set required values |
| tc7/tc17 | Authenticated StartSession after authority update |
| tc8/tc18 | Locking object Get |
| tc9/tc19 | MBRControl Get |
| tc10/tc20 | GenKey + data Read (old plaintext readable after GenKey = FAIL) |

tc10/tc20 is the most unusual: the final command is a non-TCG `Read`, but the verdict depends on whether a prior `GenKey` succeeded.

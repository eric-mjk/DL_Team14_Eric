# Running Core and Opal Dataset Subagents

Use this runbook when you want two parallel workers: one for Opal gap-case generation and one for Core gap-case continuation.

## Preconditions

- Work from the repo root: `/workspace/Eric/ws`.
- Read both handoff files before spawning workers:
  - `new_datasets/opal_gap_cases/AGENT_START.md`
  - `new_datasets/core_gap_cases/AGENT_START.md`
- Keep write scopes disjoint:
  - Opal worker writes only under `new_datasets/opal_gap_cases`.
  - Core worker writes only under `new_datasets/core_gap_cases`.
- Neither worker should edit v7 solver code unless the user explicitly changes the task.

## Subagent Prompts

Spawn both workers in parallel.

### Opal Worker

```text
You are the Opal gap-cases worker. Work only in /workspace/Eric/ws/new_datasets/opal_gap_cases unless you need read-only context elsewhere. Read /workspace/Eric/ws/new_datasets/opal_gap_cases/AGENT_START.md first and follow it as your task contract. Update AGENT_START.md recursively as you work: add a start Progress Log entry, update Current Status/Decisions/Blockers/Next Steps after material discoveries, and append a final entry listing exact files changed.

Goal: implement or continue the Opal gap-cases package end-to-end. Maintain generate_opal_gap.py, validate_debug.py, README.md, FIX_RECCOMENDATIONS.md, generated label.jsonl, manifest.json, debug_audit.json/md, and testcases. Use new_datasets/core_gap_cases as the template and new_datasets/customtest_84/generate_synthetic.py helpers. Run the documented validation workflow and a structural check. Final response must summarize files changed, commands run, counts, validation results, misses/weak reasons, and blockers.
```

### Core Worker

```text
You are the Core gap-cases worker. Work only in /workspace/Eric/ws/new_datasets/core_gap_cases unless you need read-only context elsewhere. Read /workspace/Eric/ws/new_datasets/core_gap_cases/AGENT_START.md first and follow it as your task contract. Update AGENT_START.md recursively as you work: add a start Progress Log entry, update Current Status/Decisions/Blockers/Next Steps after material discoveries, and append a final entry listing exact files changed.

Goal: run and continue the Core gap-cases workflow. Establish the current baseline, then append a coherent batch of paired pass/fail Core cases only when representable and documented. Preserve existing names and append after the latest case number. Regenerate outputs only through generate_core_gap.py, run --check, run validate_debug.py and validate_debug.py --strict, and update README.md/FIX_RECCOMENDATIONS.md/AGENT_START.md accordingly. Final response must summarize files changed, commands run, counts, validation results, misses/weak reasons, and blockers.
```

## Supervisor Duties

While workers run:

- Do not duplicate their assigned implementation work.
- Review each worker's final report against files on disk.
- Re-run structural checks for both packages.
- Re-run `--check-only` and debug validation where appropriate.
- Confirm both `AGENT_START.md` files were updated with progress, decisions, blockers, and next steps.
- Close subagents after their work is reviewed.

## Validation Commands

Opal:

```bash
python3 new_datasets/opal_gap_cases/generate_opal_gap.py --check-only
python3 new_datasets/opal_gap_cases/validate_debug.py --strict
```

Core:

```bash
python3 new_datasets/core_gap_cases/generate_core_gap.py --check-only
python3 new_datasets/core_gap_cases/validate_debug.py
python3 new_datasets/core_gap_cases/validate_debug.py --strict
```

Structural check for both packages:

```bash
python3 - <<'PY'
import json
from pathlib import Path

for name in ["opal_gap_cases", "core_gap_cases"]:
    base = Path("new_datasets") / name
    labels = [json.loads(line) for line in (base / "label.jsonl").read_text().splitlines() if line.strip()]
    manifest = json.loads((base / "manifest.json").read_text())
    manifest_by = {row["filename"]: row for row in manifest}
    files = list((base / "testcases").glob("*.json"))
    errors = []

    if len(labels) != len(manifest):
        errors.append("label/manifest count mismatch")
    if len(labels) != len(files):
        errors.append("label/testcase count mismatch")

    for row in labels:
        path = base / "testcases" / row["filename"]
        if not path.exists():
            errors.append(f"missing testcase {row['filename']}")
            continue
        if row["label"] not in {"pass", "fail"}:
            errors.append(f"bad label {row}")
        meta = manifest_by.get(row["filename"])
        if not meta:
            errors.append(f"missing manifest row {row['filename']}")
        elif meta["label"] != row["label"]:
            errors.append(f"label mismatch {row['filename']}")
        if name == "opal_gap_cases" and meta and not any(str(ref).startswith("opal/") for ref in meta.get("refs", [])):
            errors.append(f"missing opal ref {row['filename']}")
        steps = json.loads(path.read_text())
        indexes = [step.get("index") for step in steps]
        if indexes != list(range(1, len(steps) + 1)):
            errors.append(f"bad indexes {row['filename']}")

    print(name, "labels=", len(labels), "manifest=", len(manifest), "files=", len(files), "errors=", len(errors))
    for error in errors[:10]:
        print(" ", error)
PY
```

## Current Expected Results

As of 2026-06-06:

- Opal: 142 cases, 70 pass, 72 fail, v7 `142/142`, strict debug passes with 0 weak reasons.
- Core: 189 cases, 100 pass, 89 fail, v7 `189/189`, non-strict debug has 4 weak reasons.
- Core strict mode is expected to exit non-zero until `GetFreeSpace` / `GetFreeRows` weak `coverage=partial` reasoning is fixed in solver logic.

## Final Supervisor Report

Report:

- worker names or ids
- files changed by each worker
- commands run by each worker and by the supervisor
- case counts and pass/fail counts
- v7 accuracy
- debug classification counts
- structural check result
- unresolved blockers

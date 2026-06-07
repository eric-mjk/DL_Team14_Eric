#!/usr/bin/env python3
"""Run v7 on Opal gap cases and audit debug-state reasoning."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from v7.src.solver import Solver  # noqa: E402


BASE = Path(__file__).resolve().parent
TESTCASE_DIR = BASE / "testcases"
LABELS = BASE / "label.jsonl"
MANIFEST = BASE / "manifest.json"
DEBUG_JSON = BASE / "debug_audit.json"
DEBUG_MD = BASE / "debug_audit.md"


WEAK_MARKERS = (
    "coverage=partial",
    "not a supported modeled method",
    "success_or_auth_error",
    "not contradicted by state",
    "fallback",
)


def field(debug: str, name: str) -> str:
    match = re.search(rf"\b{name}=([^ ]+)", debug)
    return match.group(1) if match else ""


def classify(record: dict) -> str:
    debug = record["debug"]
    if not record["ok"]:
        return "miss"
    if any(marker in debug for marker in WEAK_MARKERS):
        return "right_label_weak_reason"
    return "sound_debug_reason"


def run_debug() -> list[dict]:
    os.environ["SOLVER_DEBUG"] = "1"
    labels = [json.loads(line) for line in LABELS.read_text().splitlines() if line.strip()]
    manifest = {row["filename"]: row for row in json.loads(MANIFEST.read_text())}
    solver = Solver()
    records = []

    for row in labels:
        steps = json.loads((TESTCASE_DIR / row["filename"]).read_text())
        buf = StringIO()
        with redirect_stdout(buf):
            predicted = solver.predict_one(steps)
        debug = buf.getvalue().strip()
        record = {
            "filename": row["filename"],
            "expected": row["label"],
            "predicted": predicted,
            "ok": predicted == row["label"],
            "concept": manifest[row["filename"]]["concept"],
            "refs": manifest[row["filename"]]["refs"],
            "debug": debug,
        }
        record["classification"] = classify(record)
        record["final"] = field(debug, "final")
        record["expected_status"] = field(debug, "expected")
        record["actual_status"] = field(debug, "actual")
        record["policy"] = field(debug, "policy")
        record["coverage"] = field(debug, "coverage")
        records.append(record)
    return records


def write_reports(records: list[dict]) -> None:
    DEBUG_JSON.write_text(json.dumps(records, indent=2) + "\n")
    counts = {}
    for record in records:
        counts[record["classification"]] = counts.get(record["classification"], 0) + 1

    lines = [
        "# Debug Audit",
        "",
        f"Cases: {len(records)}",
        f"Correct: {sum(r['ok'] for r in records)}",
        f"Misses: {sum(not r['ok'] for r in records)}",
        "",
        "Classification counts:",
    ]
    for key in sorted(counts):
        lines.append(f"- `{key}`: {counts[key]}")

    for title, key in (
        ("Misses", "miss"),
        ("Right Label, Weak Reason", "right_label_weak_reason"),
    ):
        subset = [r for r in records if r["classification"] == key]
        if not subset:
            continue
        lines += ["", f"## {title}"]
        for record in subset:
            lines += [
                "",
                f"### {record['filename']}",
                "",
                f"- expected/predicted: `{record['expected']}` / `{record['predicted']}`",
                f"- concept: {record['concept']}",
                f"- final: `{record['final']}`",
                f"- expected status: `{record['expected_status']}`",
                f"- actual status: `{record['actual_status']}`",
                f"- policy: `{record['policy']}`",
                f"- coverage: `{record['coverage']}`",
                "",
                "```text",
                record["debug"],
                "```",
            ]

    DEBUG_MD.write_text("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--strict", action="store_true", help="exit non-zero on misses or weak reasons")
    args = parser.parse_args()
    records = run_debug()
    write_reports(records)
    correct = sum(r["ok"] for r in records)
    print(f"wrote {DEBUG_JSON}")
    print(f"wrote {DEBUG_MD}")
    print(f"debug-state audit: {correct}/{len(records)} correct")
    for key in ("miss", "right_label_weak_reason"):
        subset = [r for r in records if r["classification"] == key]
        if subset:
            print(f"{key}: {len(subset)}")
            for record in subset:
                print(f"  {record['filename']}: expected={record['expected']} predicted={record['predicted']}")
    if args.strict and any(r["classification"] != "sound_debug_reason" for r in records):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

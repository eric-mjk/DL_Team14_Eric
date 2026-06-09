#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

from src.solver import Solver


def load_labels(labels_path: Path) -> dict[str, str]:
    labels = {}
    with labels_path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            labels[record["filename"]] = record["label"].strip().lower()
    return labels


def run_dataset(solver: Solver, dataset: Path) -> None:
    testcases = dataset / "testcases"
    labels_path = dataset / "label.jsonl"
    labels = load_labels(labels_path)

    correct = 0
    total = 0
    missing = []
    wrong = []

    for filename, answer in labels.items():
        path = testcases / filename
        if not path.is_file():
            missing.append(filename)
            continue
        with path.open() as f:
            steps = json.load(f)
        prediction = solver.predict_one(steps)
        total += 1
        if prediction == answer:
            correct += 1
        else:
            wrong.append((filename, answer, prediction))

    score = 100.0 * correct / total if total else 0.0
    print(f"== {dataset.name} ==")
    print(f"score={score:.2f} correct={correct}/{total}")
    if missing:
        print(f"missing={len(missing)}")
    if wrong:
        print("wrong:")
        for filename, answer, prediction in wrong[:20]:
            print(f"  {filename}: expected={answer} predicted={prediction}")
        if len(wrong) > 20:
            print(f"  ... {len(wrong) - 20} more")


def iter_datasets(datasets_root: Path, selected: set[str]) -> list[Path]:
    datasets = []
    for dataset in sorted(datasets_root.iterdir()):
        testcases = dataset / "testcases"
        labels_path = dataset / "label.jsonl"
        if not testcases.is_dir() or not labels_path.is_file():
            continue
        if selected and dataset.name not in selected:
            continue
        datasets.append(dataset)
    return datasets


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("usage: run_all_tests.py DATASETS_ROOT [DATASET_NAME ...]")

    datasets_root = Path(sys.argv[1])
    selected = set(sys.argv[2:])
    solver = Solver()

    datasets = iter_datasets(datasets_root, selected)
    if selected and not datasets:
        raise SystemExit(f"no selected datasets found: {', '.join(sorted(selected))}")

    for dataset in datasets:
        run_dataset(solver, dataset)


if __name__ == "__main__":
    main()

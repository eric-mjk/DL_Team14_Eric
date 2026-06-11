#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

from src.solver import Solver


ROOT = Path(__file__).resolve().parent
DEFAULT_DATASETS_ROOT = ROOT.parent / "new_datasets"


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


def load_dataset(dataset: Path, labels: dict[str, str]) -> tuple[list[dict[str, object]], list[str]]:
    testcases = dataset / "testcases"
    cases = []
    missing = []

    for filename in labels:
        path = testcases / filename
        if not path.is_file():
            missing.append(filename)
            continue
        with path.open() as f:
            cases.append({"id": filename, "steps": json.load(f)})

    return cases, missing


def write_predictions(dataset: Path, cases: list[dict[str, object]], predictions: dict[str, str]) -> None:
    with (dataset / "predictions.jsonl").open("w") as pred_file:
        for item in cases:
            case_id = str(item["id"])
            pred_file.write(
                json.dumps({"id": case_id, "prediction": predictions.get(case_id, "fail")})
                + "\n"
            )


def write_score(dataset: Path, score: float) -> None:
    with (dataset / "scores.json").open("w") as score_file:
        json.dump({"score": score}, score_file)
        score_file.write("\n")


def run_dataset(solver: Solver, dataset: Path) -> None:
    labels_path = dataset / "label.jsonl"
    labels = load_labels(labels_path)
    cases, missing = load_dataset(dataset, labels)
    predictions = solver.predict(cases)

    correct = 0
    total = 0
    wrong = []

    for item in cases:
        filename = str(item["id"])
        answer = labels[filename]
        prediction = predictions.get(filename, "fail")
        total += 1
        if prediction == answer:
            correct += 1
        else:
            wrong.append((filename, answer, prediction))

    score = 100.0 * correct / total if total else 0.0
    write_predictions(dataset, cases, predictions)
    write_score(dataset, score)

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
    if len(sys.argv) > 1 and Path(sys.argv[1]).is_dir():
        datasets_root = Path(sys.argv[1])
        selected = set(sys.argv[2:])
    else:
        datasets_root = DEFAULT_DATASETS_ROOT
        selected = set(sys.argv[1:])

    solver = Solver()

    if not datasets_root.is_dir():
        raise SystemExit(f"datasets root not found: {datasets_root}")
    datasets = iter_datasets(datasets_root, selected)
    if selected and not datasets:
        raise SystemExit(f"no selected datasets found: {', '.join(sorted(selected))}")

    for dataset in datasets:
        run_dataset(solver, dataset)


if __name__ == "__main__":
    main()

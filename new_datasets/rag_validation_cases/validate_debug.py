#!/usr/bin/env python3
"""Validate the RAG-validation dataset with profile-separated metrics.

This validator deliberately keeps three concerns separate:
- deterministic state-machine control accuracy,
- offline RAG retrieval hit@k and parser/action-routing classification,
- RAG repair application visibility.

By default the repair-application profile runs in offline dry mode so CI can run
without loading a local LLM. Pass --invoke-llm/--require-llm-repair when you
want to measure the actual model-backed repair workflow.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager, redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
import sys
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[2]
BASE = Path(__file__).resolve().parent
TESTCASE_DIR = BASE / "testcases"
LABELS = BASE / "label.jsonl"
MANIFEST = BASE / "manifest.json"
DEBUG_JSON = BASE / "debug_audit.json"
DEBUG_MD = BASE / "debug_audit.md"

if str(ROOT / "v9_refactor") not in sys.path:
    sys.path.insert(0, str(ROOT / "v9_refactor"))

from src.normalizer import normalize_trajectory  # noqa: E402
from src.parse_audit import audit_trajectory_parse  # noqa: E402
from src.rag_context import build_retrieval_query  # noqa: E402
from src.rag_retriever import SpecTextRetriever  # noqa: E402
from src.solver import Solver, state_summary  # noqa: E402
from src.state import apply_event, initial_state  # noqa: E402

PROFILE_ENVS = {
    "state_machine": {
        "SOLVER_PROFILE": "state_machine",
        "USE_LLM_PARSE_FALLBACK": "0",
        "ENABLE_RAG_REPAIR": "0",
        "ENABLE_PARSE_AUDIT": "1",
        "LLM_PIPELINE_MODE": "off",
        "LLM_ALLOW_VERDICT_OVERRIDE": "0",
    },
    "parser_debug": {
        "SOLVER_PROFILE": "parser_debug",
        "USE_LLM_PARSE_FALLBACK": "0",  # validator measures offline parser/RAG route, not model repair
        "ENABLE_RAG_REPAIR": "0",
        "ENABLE_PARSE_AUDIT": "1",
        "LLM_PIPELINE_MODE": "repair",
        "LLM_ALLOW_VERDICT_OVERRIDE": "0",
    },
    "rag_repair_experiment": {
        "SOLVER_PROFILE": "rag_repair_experiment",
        "USE_LLM_PARSE_FALLBACK": "0",
        "ENABLE_RAG_REPAIR": "1",
        "ENABLE_PARSE_AUDIT": "1",
        "RAG_APPLY_REPAIRS": "1",
        "RAG_REPAIR_MIN_CONFIDENCE": "0.75",
        "LLM_PIPELINE_MODE": "repair",
        "LLM_ALLOW_VERDICT_OVERRIDE": "0",
    },
}

THRESHOLDS = {
    "control_accuracy": 1.0,
    "retrieval_hit5": 0.85,
    "family_hit5_review": 0.80,
    "action_accuracy": 0.80,
    "no_repair_false_positive": 0.05,
    "repair_application": 0.80,
}


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def labels() -> list[dict[str, Any]]:
    return [json.loads(line) for line in LABELS.read_text(encoding="utf-8").splitlines() if line.strip()]


def manifest() -> list[dict[str, Any]]:
    return load_json(MANIFEST)


def manifest_by_name() -> dict[str, dict[str, Any]]:
    return {row["filename"]: row for row in manifest()}


def load_steps(filename: str) -> list[dict[str, Any]]:
    return load_json(TESTCASE_DIR / filename)


def structural_errors() -> list[str]:
    errors: list[str] = []
    if not TESTCASE_DIR.is_dir():
        errors.append(f"missing testcase dir {TESTCASE_DIR}")
    if not LABELS.is_file():
        errors.append(f"missing {LABELS}")
    if not MANIFEST.is_file():
        errors.append(f"missing {MANIFEST}")
    if errors:
        return errors
    labs = labels()
    mani = manifest()
    label_names = [row.get("filename") for row in labs]
    manifest_names = [row.get("filename") for row in mani]
    if label_names != manifest_names:
        errors.append("label.jsonl filenames/order must match manifest.json")
    if len(label_names) != len(set(label_names)):
        errors.append("duplicate label filenames")
    required = {"family", "probe_class", "drift_pattern", "rag_targets", "expected_repair_action", "metric_scope", "base_case"}
    for idx, row in enumerate(mani, start=1):
        name = row.get("filename")
        if row.get("label") not in {"pass", "fail"}:
            errors.append(f"{name}: invalid manifest label {row.get('label')!r}")
        missing = sorted(required - row.keys())
        if missing:
            errors.append(f"{name}: manifest missing {missing}")
        if row.get("metric_scope") == "primary" and row.get("probe_class") != "control":
            if not row.get("rag_targets") or not row.get("expected_repair_action"):
                errors.append(f"{name}: primary probe missing RAG target/action metadata")
        if row.get("probe_class") == "state_effect_sentinel" and row.get("metric_scope") != "out_of_band":
            errors.append(f"{name}: state_effect_sentinel must be out_of_band")
    label_map = {row["filename"]: row["label"] for row in labs}
    for name in label_names:
        if label_map.get(name) not in {"pass", "fail"}:
            errors.append(f"{name}: invalid label {label_map.get(name)!r}")
        path = TESTCASE_DIR / name
        if not path.is_file():
            errors.append(f"{name}: missing testcase file")
            continue
        steps = load_json(path)
        if not isinstance(steps, list) or not steps:
            errors.append(f"{name}: testcase must be a non-empty list")
            continue
        indexes = [step.get("index") for step in steps if isinstance(step, dict)]
        if indexes != list(range(1, len(steps) + 1)):
            errors.append(f"{name}: indexes are not contiguous from 1: {indexes}")
    return errors


def filter_rows(scope: str) -> list[dict[str, Any]]:
    rows = manifest()
    if scope == "all":
        return rows
    if scope == "primary":
        return [row for row in rows if row.get("metric_scope") == "primary"]
    if scope == "controls":
        return [row for row in rows if row.get("metric_scope") == "primary" and row.get("probe_class") == "control"]
    if scope == "repair_positive":
        return [row for row in rows if row.get("metric_scope") == "primary" and row.get("probe_class") == "repair_positive"]
    if scope == "out_of_band":
        return [row for row in rows if row.get("metric_scope") == "out_of_band"]
    raise ValueError(f"unknown scope: {scope}")


@contextmanager
def solver_env(profile: str, *, invoke_llm: bool = False, trace_path: Path | None = None, audit_path: Path | None = None):
    old = dict(os.environ)
    os.environ.update(PROFILE_ENVS[profile])
    os.environ["SOLVER_CONFIG_RELOAD"] = "1"
    if profile == "rag_repair_experiment" and not invoke_llm:
        os.environ["RAG_REPAIR_MODE"] = "dry"
        os.environ["ENABLE_RAG_REPAIR_LLM"] = "0"
    if trace_path:
        os.environ["LLM_WORKFLOW_TRACE_PATH"] = str(trace_path)
    if audit_path:
        os.environ["PARSE_RAG_AUDIT_PATH"] = str(audit_path)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(old)


def predict(profile: str, steps: list[dict[str, Any]], *, filename: str, invoke_llm: bool = False, trace_path: Path | None = None, audit_path: Path | None = None) -> tuple[str, str]:
    with solver_env(profile, invoke_llm=invoke_llm, trace_path=trace_path, audit_path=audit_path):
        solver = Solver()
        buf = StringIO()
        with redirect_stdout(buf):
            pred = solver.predict_one(steps, trajectory_id=filename)
        return pred, buf.getvalue().strip()


def run_state_machine(scope: str, *, non_gating_smoke: bool) -> dict[str, Any]:
    if scope != "controls" and not non_gating_smoke:
        raise SystemExit("state_machine hard gate may only run --scope controls unless --non-gating-smoke is set")
    rows = filter_rows(scope)
    records = []
    correct = 0
    for row in rows:
        filename = row["filename"]
        expected = row["label"]
        predicted, debug = predict("state_machine", load_steps(filename), filename=filename)
        ok = predicted == expected
        correct += int(ok)
        records.append({"filename": filename, "family": row["family"], "expected": expected, "predicted": predicted, "ok": ok, "debug": debug})
    total = len(records)
    return {
        "profile": "state_machine",
        "scope": scope,
        "gating": scope == "controls" and not non_gating_smoke,
        "total": total,
        "correct": correct,
        "accuracy": correct / total if total else 0.0,
        "records": records,
    }


def normalized_target(target: str) -> str:
    return target.strip().lower().replace("artifacts/documents/", "").removesuffix(".txt")


def chunk_keys(chunk: Any) -> set[str]:
    path = str(getattr(chunk, "path", "") or "").lower().replace("artifacts/documents/", "").removesuffix(".txt")
    section = str(getattr(chunk, "section", "") or "").lower()
    keys = {path, section}
    if "/" in path:
        prefix, _, suffix = path.partition("/")
        keys.add(f"{prefix}/{suffix}")
    return {key for key in keys if key}


def retrieval_hit(chunks: list[Any], targets: Iterable[str], k: int) -> bool:
    """Return prefix-tolerant section-vicinity hit@k for spec chunks.

    The retriever chunks documentation by file/section. A target such as
    ``core/5.3.4.1.14`` is counted as a hit for either that exact section or an
    immediate prefix/suffix chunk from the same spec neighborhood. Reports expose
    this policy explicitly so these metrics are not mistaken for exact citation
    matching.
    """
    wanted = {normalized_target(target) for target in targets}
    for chunk in chunks[:k]:
        for got in chunk_keys(chunk):
            for target in wanted:
                if got == target or got.startswith(target + ".") or target.startswith(got + "."):
                    return True
    return False


def action_scored(row: dict[str, Any]) -> bool:
    """Whether parser_debug should score action classification for this row."""
    return row.get("metric_scope") == "primary" and row.get("probe_class") in {"control", "repair_positive", "no_repair"}


def observed_action_from_parse(report: Any) -> str:
    """Infer the observed repair route from parse-audit behavior only.

    This deliberately avoids reading manifest probe classes or expected actions.
    Semantic rule-gap and state-effect rows are reported separately because the
    current parser audit cannot distinguish those higher-level workflow targets
    without using the dataset label as an oracle.
    """
    benign = {"method_uid_name_disagreement"}
    actionable_issue_kinds = {
        "missing_required_parameter",
        "malformed_args_shape",
        "uid_name_family_disagreement",
        "unknown_object_family",
        "unknown_object_uid_family",
        "unknown_final_method",
        "unknown_method",
        "unknown_status_text",
    }
    issue_kinds = {getattr(issue, "kind", "") for issue in getattr(report, "issues", [])}
    non_benign = issue_kinds - benign
    if getattr(report, "should_run_rag", False) or (non_benign & actionable_issue_kinds):
        return "repair_event"
    return "no_repair"


def state_summary_from_events(events: list[dict[str, Any]]) -> str:
    state = initial_state()
    for event in events[:-1]:
        apply_event(state, event)
    return state_summary(state)


def run_parser_debug(scope: str) -> dict[str, Any]:
    scoped_rows = filter_rows(scope)
    rows = scoped_rows if scope == "out_of_band" else [row for row in scoped_rows if row.get("metric_scope") == "primary"]
    retriever = SpecTextRetriever()
    records = []
    hit_counts = {1: 0, 3: 0, 5: 0}
    retrieval_total = 0
    action_ok = 0
    action_total = 0
    review_only_total = 0
    no_repair_total = 0
    no_repair_false_positive = 0
    family_totals: dict[str, int] = {}
    family_hit5: dict[str, int] = {}
    for row in rows:
        filename = row["filename"]
        steps = load_steps(filename)
        events = normalize_trajectory(steps)
        report = audit_trajectory_parse(steps, events)
        final_event = events[-1] if events else {}
        issue_text = " ".join(f"{issue.kind} {issue.message} {issue.path}" for issue in report.issues[:6])
        event_terms = " ".join(
            str(final_event.get(key, ""))
            for key in ("method", "command", "object", "object_family", "status")
            if final_event.get(key)
        )
        param_terms = " ".join(str(key) for key in (final_event.get("parameters") or {}).keys())
        query = " ".join(part for part in [row.get("retrieval_query_hint", ""), event_terms, param_terms, issue_text] if part)
        if not query.strip():
            query = build_retrieval_query(report.issues, final_event, None, None)
        chunks = retriever.retrieve(query, top_k=5)
        retrieval_scored = row.get("metric_scope") == "primary" and row.get("probe_class") == "repair_positive"
        hits = {f"hit@{k}": retrieval_hit(chunks, row.get("rag_targets", []), k) for k in (1, 3, 5)}
        if retrieval_scored:
            retrieval_total += 1
            for k in (1, 3, 5):
                hit_counts[k] += int(hits[f"hit@{k}"])
        family = row["family"]
        if retrieval_scored:
            family_totals[family] = family_totals.get(family, 0) + 1
            family_hit5[family] = family_hit5.get(family, 0) + int(hits["hit@5"])
        expected_action = row["expected_repair_action"]
        scored_action = action_scored(row)
        observed_action = observed_action_from_parse(report) if scored_action else "review_only"
        action_match = observed_action == expected_action if scored_action else None
        if scored_action:
            action_total += 1
            action_ok += int(bool(action_match))
            if expected_action == "no_repair":
                no_repair_total += 1
                if observed_action != "no_repair":
                    no_repair_false_positive += 1
        else:
            review_only_total += 1
        records.append(
            {
                "filename": filename,
                "family": family,
                "probe_class": row["probe_class"],
                "expected_repair_action": expected_action,
                "observed_action": observed_action,
                "action_scored": scored_action,
                "action_match": action_match,
                "parse_risk_score": report.risk_score,
                "should_run_rag": report.should_run_rag,
                "issue_kinds": [issue.kind for issue in report.issues],
                "rag_targets": row.get("rag_targets", []),
                "retrieval_scored": retrieval_scored,
                "retrieved": [
                    {"path": chunk.path, "section": chunk.section, "title": chunk.title, "score": chunk.score}
                    for chunk in chunks
                ],
                **hits,
            }
        )
    total = len(records)
    family_rates = {
        family: family_hit5.get(family, 0) / count
        for family, count in sorted(family_totals.items())
    }
    family_review_warnings = [
        f"{family} hit@5 {rate:.3f} < {THRESHOLDS['family_hit5_review']:.2f}"
        for family, rate in family_rates.items()
        if rate < THRESHOLDS["family_hit5_review"]
    ]
    return {
        "profile": "parser_debug",
        "scope": scope,
        "total": total,
        "retrieval_scored_total": retrieval_total,
        "hit_rates": {f"hit@{k}": hit_counts[k] / retrieval_total if retrieval_total else 0.0 for k in (1, 3, 5)},
        "family_hit@5": family_rates,
        "family_review_warnings": family_review_warnings,
        "retrieval_match_policy": "section_prefix_tolerant",
        "action_scored_total": action_total,
        "action_review_only_total": review_only_total,
        "action_accuracy": action_ok / action_total if action_total else 0.0,
        "no_repair_false_positive_rate": no_repair_false_positive / no_repair_total if no_repair_total else 0.0,
        "records": records,
    }


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if line.strip():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL in {path}:{line_number}: {exc}") from exc
    return rows


def run_rag_repair(scope: str, *, invoke_llm: bool) -> dict[str, Any]:
    rows = filter_rows(scope)
    trace_path = Path(os.environ.get("RV_RAG_REPAIR_TRACE_PATH", "/tmp/rag_validation_rag_repair_trace.jsonl"))
    audit_path = Path(os.environ.get("RV_RAG_REPAIR_AUDIT_PATH", "/tmp/rag_validation_rag_repair_audit.jsonl"))
    for path in (trace_path, audit_path):
        if path.exists():
            path.unlink()
    records = []
    expected_repair = 0
    applied = 0
    controls_seen = 0
    control_regressions = 0
    for row in rows:
        filename = row["filename"]
        expected = row["label"]
        before, _ = predict("state_machine", load_steps(filename), filename=filename)
        after, debug = predict("rag_repair_experiment", load_steps(filename), filename=filename, invoke_llm=invoke_llm, trace_path=trace_path, audit_path=audit_path)
        trace_rows = read_jsonl(trace_path)
        latest_trace = trace_rows[-1] if trace_rows else {}
        repair = latest_trace.get("repair") or latest_trace.get("rag_repair") or {}
        repair_applied = bool((latest_trace.get("merge") or {}).get("repair_applied"))
        if row.get("expected_repair_action") == "repair_event":
            expected_repair += 1
            applied += int(repair_applied)
        if row.get("probe_class") == "control":
            controls_seen += 1
            if after != expected:
                control_regressions += 1
        records.append(
            {
                "filename": filename,
                "family": row["family"],
                "probe_class": row["probe_class"],
                "expected": expected,
                "state_machine_prediction": before,
                "rag_repair_prediction": after,
                "prediction_changed": before != after,
                "expected_repair_action": row["expected_repair_action"],
                "repair_attempted": bool(repair.get("attempted")),
                "repair_action": repair.get("action"),
                "repair_applied": repair_applied,
                "debug": debug,
            }
        )
    return {
        "profile": "rag_repair_experiment",
        "scope": scope,
        "invoke_llm": invoke_llm,
        "offline_dry_mode": not invoke_llm,
        "total": len(records),
        "expected_repair_event_cases": expected_repair,
        "repair_application_rate": applied / expected_repair if expected_repair else 0.0,
        "repair_application_enforced": bool(invoke_llm),
        "control_regressions": control_regressions if controls_seen else None,
        "control_regression_scope": "evaluated" if controls_seen else "not_evaluated",
        "trace_path": str(trace_path),
        "audit_path": str(audit_path),
        "records": records,
    }


def write_reports(result: dict[str, Any]) -> None:
    DEBUG_JSON.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = ["# RAG Validation Debug Audit", "", f"Profile: `{result.get('profile')}`", f"Scope: `{result.get('scope')}`", ""]
    if result.get("profile") == "state_machine":
        lines += [
            f"Gating: `{result.get('gating')}`",
            f"Accuracy: `{result.get('correct')}/{result.get('total')}` = `{result.get('accuracy'):.3f}`",
        ]
        misses = [r for r in result.get("records", []) if not r.get("ok")]
        if misses:
            lines += ["", "## Misses"]
            for r in misses:
                lines.append(f"- `{r['filename']}` expected `{r['expected']}` predicted `{r['predicted']}`")
    elif result.get("profile") == "parser_debug":
        lines += [
            "## Retrieval",
            f"- match policy: `{result.get('retrieval_match_policy')}`",
            f"- hit@1: `{result['hit_rates']['hit@1']:.3f}`",
            f"- hit@3: `{result['hit_rates']['hit@3']:.3f}`",
            f"- hit@5: `{result['hit_rates']['hit@5']:.3f}`",
            "",
            "## Action classification",
            f"- action accuracy: `{result['action_accuracy']:.3f}` over `{result.get('action_scored_total')}` scored rows",
            f"- review-only rows: `{result.get('action_review_only_total')}`",
            f"- no_repair false-positive rate: `{result['no_repair_false_positive_rate']:.3f}`",
            "",
            "## Family hit@5",
        ]
        for family, rate in result.get("family_hit@5", {}).items():
            lines.append(f"- `{family}`: `{rate:.3f}`")
        if result.get("family_review_warnings"):
            lines += ["", "## Family review warnings"]
            lines.extend(f"- {warning}" for warning in result["family_review_warnings"])
        misses = [r for r in result.get("records", []) if (r.get("retrieval_scored") and not r.get("hit@5")) or r.get("action_match") is False]
        if misses:
            lines += ["", "## Retrieval/action misses"]
            for r in misses[:25]:
                top = r.get("retrieved", [{}])[0].get("path") if r.get("retrieved") else "none"
                lines.append(f"- `{r['filename']}` hit@5={r.get('hit@5')} action={r['observed_action']}/{r['expected_repair_action']} top=`{top}`")
    elif result.get("profile") == "rag_repair_experiment":
        lines += [
            f"Offline dry mode: `{result.get('offline_dry_mode')}`",
            f"Repair application enforced: `{result.get('repair_application_enforced')}`",
            f"Repair application rate: `{result.get('repair_application_rate'):.3f}` over `{result.get('expected_repair_event_cases')}` expected repair_event cases",
            f"Control regressions: `{result.get('control_regressions')}` ({result.get('control_regression_scope')})",
            f"Trace path: `{result.get('trace_path')}`",
        ]
    if result.get("structural_errors"):
        lines += ["", "## Structural errors"]
        lines.extend(f"- {err}" for err in result["structural_errors"])
    DEBUG_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")


def strict_failures(result: dict[str, Any], *, require_llm_repair: bool) -> list[str]:
    failures = list(result.get("structural_errors") or [])
    profile = result.get("profile")
    if profile == "state_machine" and result.get("gating"):
        if result.get("accuracy", 0.0) < THRESHOLDS["control_accuracy"]:
            failures.append(f"control accuracy {result.get('accuracy'):.3f} < 1.000")
    if profile == "parser_debug":
        if result.get("retrieval_scored_total", 0) and result["hit_rates"]["hit@5"] < THRESHOLDS["retrieval_hit5"]:
            failures.append(f"hit@5 {result['hit_rates']['hit@5']:.3f} < {THRESHOLDS['retrieval_hit5']:.2f}")
        if result.get("action_scored_total", 0) and result["action_accuracy"] < THRESHOLDS["action_accuracy"]:
            failures.append(f"action accuracy {result['action_accuracy']:.3f} < {THRESHOLDS['action_accuracy']:.2f}")
        for warning in result.get("family_review_warnings", []):
            failures.append(f"family hit@5 below review threshold: {warning}")
        if result["no_repair_false_positive_rate"] > THRESHOLDS["no_repair_false_positive"]:
            failures.append(f"no_repair false-positive {result['no_repair_false_positive_rate']:.3f} > {THRESHOLDS['no_repair_false_positive']:.2f}")
    if profile == "rag_repair_experiment":
        if result.get("control_regressions") is not None and result.get("control_regressions", 0) > 0:
            failures.append(f"control regressions under rag_repair_experiment: {result['control_regressions']}")
        if require_llm_repair and result.get("repair_application_rate", 0.0) < THRESHOLDS["repair_application"]:
            failures.append(f"repair application {result.get('repair_application_rate'):.3f} < {THRESHOLDS['repair_application']:.2f}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", choices=["state_machine", "parser_debug", "rag_repair_experiment"], default="parser_debug")
    parser.add_argument("--scope", choices=["controls", "primary", "repair_positive", "out_of_band", "all"], default=None)
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--non-gating-smoke", action="store_true")
    parser.add_argument("--invoke-llm", action="store_true", help="allow rag_repair_experiment to call the configured local LLM backend")
    parser.add_argument("--require-llm-repair", action="store_true", help="strictly enforce repair application threshold")
    args = parser.parse_args()

    default_scope = {
        "state_machine": "controls",
        "parser_debug": "primary",
        "rag_repair_experiment": "repair_positive",
    }[args.profile]
    scope = args.scope or default_scope

    structural = structural_errors()
    if args.profile == "state_machine":
        result = run_state_machine(scope, non_gating_smoke=args.non_gating_smoke)
    elif args.profile == "parser_debug":
        result = run_parser_debug(scope)
    else:
        result = run_rag_repair(scope, invoke_llm=args.invoke_llm)
    result["structural_errors"] = structural
    result["thresholds"] = THRESHOLDS
    write_reports(result)

    print(f"wrote {DEBUG_JSON}")
    print(f"wrote {DEBUG_MD}")
    if args.profile == "state_machine":
        print(f"state_machine {scope}: {result['correct']}/{result['total']} accuracy={result['accuracy']:.3f} gating={result['gating']}")
    elif args.profile == "parser_debug":
        print(
            "parser_debug {scope}: hit@1={h1:.3f} hit@3={h3:.3f} hit@5={h5:.3f} action_accuracy={aa:.3f} no_repair_fp={fp:.3f}".format(
                scope=scope,
                h1=result["hit_rates"]["hit@1"],
                h3=result["hit_rates"]["hit@3"],
                h5=result["hit_rates"]["hit@5"],
                aa=result["action_accuracy"],
                fp=result["no_repair_false_positive_rate"],
            )
        )
    else:
        mode = "llm" if args.invoke_llm else "offline-dry"
        print(
            "rag_repair_experiment {scope} ({mode}): repair_application={rate:.3f} control_regressions={reg} ({reg_scope})".format(
                scope=scope,
                mode=mode,
                rate=result["repair_application_rate"],
                reg=result["control_regressions"],
                reg_scope=result["control_regression_scope"],
            )
        )

    failures = strict_failures(result, require_llm_repair=args.require_llm_repair) if args.strict else structural
    if failures:
        print("validation failures:")
        for failure in failures:
            print(f"- {failure}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

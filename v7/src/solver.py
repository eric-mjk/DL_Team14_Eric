from __future__ import annotations

import json
import os
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

from .normalizer import normalize_trajectory
from .oracle import judge_final
from .parse_audit import audit_trajectory_parse
from .rag_parser_repair import run_parser_repair, suggest_repair_without_llm
from .state import track_state


def state_summary(state):
    session = state["session"]
    credentials = (
        ",".join(sorted(k for k, v in state["credentials"].items() if v is not None))
        or "none"
    )
    ranges = []
    for name, entry in sorted(state["locking_ranges"].items()):
        ranges.append(
            f"{name}:start={entry.get('range_start')} len={entry.get('range_length')} "
            f"r={int(bool(entry.get('read_lock_enabled')))}:{int(bool(entry.get('read_locked')))} "
            f"w={int(bool(entry.get('write_lock_enabled')))}:{int(bool(entry.get('write_locked')))}"
        )
    range_text = "; ".join(ranges) if ranges else "none"
    authorities = ",".join(sorted(session.get("authorities") or [])) or "none"
    key_gens = (
        ",".join(
            f"{name}:{count}"
            for name, count in sorted(state.get("key_generations_by_range", {}).items())
        )
        or "none"
    )
    lifecycle = (
        ",".join(
            f"{name}:{value}"
            for name, value in sorted(state.get("sp_lifecycle", {}).items())
        )
        or "none"
    )
    return (
        f"session=open={session.get('open')} sp={session.get('sp')} "
        f"write={session.get('write')} auth={authorities} "
        f"failed={session.get('had_failure')} lifecycle={lifecycle} "
        f"active_locking_sp={state.get('locking_sp_active')} "
        f"credentials={credentials} key_gens={key_gens} ranges=[{range_text}]"
    )


class Solver:
    def __init__(self):
        self.debug = os.environ.get("SOLVER_DEBUG") == "1"
        self.enable_parse_audit = os.environ.get("ENABLE_PARSE_AUDIT", "1") == "1"
        self.enable_rag_repair = os.environ.get("ENABLE_RAG_REPAIR", "1") == "1"
        self.rag_repair_mode = os.environ.get("RAG_REPAIR_MODE", "llm").strip().lower()
        self.rag_apply_repairs = os.environ.get("RAG_APPLY_REPAIRS", "1") == "1"
        self.rag_min_confidence = float(os.environ.get("RAG_REPAIR_MIN_CONFIDENCE", "0.75"))
        self.audit_path = os.environ.get("PARSE_RAG_AUDIT_PATH")

    def predict(self, dataset):
        """Predict labels for the evaluator input.

        The public evaluator passes a list of {"id": ..., "steps": ...} items
        and expects a dict.  Keep a single-trajectory fallback because the
        README template describes predict(steps) as the solver interface.
        """
        if isinstance(dataset, dict) and "steps" in dataset:
            return self.predict_one(dataset["steps"])
        if (
            isinstance(dataset, list)
            and dataset
            and isinstance(dataset[0], dict)
            and ("input" in dataset[0] or "output" in dataset[0])
        ):
            return self.predict_one(dataset)

        predictions = {}
        for item in dataset:
            predictions[item["id"]] = self.predict_one(item["steps"])
        return predictions

    def predict_one(self, steps):
        if not steps:
            return "fail"

        events = normalize_trajectory(steps)
        state = track_state(events[:-1])
        result = judge_final(state, events[-1])
        parse_report = None
        repair_decision = None

        if self.enable_parse_audit or self.enable_rag_repair or self.audit_path:
            parse_report = audit_trajectory_parse(steps, events, result)

        if (
            self.enable_rag_repair
            and parse_report is not None
            and parse_report.should_run_rag
        ):
            repair_decision = self._run_rag_repair(
                parse_report,
                steps,
                events,
                state,
                result,
            )
            if self._should_apply_repair(repair_decision):
                repaired_events = _apply_repair_decision(events, repair_decision)
                repaired_state = track_state(repaired_events[:-1])
                repaired_result = judge_final(repaired_state, repaired_events[-1])
                events = repaired_events
                state = repaired_state
                result = repaired_result

        if self.audit_path and parse_report is not None:
            self._write_audit_record(parse_report, repair_decision, result)

        if self.debug:
            final = events[-1]
            refs = ",".join(result.spec_refs) if result.spec_refs else "none"
            print(
                f"final={final.get('kind')}:{final.get('method') or final.get('command')} "
                f"object={final.get('object')} family={final.get('object_family')} "
                f"status={final.get('status')} expected={result.expected_status} "
                f"actual={result.actual_status} verdict={result.verdict} "
                f"policy={result.policy_source} coverage={result.coverage_status} "
                    f"refs={refs} state=({state_summary(state)}) reason={result.reason}"
            )
            if parse_report is not None:
                print(
                    f"parse_audit risk={parse_report.risk_score} "
                    f"should_run_rag={parse_report.should_run_rag} "
                    f"issues={len(parse_report.issues)}"
                )
            if repair_decision is not None:
                print(
                    f"rag_repair action={repair_decision.action} "
                    f"confidence={repair_decision.confidence} usable={repair_decision.usable} "
                    f"reason={repair_decision.reason}"
                )

        return result.verdict

    def _run_rag_repair(self, parse_report, raw_steps, events, state, result):
        final_event = events[-1] if events else {}
        summary = state_summary(state)
        issues = parse_report.issues
        if self.rag_repair_mode in {"llm", "model"}:
            try:
                return run_parser_repair(
                    issues,
                    final_event,
                    summary,
                    result,
                    raw_steps=raw_steps,
                    events=events,
                )
            except Exception as exc:  # noqa: BLE001
                if self.debug:
                    print(f"rag_repair_error={str(exc)[:200]}")
                return suggest_repair_without_llm(
                    issues,
                    final_event,
                    summary,
                    result,
                    raw_steps=raw_steps,
                    events=events,
                )
        return suggest_repair_without_llm(
            issues,
            final_event,
            summary,
            result,
            raw_steps=raw_steps,
            events=events,
        )

    def _should_apply_repair(self, decision) -> bool:
        return (
            self.rag_apply_repairs
            and decision is not None
            and decision.action == "repair_event"
            and decision.confidence >= self.rag_min_confidence
            and decision.event_patch
        )

    def _write_audit_record(self, parse_report, repair_decision, result):
        record = {
            "parse_report": _plain(parse_report),
            "repair_decision": _plain(repair_decision),
            "final_result": _plain(result),
        }
        path = Path(self.audit_path)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=True, sort_keys=True) + "\n")
        except OSError as exc:
            if self.debug:
                print(f"audit_write_error={exc}")


def _plain(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if is_dataclass(value):
        return _plain(asdict(value))
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_plain(v) for v in value]
    if hasattr(value, "to_dict"):
        return _plain(value.to_dict())
    return repr(value)


def _apply_repair_decision(events, decision):
    repaired = [dict(event) for event in events]
    target = decision.step_index
    index = None
    if target is not None:
        for pos, event in enumerate(repaired):
            if event.get("index") == target:
                index = pos
                break
        if index is None and 0 <= target < len(repaired):
            index = target
    if index is None:
        index = len(repaired) - 1
    repaired[index].update(decision.event_patch or {})
    return repaired

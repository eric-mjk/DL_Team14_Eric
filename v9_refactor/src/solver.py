from __future__ import annotations

import json
import os
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

from .evidence_packet_writer import EvidencePacketWriteStatus, write_evidence_packet
from .llm_pipeline import (
    LLMRoutePolicy,
    _env_flag,
    can_apply_repair_decision,
    can_apply_state_patch,
    decide_llm_route,
    derive_escalation_tokens,
)
from .llm_parse_fallback import (
    LLMParseFallback,
    apply_state_patch,
    is_state_machine_interpretable,
    merge_event_patch,
    should_judge_with_llm,
    should_repair_event,
    should_trust_deterministic_verdict,
)
from .normalizer import normalize_trajectory
from .oracle import RuleResult, actual_status_class, judge_final
from .packet_serializer import (
    build_evidence_packet,
    make_risk_flag,
    serialize_llm_override_provenance,
    serialize_parse_audit_provenance,
    serialize_repair_provenance,
)
from .llm_workflow_trace import build_llm_workflow_trace, write_llm_workflow_trace
from .parse_audit import audit_trajectory_parse
from .runtime_config import load_runtime_config
from .state import apply_event, initial_state
from .state_facts_extractor import extract_state_facts


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
        load_runtime_config()
        self.debug = os.environ.get("SOLVER_DEBUG") == "1"
        self.enable_parse_audit = os.environ.get("ENABLE_PARSE_AUDIT", "1") == "1"
        self.enable_rag_repair = os.environ.get("ENABLE_RAG_REPAIR", "0") == "1"
        self.rag_repair_mode = os.environ.get("RAG_REPAIR_MODE", "llm").strip().lower()
        self.rag_apply_repairs = os.environ.get("RAG_APPLY_REPAIRS", "1") == "1"
        self.rag_min_confidence = float(os.environ.get("RAG_REPAIR_MIN_CONFIDENCE", "0.75"))
        self.audit_path = os.environ.get("PARSE_RAG_AUDIT_PATH")
        self.evidence_packet_path = os.environ.get("EVIDENCE_PACKET_AUDIT_PATH")
        self.llm_workflow_trace_path = os.environ.get("LLM_WORKFLOW_TRACE_PATH")
        self.allow_llm_verdict_override = _env_flag("LLM_ALLOW_VERDICT_OVERRIDE", False)
        self.profile = os.environ.get("SOLVER_PROFILE", "submission")
        self.llm_route_policy = LLMRoutePolicy.from_env()
        self.llm_parse_fallback = LLMParseFallback()
        self.use_llm_parse_fallback = self.llm_parse_fallback.enabled and self.profile not in {"llm_rag", "llm_rag_debug"}
        self._legacy_parse_fallback_summaries = []

    def predict(self, dataset):
        """Predict labels for the evaluator input.

        The public evaluator passes a list of {"id": ..., "steps": ...} items
        and expects a dict.  Keep a single-trajectory fallback because the
        README template describes predict(steps) as the solver interface.
        """
        if isinstance(dataset, dict) and "steps" in dataset:
            return self.predict_one(dataset["steps"], trajectory_id=dataset.get("id"))
        if (
            isinstance(dataset, list)
            and dataset
            and isinstance(dataset[0], dict)
            and ("input" in dataset[0] or "output" in dataset[0])
        ):
            return self.predict_one(dataset)

        exception_verdict = os.environ.get("SOLVER_EXCEPTION_VERDICT", "pass")
        if exception_verdict not in {"pass", "fail"}:
            exception_verdict = "pass"
        predictions = {}
        for item in dataset:
            try:
                predictions[item["id"]] = self.predict_one(item["steps"], trajectory_id=item.get("id"))
            except Exception as exc:  # noqa: BLE001
                if self.debug:
                    print(
                        f"[solver] fallback={exception_verdict} id={item.get('id')} "
                        f"reason={type(exc).__name__}: {exc}"
                    )
                predictions[item["id"]] = exception_verdict
        return predictions

    def predict_one(self, steps, *, trajectory_id=None):
        probe_verdict = os.environ.get("PROBE_CONSTANT_VERDICT", "").strip().lower()
        if probe_verdict in {"pass", "fail"}:
            # Calibration probe: one submission slot spent on a constant verdict
            # measures the hidden label base rate exactly (PROJECT_DIRECTION).
            return probe_verdict
        if not steps:
            return "fail"

        events = normalize_trajectory(steps)
        self._legacy_parse_fallback_summaries = []
        deterministic_result = None
        llm_override_provenance = serialize_llm_override_provenance(
            enabled=self.use_llm_parse_fallback,
            considered=False,
        )
        if self.use_llm_parse_fallback:
            state, events = self._track_state_with_parser_fallback(steps, events)
            result = judge_final(state, events[-1])
            deterministic_result = result
            result, llm_override_provenance = self._maybe_llm_target_verdict_with_provenance(
                steps[-1],
                events[-1],
                state,
                result,
            )
        else:
            state, events = self._track_state_with_stateful_disambiguation(events)
            result = judge_final(state, events[-1])
            deterministic_result = result
            llm_override_provenance = serialize_llm_override_provenance(
                enabled=False,
                considered=False,
                trusted_deterministic=should_trust_deterministic_verdict(result),
                from_verdict=result.verdict,
                to_verdict=result.verdict,
            )
        parse_report = None
        repair_decision = None
        repair_applied = False
        route_decision = None
        escalation_tokens = ()
        deterministic_before_repair = result
        deterministic_after_repair = result
        audit_write_status = EvidencePacketWriteStatus(attempted=False, recorded=False)

        if self.enable_parse_audit or self.enable_rag_repair or self.audit_path or self.llm_workflow_trace_path:
            parse_report = audit_trajectory_parse(steps, events, result)
        target_index = _target_event_index(events)
        route_decision = decide_llm_route(
            parse_report=parse_report,
            rule_result=result,
            risk_flags=self._solver_risk_flags(result, events, llm_override_provenance),
            policy=self.llm_route_policy,
        )
        escalation_tokens = derive_escalation_tokens(
            parse_report=parse_report,
            route_decision=route_decision,
            rule_result=result,
            target_index=target_index,
        )

        if (
            self.enable_rag_repair
            and not self.use_llm_parse_fallback
            and parse_report is not None
            and route_decision.invoke_model
            and {"repair_event", "state_effect"} & set(route_decision.allowed_actions)
        ):
            repair_decision = self._run_rag_repair(
                parse_report,
                steps,
                events,
                state,
                result,
            )
            escalation_tokens = derive_escalation_tokens(
                parse_report=parse_report,
                route_decision=route_decision,
                rule_result=result,
                repair_decision=repair_decision,
                validation_error=getattr(repair_decision, "validation_error", None),
                target_index=target_index,
            )
            deterministic_before_repair = result
            if self._can_apply_repair(repair_decision, route_decision, escalation_tokens):
                repaired_events = _apply_repair_decision(events, repair_decision)
                repaired_state, repaired_events = self._track_state_with_stateful_disambiguation(repaired_events)
                repaired_result = judge_final(repaired_state, repaired_events[-1])
                events = repaired_events
                state = repaired_state
                result = repaired_result
                repair_applied = True
                deterministic_after_repair = repaired_result
            elif self._can_apply_state_patch(repair_decision, route_decision, escalation_tokens, events):
                apply_state_patch(state, repair_decision.state_patch)
                repaired_result = judge_final(state, events[-1])
                result = repaired_result
                repair_applied = True
                deterministic_after_repair = repaired_result

        if self.audit_path and parse_report is not None:
            audit_write_status = self._write_audit_record(parse_report, repair_decision, result, escalation_tokens)

        if self.evidence_packet_path:
            self._write_evidence_packet(
                events=events,
                state=state,
                result=result,
                deterministic_result=deterministic_result,
                parse_report=parse_report,
                repair_decision=repair_decision,
                repair_applied=repair_applied,
                escalation_tokens=escalation_tokens,
                llm_override_provenance=llm_override_provenance,
                audit_write_status=audit_write_status,
                trajectory_id=trajectory_id,
            )

        if self.llm_workflow_trace_path:
            self._write_llm_workflow_trace(
                route_decision=route_decision,
                parse_report=parse_report,
                deterministic_before=deterministic_before_repair,
                deterministic_after=deterministic_after_repair,
                repair_decision=repair_decision,
                repair_applied=repair_applied,
                escalation_tokens=escalation_tokens,
                legacy_parse_fallback_summaries=self._legacy_parse_fallback_summaries,
                llm_override_provenance=llm_override_provenance,
                audit_write_status=audit_write_status,
                trajectory_id=trajectory_id,
            )

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

    def _write_llm_workflow_trace(
        self,
        *,
        route_decision,
        parse_report,
        deterministic_before,
        deterministic_after,
        repair_decision,
        repair_applied,
        escalation_tokens,
        legacy_parse_fallback_summaries,
        llm_override_provenance,
        audit_write_status,
        trajectory_id,
    ):
        trace = build_llm_workflow_trace(
            trajectory_id=trajectory_id,
            task="judge_target",
            profile=os.environ.get("SOLVER_PROFILE", "unknown"),
            source="solver.predict_one",
            route_decision=route_decision,
            parse_report=parse_report,
            deterministic_before=deterministic_before,
            deterministic_after=deterministic_after,
            repair_decision=repair_decision,
            repair_attempted=repair_decision is not None,
            repair_applied=repair_applied,
            escalation_tokens=escalation_tokens,
            legacy_parse_fallback_summaries=legacy_parse_fallback_summaries,
            llm_override_provenance=llm_override_provenance,
            legacy_parse_fallback_enabled=self.use_llm_parse_fallback,
            rag_repair_enabled=self.enable_rag_repair,
            parse_audit_enabled=self.enable_parse_audit,
            parse_audit_path=self.audit_path,
            parse_audit_write_status=audit_write_status,
            evidence_packet_path=self.evidence_packet_path,
            evidence_packet_enabled=bool(self.evidence_packet_path),
        )
        status = write_llm_workflow_trace(trace, self.llm_workflow_trace_path)
        if self.debug and status.error:
            print(f"llm_workflow_trace_write_error={status.error}")

    def _write_evidence_packet(
        self,
        *,
        events,
        state,
        result,
        deterministic_result,
        parse_report,
        repair_decision,
        repair_applied,
        escalation_tokens,
        llm_override_provenance,
        audit_write_status,
        trajectory_id,
    ):
        parse_attempted = parse_report is not None
        repair_attempted = repair_decision is not None
        packet = build_evidence_packet(
            trajectory_id=trajectory_id,
            task="judge_target",
            profile=os.environ.get("SOLVER_PROFILE", "unknown"),
            source="solver.predict_one",
            events=events,
            state_facts=extract_state_facts(state),
            rule_result=result,
            deterministic_result=deterministic_result,
            parse_audit_provenance=serialize_parse_audit_provenance(
                enabled=self.enable_parse_audit,
                attempted=parse_attempted,
                report=parse_report,
                write_status=audit_write_status,
                path=self.audit_path,
                reason=None if parse_attempted else "parse_audit_not_run",
            ),
            repair_provenance=serialize_repair_provenance(
                enabled=self.enable_rag_repair or self.use_llm_parse_fallback,
                attempted=repair_attempted,
                decision=repair_decision,
                applied=repair_applied,
                source="rag_repair" if repair_decision is not None else "none",
                escalation_tokens=escalation_tokens,
            ),
            llm_override_provenance=llm_override_provenance,
            subsystem_flags={
                "deterministic_first": True,
                "no_verdict_changes": not (llm_override_provenance.get("delta") or {}).get("verdict_changed", False),
                "evidence_packet_enabled": True,
                "evidence_packet_path_present": bool(self.evidence_packet_path),
                "parse_audit_enabled": self.enable_parse_audit,
                "parse_audit_path_present": bool(self.audit_path),
                "llm_parse_fallback_enabled": self.use_llm_parse_fallback,
                "rag_repair_enabled": self.enable_rag_repair,
                "trajectory_id_present": trajectory_id is not None,
            },
            risk_flags=self._solver_risk_flags(result, events, llm_override_provenance),
        )
        status = write_evidence_packet(packet, self.evidence_packet_path)
        if self.debug and status.error:
            print(f"evidence_packet_write_error={status.error}")

    def _solver_risk_flags(self, result, events, llm_override_provenance):
        flags = []
        confidence = float(getattr(result, "confidence", 0.0) or 0.0)
        if confidence >= 0.9:
            flags.append(make_risk_flag("deterministic.high_confidence", "deterministic oracle confidence is high"))
        elif confidence < 0.5:
            flags.append(make_risk_flag("deterministic.low_confidence", "deterministic oracle confidence is low"))
        if not getattr(result, "spec_refs", None):
            flags.append(make_risk_flag("deterministic.missing_spec_refs", "RuleResult.spec_refs is empty"))
        final = events[-1] if events else {}
        unknown = [
            field
            for field in ("kind", "method", "command", "object", "object_family", "status")
            if final.get(field) in {None, "unknown", ""}
        ]
        if unknown:
            flags.append(
                make_risk_flag(
                    "deterministic.unknown_fields",
                    "terminal event has unknown fields: " + ",".join(unknown),
                )
            )
        if llm_override_provenance.get("considered"):
            flags.append(make_risk_flag("override.considered", "LLM verdict override path was considered"))
        if llm_override_provenance.get("blocked_by_high_conf_deterministic"):
            flags.append(
                make_risk_flag(
                    "override.blocked_by_high_conf_deterministic",
                    "LLM verdict override was blocked by trusted deterministic result",
                )
            )
        if llm_override_provenance.get("applied") and llm_override_provenance.get("delta", {}).get("verdict_changed"):
            flags.append(
                make_risk_flag(
                    "override.verdict_changed_unexpected",
                    "LLM verdict override changed the final verdict",
                )
            )
        return flags

    def _track_state_with_stateful_disambiguation(self, events):
        repaired_events = [dict(event) for event in events]
        state = initial_state()
        for position, event in enumerate(events[:-1]):
            repaired_event = self._stateful_disambiguate_method(event, state)
            repaired_events[position] = repaired_event
            apply_event(state, repaired_event)
            self._record_failed_observation(state, repaired_event)
        repaired_events[-1] = self._stateful_disambiguate_method(events[-1], state)
        return state, repaired_events

    def _track_state_with_parser_fallback(self, raw_steps, events):
        repaired_events = [dict(event) for event in events]
        state = initial_state()
        for position, event in enumerate(events[:-1]):
            raw_step = raw_steps[position] if position < len(raw_steps) else {}
            repaired_event, decision = self._repair_pre_target_event(raw_step, event, state)
            repaired_event = self._stateful_disambiguate_method(repaired_event, state)
            repaired_events[position] = repaired_event
            apply_event(state, repaired_event)
            self._record_failed_observation(state, repaired_event, raw_step)
            self._apply_pre_target_state_patch(decision, state, repaired_event)

        final_raw = raw_steps[-1] if raw_steps else {}
        target_event = self._repair_target_event(final_raw, events[-1], state)
        repaired_events[-1] = self._stateful_disambiguate_method(target_event, state)
        return state, repaired_events

    def _stateful_disambiguate_method(self, event, state):
        if not event.get("method_inferred"):
            return event
        if (
            event.get("method") == "Activate"
            and event.get("object") == "LockingSP"
            and state.get("locking_sp_active") is True
            and not event.get("required_parameters")
            and not event.get("optional_parameters")
        ):
            updated = dict(event)
            updated["method"] = "RevertSP"
            updated["method_inferred_from_state"] = True
            if self.debug:
                print(
                    "[parser] inferred no-arg LockingSP method as RevertSP "
                    "because LockingSP is already active"
                )
            return updated
        return event

    def _record_failed_observation(self, state, event, raw_step=None):
        try:
            status_class = actual_status_class(event)
        except Exception:  # noqa: BLE001
            status_class = str(event.get("status") or "")
        if status_class in {"success", "data_success"}:
            return

        observation = {
            "index": event.get("index"),
            "kind": event.get("kind"),
            "method": event.get("method"),
            "command": event.get("command"),
            "object": event.get("object"),
            "object_family": event.get("object_family"),
            "status": event.get("status"),
            "status_class": status_class,
            "authority": event.get("authority"),
            "sp": event.get("sp") or (state.get("session") or {}).get("sp"),
            "reason_signal": _failed_observation_signal(event),
        }
        if isinstance(raw_step, dict):
            raw_input = raw_step.get("input") if isinstance(raw_step.get("input"), dict) else {}
            raw_output = raw_step.get("output") if isinstance(raw_step.get("output"), dict) else {}
            observation["raw_method"] = _raw_method_name(raw_input)
            observation["raw_status"] = raw_output.get("status_codes") or raw_input.get("status_codes")
        state.setdefault("failed_observations", []).append(observation)
        if len(state["failed_observations"]) > 32:
            state["failed_observations"] = state["failed_observations"][-32:]

    def _repair_pre_target_event(self, raw_step, event, state):
        if not should_repair_event(
            event,
            include_no_family=os.environ.get("LLM_PARSE_REPAIR_NO_FAMILY_PRETARGET", "0") == "1",
            include_non_rw_commands=os.environ.get("LLM_PARSE_REPAIR_NON_RW_COMMANDS_PRETARGET", "0") == "1",
        ):
            return event, None
        decision = self.llm_parse_fallback.repair_event(
            raw_step=raw_step,
            normalized_event=event,
            state=state,
            is_target=False,
        )
        if decision.usable and decision.normalized_event:
            repaired = merge_event_patch(event, decision.normalized_event)
            self._record_legacy_parse_fallback_summary(
                decision,
                event=event,
                is_target=False,
                applied=True,
            )
            if self.debug:
                print(
                    f"[llm-parse] repaired pre-target event index={event.get('index')} "
                    f"confidence={decision.confidence:.2f} reason={decision.reason}"
                )
            return repaired, decision
        self._record_legacy_parse_fallback_summary(
            decision,
            event=event,
            is_target=False,
            applied=False,
        )
        return event, decision

    def _apply_pre_target_state_patch(self, decision, state, event=None):
        if decision is None or not decision.usable or not decision.state_patch:
            return
        if event is not None and is_state_machine_interpretable(event):
            # apply_event already replayed this modeled method; an LLM patch on
            # top overwrites correct tracked state (observed on EndSession:
            # bogus sp_lifecycle/locking_sp_active resets flipping verdicts).
            if self.debug:
                keys = ",".join(sorted(decision.state_patch)) or "none"
                print(
                    f"[llm-parse] skipped state patch keys={keys} for "
                    f"interpretable event index={event.get('index')}"
                )
            return
        if self.debug:
            keys = ",".join(sorted(decision.state_patch)) or "none"
            print(
                f"[llm-parse] applying state patch keys={keys} "
                f"confidence={decision.confidence:.2f} reason={decision.reason}"
            )
        apply_state_patch(state, decision.state_patch)

    def _repair_target_event(self, raw_step, event, state):
        if not should_repair_event(event):
            return event
        decision = self.llm_parse_fallback.repair_event(
            raw_step=raw_step,
            normalized_event=event,
            state=state,
            is_target=True,
        )
        if decision.usable and decision.normalized_event:
            repaired = merge_event_patch(event, decision.normalized_event)
            self._record_legacy_parse_fallback_summary(
                decision,
                event=event,
                is_target=True,
                applied=True,
            )
            if self.debug:
                print(
                    f"[llm-parse] repaired target event index={event.get('index')} "
                    f"confidence={decision.confidence:.2f} reason={decision.reason}"
                )
            return repaired
        self._record_legacy_parse_fallback_summary(
            decision,
            event=event,
            is_target=True,
            applied=False,
        )
        return event

    def _record_legacy_parse_fallback_summary(self, decision, *, event, is_target, applied):
        if decision is None:
            return
        normalized_event = decision.normalized_event if isinstance(decision.normalized_event, dict) else {}
        state_patch = decision.state_patch if isinstance(decision.state_patch, dict) else {}
        self._legacy_parse_fallback_summaries.append(
            {
                "step_index": event.get("index") if isinstance(event, dict) else None,
                "is_target": bool(is_target),
                "attempted": True,
                "applied": bool(applied),
                "usable": bool(decision.usable),
                "confidence": float(decision.confidence or 0.0),
                "reason": decision.reason or "",
                "event_patch_fields": sorted(str(key) for key in normalized_event),
                "state_patch_fields": sorted(str(key) for key in state_patch),
            }
        )
        if len(self._legacy_parse_fallback_summaries) > 16:
            self._legacy_parse_fallback_summaries = self._legacy_parse_fallback_summaries[-16:]

    def _maybe_llm_target_verdict(self, raw_step, event, state, result):
        updated, _provenance = self._maybe_llm_target_verdict_with_provenance(raw_step, event, state, result)
        return updated

    def _maybe_llm_target_verdict_with_provenance(self, raw_step, event, state, result):
        has_failed_context = (
            bool(state.get("failed_observations"))
            and os.environ.get("LLM_PARSE_JUDGE_WITH_FAILURE_CONTEXT", "0") == "1"
        )
        if not should_judge_with_llm(event, result) and not has_failed_context:
            return result, serialize_llm_override_provenance(
                enabled=self.use_llm_parse_fallback,
                considered=False,
                trusted_deterministic=should_trust_deterministic_verdict(result),
                from_verdict=result.verdict,
                to_verdict=result.verdict,
            )
        decision = self.llm_parse_fallback.judge_target(
            raw_step=raw_step,
            normalized_event=event,
            state=state,
            rule_result=result,
        )
        if not decision.usable or decision.verdict not in {"pass", "fail"}:
            return result, serialize_llm_override_provenance(
                enabled=self.use_llm_parse_fallback,
                considered=True,
                attempted=True,
                decision=decision,
                trusted_deterministic=should_trust_deterministic_verdict(result),
                from_verdict=result.verdict,
                to_verdict=result.verdict,
                reason="llm_decision_not_usable",
            )
        if should_trust_deterministic_verdict(result):
            if self.debug:
                print(
                    "[llm-parse] ignored target verdict override because "
                    "deterministic oracle is implemented/high-confidence"
                )
            return result, serialize_llm_override_provenance(
                enabled=self.use_llm_parse_fallback,
                considered=True,
                attempted=True,
                applied=False,
                blocked_by_high_conf_deterministic=True,
                trusted_deterministic=True,
                decision=decision,
                from_verdict=result.verdict,
                to_verdict=result.verdict,
                reason="blocked_by_high_conf_deterministic",
            )
        if not self.allow_llm_verdict_override:
            if self.debug:
                print(
                    "[llm-parse] ignored target verdict override because "
                    "LLM_ALLOW_VERDICT_OVERRIDE is not enabled"
                )
            return result, serialize_llm_override_provenance(
                enabled=self.use_llm_parse_fallback,
                considered=True,
                attempted=True,
                applied=False,
                blocked_by_high_conf_deterministic=False,
                trusted_deterministic=False,
                decision=decision,
                from_verdict=result.verdict,
                to_verdict=result.verdict,
                reason="llm_verdict_override_disabled",
                allow_verdict_override=False,
            )
        if self.debug:
            print(
                f"[llm-parse] target verdict={decision.verdict} "
                f"confidence={decision.confidence:.2f} reason={decision.reason}"
            )
        updated = RuleResult(
            verdict=decision.verdict,
            confidence=decision.confidence,
            reason=decision.reason or result.reason,
            expected_status=result.expected_status,
            actual_status=result.actual_status,
            spec_refs=result.spec_refs,
            policy_source="llm_parse_fallback",
            coverage_status="llm_override",
        )
        return updated, serialize_llm_override_provenance(
            enabled=self.use_llm_parse_fallback,
            considered=True,
            attempted=True,
            applied=True,
            decision=decision,
            trusted_deterministic=False,
            from_verdict=result.verdict,
            to_verdict=updated.verdict,
            allow_verdict_override=True,
        )

    def _run_rag_repair(self, parse_report, raw_steps, events, state, result):
        from .rag_parser_repair import run_parser_repair, suggest_repair_without_llm

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

    def _can_apply_repair(self, decision, route_decision, escalation_tokens) -> bool:
        return self.rag_apply_repairs and can_apply_repair_decision(
            {},
            decision,
            route_decision,
            escalation_tokens,
            self.llm_route_policy,
        )

    def _can_apply_state_patch(self, decision, route_decision, escalation_tokens, events) -> bool:
        event = _event_for_repair_decision(events, decision)
        return self.rag_apply_repairs and can_apply_state_patch(
            event,
            decision,
            route_decision,
            escalation_tokens,
            self.llm_route_policy,
        )

    def _write_audit_record(self, parse_report, repair_decision, result, escalation_tokens):
        record = {
            "parse_report": _plain(parse_report),
            "repair_decision": _repair_decision_audit_summary(repair_decision),
            "final_result": _plain(result),
            "escalation_tokens": list(escalation_tokens or ()),
        }
        path = Path(self.audit_path)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=True, sort_keys=True) + "\n")
            return EvidencePacketWriteStatus(
                attempted=True,
                recorded=True,
                path=str(path),
                error=None,
            )
        except OSError as exc:
            if self.debug:
                print(f"audit_write_error={exc}")
            return EvidencePacketWriteStatus(
                attempted=True,
                recorded=False,
                path=str(path),
                error=str(exc),
            )


def _failed_observation_signal(event):
    method = event.get("method")
    if method in {"Authenticate", "StartSession"}:
        return "auth_or_credential_evidence"
    if method in {"Set", "Get"}:
        return "table_access_or_value_evidence"
    if method in {"Activate", "RevertSP", "Revert"}:
        return "sp_lifecycle_evidence"
    if event.get("kind") in {"read", "write"}:
        return "data_command_evidence"
    if event.get("status"):
        return "failure_status_evidence"
    return "unknown_failure_evidence"


def _raw_method_name(raw_input):
    method = raw_input.get("method") if isinstance(raw_input, dict) else None
    if isinstance(method, dict):
        return method.get("name") or method.get("uid")
    return raw_input.get("command") if isinstance(raw_input, dict) else None


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


def _repair_decision_audit_summary(decision: Any) -> Any:
    if decision is None:
        return None
    event_patch = getattr(decision, "event_patch", None) or {}
    state_patch = getattr(decision, "state_patch", None) or {}
    evidence = getattr(decision, "evidence", None) or []
    return {
        "action": getattr(decision, "action", None),
        "confidence": getattr(decision, "confidence", None),
        "reason": _safe_audit_reason(getattr(decision, "reason", None)),
        "step_index": getattr(decision, "step_index", None),
        "event_patch": _plain(event_patch),
        "state_effect": getattr(decision, "state_effect", None),
        "state_patch_present": bool(state_patch),
        "state_patch_fields": sorted(str(key) for key in state_patch) if isinstance(state_patch, dict) else [],
        "validation_error": getattr(decision, "validation_error", None),
        "evidence_count": len(evidence),
    }


def _target_event_index(events: list[dict[str, Any]] | tuple[dict[str, Any], ...]) -> int | None:
    if not events:
        return None
    final = events[-1]
    if isinstance(final, dict) and isinstance(final.get("index"), int):
        return final["index"]
    return len(events) - 1


def _safe_audit_reason(reason: Any) -> Any:
    if reason is None:
        return None
    text = str(reason)
    marker = "; raw="
    if marker in text:
        text = text.split(marker, 1)[0] + "; raw=<omitted>"
    return text[:500]


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


def _event_for_repair_decision(events, decision):
    if not events:
        return {}
    target = getattr(decision, "step_index", None)
    index = None
    if target is not None:
        for pos, event in enumerate(events):
            if isinstance(event, dict) and event.get("index") == target:
                index = pos
                break
        if index is None and isinstance(target, int) and 0 <= target < len(events):
            index = target
    if index is None:
        index = len(events) - 1
    event = dict(events[index])
    event["is_target"] = index == len(events) - 1
    return event


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}

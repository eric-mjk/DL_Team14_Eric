from __future__ import annotations

import json
from dataclasses import asdict, dataclass, is_dataclass
from datetime import UTC, datetime
from pathlib import Path
import re
from typing import Any
from uuid import uuid4

from .rag_schema import ALLOWED_EVENT_PATCH_FIELDS


SCHEMA_VERSION = "llm_workflow_trace_v1"
MAX_TEXT_CHARS = 320
MAX_REASON_CHARS = 500
MAX_LIST_ITEMS = 16
MAX_EVIDENCE_TEXT_CHARS = 260

SENSITIVE_EVENT_PATCH_FIELDS = {
    "parameters",
    "required_parameters",
    "optional_parameters",
    "values",
    "where",
}

FORBIDDEN_KEYS = {
    "raw_step",
    "raw_steps",
    "_state_snapshot",
    "state_snapshot",
    "state",
    "prompt",
    "raw_prompt",
    "system_prompt",
    "user_prompt",
    "response",
    "raw_response",
    "_raw_model_response",
    "recent_history",
    "recent_failed_observations",
}

SENSITIVE_KEY_FRAGMENTS = (
    "credential",
    "password",
    "passwd",
    "secret",
    "pin",
    "proof",
    "challenge",
    "token",
    "private",
)

SENSITIVE_VALUE_PATTERN = re.compile(
    r"(credential|password|passwd|secret|pin|proof|challenge|token|_raw_model_response|raw model response)",
    flags=re.IGNORECASE,
)


@dataclass(frozen=True)
class LLMWorkflowTraceWriteStatus:
    attempted: bool
    recorded: bool
    path: str | None = None
    record_id: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def write_llm_workflow_trace(record: dict[str, Any], path: str | Path | None) -> LLMWorkflowTraceWriteStatus:
    """Append one bounded LLM workflow trace record to ``path`` as JSONL.

    This writer is observational only: write errors are returned as status
    instead of changing solver prediction behavior.
    """

    if not path:
        return LLMWorkflowTraceWriteStatus(attempted=False, recorded=False)

    record_id = str(uuid4())
    trace = sanitize_trace_value(record)
    if not isinstance(trace, dict):
        trace = {"payload": trace}
    trace.setdefault("identity", {})
    if isinstance(trace["identity"], dict):
        trace["identity"].setdefault("record_id", record_id)

    target = Path(path)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(trace, ensure_ascii=True, sort_keys=True) + "\n")
    except OSError as exc:
        return LLMWorkflowTraceWriteStatus(
            attempted=True,
            recorded=False,
            path=str(target),
            record_id=record_id,
            error=str(exc),
        )
    return LLMWorkflowTraceWriteStatus(
        attempted=True,
        recorded=True,
        path=str(target),
        record_id=record_id,
        error=None,
    )


def build_llm_workflow_trace(
    *,
    trajectory_id: str | None,
    task: str,
    profile: str,
    source: str,
    route_decision: Any = None,
    parse_report: Any = None,
    deterministic_before: Any = None,
    deterministic_after: Any = None,
    repair_decision: Any = None,
    repair_applied: bool = False,
    repair_attempted: bool = False,
    legacy_parse_fallback_summaries: list[dict[str, Any]] | None = None,
    llm_override_provenance: dict[str, Any] | None = None,
    legacy_parse_fallback_enabled: bool = False,
    rag_repair_enabled: bool = False,
    parse_audit_enabled: bool = False,
    parse_audit_path: str | None = None,
    parse_audit_write_status: Any = None,
    evidence_packet_path: str | None = None,
    evidence_packet_enabled: bool = False,
) -> dict[str, Any]:
    """Build the compact process-audit trace for parser/LLM/RAG workflow.

    The trace is a bounded index for humans/LLMs, not a raw debug dump. It
    deliberately summarizes route decisions, parse risks, repair decisions,
    merge/application status, and final deterministic provenance.
    """

    before_summary = serialize_rule_result(deterministic_before)
    after_summary = serialize_rule_result(deterministic_after)
    repair_summary = serialize_repair_decision(
        repair_decision,
        enabled=rag_repair_enabled,
        attempted=repair_attempted,
        applied=repair_applied,
    )
    rag_summary = {
        "enabled": bool(rag_repair_enabled),
        "attempted": bool(repair_attempted),
        "model_called": bool(repair_summary.get("model_called")),
        "evidence": repair_summary.get("evidence", []),
        "evidence_count": repair_summary.get("evidence_count", 0),
        "retrieval_query_available": False,
    }
    final_source = "deterministic"
    if llm_override_provenance and llm_override_provenance.get("applied"):
        final_source = "llm_parse_fallback"

    return sanitize_trace_value(
        {
            "schema_version": SCHEMA_VERSION,
            "emitted_at": datetime.now(UTC).isoformat(),
            "identity": {
                "trajectory_id": trajectory_id,
                "task": task,
                "profile": profile,
                "source": source,
            },
            "artifact_policy": {
                "bounded_summary_only": True,
                "legacy_parse_audit_cross_reference_only": True,
                "parse_audit_path_present": bool(parse_audit_path),
                "parse_audit_path": parse_audit_path if parse_audit_path else None,
                "evidence_packet_path_present": bool(evidence_packet_path),
                "evidence_packet_path": evidence_packet_path if evidence_packet_path else None,
            },
            "route": serialize_route_decision(route_decision),
            "parse_audit": serialize_parse_audit(
                parse_report,
                enabled=parse_audit_enabled,
                write_status=parse_audit_write_status,
            ),
            "legacy_parse_fallback": {
                "enabled": bool(legacy_parse_fallback_enabled),
                "coverage": "bounded_repair_and_override_provenance_only",
                "raw_debug_audit_separate": True,
                "repairs": sanitize_trace_value(legacy_parse_fallback_summaries or []),
                "repair_count": len(legacy_parse_fallback_summaries or []),
            },
            "rag": rag_summary,
            "repair": repair_summary,
            "rag_repair": repair_summary,
            "deterministic_before": before_summary,
            "deterministic_after": after_summary,
            "merge": {
                "repair_attempted": bool(repair_attempted),
                "repair_applied": bool(repair_applied),
                "application": "applied_and_rejudged" if repair_applied else "not_applied",
                "deterministic_before": before_summary,
                "deterministic_after": after_summary,
                "verdict_changed_by_repair": _verdict(before_summary) != _verdict(after_summary),
            },
            "verdict_policy": {
                "deterministic_first": True,
                "final_verdict_source": final_source,
                "direct_llm_verdict_override_allowed": bool(
                    llm_override_provenance and llm_override_provenance.get("allow_verdict_override")
                ),
                "llm_override": sanitize_trace_value(llm_override_provenance or {}),
            },
            "subsystem_flags": {
                "parse_audit_enabled": bool(parse_audit_enabled),
                "llm_parse_fallback_enabled": bool(legacy_parse_fallback_enabled),
                "rag_repair_enabled": bool(rag_repair_enabled),
                "evidence_packet_enabled": bool(evidence_packet_enabled),
                "workflow_trace_enabled": True,
            },
        }
    )


def serialize_route_decision(decision: Any) -> dict[str, Any]:
    if decision is None:
        return {
            "route": "unknown",
            "reason": "route decision not computed",
            "confidence": 0.0,
            "risk_codes": [],
            "allowed_actions": [],
            "invoke_model": False,
            "allow_verdict_override": False,
        }
    return {
        "route": str(getattr(decision, "route", "unknown") or "unknown"),
        "reason": _bounded_text(getattr(decision, "reason", "") or "", MAX_REASON_CHARS),
        "confidence": _bounded_float(getattr(decision, "confidence", 0.0)),
        "risk_codes": [str(code) for code in list(getattr(decision, "risk_codes", ()) or ())[:MAX_LIST_ITEMS]],
        "allowed_actions": [
            str(action) for action in list(getattr(decision, "allowed_actions", ()) or ())[:MAX_LIST_ITEMS]
        ],
        "invoke_model": bool(getattr(decision, "invoke_model", False)),
        "allow_verdict_override": bool(getattr(decision, "allow_verdict_override", False)),
    }


def serialize_parse_audit(report: Any, *, enabled: bool, write_status: Any = None) -> dict[str, Any]:
    if report is None:
        return {
            "enabled": bool(enabled),
            "attempted": False,
            "risk_score": 0,
            "should_run_rag": False,
            "issue_count": 0,
            "issues": [],
            "write_status": _write_status_summary(write_status),
        }
    issues = []
    for issue in list(getattr(report, "issues", ()) or ())[:MAX_LIST_ITEMS]:
        issues.append(
            {
                "severity": str(getattr(issue, "severity", "") or ""),
                "kind": str(getattr(issue, "kind", "") or ""),
                "step_index": getattr(issue, "step_index", None),
                "path": _bounded_text(getattr(issue, "path", "") or "", 160),
                "message": _bounded_text(getattr(issue, "message", "") or "", MAX_REASON_CHARS),
            }
        )
    return {
        "enabled": bool(enabled),
        "attempted": True,
        "risk_score": _bounded_int(getattr(report, "risk_score", 0)),
        "should_run_rag": bool(getattr(report, "should_run_rag", False)),
        "issue_count": len(getattr(report, "issues", ()) or ()),
        "issues": issues,
        "write_status": _write_status_summary(write_status),
    }


def serialize_rule_result(result: Any) -> dict[str, Any]:
    if result is None:
        return {
            "present": False,
            "verdict": None,
            "confidence": 0.0,
            "policy_source": None,
            "coverage_status": None,
            "reason": None,
            "expected_status": None,
            "actual_status": None,
            "spec_refs": [],
        }
    return {
        "present": True,
        "verdict": str(getattr(result, "verdict", "") or ""),
        "confidence": _bounded_float(getattr(result, "confidence", 0.0)),
        "policy_source": str(getattr(result, "policy_source", "") or ""),
        "coverage_status": str(getattr(result, "coverage_status", "") or ""),
        "reason": _bounded_text(getattr(result, "reason", "") or "", MAX_REASON_CHARS),
        "expected_status": _bounded_text(getattr(result, "expected_status", "") or "", MAX_TEXT_CHARS),
        "actual_status": _bounded_text(getattr(result, "actual_status", "") or "", MAX_TEXT_CHARS),
        "spec_refs": [str(ref) for ref in list(getattr(result, "spec_refs", ()) or ())[:MAX_LIST_ITEMS]],
    }


def serialize_repair_decision(
    decision: Any,
    *,
    enabled: bool,
    attempted: bool,
    applied: bool,
) -> dict[str, Any]:
    evidence = []
    for chunk in list(getattr(decision, "evidence", ()) or ())[:MAX_LIST_ITEMS]:
        evidence.append(
            {
                "section": _bounded_text(getattr(chunk, "section", "") or "", 180),
                "path": _bounded_text(getattr(chunk, "path", "") or "", 240),
                "title": _bounded_text(getattr(chunk, "title", "") or "", 180),
                "score": _bounded_float(getattr(chunk, "score", 0.0)),
                "text_summary": _bounded_text(getattr(chunk, "text", "") or "", MAX_EVIDENCE_TEXT_CHARS),
            }
        )

    if decision is None:
        return {
            "enabled": bool(enabled),
            "attempted": bool(attempted),
            "applied": bool(applied),
            "model_called": False,
            "action": None,
            "confidence": 0.0,
            "usable": False,
            "reason": None,
            "step_index": None,
            "event_patch": {},
            "state_effect": None,
            "evidence": evidence,
            "evidence_count": 0,
        }

    raw = getattr(decision, "raw", {}) or {}
    model_called = isinstance(raw, dict) and "_raw_model_response" in raw
    patch = getattr(decision, "event_patch", None) or {}
    safe_patch = _safe_event_patch(patch)
    return {
        "enabled": bool(enabled),
        "attempted": True,
        "applied": bool(applied),
        "model_called": bool(model_called),
        "action": str(getattr(decision, "action", "") or ""),
        "confidence": _bounded_float(getattr(decision, "confidence", 0.0)),
        "usable": bool(getattr(decision, "usable", False)),
        "reason": _safe_reason(getattr(decision, "reason", "") or ""),
        "step_index": getattr(decision, "step_index", None),
        "event_patch": safe_patch,
        "state_effect": _bounded_text(getattr(decision, "state_effect", "") or "", 120)
        if getattr(decision, "state_effect", None) is not None
        else None,
        "evidence": evidence,
        "evidence_count": len(getattr(decision, "evidence", ()) or ()),
    }


def sanitize_trace_value(value: Any) -> Any:
    """Return a JSON-safe bounded value with raw/debug/secrets removed."""

    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return _bounded_text(value, MAX_TEXT_CHARS)
    if is_dataclass(value):
        return sanitize_trace_value(asdict(value))
    if isinstance(value, dict):
        safe: dict[str, Any] = {}
        for key, item in value.items():
            text_key = str(key)
            if _is_forbidden_key(text_key):
                continue
            if _is_sensitive_key(text_key):
                safe[text_key] = "<redacted>"
            else:
                safe[text_key] = sanitize_trace_value(item)
        return safe
    if isinstance(value, (list, tuple, set)):
        return [sanitize_trace_value(item) for item in list(value)[:MAX_LIST_ITEMS]]
    return _bounded_text(repr(value), MAX_TEXT_CHARS)


def _safe_event_patch(patch: dict[str, Any]) -> dict[str, Any]:
    safe_patch: dict[str, Any] = {}
    for key, value in patch.items():
        text_key = str(key)
        if text_key not in ALLOWED_EVENT_PATCH_FIELDS or _is_forbidden_key(text_key):
            continue
        if text_key in SENSITIVE_EVENT_PATCH_FIELDS:
            safe_patch[text_key] = _shape_summary(value)
        elif _is_sensitive_key(text_key):
            safe_patch[text_key] = "<redacted>"
        else:
            safe_patch[text_key] = sanitize_trace_value(value)
    return safe_patch


def _shape_summary(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return {
            "omitted": True,
            "kind": "object",
            "key_count": len(value),
            "keys": [str(key) for key in list(value)[:MAX_LIST_ITEMS]],
        }
    if isinstance(value, (list, tuple, set)):
        return {"omitted": True, "kind": "list", "item_count": len(value)}
    return {"omitted": True, "kind": type(value).__name__}


def _safe_reason(value: Any) -> str:
    text = str(value or "")
    for marker in ("; raw=", " raw=", "raw="):
        index = text.find(marker)
        if index >= 0:
            text = text[:index] + " model-output=<omitted>"
            break
    return _bounded_text(text, MAX_REASON_CHARS)


def _write_status_summary(status: Any) -> dict[str, Any]:
    if status is None:
        return {"attempted": False, "recorded": False, "path_present": False, "record_id": None, "error": None}
    return {
        "attempted": bool(getattr(status, "attempted", False)),
        "recorded": bool(getattr(status, "recorded", False)),
        "path_present": bool(getattr(status, "path", None)),
        "record_id": getattr(status, "record_id", None),
        "error": _bounded_text(getattr(status, "error", "") or "", MAX_TEXT_CHARS)
        if getattr(status, "error", None)
        else None,
    }


def _bounded_text(value: Any, limit: int) -> str:
    text = _scrub_forbidden_text(str(value))
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 15)].rstrip() + "...<truncated>"


def _scrub_forbidden_text(text: str) -> str:
    replacements = {
        "raw_step": "raw-step",
        "_state_snapshot": "state-snapshot",
        "state_snapshot": "state-snapshot",
        "prompt": "model-input",
        "Prompt": "Model-input",
        "PROMPT": "MODEL-INPUT",
        "response": "model-output",
        "Response": "Model-output",
        "RESPONSE": "MODEL-OUTPUT",
    }
    for needle, replacement in replacements.items():
        text = text.replace(needle, replacement)
    if SENSITIVE_VALUE_PATTERN.search(text):
        return "<redacted>"
    return text


def _bounded_float(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    if number < 0.0:
        return 0.0
    if number > 1.0:
        return 1.0
    return number


def _bounded_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _is_forbidden_key(key: str) -> bool:
    return key.strip().lower() in FORBIDDEN_KEYS


def _is_sensitive_key(key: str) -> bool:
    lowered = key.strip().lower()
    return any(fragment in lowered for fragment in SENSITIVE_KEY_FRAGMENTS)


def _verdict(summary: Any) -> str | None:
    if isinstance(summary, dict):
        value = summary.get("verdict")
        return str(value) if value is not None else None
    return None


__all__ = [
    "SCHEMA_VERSION",
    "LLMWorkflowTraceWriteStatus",
    "build_llm_workflow_trace",
    "sanitize_trace_value",
    "serialize_parse_audit",
    "serialize_repair_decision",
    "serialize_route_decision",
    "serialize_rule_result",
    "write_llm_workflow_trace",
]

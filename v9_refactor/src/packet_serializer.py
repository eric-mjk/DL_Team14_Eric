from __future__ import annotations

import re
from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime
from typing import Any


SCHEMA_VERSION = "v2"
NORMALIZED_EVENTS_POLICY_VERSION = "normalized_events_v1"
RISK_FLAGS_TAXONOMY_VERSION = "risk_flags_v1"

DEFAULT_EVENT_CAP = 16
DEFAULT_HEAD_COUNT = 8
DEFAULT_TAIL_COUNT = 8

NORMALIZED_EVENT_FIELDS = (
    "index",
    "kind",
    "method",
    "command",
    "object",
    "object_family",
    "status",
    "reason",
    "confidence",
    "verdict",
)

TERMINAL_EVENT_FIELDS = (
    "index",
    "kind",
    "method",
    "command",
    "object",
    "object_family",
    "status",
)

ALLOWED_RISK_CODES = frozenset(
    {
        "parse_audit.enabled",
        "parse_audit.record_written",
        "parse_audit.write_error",
        "parse_audit.record_missing",
        "repair.attempted",
        "repair.applied",
        "repair.noop",
        "repair.event_delta",
        "repair.state_delta",
        "override.considered",
        "override.blocked_by_high_conf_deterministic",
        "override.attempted",
        "override.applied",
        "override.verdict_changed_unexpected",
        "deterministic.high_confidence",
        "deterministic.low_confidence",
        "deterministic.missing_spec_refs",
        "deterministic.ambiguous_fields",
        "deterministic.unknown_fields",
        "deterministic.rule_conflict",
        "packet.normalized_events_truncated",
        "packet.state_facts_truncated",
        "packet.schema_mismatch",
        "packet.required_field_missing",
    }
)

RISK_PRODUCER_BY_PREFIX = {
    "parse_audit.": "parse_audit",
    "repair.": "repair",
    "override.": "solver",
    "deterministic.": "solver",
    "packet.": "serializer",
}

RISK_DEFAULT_SEVERITY = {
    "parse_audit.enabled": "info",
    "parse_audit.record_written": "info",
    "repair.attempted": "info",
    "override.considered": "info",
    "override.blocked_by_high_conf_deterministic": "info",
    "deterministic.high_confidence": "info",
    "repair.applied": "warn",
    "repair.noop": "warn",
    "deterministic.low_confidence": "warn",
    "deterministic.missing_spec_refs": "warn",
    "deterministic.ambiguous_fields": "warn",
    "packet.normalized_events_truncated": "warn",
    "packet.state_facts_truncated": "warn",
    "parse_audit.write_error": "error",
    "override.verdict_changed_unexpected": "error",
    "deterministic.rule_conflict": "error",
    "packet.schema_mismatch": "error",
    "packet.required_field_missing": "error",
}

SENSITIVE_REASON_PATTERN = re.compile(
    r"(credential|password|passwd|secret|pin|proof|challenge|token|_raw_model_response|raw model response)",
    flags=re.IGNORECASE,
)


def build_evidence_packet(
    *,
    trajectory_id: str | None = None,
    task: str = "judge_target",
    profile: str = "unknown",
    source: str = "solver.predict_one",
    events: list[dict[str, Any]] | None = None,
    state_facts: dict[str, Any] | None = None,
    rule_result: Any = None,
    deterministic_result: Any = None,
    parse_audit_provenance: dict[str, Any] | None = None,
    repair_provenance: dict[str, Any] | None = None,
    llm_override_provenance: dict[str, Any] | None = None,
    subsystem_flags: dict[str, Any] | None = None,
    risk_flags: list[dict[str, Any]] | None = None,
    emitted_at_utc: str | None = None,
) -> dict[str, Any]:
    """Package precomputed facts into the v2 evidence packet schema."""

    events = events or []
    result = rule_result or deterministic_result
    deterministic = deterministic_result or rule_result
    normalized_events = serialize_normalized_events(events)
    rule_trace = serialize_rule_trace(deterministic, llm_override_provenance)
    spec_refs = _dedupe(
        list(_get(deterministic, "spec_refs", ()) or ())
        + list(_get(result, "spec_refs", ()) or ())
    )
    merged_flags = []
    merged_flags.extend(risk_flags or [])
    merged_flags.extend(_derive_serializer_risk_flags(normalized_events, state_facts))

    return _json_ready(
        {
            "schema_version": SCHEMA_VERSION,
            "identity": {
                "trajectory_id": trajectory_id,
                "task": task,
                "profile": profile,
                "source": source,
                "emitted_at_utc": emitted_at_utc or datetime.now(UTC).isoformat(),
            },
            "final_view": serialize_final_view(result, events[-1] if events else None, llm_override_provenance),
            "normalized_events": normalized_events,
            "state_facts": state_facts or {},
            "rule_trace": rule_trace,
            "spec_references": spec_refs,
            "risk_flags_taxonomy_version": RISK_FLAGS_TAXONOMY_VERSION,
            "risk_flags": serialize_risk_flags(merged_flags),
            "provenance": {
                "parse_audit": parse_audit_provenance or serialize_parse_audit_provenance(enabled=False),
                "repair": repair_provenance or serialize_repair_provenance(enabled=False),
                "llm_verdict_override": llm_override_provenance
                or serialize_llm_override_provenance(enabled=False),
            },
            "subsystem_flags": _default_subsystem_flags(
                subsystem_flags,
                trajectory_id,
                llm_override_provenance,
            ),
        }
    )


def serialize_normalized_events(
    events: list[dict[str, Any]] | None,
    *,
    cap: int = DEFAULT_EVENT_CAP,
    head_count: int = DEFAULT_HEAD_COUNT,
    tail_count: int = DEFAULT_TAIL_COUNT,
) -> dict[str, Any]:
    events = events or []
    total = len(events)
    if total <= cap:
        selected = list(events)
        mode = "full"
        omitted_span = {"start_index": None, "end_index": None, "count": 0}
    else:
        head = list(events[:head_count])
        tail = list(events[-tail_count:]) if tail_count else []
        selected = head + tail
        mode = "bounded_head_tail"
        omitted_count = max(total - len(selected), 0)
        omitted_span = {
            "start_index": head_count,
            "end_index": max(total - tail_count - 1, head_count - 1),
            "count": omitted_count,
        }

    truncated = total > len(selected)
    return {
        "policy": {
            "version": NORMALIZED_EVENTS_POLICY_VERSION,
            "mode": mode,
            "cap": cap,
            "head_count": head_count,
            "tail_count": tail_count,
            "omitted_span": omitted_span,
        },
        "total_count": total,
        "included_count": len(selected),
        "truncated": truncated,
        "omitted_count": total - len(selected),
        "slice_start_index": _event_index(selected[0], 0) if selected else None,
        "slice_end_index": _event_index(selected[-1], len(selected) - 1) if selected else None,
        "items": [_compact_event(event, NORMALIZED_EVENT_FIELDS) for event in selected],
    }


def serialize_final_view(
    result: Any,
    terminal_event: dict[str, Any] | None,
    llm_override_provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "verdict": _get(result, "verdict"),
        "expected_status": _get(result, "expected_status"),
        "actual_status": _get(result, "actual_status"),
        "confidence": _get(result, "confidence"),
        "reason": _get(result, "reason"),
        "policy_source": _get(result, "policy_source"),
        "coverage_status": _get(result, "coverage_status"),
        "verdict_changed_by_llm": bool(
            ((llm_override_provenance or {}).get("delta") or {}).get("verdict_changed")
        ),
        "terminal_event_summary": _compact_event(terminal_event or {}, TERMINAL_EVENT_FIELDS),
    }


def serialize_rule_trace(deterministic_result: Any, override_provenance: dict[str, Any] | None = None) -> dict[str, Any]:
    override = override_provenance or {}
    delta = override.get("delta") or {}
    return {
        "deterministic_result": serialize_rule_result(deterministic_result),
        "pre_override_verdict": delta.get("from_verdict"),
        "post_override_verdict": delta.get("to_verdict"),
        "override_guard": {
            "trusted_deterministic": bool(override.get("trusted_deterministic")),
            "llm_judge_considered": bool(override.get("considered")),
            "llm_judge_triggered": bool(override.get("attempted")),
            "blocked_by_high_conf_deterministic": bool(override.get("blocked_by_high_conf_deterministic")),
        },
    }


def serialize_rule_result(result: Any) -> dict[str, Any] | None:
    if result is None:
        return None
    return {
        "verdict": _get(result, "verdict"),
        "confidence": _get(result, "confidence"),
        "reason": _get(result, "reason"),
        "expected_status": _get(result, "expected_status"),
        "actual_status": _get(result, "actual_status"),
        "policy_source": _get(result, "policy_source"),
        "coverage_status": _get(result, "coverage_status"),
        "spec_refs": list(_get(result, "spec_refs", ()) or ()),
    }


def serialize_parse_audit_provenance(
    *,
    enabled: bool,
    attempted: bool = False,
    report: Any = None,
    write_status: Any = None,
    path: str | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    status = _plain(write_status) if write_status is not None else {}
    issues = _get(report, "issues", []) or []
    return {
        "enabled": enabled,
        "attempted": attempted,
        "recorded": bool(status.get("recorded")) if isinstance(status, dict) else False,
        "path": path or (status.get("path") if isinstance(status, dict) else None),
        "record_id": status.get("record_id") if isinstance(status, dict) else None,
        "error": status.get("error") if isinstance(status, dict) else None,
        "reason": reason,
        "delta": {
            "issues_count": len(issues),
            "risk_score": _get(report, "risk_score", 0) if report is not None else 0,
            "should_run_rag": bool(_get(report, "should_run_rag", False)),
            "record_written": bool(status.get("recorded")) if isinstance(status, dict) else False,
        },
    }


def serialize_repair_provenance(
    *,
    enabled: bool,
    attempted: bool = False,
    decision: Any = None,
    applied: bool = False,
    source: str = "none",
) -> dict[str, Any]:
    event_patch = _get(decision, "event_patch", None) or {}
    state_patch = _get(decision, "state_patch", None) or {}
    action = _get(decision, "action", None)
    return {
        "enabled": enabled,
        "attempted": attempted,
        "applied": applied,
        "decision_kind": action or ("no_repair" if attempted else "none"),
        "confidence": _get(decision, "confidence", None),
        "reason": _safe_provenance_reason(_get(decision, "reason", None)),
        "source": source,
        "delta": {
            "event_changed": bool(event_patch),
            "state_changed": bool(state_patch),
            "event_patch_fields": sorted(str(key) for key in event_patch),
            "state_patch_fields": sorted(str(key) for key in state_patch),
        },
    }


def serialize_llm_override_provenance(
    *,
    enabled: bool,
    considered: bool = False,
    attempted: bool = False,
    applied: bool = False,
    blocked_by_high_conf_deterministic: bool = False,
    trusted_deterministic: bool = False,
    allow_verdict_override: bool = False,
    decision: Any = None,
    from_verdict: str | None = None,
    to_verdict: str | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    decision_verdict = _get(decision, "verdict", None) or to_verdict
    return {
        "enabled": enabled,
        "considered": considered,
        "attempted": attempted,
        "applied": applied,
        "allow_verdict_override": allow_verdict_override,
        "trusted_deterministic": trusted_deterministic,
        "blocked_by_high_conf_deterministic": blocked_by_high_conf_deterministic,
        "decision_verdict": decision_verdict,
        "decision_confidence": _get(decision, "confidence", None),
        "policy_source": "llm_parse_fallback" if attempted else None,
        "coverage_status": "llm_override" if applied else None,
        "reason": _safe_provenance_reason(reason or _get(decision, "reason", None)),
        "delta": {
            "verdict_changed": bool(from_verdict and to_verdict and from_verdict != to_verdict),
            "from_verdict": from_verdict,
            "to_verdict": to_verdict,
        },
    }


def _safe_provenance_reason(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    for marker in ("; raw=", " raw=", "raw="):
        index = text.find(marker)
        if index >= 0:
            text = text[:index] + " model-output=<omitted>"
            break
    replacements = {
        "raw_step": "raw-step",
        "_state_snapshot": "state-snapshot",
        "state_snapshot": "state-snapshot",
        "prompt": "model-input",
        "response": "model-output",
    }
    for needle, replacement in replacements.items():
        text = text.replace(needle, replacement)
    if SENSITIVE_REASON_PATTERN.search(text):
        return "<redacted>"
    if len(text) > 500:
        return text[:485].rstrip() + "...<truncated>"
    return text


def make_risk_flag(
    code: str,
    detail: str,
    *,
    severity: str | None = None,
    producer: str | None = None,
) -> dict[str, str]:
    if code not in ALLOWED_RISK_CODES:
        raise ValueError(f"unknown evidence packet risk flag code: {code}")
    return {
        "code": code,
        "severity": severity or RISK_DEFAULT_SEVERITY.get(code, "warn"),
        "producer": producer or _producer_for_code(code),
        "detail": detail,
    }


def serialize_risk_flags(flags: list[dict[str, Any]]) -> list[dict[str, str]]:
    out = []
    for flag in flags:
        code = str(flag.get("code"))
        out.append(
            make_risk_flag(
                code,
                str(flag.get("detail") or ""),
                severity=flag.get("severity"),
                producer=flag.get("producer"),
            )
        )
    return out


def _derive_serializer_risk_flags(
    normalized_events: dict[str, Any],
    state_facts: dict[str, Any] | None,
) -> list[dict[str, str]]:
    flags: list[dict[str, str]] = []
    if normalized_events.get("truncated"):
        flags.append(
            make_risk_flag(
                "packet.normalized_events_truncated",
                f"omitted {normalized_events.get('omitted_count')} normalized events",
            )
        )
    if ((state_facts or {}).get("meta") or {}).get("facts_truncated"):
        flags.append(make_risk_flag("packet.state_facts_truncated", "state_facts hit a size guard"))
    return flags


def _default_subsystem_flags(
    flags: dict[str, Any] | None,
    trajectory_id: str | None,
    llm_override_provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    override_changed = bool(
        ((llm_override_provenance or {}).get("delta") or {}).get("verdict_changed")
    )
    base = {
        "deterministic_first": True,
        "no_verdict_changes": not override_changed,
        "evidence_packet_enabled": True,
        "evidence_packet_path_present": True,
        "parse_audit_enabled": False,
        "parse_audit_path_present": False,
        "llm_parse_fallback_enabled": False,
        "rag_repair_enabled": False,
        "trajectory_id_present": trajectory_id is not None,
    }
    base.update(flags or {})
    return base


def _compact_event(event: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    return {field: _json_ready(event.get(field)) for field in fields}


def _event_index(event: dict[str, Any], fallback: int) -> int:
    value = event.get("index")
    return value if isinstance(value, int) else fallback


def _producer_for_code(code: str) -> str:
    for prefix, producer in RISK_PRODUCER_BY_PREFIX.items():
        if code.startswith(prefix):
            return producer
    return "serializer"


def _dedupe(items: list[Any]) -> list[str]:
    out: list[str] = []
    for item in items:
        text = str(item)
        if text not in out:
            out.append(text)
    return out


def _get(value: Any, key: str, default: Any = None) -> Any:
    if value is None:
        return default
    if isinstance(value, dict):
        return value.get(key, default)
    return getattr(value, key, default)


def _plain(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if is_dataclass(value):
        return _plain(asdict(value))
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_plain(item) for item in value]
    if hasattr(value, "to_dict"):
        return _plain(value.to_dict())
    return repr(value)


def _json_ready(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, set):
        return sorted(_json_ready(item) for item in value)
    if isinstance(value, tuple):
        return [_json_ready(item) for item in value]
    if isinstance(value, list):
        return [_json_ready(item) for item in value]
    return value

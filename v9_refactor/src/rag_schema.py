"""Schemas and validation for RAG-assisted parser repair.

This module is intentionally independent from the state-machine implementation.
Runtime RAG/LLM code may propose only constrained event patches or whitelisted
state-effect labels; it must not generate executable code.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any


ALLOWED_ACTIONS = frozenset(
    {
        "repair_event",
        "state_effect",
        "no_repair",
        "needs_rule_patch",
    }
)

ALLOWED_STATE_EFFECTS = frozenset(
    {
        "no_effect",
        "open_session",
        "sync_session_ids",
        "close_session",
        "authenticate_authority",
        "set_table_columns",
        "activate_locking_sp",
        "revert_sp",
        "reset_like_event",
        "gen_key",
    }
)

ALLOWED_EVENT_PATCH_FIELDS = frozenset(
    {
        "kind",
        "method",
        "command",
        "object_uid",
        "object",
        "object_family",
        "status",
        "result",
        "parameters",
        "required_parameters",
        "optional_parameters",
        "spid",
        "sp",
        "write",
        "authority",
        "where",
        "count",
        "values",
        "lba",
        "pattern",
    }
)

ALLOWED_STATE_PATCH_FIELDS = frozenset(
    {
        "locking_sp_active",
        "credentials",
        "sp_lifecycle",
        "trylimit_by_authority",
        "failed_auth_counts",
        "session",
        "locking_ranges",
        "mbr",
        "writes",
    }
)

ALLOWED_VERDICTS = frozenset({"pass", "fail"})


@dataclass(frozen=True)
class RetrievedChunk:
    """A spec/document snippet returned by the offline retriever."""

    section: str
    path: str
    title: str
    text: str
    score: float = 0.0


@dataclass(frozen=True)
class RepairDecision:
    """Validated LLM/RAG parser-repair decision."""

    action: str
    confidence: float
    reason: str = ""
    step_index: int | None = None
    event_patch: dict[str, Any] | None = None
    state_effect: str | None = None
    state_patch: dict[str, Any] | None = None
    verdict: str | None = None
    validation_error: str | None = None
    evidence: list[RetrievedChunk] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def usable(self) -> bool:
        if self.action == "repair_event":
            return self.event_patch is not None and self.confidence > 0.0
        if self.action == "state_effect":
            return (self.state_effect is not None or self.state_patch is not None) and self.confidence > 0.0
        return False


class RepairValidationError(ValueError):
    """Raised when model output violates the constrained repair schema."""


def _coerce_json_object(payload: str | dict[str, Any]) -> dict[str, Any]:
    if isinstance(payload, dict):
        return dict(payload)
    if not isinstance(payload, str):
        raise RepairValidationError(f"expected JSON object or string, got {type(payload).__name__}")

    text = payload.strip()
    if not text:
        raise RepairValidationError("empty JSON response")
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, flags=re.DOTALL)
        if not match:
            raise RepairValidationError("response does not contain a JSON object")
        try:
            value = json.loads(match.group(0))
        except json.JSONDecodeError as exc:
            raise RepairValidationError(f"invalid JSON object: {exc}") from exc
    if not isinstance(value, dict):
        raise RepairValidationError("repair response must be a JSON object")
    return value


def _validate_confidence(value: Any) -> float:
    if isinstance(value, bool):
        raise RepairValidationError("confidence must be numeric, not boolean")
    try:
        confidence = float(value)
    except (TypeError, ValueError) as exc:
        raise RepairValidationError("confidence must be a number in [0, 1]") from exc
    if not 0.0 <= confidence <= 1.0:
        raise RepairValidationError("confidence must be in [0, 1]")
    return confidence


def _validate_step_index(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise RepairValidationError("step_index must be an integer")
    try:
        idx = int(value)
    except (TypeError, ValueError) as exc:
        raise RepairValidationError("step_index must be an integer") from exc
    if idx < 0:
        raise RepairValidationError("step_index must be non-negative")
    return idx


def validate_event_patch(value: Any) -> dict[str, Any]:
    """Validate a repair_event patch and return a shallow copy."""

    if not isinstance(value, dict):
        raise RepairValidationError("event_patch must be an object")
    unknown = sorted(set(value) - ALLOWED_EVENT_PATCH_FIELDS)
    if unknown:
        raise RepairValidationError(f"event_patch contains unknown fields: {', '.join(unknown)}")
    if not value:
        raise RepairValidationError("event_patch must not be empty for repair_event")
    return dict(value)


def validate_state_patch(value: Any) -> dict[str, Any]:
    """Validate a bounded state patch and return a shallow copy.

    Nested interpretation is owned by ``llm_parse_fallback.apply_state_patch``.
    This schema gate only allows the top-level domains that the existing mutator
    already understands.
    """

    if not isinstance(value, dict):
        raise RepairValidationError("state_patch must be an object")
    unknown = sorted(set(value) - ALLOWED_STATE_PATCH_FIELDS)
    if unknown:
        raise RepairValidationError(f"state_patch contains unknown fields: {', '.join(unknown)}")
    return dict(value)


def validate_repair_decision(payload: str | dict[str, Any], evidence: list[RetrievedChunk] | None = None) -> RepairDecision:
    """Parse and validate constrained LLM JSON output.

    Accepted shape:
      {
        "action": "repair_event|state_effect|no_repair|needs_rule_patch",
        "confidence": 0.0-1.0,
        "step_index": 3,
        "event_patch": {...},
        "state_effect": "open_session",
        "state_patch": {...},
        "verdict": "pass|fail",
        "reason": "..."
      }
    """

    data = _coerce_json_object(payload)
    action = data.get("action")
    if action not in ALLOWED_ACTIONS:
        raise RepairValidationError(f"unknown repair action: {action!r}")

    confidence = _validate_confidence(data.get("confidence", 0.0))
    step_index = _validate_step_index(data.get("step_index"))
    reason = data.get("reason") or ""
    if not isinstance(reason, str):
        raise RepairValidationError("reason must be a string when present")

    verdict = data.get("verdict")
    if verdict is not None and verdict not in ALLOWED_VERDICTS:
        raise RepairValidationError(f"invalid verdict: {verdict!r}")

    event_patch = data.get("event_patch")
    state_effect = data.get("state_effect")
    state_patch = data.get("state_patch")

    if action == "repair_event":
        event_patch = validate_event_patch(event_patch)
        if state_patch is not None:
            raise RepairValidationError("state_patch is only allowed for state_effect actions")
    elif event_patch is not None:
        event_patch = validate_event_patch(event_patch)

    if action == "state_effect":
        if state_effect not in ALLOWED_STATE_EFFECTS:
            raise RepairValidationError(f"unknown state_effect: {state_effect!r}")
    elif state_effect is not None:
        if state_effect not in ALLOWED_STATE_EFFECTS:
            raise RepairValidationError(f"unknown state_effect: {state_effect!r}")

    if state_patch is not None:
        if action != "state_effect":
            raise RepairValidationError("state_patch is only allowed for state_effect actions")
        state_patch = validate_state_patch(state_patch)

    return RepairDecision(
        action=action,
        confidence=confidence,
        reason=reason,
        step_index=step_index,
        event_patch=event_patch,
        state_effect=state_effect,
        state_patch=state_patch,
        verdict=verdict,
        evidence=list(evidence or []),
        raw=data,
    )


def no_repair_decision(
    reason: str,
    *,
    confidence: float = 1.0,
    evidence: list[RetrievedChunk] | None = None,
    validation_error: str | None = None,
) -> RepairDecision:
    raw = {"action": "no_repair", "confidence": confidence, "reason": reason}
    if validation_error:
        raw["validation_error"] = validation_error
    return RepairDecision(
        action="no_repair",
        confidence=_validate_confidence(confidence),
        reason=reason,
        validation_error=validation_error,
        evidence=list(evidence or []),
        raw=raw,
    )

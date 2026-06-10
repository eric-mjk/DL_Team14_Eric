from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any


ROUTE_NONE = "none"
ROUTE_PARSE_REPAIR_DRY_RUN = "parse_repair_dry_run"
ROUTE_PARSE_REPAIR_LLM = "parse_repair_llm"
ROUTE_AUDIT_ONLY_LLM = "audit_only_llm"
ROUTE_NEEDS_RULE_PATCH = "needs_rule_patch"

MODE_OFF = "off"
MODE_AUDIT = "audit"
MODE_REPAIR = "repair"
MODE_AGGRESSIVE = "aggressive"

PARSER_DAMAGE_KINDS = frozenset(
    {
        "malformed_step",
        "missing_event",
        "missing_method",
        "unknown_method",
        "unmapped_method_uid",
        "method_uid_name_disagreement",
        "parsed_method_uid_disagreement",
        "unknown_successful_history_method",
        "unknown_final_method",
        "missing_command_or_method",
        "unknown_command",
        "final_command_fallback_like",
        "unparsed_lba",
        "unparsed_pattern",
        "unconsumed_important_field",
    }
)

RULE_CONFLICT_RISK_CODES = frozenset(
    {
        "deterministic.rule_conflict",
        "override.verdict_changed_unexpected",
    }
)

LOW_EXPLANATION_RISK_CODES = frozenset(
    {
        "deterministic.low_confidence",
        "deterministic.missing_spec_refs",
        "deterministic.unknown_fields",
        "deterministic.ambiguous_fields",
    }
)


@dataclass(frozen=True)
class LLMRoutePolicy:
    """Runtime policy for deciding if an LLM/RAG path is allowed.

    The policy is intentionally separate from model backends.  It can be tested
    cheaply and used by the solver without importing vLLM/transformers.
    """

    mode: str = MODE_OFF
    allow_verdict_override: bool = False
    trust_min_confidence: float = 0.95
    route_min_risk_score: int = 5

    @classmethod
    def from_env(cls) -> "LLMRoutePolicy":
        mode = os.environ.get("LLM_PIPELINE_MODE", MODE_OFF).strip().lower() or MODE_OFF
        if mode not in {MODE_OFF, MODE_AUDIT, MODE_REPAIR, MODE_AGGRESSIVE}:
            mode = MODE_OFF
        return cls(
            mode=mode,
            allow_verdict_override=_env_flag("LLM_ALLOW_VERDICT_OVERRIDE", False),
            trust_min_confidence=_env_float("LLM_PARSE_TRUST_MIN_CONFIDENCE", 0.95),
            route_min_risk_score=_env_int("LLM_ROUTE_MIN_RISK", 5),
        )


@dataclass(frozen=True)
class LLMRouteDecision:
    """Deterministic routing decision for later LLM/RAG work."""

    route: str
    reason: str
    confidence: float
    risk_codes: tuple[str, ...] = ()
    allowed_actions: tuple[str, ...] = ()
    invoke_model: bool = False
    allow_verdict_override: bool = False


def decide_llm_route(
    *,
    parse_report: Any = None,
    rule_result: Any = None,
    risk_flags: list[dict[str, Any]] | tuple[dict[str, Any], ...] | None = None,
    policy: LLMRoutePolicy | None = None,
) -> LLMRouteDecision:
    """Return a cheap, model-free LLM/RAG routing decision.

    This function does not call an LLM, does not mutate state, and does not
    change verdicts.  It centralizes the policy that future solver wiring should
    use before invoking parser repair or audit-only LLM logic.
    """

    policy = policy or LLMRoutePolicy.from_env()
    if policy.mode == MODE_OFF:
        return LLMRouteDecision(
            route=ROUTE_NONE,
            reason="LLM pipeline mode is off",
            confidence=1.0,
            allowed_actions=(),
            invoke_model=False,
            allow_verdict_override=False,
        )

    risk_codes = classify_llm_risk_codes(parse_report=parse_report, rule_result=rule_result, risk_flags=risk_flags)
    confidence = _rule_confidence(rule_result)

    if _is_trusted_deterministic(rule_result, policy.trust_min_confidence) and not _has_high_parse_risk(parse_report):
        return LLMRouteDecision(
            route=ROUTE_NONE,
            reason="trusted high-confidence deterministic result",
            confidence=confidence,
            risk_codes=risk_codes,
            allowed_actions=(),
            invoke_model=False,
            allow_verdict_override=False,
        )

    if "parser_damage" in risk_codes:
        invoke = policy.mode in {MODE_REPAIR, MODE_AGGRESSIVE}
        return LLMRouteDecision(
            route=ROUTE_PARSE_REPAIR_LLM if invoke else ROUTE_PARSE_REPAIR_DRY_RUN,
            reason="parser damage or high parse-audit risk detected",
            confidence=max(0.0, min(1.0, 1.0 - confidence if confidence else 0.5)),
            risk_codes=risk_codes,
            allowed_actions=("repair_event", "state_effect", "no_repair", "needs_rule_patch"),
            invoke_model=invoke,
            allow_verdict_override=False,
        )

    if "rule_conflict" in risk_codes:
        return LLMRouteDecision(
            route=ROUTE_AUDIT_ONLY_LLM if policy.mode in {MODE_AUDIT, MODE_REPAIR, MODE_AGGRESSIVE} else ROUTE_NONE,
            reason="rule conflict risk requires audit, not direct verdict override",
            confidence=0.65,
            risk_codes=risk_codes,
            allowed_actions=("no_repair", "needs_rule_patch"),
            invoke_model=policy.mode in {MODE_AUDIT, MODE_AGGRESSIVE},
            allow_verdict_override=False,
        )

    if "oracle_abstains" in risk_codes:
        return LLMRouteDecision(
            route=ROUTE_NEEDS_RULE_PATCH,
            reason="deterministic oracle fallback/partial coverage with no parser damage",
            confidence=0.7,
            risk_codes=risk_codes,
            allowed_actions=("needs_rule_patch", "no_repair"),
            invoke_model=False,
            allow_verdict_override=False,
        )

    if "low_explanation_quality" in risk_codes:
        invoke = policy.mode in {MODE_AUDIT, MODE_AGGRESSIVE}
        return LLMRouteDecision(
            route=ROUTE_AUDIT_ONLY_LLM if invoke else ROUTE_NONE,
            reason="deterministic explanation/spec-reference quality is low",
            confidence=0.55,
            risk_codes=risk_codes,
            allowed_actions=("no_repair", "needs_rule_patch"),
            invoke_model=invoke,
            allow_verdict_override=False,
        )

    return LLMRouteDecision(
        route=ROUTE_NONE,
        reason="no LLM/RAG route trigger matched",
        confidence=max(confidence, 0.0),
        risk_codes=risk_codes,
        allowed_actions=(),
        invoke_model=False,
        allow_verdict_override=False,
    )


def classify_llm_risk_codes(
    *,
    parse_report: Any = None,
    rule_result: Any = None,
    risk_flags: list[dict[str, Any]] | tuple[dict[str, Any], ...] | None = None,
) -> tuple[str, ...]:
    """Map low-level audit/rule/packet signals into LLM routing risks."""

    codes: list[str] = []
    parse_issue_kinds = _parse_issue_kinds(parse_report)
    if _has_high_parse_risk(parse_report) or parse_issue_kinds & PARSER_DAMAGE_KINDS:
        codes.append("parser_damage")

    policy_source = str(getattr(rule_result, "policy_source", "") or "")
    coverage_status = str(getattr(rule_result, "coverage_status", "") or "")
    if policy_source == "fallback" or coverage_status in {"partial", "fallback", "unknown"}:
        codes.append("oracle_abstains")

    flag_codes = _risk_flag_codes(risk_flags)
    if flag_codes & RULE_CONFLICT_RISK_CODES:
        codes.append("rule_conflict")

    if (
        flag_codes & LOW_EXPLANATION_RISK_CODES
        or _rule_confidence(rule_result) < 0.5
        or not tuple(getattr(rule_result, "spec_refs", ()) or ())
    ):
        codes.append("low_explanation_quality")

    return tuple(dict.fromkeys(codes))


def _has_high_parse_risk(parse_report: Any) -> bool:
    if parse_report is None:
        return False
    if bool(getattr(parse_report, "should_run_rag", False)):
        return True
    return any(str(getattr(issue, "severity", "") or "") == "high" for issue in getattr(parse_report, "issues", ()) or ())


def _parse_issue_kinds(parse_report: Any) -> set[str]:
    if parse_report is None:
        return set()
    return {str(getattr(issue, "kind", "") or "") for issue in getattr(parse_report, "issues", ()) or ()}


def _risk_flag_codes(risk_flags: list[dict[str, Any]] | tuple[dict[str, Any], ...] | None) -> set[str]:
    codes = set()
    for flag in risk_flags or ():
        if isinstance(flag, dict) and flag.get("code"):
            codes.add(str(flag["code"]))
    return codes


def _rule_confidence(rule_result: Any) -> float:
    try:
        return float(getattr(rule_result, "confidence", 0.0) or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _is_trusted_deterministic(rule_result: Any, min_confidence: float) -> bool:
    if rule_result is None:
        return False
    return (
        str(getattr(rule_result, "coverage_status", "") or "") == "implemented"
        and str(getattr(rule_result, "policy_source", "") or "") != "fallback"
        and _rule_confidence(rule_result) >= min_confidence
    )


def _env_flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


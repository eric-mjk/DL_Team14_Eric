import unittest

from src.llm_pipeline import (
    LLMRoutePolicy,
    ROUTE_AUDIT_ONLY_LLM,
    ROUTE_NEEDS_RULE_PATCH,
    ROUTE_NONE,
    ROUTE_PARSE_REPAIR_DRY_RUN,
    ROUTE_PARSE_REPAIR_LLM,
    can_apply_repair_decision,
    can_apply_state_patch,
    can_challenge_verdict,
    classify_llm_risk_codes,
    decide_llm_route,
    derive_escalation_tokens,
)
from src.oracle import RuleResult
from src.parse_audit import ParseAuditReport, ParseIssue
from src.rag_schema import RepairDecision


class LLMRouteDecisionTest(unittest.TestCase):
    def test_off_mode_never_routes(self):
        report = ParseAuditReport(
            issues=[ParseIssue("high", "missing_method", 0, "input.method", "missing")],
            risk_score=5,
            should_run_rag=True,
        )

        decision = decide_llm_route(
            parse_report=report,
            rule_result=RuleResult("pass", 0.1, "fallback", policy_source="fallback", coverage_status="partial"),
            policy=LLMRoutePolicy(mode="off"),
        )

        self.assertEqual(decision.route, ROUTE_NONE)
        self.assertFalse(decision.invoke_model)
        self.assertFalse(decision.allow_verdict_override)

    def test_high_confidence_deterministic_result_does_not_route(self):
        result = RuleResult(
            "pass",
            0.99,
            "implemented rule",
            spec_refs=("spec/core",),
            policy_source="rule",
            coverage_status="implemented",
        )

        decision = decide_llm_route(rule_result=result, policy=LLMRoutePolicy(mode="repair"))

        self.assertEqual(decision.route, ROUTE_NONE)
        self.assertFalse(decision.invoke_model)

    def test_parser_damage_routes_to_dry_run_in_audit_mode(self):
        report = ParseAuditReport(
            issues=[ParseIssue("high", "missing_method", 3, "input.method", "missing")],
            risk_score=5,
            should_run_rag=True,
        )

        decision = decide_llm_route(
            parse_report=report,
            rule_result=RuleResult("fail", 0.4, "low", spec_refs=("spec/core",)),
            policy=LLMRoutePolicy(mode="audit"),
        )

        self.assertEqual(decision.route, ROUTE_PARSE_REPAIR_DRY_RUN)
        self.assertFalse(decision.invoke_model)
        self.assertIn("parser_damage", decision.risk_codes)

    def test_parser_damage_routes_to_llm_in_repair_mode(self):
        report = ParseAuditReport(
            issues=[ParseIssue("high", "unknown_final_method", 9, "input.method", "unknown")],
            risk_score=5,
            should_run_rag=True,
        )

        decision = decide_llm_route(
            parse_report=report,
            rule_result=RuleResult("fail", 0.4, "low", spec_refs=("spec/core",)),
            policy=LLMRoutePolicy(mode="repair"),
        )

        self.assertEqual(decision.route, ROUTE_PARSE_REPAIR_LLM)
        self.assertTrue(decision.invoke_model)
        self.assertFalse(decision.allow_verdict_override)

    def test_oracle_abstain_without_parser_damage_routes_to_rule_patch(self):
        decision = decide_llm_route(
            rule_result=RuleResult(
                "pass",
                0.6,
                "fallback",
                spec_refs=("spec/core",),
                policy_source="fallback",
                coverage_status="partial",
            ),
            policy=LLMRoutePolicy(mode="repair"),
        )

        self.assertEqual(decision.route, ROUTE_NEEDS_RULE_PATCH)
        self.assertFalse(decision.invoke_model)
        self.assertIn("oracle_abstains", decision.risk_codes)

    def test_low_explanation_quality_can_route_to_audit_llm(self):
        decision = decide_llm_route(
            rule_result=RuleResult("pass", 0.7, "missing refs", spec_refs=()),
            risk_flags=[{"code": "deterministic.missing_spec_refs"}],
            policy=LLMRoutePolicy(mode="audit"),
        )

        self.assertEqual(decision.route, ROUTE_AUDIT_ONLY_LLM)
        self.assertTrue(decision.invoke_model)
        self.assertFalse(decision.allow_verdict_override)

    def test_classification_deduplicates_codes(self):
        report = ParseAuditReport(
            issues=[ParseIssue("high", "missing_method", 1, "input.method", "missing")],
            risk_score=5,
            should_run_rag=True,
        )

        codes = classify_llm_risk_codes(
            parse_report=report,
            rule_result=RuleResult("pass", 0.1, "low", spec_refs=()),
            risk_flags=[{"code": "deterministic.low_confidence"}],
        )

        self.assertEqual(codes.count("parser_damage"), 1)
        self.assertIn("low_explanation_quality", codes)

    def test_escalation_tokens_include_state_gap_and_schema_violation(self):
        report = ParseAuditReport(
            issues=[ParseIssue("high", "unknown_successful_history_method", 0, "input.method", "unknown")],
            risk_score=5,
            should_run_rag=True,
        )
        result = RuleResult("pass", 0.6, "fallback", policy_source="fallback", coverage_status="partial")
        decision = decide_llm_route(parse_report=report, rule_result=result, policy=LLMRoutePolicy(mode="repair"))

        tokens = derive_escalation_tokens(
            parse_report=report,
            route_decision=decision,
            rule_result=result,
            validation_error="bad json",
            target_index=1,
        )

        self.assertIn("route:parser_damage", tokens)
        self.assertIn("parser_damage", tokens)
        self.assertIn("unresolved_state_effect_gap", tokens)
        self.assertIn("schema_violation", tokens)
        self.assertIn("verdict_gap", tokens)

    def test_state_patch_gate_requires_explicit_policy_token_and_success_pre_target(self):
        route = decide_llm_route(
            parse_report=ParseAuditReport(
                issues=[ParseIssue("high", "unknown_successful_history_method", 0, "input.method", "unknown")],
                risk_score=5,
                should_run_rag=True,
            ),
            rule_result=RuleResult("pass", 0.4, "low", spec_refs=("spec",)),
            policy=LLMRoutePolicy(mode="repair", allow_state_patch=True),
        )
        repair = RepairDecision(
            action="state_effect",
            confidence=0.9,
            reason="successful unknown method opened session",
            state_effect="open_session",
            state_patch={"session": {"open": True}},
        )

        self.assertTrue(
            can_apply_state_patch(
                {"status": "success", "is_target": False},
                repair,
                route,
                ("unresolved_state_effect_gap",),
                LLMRoutePolicy(mode="repair", allow_state_patch=True, repair_min_confidence=0.72),
            )
        )
        self.assertFalse(
            can_apply_state_patch(
                {"status": "success", "is_target": True},
                repair,
                route,
                ("unresolved_state_effect_gap",),
                LLMRoutePolicy(mode="repair", allow_state_patch=True),
            )
        )
        self.assertFalse(
            can_apply_state_patch(
                {"status": "success", "is_target": False},
                repair,
                route,
                (),
                LLMRoutePolicy(mode="repair", allow_state_patch=True),
            )
        )

    def test_state_patch_gate_rejects_dry_run_no_effect_and_missing_status(self):
        audit_route = decide_llm_route(
            parse_report=ParseAuditReport(
                issues=[ParseIssue("high", "unknown_successful_history_method", 0, "input.method", "unknown")],
                risk_score=5,
                should_run_rag=True,
            ),
            rule_result=RuleResult("pass", 0.4, "low", spec_refs=("spec",)),
            policy=LLMRoutePolicy(mode="audit", allow_state_patch=True),
        )
        repair = RepairDecision(
            action="state_effect",
            confidence=0.9,
            reason="state patch",
            state_effect="open_session",
            state_patch={"session": {"open": True}},
        )
        self.assertFalse(
            can_apply_state_patch(
                {"status": "success", "is_target": False},
                repair,
                audit_route,
                ("unresolved_state_effect_gap",),
                LLMRoutePolicy(mode="audit", allow_state_patch=True),
            )
        )

        repair_route = decide_llm_route(
            parse_report=ParseAuditReport(
                issues=[ParseIssue("high", "unknown_successful_history_method", 0, "input.method", "unknown")],
                risk_score=5,
                should_run_rag=True,
            ),
            rule_result=RuleResult("pass", 0.4, "low", spec_refs=("spec",)),
            policy=LLMRoutePolicy(mode="repair", allow_state_patch=True),
        )
        self.assertFalse(
            can_apply_state_patch(
                {"is_target": False},
                repair,
                repair_route,
                ("unresolved_state_effect_gap",),
                LLMRoutePolicy(mode="repair", allow_state_patch=True),
            )
        )
        no_effect = RepairDecision(
            action="state_effect",
            confidence=0.9,
            reason="state patch",
            state_effect="no_effect",
            state_patch={"session": {"open": True}},
        )
        self.assertFalse(
            can_apply_state_patch(
                {"status": "success", "is_target": False},
                no_effect,
                repair_route,
                ("unresolved_state_effect_gap",),
                LLMRoutePolicy(mode="repair", allow_state_patch=True),
            )
        )

    def test_state_patch_gate_cannot_be_authorized_by_model_patch_itself(self):
        report = ParseAuditReport(
            issues=[ParseIssue("high", "unknown_final_method", 1, "input.method", "target method unknown")],
            risk_score=5,
            should_run_rag=True,
        )
        route = decide_llm_route(
            parse_report=report,
            rule_result=RuleResult("fail", 0.4, "low", spec_refs=("spec",)),
            policy=LLMRoutePolicy(mode="repair", allow_state_patch=True),
        )
        repair = RepairDecision(
            action="state_effect",
            confidence=0.9,
            reason="model proposes state mutation",
            step_index=0,
            state_effect="open_session",
            state_patch={"session": {"open": True}},
        )

        tokens = derive_escalation_tokens(
            parse_report=report,
            route_decision=route,
            rule_result=RuleResult("fail", 0.4, "low", spec_refs=("spec",)),
            repair_decision=repair,
            target_index=1,
        )

        self.assertIn("model_proposed_state_patch", tokens)
        self.assertNotIn("unresolved_state_effect_gap", tokens)
        self.assertFalse(
            can_apply_state_patch(
                {"status": "success", "is_target": False},
                repair,
                route,
                tokens,
                LLMRoutePolicy(mode="repair", allow_state_patch=True),
            )
        )

    def test_target_only_state_gap_requires_target_index_to_block_patch_token(self):
        report = ParseAuditReport(
            issues=[ParseIssue("high", "missing_method", 1, "input.method", "target method missing")],
            risk_score=5,
            should_run_rag=True,
        )
        route = decide_llm_route(
            parse_report=report,
            rule_result=RuleResult("fail", 0.4, "low", spec_refs=("spec",)),
            policy=LLMRoutePolicy(mode="repair", allow_state_patch=True),
        )
        repair = RepairDecision(
            action="state_effect",
            confidence=0.9,
            reason="model proposes state mutation",
            step_index=0,
            state_effect="open_session",
            state_patch={"session": {"open": True}},
        )

        tokens_without_target_index = derive_escalation_tokens(
            parse_report=report,
            route_decision=route,
            rule_result=RuleResult("fail", 0.4, "low", spec_refs=("spec",)),
            repair_decision=repair,
            target_index=None,
        )
        tokens_with_target_index = derive_escalation_tokens(
            parse_report=report,
            route_decision=route,
            rule_result=RuleResult("fail", 0.4, "low", spec_refs=("spec",)),
            repair_decision=repair,
            target_index=1,
        )

        self.assertIn("unresolved_state_effect_gap", tokens_without_target_index)
        self.assertNotIn("unresolved_state_effect_gap", tokens_with_target_index)
        self.assertFalse(
            can_apply_state_patch(
                {"status": "success", "is_target": False},
                repair,
                route,
                tokens_with_target_index,
                LLMRoutePolicy(mode="repair", allow_state_patch=True),
            )
        )

    def test_event_repair_gate_uses_route_and_confidence(self):
        route = decide_llm_route(
            parse_report=ParseAuditReport(
                issues=[ParseIssue("high", "missing_method", 0, "input.method", "missing")],
                risk_score=5,
                should_run_rag=True,
            ),
            rule_result=RuleResult("fail", 0.4, "low", spec_refs=("spec",)),
            policy=LLMRoutePolicy(mode="repair", repair_min_confidence=0.8),
        )
        repair = RepairDecision(action="repair_event", confidence=0.85, event_patch={"method": "Get"})
        weak = RepairDecision(action="repair_event", confidence=0.5, event_patch={"method": "Get"})

        self.assertTrue(can_apply_repair_decision({}, repair, route, (), LLMRoutePolicy(mode="repair", repair_min_confidence=0.8)))
        self.assertFalse(can_apply_repair_decision({}, weak, route, (), LLMRoutePolicy(mode="repair", repair_min_confidence=0.8)))

    def test_verdict_challenge_denied_unless_policy_and_route_allow(self):
        result = RuleResult("pass", 0.4, "fallback", policy_source="fallback", coverage_status="partial")
        route = decide_llm_route(rule_result=result, policy=LLMRoutePolicy(mode="repair", allow_verdict_override=True))

        self.assertFalse(
            can_challenge_verdict(
                result,
                route,
                ("verdict_gap",),
                LLMRoutePolicy(mode="repair", allow_verdict_override=True),
            )
        )


if __name__ == "__main__":
    unittest.main()

import unittest

from src.llm_pipeline import (
    LLMRoutePolicy,
    ROUTE_AUDIT_ONLY_LLM,
    ROUTE_NEEDS_RULE_PATCH,
    ROUTE_NONE,
    ROUTE_PARSE_REPAIR_DRY_RUN,
    ROUTE_PARSE_REPAIR_LLM,
    classify_llm_risk_codes,
    decide_llm_route,
)
from src.oracle import RuleResult
from src.parse_audit import ParseAuditReport, ParseIssue


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


if __name__ == "__main__":
    unittest.main()

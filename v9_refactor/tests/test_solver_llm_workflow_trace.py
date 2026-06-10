import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.llm_parse_fallback import LLMParseDecision, LLMParseFallback
from src.oracle import RuleResult
from src.parse_audit import ParseAuditReport, ParseIssue
from src.rag_schema import RepairDecision, RetrievedChunk
from src.solver import Solver


PROPERTIES_PASS = [
    {
        "input": {
            "method": {"name": "Properties"},
            "invoking_id": {
                "uid": "00000000000000FF",
                "name": "SessionManager",
            },
        },
        "output": {"status_codes": "SUCCESS", "return_values": []},
    }
]

PROPERTIES_FAIL = [
    {
        "input": {
            "method": {"name": "Properties"},
            "invoking_id": {
                "uid": "0000020500000002",
                "name": "LockingSP",
            },
        },
        "output": {"status_codes": "SUCCESS", "return_values": []},
    }
]


def _env(**overrides):
    base = {
        "SOLVER_PROFILE": "state_machine",
        "USE_LLM_PARSE_FALLBACK": "0",
        "ENABLE_PARSE_AUDIT": "0",
        "ENABLE_RAG_REPAIR": "0",
        "EVIDENCE_PACKET_AUDIT_PATH": "",
        "PARSE_RAG_AUDIT_PATH": "",
        "LLM_WORKFLOW_TRACE_PATH": "",
        "LLM_ALLOW_VERDICT_OVERRIDE": "0",
        "LLM_PIPELINE_MODE": "off",
    }
    base.update(overrides)
    return patch.dict(os.environ, base, clear=False)


class SolverLLMWorkflowTraceParityTest(unittest.TestCase):
    def test_trace_unset_does_not_write_trace_and_preserves_verdict(self):
        with tempfile.TemporaryDirectory() as td:
            trace_path = Path(td) / "trace.jsonl"
            with _env(LLM_WORKFLOW_TRACE_PATH=""):
                verdict = Solver().predict_one(PROPERTIES_PASS)

            self.assertEqual(verdict, "pass")
            self.assertFalse(trace_path.exists())

    def test_trace_enabled_preserves_verdict_and_records_no_route(self):
        with tempfile.TemporaryDirectory() as td:
            trace_path = Path(td) / "trace.jsonl"
            with _env():
                off = Solver().predict_one(PROPERTIES_PASS)
            with _env(LLM_WORKFLOW_TRACE_PATH=str(trace_path), LLM_PIPELINE_MODE="audit"):
                on = Solver().predict_one(PROPERTIES_PASS, trajectory_id="case-1")

            self.assertEqual(on, off)
            record = json.loads(trace_path.read_text().splitlines()[0])
            self.assertEqual(record["identity"]["trajectory_id"], "case-1")
            self.assertEqual(record["route"]["route"], "none")
            self.assertFalse(record["route"]["invoke_model"])
            self.assertFalse(record["route"]["allow_verdict_override"])
            self.assertEqual(record["verdict_policy"]["final_verdict_source"], "deterministic")

    def test_trace_enabled_does_not_invoke_llm_fallback_methods_by_itself(self):
        with tempfile.TemporaryDirectory() as td:
            trace_path = Path(td) / "trace.jsonl"
            with patch.object(LLMParseFallback, "repair_event", side_effect=AssertionError("extra repair call")), patch.object(
                LLMParseFallback,
                "judge_target",
                side_effect=AssertionError("extra judge call"),
            ), _env(LLM_WORKFLOW_TRACE_PATH=str(trace_path), USE_LLM_PARSE_FALLBACK="0"):
                verdict = Solver().predict_one(PROPERTIES_PASS)

            self.assertEqual(verdict, "pass")
            self.assertTrue(trace_path.exists())


class SolverLLMWorkflowTraceRAGTest(unittest.TestCase):
    def test_rag_repair_visibility_and_before_after_ordering(self):
        parse_report = ParseAuditReport(
            issues=[ParseIssue("high", "missing_method", 0, "input.method", "missing method")],
            risk_score=5,
            should_run_rag=True,
        )
        decision = RepairDecision(
            action="repair_event",
            confidence=0.9,
            reason="repair method",
            step_index=0,
            event_patch={"method": "Properties", "object": "SessionManager", "object_family": "SessionManager"},
            evidence=[RetrievedChunk("Core", "spec.md", "Properties", "Properties returns TPer properties.", 0.8)],
        )
        before = RuleResult("fail", 0.4, "before repair", policy_source="fallback", coverage_status="partial")
        after = RuleResult("pass", 0.99, "after repair", spec_refs=("Core:Properties",))

        with tempfile.TemporaryDirectory() as td:
            trace_path = Path(td) / "trace.jsonl"
            with _env(ENABLE_RAG_REPAIR="1", RAG_REPAIR_MODE="dry_run", LLM_WORKFLOW_TRACE_PATH=str(trace_path)), patch(
                "src.solver.audit_trajectory_parse",
                return_value=parse_report,
            ), patch.object(Solver, "_run_rag_repair", return_value=decision), patch(
                "src.solver.judge_final",
                side_effect=[before, after],
            ):
                verdict = Solver().predict_one(PROPERTIES_FAIL)

            self.assertEqual(verdict, "pass")
            record = json.loads(trace_path.read_text().splitlines()[0])
            self.assertTrue(record["rag_repair"]["attempted"])
            self.assertTrue(record["rag_repair"]["applied"])
            self.assertEqual(record["rag_repair"]["action"], "repair_event")
            self.assertEqual(record["rag_repair"]["event_patch"]["method"], "Properties")
            self.assertEqual(record["deterministic_before"]["verdict"], "fail")
            self.assertEqual(record["deterministic_after"]["verdict"], "pass")
            self.assertTrue(record["merge"]["verdict_changed_by_repair"])


class SolverLLMVerdictOverrideGuardTest(unittest.TestCase):
    def test_trace_disabled_default_blocks_opposite_llm_verdict(self):
        deterministic = RuleResult("pass", 0.3, "low trust", policy_source="fallback", coverage_status="partial")
        llm_decision = LLMParseDecision(usable=True, confidence=0.99, reason="opposite", verdict="fail")

        with _env(USE_LLM_PARSE_FALLBACK="1", LLM_WORKFLOW_TRACE_PATH=""), patch(
            "src.solver.judge_final",
            return_value=deterministic,
        ), patch.object(LLMParseFallback, "repair_event", return_value=LLMParseDecision()), patch.object(
            LLMParseFallback,
            "judge_target",
            return_value=llm_decision,
        ):
            verdict = Solver().predict_one(PROPERTIES_PASS)

        self.assertEqual(verdict, "pass")

    def test_trace_enabled_default_blocks_opposite_llm_verdict_and_records_reason(self):
        deterministic = RuleResult("pass", 0.3, "low trust", policy_source="fallback", coverage_status="partial")
        llm_decision = LLMParseDecision(usable=True, confidence=0.99, reason="opposite", verdict="fail")

        with tempfile.TemporaryDirectory() as td:
            trace_path = Path(td) / "trace.jsonl"
            with _env(USE_LLM_PARSE_FALLBACK="1", LLM_WORKFLOW_TRACE_PATH=str(trace_path)), patch(
                "src.solver.judge_final",
                return_value=deterministic,
            ), patch.object(LLMParseFallback, "repair_event", return_value=LLMParseDecision()), patch.object(
                LLMParseFallback,
                "judge_target",
                return_value=llm_decision,
            ):
                verdict = Solver().predict_one(PROPERTIES_PASS)

            self.assertEqual(verdict, "pass")
            record = json.loads(trace_path.read_text().splitlines()[0])
            override = record["verdict_policy"]["llm_override"]
            self.assertTrue(override["considered"])
            self.assertTrue(override["attempted"])
            self.assertFalse(override["applied"])
            self.assertEqual(override["reason"], "llm_verdict_override_disabled")
            self.assertEqual(record["verdict_policy"]["final_verdict_source"], "deterministic")

    def test_allow_verdict_override_opt_in_preserves_legacy_override_path(self):
        deterministic = RuleResult("pass", 0.3, "low trust", policy_source="fallback", coverage_status="partial")
        llm_decision = LLMParseDecision(usable=True, confidence=0.99, reason="opposite", verdict="fail")

        with _env(USE_LLM_PARSE_FALLBACK="1", LLM_ALLOW_VERDICT_OVERRIDE="1"), patch(
            "src.solver.judge_final",
            return_value=deterministic,
        ), patch.object(LLMParseFallback, "repair_event", return_value=LLMParseDecision()), patch.object(
            LLMParseFallback,
            "judge_target",
            return_value=llm_decision,
        ):
            verdict = Solver().predict_one(PROPERTIES_PASS)

        self.assertEqual(verdict, "fail")


if __name__ == "__main__":
    unittest.main()

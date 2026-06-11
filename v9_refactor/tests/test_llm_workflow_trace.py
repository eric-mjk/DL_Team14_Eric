import json
import tempfile
import unittest
from pathlib import Path

from src.llm_pipeline import LLMRouteDecision
from src.llm_workflow_trace import (
    SCHEMA_VERSION,
    build_llm_workflow_trace,
    sanitize_trace_value,
    serialize_repair_decision,
    write_llm_workflow_trace,
)
from src.oracle import RuleResult
from src.parse_audit import ParseAuditReport, ParseIssue
from src.rag_schema import RepairDecision, RetrievedChunk


class LLMWorkflowTraceWriterTest(unittest.TestCase):
    def test_empty_path_is_noop(self):
        status = write_llm_workflow_trace({"schema_version": SCHEMA_VERSION}, "")
        self.assertFalse(status.attempted)
        self.assertFalse(status.recorded)

    def test_writer_appends_jsonl_with_record_id(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "trace.jsonl"
            status = write_llm_workflow_trace({"schema_version": SCHEMA_VERSION, "identity": {}}, path)

            self.assertTrue(status.attempted)
            self.assertTrue(status.recorded)
            record = json.loads(path.read_text().splitlines()[0])
            self.assertEqual(record["schema_version"], SCHEMA_VERSION)
            self.assertEqual(record["identity"]["record_id"], status.record_id)


class LLMWorkflowTraceSchemaTest(unittest.TestCase):
    def test_trace_schema_contains_required_workflow_sections(self):
        trace = build_llm_workflow_trace(
            trajectory_id="case-1",
            task="judge_target",
            profile="state_machine",
            source="test",
            route_decision=LLMRouteDecision(
                route="none",
                reason="trusted",
                confidence=0.99,
                risk_codes=(),
                allowed_actions=(),
                invoke_model=False,
                allow_verdict_override=False,
            ),
            parse_report=ParseAuditReport(
                issues=[ParseIssue("low", "missing_method", 0, "input.method", "missing", {"name": "x"})],
                risk_score=1,
                should_run_rag=False,
            ),
            deterministic_before=RuleResult("pass", 0.99, "before", spec_refs=("Core:1",)),
            deterministic_after=RuleResult("pass", 0.99, "after", spec_refs=("Core:1",)),
            repair_decision=RepairDecision(
                action="no_repair",
                confidence=1.0,
                reason="dry",
                evidence=[RetrievedChunk("s", "doc.md", "Title", "chunk text", 0.7)],
            ),
            repair_attempted=True,
            repair_applied=False,
            escalation_tokens=("route:parser_damage", "schema_violation"),
        )

        for key in (
            "identity",
            "route",
            "parse_audit",
            "rag",
            "repair",
            "rag_repair",
            "deterministic_before",
            "deterministic_after",
            "merge",
            "verdict_policy",
        ):
            self.assertIn(key, trace)
        self.assertEqual(trace["schema_version"], SCHEMA_VERSION)
        self.assertEqual(trace["route"]["route"], "none")
        self.assertEqual(trace["parse_audit"]["issue_count"], 1)
        self.assertEqual(trace["rag"]["evidence_count"], 1)
        self.assertEqual(trace["repair"]["action"], "no_repair")
        self.assertEqual(trace["escalation_tokens"], ["route:parser_damage", "schema_violation"])

    def test_trace_redacts_forbidden_raw_debug_fields_and_sensitive_values(self):
        unsafe = {
            "raw_step": "RAW_STEP_MARKER",
            "_state_snapshot": {"secret": "STATE_MARKER"},
            "state_snapshot": "STATE_SNAPSHOT_MARKER",
            "prompt": "PROMPT_MARKER",
            "response": "RESPONSE_MARKER",
            "safe": {"credential": "CREDENTIAL_MARKER", "normal": "kept"},
        }

        sanitized = sanitize_trace_value(unsafe)
        blob = json.dumps(sanitized, sort_keys=True)

        for forbidden in (
            "raw_step",
            "_state_snapshot",
            "state_snapshot",
            "prompt",
            "response",
            "RAW_STEP_MARKER",
            "STATE_MARKER",
            "STATE_SNAPSHOT_MARKER",
            "PROMPT_MARKER",
            "RESPONSE_MARKER",
            "CREDENTIAL_MARKER",
        ):
            self.assertNotIn(forbidden, blob)
        self.assertEqual(sanitized["safe"]["credential"], "<redacted>")
        self.assertEqual(sanitized["safe"]["normal"], "kept")

    def test_trace_bounds_long_values_and_lists(self):
        sanitized = sanitize_trace_value({"text": "x" * 2000, "items": list(range(40))})
        self.assertLess(len(sanitized["text"]), 400)
        self.assertIn("<truncated>", sanitized["text"])
        self.assertEqual(len(sanitized["items"]), 16)

    def test_repair_decision_redacts_sensitive_patch_values_and_raw_reason(self):
        decision = RepairDecision(
            action="repair_event",
            confidence=0.9,
            reason="LLM repair output failed validation: bad; raw=SECRET_MODEL_RESPONSE",
            step_index=0,
            event_patch={
                "method": "Set",
                "values": {"PIN": "SECRET_PIN_MARKER"},
                "required_parameters": {"HostChallenge": "CHALLENGE_MARKER"},
                "status": "success",
            },
        )

        summary = serialize_repair_decision(decision, enabled=True, attempted=True, applied=False)
        blob = json.dumps(summary, sort_keys=True)

        self.assertEqual(summary["event_patch"]["method"], "Set")
        self.assertEqual(summary["event_patch"]["status"], "success")
        self.assertTrue(summary["event_patch"]["values"]["omitted"])
        self.assertTrue(summary["event_patch"]["required_parameters"]["omitted"])
        for forbidden in ("SECRET_MODEL_RESPONSE", "SECRET_PIN_MARKER", "CHALLENGE_MARKER", "raw="):
            self.assertNotIn(forbidden, blob)

    def test_repair_decision_summarizes_state_patch_without_values(self):
        decision = RepairDecision(
            action="state_effect",
            confidence=0.9,
            reason="bounded state effect",
            step_index=0,
            state_effect="open_session",
            state_patch={"session": {"open": True, "authority": "secret"}, "credentials": {"x": "y"}},
        )

        summary = serialize_repair_decision(decision, enabled=True, attempted=True, applied=True)
        blob = json.dumps(summary, sort_keys=True)

        self.assertTrue(summary["state_patch_present"])
        self.assertEqual(summary["state_patch_fields"], ["credentials", "session"])
        self.assertNotIn("authority", blob)
        self.assertNotIn("secret", blob)

    def test_legacy_parse_fallback_summaries_are_bounded(self):
        trace = build_llm_workflow_trace(
            trajectory_id=None,
            task="judge_target",
            profile="state_machine",
            source="test",
            legacy_parse_fallback_enabled=True,
            legacy_parse_fallback_summaries=[
                {
                    "step_index": 0,
                    "is_target": False,
                    "applied": True,
                    "event_patch_fields": ["method"],
                    "state_patch_fields": ["credentials"],
                    "reason": "repaired parser damage",
                }
            ],
        )

        self.assertEqual(trace["legacy_parse_fallback"]["repair_count"], 1)
        self.assertEqual(trace["legacy_parse_fallback"]["repairs"][0]["event_patch_fields"], ["method"])


if __name__ == "__main__":
    unittest.main()

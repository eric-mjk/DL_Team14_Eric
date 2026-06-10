import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.llm_parse_fallback import LLMParseFallback
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
    }
    base.update(overrides)
    return patch.dict(os.environ, base, clear=False)


class SolverEvidencePacketParityTest(unittest.TestCase):
    def test_packet_on_off_verdict_parity_for_pass_and_fail(self):
        for steps in (PROPERTIES_PASS, PROPERTIES_FAIL):
            with self.subTest(steps=steps):
                with _env():
                    off = Solver().predict_one(steps)

                with tempfile.TemporaryDirectory() as td:
                    packet_path = Path(td) / "packet.jsonl"
                    with _env(EVIDENCE_PACKET_AUDIT_PATH=str(packet_path)):
                        on = Solver().predict_one(steps)

                    self.assertEqual(on, off)
                    self.assertTrue(packet_path.exists())

    def test_dataset_id_is_preserved_as_optional_trajectory_id(self):
        with tempfile.TemporaryDirectory() as td:
            packet_path = Path(td) / "packet.jsonl"
            with _env(EVIDENCE_PACKET_AUDIT_PATH=str(packet_path)):
                predictions = Solver().predict([{"id": "case-1", "steps": PROPERTIES_PASS}])

            packet = json.loads(packet_path.read_text().splitlines()[0])
            self.assertEqual(predictions, {"case-1": "pass"})
            self.assertEqual(packet["identity"]["trajectory_id"], "case-1")

    def test_missing_dataset_id_emits_null_trajectory_id(self):
        with tempfile.TemporaryDirectory() as td:
            packet_path = Path(td) / "packet.jsonl"
            with _env(EVIDENCE_PACKET_AUDIT_PATH=str(packet_path)):
                verdict = Solver().predict_one(PROPERTIES_PASS)

            packet = json.loads(packet_path.read_text().splitlines()[0])
            self.assertEqual(verdict, "pass")
            self.assertIsNone(packet["identity"]["trajectory_id"])


class SolverEvidencePacketPathIndependenceTest(unittest.TestCase):
    def test_evidence_path_only_does_not_write_parse_audit_path(self):
        with tempfile.TemporaryDirectory() as td:
            packet_path = Path(td) / "packet.jsonl"
            audit_path = Path(td) / "audit.jsonl"
            with _env(EVIDENCE_PACKET_AUDIT_PATH=str(packet_path), PARSE_RAG_AUDIT_PATH=""):
                Solver().predict_one(PROPERTIES_PASS)

            self.assertTrue(packet_path.exists())
            self.assertFalse(audit_path.exists())

    def test_parse_audit_path_only_does_not_write_packet_path(self):
        with tempfile.TemporaryDirectory() as td:
            packet_path = Path(td) / "packet.jsonl"
            audit_path = Path(td) / "audit.jsonl"
            with _env(ENABLE_PARSE_AUDIT="1", PARSE_RAG_AUDIT_PATH=str(audit_path), EVIDENCE_PACKET_AUDIT_PATH=""):
                Solver().predict_one(PROPERTIES_PASS)

            self.assertTrue(audit_path.exists())
            self.assertFalse(packet_path.exists())


class SolverEvidencePacketNoLLMCallsTest(unittest.TestCase):
    def test_packet_emission_does_not_invoke_llm_fallback_methods(self):
        with tempfile.TemporaryDirectory() as td:
            packet_path = Path(td) / "packet.jsonl"
            with patch.object(LLMParseFallback, "repair_event", side_effect=AssertionError("extra repair LLM call")), patch.object(
                LLMParseFallback,
                "judge_target",
                side_effect=AssertionError("extra judge LLM call"),
            ), _env(EVIDENCE_PACKET_AUDIT_PATH=str(packet_path)):
                verdict = Solver().predict_one(PROPERTIES_PASS)

            self.assertEqual(verdict, "pass")
            self.assertTrue(packet_path.exists())


class SolverEvidencePacketSchemaTest(unittest.TestCase):
    def test_solver_packet_schema_smoke(self):
        with tempfile.TemporaryDirectory() as td:
            packet_path = Path(td) / "packet.jsonl"
            with _env(EVIDENCE_PACKET_AUDIT_PATH=str(packet_path)):
                verdict = Solver().predict_one(PROPERTIES_PASS)

            packet = json.loads(packet_path.read_text().splitlines()[0])
            self.assertEqual(packet["final_view"]["verdict"], verdict)
            self.assertEqual(packet["schema_version"], "v2")
            self.assertEqual(packet["risk_flags_taxonomy_version"], "risk_flags_v1")
            self.assertEqual(packet["normalized_events"]["policy"]["version"], "normalized_events_v1")
            self.assertEqual(packet["state_facts"]["meta"]["source_whitelist_version"], "state_facts_v1")
            self.assertFalse(packet["provenance"]["parse_audit"]["enabled"])
            self.assertTrue(packet["rule_trace"]["override_guard"]["trusted_deterministic"])
            self.assertEqual(
                set(packet["final_view"]["terminal_event_summary"]),
                {"index", "kind", "method", "command", "object", "object_family", "status"},
            )

            blob = json.dumps(packet)
            for forbidden in ("raw_step", "_state_snapshot", "recent_history", "recent_failed_observations"):
                self.assertNotIn(forbidden, blob)


if __name__ == "__main__":
    unittest.main()

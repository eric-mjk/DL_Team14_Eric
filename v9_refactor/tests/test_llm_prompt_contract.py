import json
import os
import unittest
from unittest.mock import patch

os.environ.setdefault("SOLVER_PROFILE", "state_machine")

from src.llm_parse_fallback import LLMParseFallback, _extract_prompt_rag_context
from src.state import initial_state


class LLMPromptContractTest(unittest.TestCase):
    def test_llm_parse_prompt_contains_stable_input_envelope(self):
        fallback = LLMParseFallback()
        fallback.enable_rag = False
        event = {
            "index": 7,
            "kind": "method",
            "method": "Get",
            "object": "LockingSP",
            "object_family": "SP",
            "status": "success",
        }

        prompt = fallback._build_prompt(
            task="judge_target",
            raw_step={"input": {"method": {"name": "Get"}}, "output": {"status_codes": "SUCCESS"}},
            normalized_event=event,
            state=initial_state(),
            rule_result=None,
        )

        self.assertIn("Return JSON only with this schema", prompt)
        marker = "INPUT:\n"
        self.assertIn(marker, prompt)
        payload = json.loads(prompt.split(marker, 1)[1])
        self.assertEqual(payload["task"], "judge_target")
        self.assertEqual(payload["current_normalized_event"]["method"], "Get")
        self.assertEqual(payload["retrieved_spec_context"], "RAG disabled.")
        self.assertIn("state_before_step", payload)
        self.assertIn("rule_result", payload)
        self.assertEqual(
            set(payload),
            {
                "task",
                "raw_step",
                "current_normalized_event",
                "state_before_step",
                "retrieved_spec_context",
                "rule_result",
            },
        )
        for forbidden in (
            "evidence_packet",
            "state_facts",
            "normalized_events",
            "rule_trace",
            "risk_flags",
            "provenance",
            "subsystem_flags",
            "spec_references",
        ):
            self.assertNotIn(forbidden, payload)
            self.assertNotIn(forbidden, prompt)

    def test_prompt_rag_context_extractor_surfaces_embedded_context(self):
        prompt = 'prefix INPUT:\n{"retrieved_spec_context": "abc", "task": "x"}'
        self.assertEqual(_extract_prompt_rag_context(prompt), "abc")


if __name__ == "__main__":
    unittest.main()

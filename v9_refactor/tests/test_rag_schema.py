import unittest

from src.rag_parser_repair import parse_repair_response, run_parser_repair
from src.rag_schema import RepairValidationError, validate_repair_decision


class RAGRepairSchemaTest(unittest.TestCase):
    def test_state_effect_accepts_bounded_state_patch(self):
        decision = validate_repair_decision(
            {
                "action": "state_effect",
                "confidence": 0.9,
                "step_index": 0,
                "event_patch": None,
                "state_effect": "open_session",
                "state_patch": {"session": {"open": True}},
                "reason": "successful history method opens a session",
            }
        )

        self.assertEqual(decision.action, "state_effect")
        self.assertEqual(decision.state_patch, {"session": {"open": True}})
        self.assertTrue(decision.usable)

    def test_repair_event_rejects_state_patch(self):
        with self.assertRaises(RepairValidationError):
            validate_repair_decision(
                {
                    "action": "repair_event",
                    "confidence": 0.9,
                    "step_index": 0,
                    "event_patch": {"method": "Get"},
                    "state_effect": None,
                    "state_patch": {"session": {"open": True}},
                    "reason": "not allowed",
                }
            )

    def test_state_patch_rejects_unknown_top_level_key(self):
        with self.assertRaises(RepairValidationError):
            validate_repair_decision(
                {
                    "action": "state_effect",
                    "confidence": 0.9,
                    "step_index": 0,
                    "event_patch": None,
                    "state_effect": "open_session",
                    "state_patch": {"unknown_domain": {"open": True}},
                    "reason": "not allowed",
                }
            )

    def test_parse_response_keeps_raw_model_response(self):
        decision = parse_repair_response(
            '{"action":"state_effect","confidence":0.9,"step_index":0,'
            '"event_patch":null,"state_effect":"open_session",'
            '"state_patch":{"session":{"open":true}},"reason":"ok"}'
        )

        self.assertIn("_raw_model_response", decision.raw)
        self.assertEqual(decision.state_patch, {"session": {"open": True}})

    def test_run_parser_repair_surfaces_validation_error(self):
        decision = run_parser_repair(
            [],
            {},
            llm_callable=lambda _prompt: '{"action":"repair_event","confidence":0.9,"event_patch":{}',
        )

        self.assertEqual(decision.action, "no_repair")
        self.assertIsNotNone(decision.validation_error)
        self.assertIn("validation", decision.reason)


if __name__ == "__main__":
    unittest.main()

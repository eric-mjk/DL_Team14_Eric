import json
import os
import tempfile
import unittest
from pathlib import Path

from src import runtime_config


class RuntimeConfigTest(unittest.TestCase):
    CONFIG_KEYS = {
        "SOLVER_CONFIG_PATH",
        "SOLVER_CONFIG_RELOAD",
        "SOLVER_PROFILE",
        "USE_LLM_PARSE_FALLBACK",
        "ENABLE_RAG_REPAIR",
        "LLM_PARSE_MIN_CONFIDENCE",
        "LLM_PIPELINE_MODE",
        "MODEL_NAME",
        "LLM_PARSE_MAX_MODEL_LEN",
        "LLM_DEBUG_DIR",
        "LLM_WORKFLOW_TRACE_PATH",
        "EVIDENCE_PACKET_AUDIT_PATH",
        "PARSE_RAG_AUDIT_PATH",
        "RAG_PROMPT_AUDIT_PATH",
        "LLM_ALLOW_VERDICT_OVERRIDE",
        "LLM_ALLOW_STATE_PATCH",
        "RAG_REPAIR_MODE",
        "RAG_APPLY_REPAIRS",
        "RAG_REPAIR_MIN_CONFIDENCE",
        "HF_HOME",
        "HF_HUB_OFFLINE",
        "RAG_REPAIR_PROMPT_MAX_CHARS",
        "ENABLE_RAG_REPAIR_LLM",
        "RAG_REPAIR_MAX_MODEL_LEN",
        "RAG_REPAIR_MAX_NEW_TOKENS",
        "RAG_REPAIR_TEMPERATURE",
        "RAG_REPAIR_STRUCTURED_OUTPUT",
    }

    def setUp(self):
        self._old_env = os.environ.copy()
        for key in self.CONFIG_KEYS:
            os.environ.pop(key, None)
        runtime_config._LOADED_PATHS.clear()

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._old_env)
        runtime_config._LOADED_PATHS.clear()

    def test_json_config_loads_settings_and_preserves_explicit_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "solver.json"
            path.write_text(
                json.dumps(
                    {
                        "_comment": "ignored metadata",
                        "settings": {
                            "USE_LLM_PARSE_FALLBACK": True,
                            "ENABLE_RAG_REPAIR": False,
                            "LLM_PARSE_MIN_CONFIDENCE": 0.72,
                        },
                    }
                ),
                encoding="utf-8",
            )
            os.environ["SOLVER_CONFIG_PATH"] = str(path)
            os.environ["USE_LLM_PARSE_FALLBACK"] = "0"

            loaded = runtime_config.load_runtime_config()

            self.assertEqual(path.resolve(), loaded)
            self.assertEqual("0", os.environ["USE_LLM_PARSE_FALLBACK"])
            self.assertEqual("0", os.environ["ENABLE_RAG_REPAIR"])
            self.assertEqual("0.72", os.environ["LLM_PARSE_MIN_CONFIDENCE"])

    def test_yaml_config_loads_settings_section_without_pyyaml(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "solver.yaml"
            path.write_text(
                """
                # comments are ignored
                settings:
                  USE_LLM_PARSE_FALLBACK: true
                  ENABLE_RAG_REPAIR: false
                  LLM_PIPELINE_MODE: repair # inline comments are ignored
                  MODEL_NAME: "Qwen/Qwen3.5-9B"
                  LLM_PARSE_MAX_MODEL_LEN: 4096
                """,
                encoding="utf-8",
            )
            os.environ["SOLVER_CONFIG_PATH"] = str(path)

            runtime_config.load_runtime_config()

            self.assertEqual("1", os.environ["USE_LLM_PARSE_FALLBACK"])
            self.assertEqual("0", os.environ["ENABLE_RAG_REPAIR"])
            self.assertEqual("repair", os.environ["LLM_PIPELINE_MODE"])
            self.assertEqual("Qwen/Qwen3.5-9B", os.environ["MODEL_NAME"])
            self.assertEqual("4096", os.environ["LLM_PARSE_MAX_MODEL_LEN"])

    def test_named_profile_can_resolve_yaml_config(self):
        os.environ["SOLVER_PROFILE"] = "trace_debug"

        loaded = runtime_config.load_runtime_config()

        self.assertEqual((Path(__file__).resolve().parents[1] / "src" / "configs" / "trace_debug.yaml"), loaded)
        self.assertEqual("audit", os.environ["LLM_PIPELINE_MODE"])
        self.assertEqual("0", os.environ["USE_LLM_PARSE_FALLBACK"])

    def test_default_profile_is_submission_yaml(self):
        loaded = runtime_config.load_runtime_config()

        self.assertEqual((Path(__file__).resolve().parents[1] / "src" / "configs" / "submission.yaml"), loaded)
        self.assertEqual("off", os.environ["LLM_PIPELINE_MODE"])
        self.assertEqual("0", os.environ["ENABLE_RAG_REPAIR"])
        self.assertEqual("1", os.environ["USE_LLM_PARSE_FALLBACK"])
        self.assertEqual("1", os.environ["LLM_ALLOW_VERDICT_OVERRIDE"])
        self.assertEqual("0", os.environ["LLM_PARSE_TRUST_IMPLEMENTED_HIGH_CONF"])
        self.assertEqual("0", os.environ["LLM_PARSE_ENABLE_RAG"])
        self.assertEqual("0.82", os.environ["LLM_PARSE_MIN_CONFIDENCE"])

    def test_llm_rag_profile_is_canonical_repair_without_verdict_override(self):
        os.environ["SOLVER_PROFILE"] = "llm_rag"

        loaded = runtime_config.load_runtime_config()

        self.assertEqual((Path(__file__).resolve().parents[1] / "src" / "configs" / "llm_rag.yaml"), loaded)
        self.assertEqual("repair", os.environ["LLM_PIPELINE_MODE"])
        self.assertEqual("1", os.environ["ENABLE_RAG_REPAIR"])
        self.assertEqual("0", os.environ["USE_LLM_PARSE_FALLBACK"])
        self.assertEqual("0", os.environ["LLM_ALLOW_VERDICT_OVERRIDE"])

    def test_llm_debug_dir_fans_out_existing_artifact_paths_without_overwriting(self):
        os.environ["SOLVER_PROFILE"] = "llm_rag_debug"
        os.environ["LLM_DEBUG_DIR"] = "/tmp/custom-debug"
        os.environ["PARSE_RAG_AUDIT_PATH"] = "/tmp/explicit-parse.jsonl"

        runtime_config.load_runtime_config()

        self.assertEqual("/tmp/custom-debug/workflow_trace.jsonl", os.environ["LLM_WORKFLOW_TRACE_PATH"])
        self.assertEqual("/tmp/custom-debug/evidence_packets.jsonl", os.environ["EVIDENCE_PACKET_AUDIT_PATH"])
        self.assertEqual("/tmp/explicit-parse.jsonl", os.environ["PARSE_RAG_AUDIT_PATH"])
        self.assertNotIn("RAG_PROMPT_AUDIT_PATH", os.environ)


if __name__ == "__main__":
    unittest.main()

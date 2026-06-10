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
        self.assertEqual("0", os.environ["USE_LLM_PARSE_FALLBACK"])


if __name__ == "__main__":
    unittest.main()

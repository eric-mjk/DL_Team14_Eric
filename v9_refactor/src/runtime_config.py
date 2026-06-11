from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


_LOADED_PATHS: set[Path] = set()


def _source_config_dir() -> Path:
    return Path(__file__).resolve().parent / "configs"


def _profile_path() -> Path | None:
    explicit = os.environ.get("SOLVER_CONFIG_PATH")
    if explicit:
        return Path(explicit).expanduser().resolve()

    profile = os.environ.get("SOLVER_PROFILE", "submission").strip()
    if not profile:
        return None
    if "/" in profile or "\\" in profile or _has_config_suffix(profile):
        return Path(profile).expanduser().resolve()
    for suffix in (".yaml", ".yml", ".json"):
        config_profile = _source_config_dir() / f"{profile}{suffix}"
        if config_profile.is_file():
            return config_profile
    return _source_config_dir() / f"{profile}.yaml"


def load_runtime_config() -> Path | None:
    path = _profile_path()
    if path is None:
        return None
    if path in _LOADED_PATHS and os.environ.get("SOLVER_CONFIG_RELOAD") != "1":
        return path
    if not path.is_file():
        _LOADED_PATHS.add(path)
        return None

    for key, value in _read_config_values(path).items():
        if key:
            os.environ.setdefault(key, _env_value(value))

    _expand_debug_dir()
    _LOADED_PATHS.add(path)
    return path


def _expand_debug_dir() -> None:
    """Fan out one debug directory into the existing bounded artifact paths."""

    debug_dir = os.environ.get("LLM_DEBUG_DIR")
    if not debug_dir:
        return
    base = Path(debug_dir).expanduser()
    defaults = {
        "LLM_WORKFLOW_TRACE_PATH": "workflow_trace.jsonl",
        "EVIDENCE_PACKET_AUDIT_PATH": "evidence_packets.jsonl",
        "PARSE_RAG_AUDIT_PATH": "parse_rag_audit.jsonl",
    }
    for key, filename in defaults.items():
        os.environ.setdefault(key, str(base / filename))


def _has_config_suffix(value: str) -> bool:
    return value.endswith((".json", ".yaml", ".yml"))


def _read_config_values(path: Path) -> dict[str, Any]:
    suffix = path.suffix.lower()
    if suffix == ".json":
        return _read_json_config(path)
    if suffix in {".yaml", ".yml"}:
        return _read_simple_yaml_config(path)
    return {}


def _read_json_config(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return {}
    return _extract_env_mapping(data)


def _read_simple_yaml_config(path: Path) -> dict[str, Any]:
    """Read the small YAML subset used by editable solver configs.

    This intentionally avoids adding PyYAML.  Supported syntax is enough for
    hand-edited config files:

    - comments and blank lines;
    - optional top-level `env:` or `settings:` section;
    - `KEY: value` pairs, where values are strings, booleans, ints, floats, or
      null-ish tokens.

    Nested objects/lists are deliberately not supported; advanced profiles can
    still use JSON or the existing `.env` format.
    """

    values: dict[str, Any] = {}
    active_section: str | None = None
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("- "):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        line = _strip_inline_comment(stripped)
        if not line or ":" not in line:
            continue
        key, raw_value = line.split(":", 1)
        key = key.strip()
        raw_value = raw_value.strip()
        if indent == 0 and not raw_value:
            active_section = key
            continue
        if active_section and active_section not in {"env", "settings"} and indent > 0:
            continue
        if active_section in {"env", "settings"} and indent == 0:
            active_section = None
        if not key or key.startswith("_"):
            continue
        values[key] = _parse_scalar(raw_value)
    return values


def _extract_env_mapping(data: dict[str, Any]) -> dict[str, Any]:
    for section in ("env", "settings"):
        nested = data.get(section)
        if isinstance(nested, dict):
            return {str(k): v for k, v in nested.items() if not str(k).startswith("_")}
    return {str(k): v for k, v in data.items() if not str(k).startswith("_")}


def _strip_inline_comment(line: str) -> str:
    in_single = False
    in_double = False
    for idx, char in enumerate(line):
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        elif char == "#" and not in_single and not in_double:
            return line[:idx].rstrip()
    return line


def _parse_scalar(raw: str) -> Any:
    if raw == "":
        return ""
    value = raw.strip().strip("'\"")
    lowered = value.lower()
    if lowered in {"true", "yes"}:
        return True
    if lowered in {"false", "no"}:
        return False
    if lowered in {"null", "none", "~"}:
        return None
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        return value


def _env_value(value: Any) -> str:
    if isinstance(value, bool):
        return "1" if value else "0"
    if value is None:
        return ""
    return str(value)

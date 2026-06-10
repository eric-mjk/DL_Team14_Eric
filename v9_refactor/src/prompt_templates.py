from __future__ import annotations

import os
from pathlib import Path
from string import Template


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROMPT_DIR = ROOT / "artifacts" / "prompts"


def prompt_dir() -> Path:
    configured = os.environ.get("SOLVER_PROMPT_DIR")
    if configured:
        return Path(configured).expanduser().resolve()
    return DEFAULT_PROMPT_DIR


def load_prompt(name: str) -> str:
    path = prompt_dir() / name
    return path.read_text(encoding="utf-8").strip()


def render_prompt(name: str, **values: object) -> str:
    template = Template(load_prompt(name))
    return template.safe_substitute({key: str(value) for key, value in values.items()})

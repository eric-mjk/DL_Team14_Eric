from __future__ import annotations

import os
from pathlib import Path


_LOADED_PATHS: set[Path] = set()


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _profile_path() -> Path | None:
    explicit = os.environ.get("SOLVER_CONFIG_PATH")
    if explicit:
        return Path(explicit).expanduser().resolve()

    profile = os.environ.get("SOLVER_PROFILE", "state_machine").strip()
    if not profile:
        return None
    if "/" in profile or "\\" in profile or profile.endswith(".env"):
        return Path(profile).expanduser().resolve()
    return _project_root() / "artifacts" / "runtime_profiles" / f"{profile}.env"


def load_runtime_config() -> Path | None:
    path = _profile_path()
    if path is None:
        return None
    if path in _LOADED_PATHS and os.environ.get("SOLVER_CONFIG_RELOAD") != "1":
        return path
    if not path.is_file():
        _LOADED_PATHS.add(path)
        return None

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'\"")
        if key:
            os.environ.setdefault(key, value)

    _LOADED_PATHS.add(path)
    return path

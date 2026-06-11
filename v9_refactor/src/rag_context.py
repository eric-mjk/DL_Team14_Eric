"""Context builders for parser-repair RAG prompts."""
from __future__ import annotations

import json
import re
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

from .normalizer import dict_value
from .rag_schema import RetrievedChunk
from .spec_docs import COLUMN_NAME_NUMBERS, METHOD_UID_NAMES, compact_uid


IMPORTANT_KEYS = (
    "method",
    "command",
    "object_uid",
    "object",
    "object_family",
    "status",
    "result",
    "spid",
    "sp",
    "write",
    "authority",
    "where",
    "count",
    "values",
    "lba",
    "pattern",
)


STATE_MACHINE_CONTRACT = """\
The existing deterministic state-machine code consumes normalized event dicts, not raw JSON.

Solver flow:
```python
events = normalize_trajectory(raw_steps)
state = track_state(events[:-1])
result = judge_final(state, events[-1])
```

Normalizer contract:
```python
event = {
  "kind": "method|read|write|command|discovery",
  "method": "StartSession|Get|Set|Activate|...",
  "command": "Read|Write|Power Cycle|...",
  "object_uid": compact UID string,
  "object": canonical object name,
  "object_family": "SP|C_PIN|Locking|MBRControl|MBR|MediaKey|...",
  "status": normalized output status,
  "parameters": merged required + optional args,
  "required_parameters": parsed required args,
  "optional_parameters": parsed optional args,
  "spid": StartSession SPID,
  "sp": "AdminSP|LockingSP",
  "write": bool,
  "authority": canonical authority,
  "where": Where arg,
  "count": Count arg,
  "values": Set Values,
  "lba": normalized data-command LBA tuple,
  "pattern": Write pattern,
  "result": data-command output result,
}
```

State update contract:
```python
track_state(events[:-1]) applies only successful/accepted history events.
Known successful methods mutate state: StartSession, SyncSession, EndSession/CloseSession,
Authenticate, Get, Set, Activate, GenKey, Revert, RevertSP, CreateLog, AddACE,
RemoveACE, DeleteMethod, Delete, reset-like commands, Read, Write.
Unknown successful history methods may be important, but they cannot mutate state unless
classified into a whitelisted state_effect.
```

Oracle contract:
```python
judge_final(state, final_event) compares expected protocol status with actual status.
Unknown final methods are expected to return invalid_parameter.
The LLM must repair parsed normalized event fields only when raw input clearly supports it.
If the deterministic parser already understood the input, return no_repair.
```
"""


INPUT_PARSER_CONCERNS = """\
Private-leaderboard parser risks we are actively checking:
- Method args may be outside required/optional wrappers, e.g. args.SPID or args.Write.
- Known arguments may appear under unexpected casing or aliases, e.g. Pattern vs pattern, Lba vs LBA.
- Set Values may be a dict instead of a list, including nested RowValues/Values wrappers.
- Invoking IDs may include useful UID but misleading or generic names; UID is usually stronger evidence.
- Known methods or objects may appear with UID/name disagreement.
- Successful history events before the final step may carry state effects; do not reason from only the final event.
- Output status/result text may be misspelled, oddly cased, or placed under non-standard keys.
- Raw fields that do not appear in the normalized event may indicate parser loss.
"""


SOURCE_EXCERPTS = (
    ("normalizer.py", ("normalize_args", "arg_value", "normalize_record"), 1100),
    ("state.py", ("success_like", "remember_successful_start_session", "track_state"), 1300),
    ("oracle.py", ("actual_status_class", "expected_status_result", "judge_final"), 1300),
)


def _to_plain(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, dict):
        return {str(k): _to_plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_to_plain(v) for v in value]
    if hasattr(value, "__dict__"):
        return {str(k): _to_plain(v) for k, v in vars(value).items() if not k.startswith("_")}
    return repr(value)


def _safe_json(value: Any, max_chars: int = 1200) -> str:
    try:
        text = json.dumps(_to_plain(value), sort_keys=True, ensure_ascii=True)
    except TypeError:
        text = repr(value)
    if len(text) > max_chars:
        return text[:max_chars] + "...<truncated>"
    return text


def _source_root() -> Path:
    return Path(__file__).resolve().parent


def _extract_function_excerpt(text: str, function_name: str, max_chars: int) -> str:
    pattern = re.compile(rf"^def {re.escape(function_name)}\(", flags=re.MULTILINE)
    match = pattern.search(text)
    if not match:
        return f"# def {function_name}(...) not found"
    start = match.start()
    next_match = re.search(r"\n(?=def [A-Za-z_][A-Za-z0-9_]*\()", text[match.end():], flags=re.MULTILINE)
    end = match.end() + next_match.start() + 1 if next_match else len(text)
    excerpt = text[start:end].strip()
    if len(excerpt) > max_chars:
        excerpt = excerpt[:max_chars].rstrip() + "\n# ...<truncated>"
    return excerpt


def current_state_machine_source_context(max_chars: int = 5200) -> str:
    """Return compact excerpts from the current parser/state/oracle source files."""

    blocks: list[str] = []
    used = 0
    for filename, function_names, per_function_chars in SOURCE_EXCERPTS:
        path = _source_root() / filename
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            block = f"### {filename}\n# could not read source: {exc}"
        else:
            excerpts = [
                _extract_function_excerpt(text, function_name, per_function_chars)
                for function_name in function_names
            ]
            block = f"### {filename}\n" + "\n\n".join(excerpts)
        remaining = max_chars - used
        if remaining <= 0:
            break
        if len(block) > remaining:
            block = block[:remaining].rstrip() + "\n# ...<truncated>"
        blocks.append(block)
        used += len(block) + 2
    return "\n\n".join(blocks)


def _field(value: Any, name: str, default: Any = None) -> Any:
    if value is None:
        return default
    if isinstance(value, dict):
        return value.get(name, default)
    return getattr(value, name, default)


def summarize_parse_issues(parse_issues: list[Any] | tuple[Any, ...] | None, max_issues: int = 8) -> str:
    issues = list(parse_issues or [])
    if not issues:
        return "No parse-audit issues were supplied."
    lines = []
    for issue in issues[:max_issues]:
        severity = _field(issue, "severity", "?")
        kind = _field(issue, "kind", "?")
        step_index = _field(issue, "step_index", None)
        path = _field(issue, "path", "")
        message = _field(issue, "message", "")
        raw_value = _field(issue, "raw_value", None)
        where = f"step={step_index}" if step_index is not None else "step=?"
        line = f"- {where} severity={severity} kind={kind}"
        if path:
            line += f" path={path}"
        if message:
            line += f" message={message}"
        if raw_value is not None:
            line += f" raw={_safe_json(raw_value, max_chars=240)}"
        lines.append(line)
    if len(issues) > max_issues:
        lines.append(f"- ... {len(issues) - max_issues} additional issues omitted")
    return "\n".join(lines)


def summarize_event(event: Any, max_chars: int = 1600) -> str:
    plain = _to_plain(event)
    if isinstance(plain, dict):
        compact: dict[str, Any] = {}
        for key in IMPORTANT_KEYS:
            if key in plain and plain[key] is not None:
                compact[key] = plain[key]
        parameters = plain.get("parameters")
        if parameters:
            compact["parameters"] = parameters
        required = plain.get("required_parameters")
        optional = plain.get("optional_parameters")
        if required:
            compact["required_parameters"] = required
        if optional:
            compact["optional_parameters"] = optional
        if compact:
            return _safe_json(compact, max_chars=max_chars)
    return _safe_json(plain, max_chars=max_chars)


def summarize_protocol_facts(
    raw_steps: list[Any] | tuple[Any, ...] | None,
    events: list[Any] | tuple[Any, ...] | None,
    max_lines: int = 18,
) -> str:
    """Summarize exact protocol identifiers the LLM is weak at inferring."""

    lines: list[str] = []
    event_list = list(events or [])
    for event in event_list:
        plain = _to_plain(event)
        if not isinstance(plain, dict):
            continue
        parts = []
        index = plain.get("index")
        method_uid = compact_uid(plain.get("method_uid"))
        if method_uid:
            parts.append(f"method_uid={method_uid}")
            mapped = METHOD_UID_NAMES.get(method_uid)
            if mapped:
                parts.append(f"method_uid_name={mapped}")
        object_uid = compact_uid(plain.get("object_uid"))
        if object_uid:
            parts.append(f"object_uid={object_uid}")
        for key in ("method", "object", "object_family", "spid", "sp", "authority", "status", "result"):
            value = plain.get(key)
            if value not in (None, "", [], {}):
                parts.append(f"{key}={value}")
        values = plain.get("values")
        if isinstance(values, list) and values:
            columns = sorted({str(k) for row in values if isinstance(row, dict) for k in row.keys()})[:12]
            if columns:
                parts.append(f"value_columns={columns}")
        if parts:
            lines.append(f"- step={index if index is not None else '?'} " + " ".join(parts))
        if len(lines) >= max_lines:
            break

    column_lines = []
    for family in ("Locking", "C_PIN", "MBRControl", "Authority", "MethodID", "AccessControl"):
        mapping = COLUMN_NAME_NUMBERS.get(family)
        if not mapping:
            continue
        preview = ", ".join(f"{name}->{number}" for name, number in list(mapping.items())[:10])
        column_lines.append(f"- {family} columns: {preview}")

    if not lines and not column_lines:
        return "No protocol UID/column facts available from normalized events."
    return "\n".join(
        [
            "Exact protocol facts from normalized events and spec mappings:",
            *(lines or ["- No UID-bearing normalized events supplied."]),
            "Column-number facts for common tables:",
            *column_lines[:6],
        ]
    )


def summarize_rule_result(rule_result: Any, max_chars: int = 1000) -> str:
    if rule_result is None:
        return "No deterministic rule result supplied."
    if isinstance(rule_result, str):
        return rule_result[:max_chars]
    return _safe_json(rule_result, max_chars=max_chars)


def _raw_method_name(step: Any) -> str:
    if not isinstance(step, dict):
        return "?"
    inp = step.get("input") if isinstance(step.get("input"), dict) else {}
    method = dict_value(inp, "method")
    if isinstance(method, dict):
        return str(dict_value(method, "name") or "?")
    command = dict_value(inp, "command")
    return str(command or "?")


def _raw_status(step: Any) -> str:
    if not isinstance(step, dict):
        return "?"
    out = step.get("output") if isinstance(step.get("output"), dict) else {}
    inp = step.get("input") if isinstance(step.get("input"), dict) else {}
    return str(dict_value(out, "status_codes") or dict_value(inp, "status_codes") or dict_value(out, "result") or "?")


def _raw_args_keys(step: Any) -> list[str]:
    if not isinstance(step, dict):
        return []
    inp = step.get("input") if isinstance(step.get("input"), dict) else {}
    method = dict_value(inp, "method")
    args = dict_value(method, "args") if isinstance(method, dict) else dict_value(inp, "args")
    if isinstance(args, dict):
        keys = []
        for key, value in args.items():
            if str(key).lower() in {"required", "optional"} and isinstance(value, dict):
                keys.extend(f"{key}.{subkey}" for subkey in value.keys())
            else:
                keys.append(str(key))
        return keys[:12]
    if isinstance(args, list):
        keys = []
        for item in args:
            if isinstance(item, dict):
                keys.extend(str(key) for key in item.keys())
        return keys[:12]
    return []


def summarize_trajectory(
    raw_steps: list[Any] | tuple[Any, ...] | None,
    events: list[Any] | tuple[Any, ...] | None,
    parse_issues: list[Any] | tuple[Any, ...] | None,
    *,
    max_steps: int = 80,
    max_raw_issue_chars: int = 1800,
) -> str:
    """Summarize all prior/final command-response records plus full raw issue steps."""

    raw_list = list(raw_steps or [])
    event_list = list(events or [])
    total = max(len(raw_list), len(event_list))
    if total == 0:
        return "No trajectory supplied."

    issue_steps = {
        _field(issue, "step_index", None)
        for issue in list(parse_issues or [])
        if _field(issue, "step_index", None) is not None
    }
    final_pos = total - 1
    lines = ["Compact trajectory. Every line includes the raw response/status before the final judgment:"]
    if total > max_steps:
        lines.append(f"Trajectory has {total} steps; showing first 8, last {max_steps - 8}, and all issue steps.")
    shown_positions = set()
    if total <= max_steps:
        shown_positions.update(range(total))
    else:
        shown_positions.update(range(min(8, total)))
        shown_positions.update(range(max(0, total - (max_steps - 8)), total))
        for pos, raw in enumerate(raw_list):
            idx = raw.get("index") if isinstance(raw, dict) else pos
            if idx in issue_steps:
                shown_positions.add(pos)
    for pos in sorted(shown_positions):
        raw = raw_list[pos] if pos < len(raw_list) else None
        event = event_list[pos] if pos < len(event_list) else None
        idx = raw.get("index") if isinstance(raw, dict) and raw.get("index") is not None else pos
        marker = " FINAL" if pos == final_pos else ""
        parsed = _to_plain(event)
        parsed_summary = {}
        if isinstance(parsed, dict):
            for key in ("kind", "method", "command", "object", "object_family", "object_uid", "status", "result", "sp", "write", "authority"):
                value = parsed.get(key)
                if value not in (None, "", [], {}):
                    parsed_summary[key] = value
        lines.append(
            f"- step={idx}{marker} raw={_raw_method_name(raw)} raw_status={_raw_status(raw)} "
            f"arg_keys={_raw_args_keys(raw)} parsed={_safe_json(parsed_summary, max_chars=700)}"
        )

    raw_blocks = []
    for pos, raw in enumerate(raw_list):
        idx = raw.get("index") if isinstance(raw, dict) and raw.get("index") is not None else pos
        if idx in issue_steps or pos == final_pos:
            raw_blocks.append(f"RAW_STEP {idx}:\n{_safe_json(raw, max_chars=max_raw_issue_chars)}")
    if raw_blocks:
        lines.append("\nFull raw JSON for issue steps and final step:")
        lines.extend(raw_blocks[:8])
    return "\n".join(lines)


def build_retrieval_query(
    parse_issues: list[Any] | tuple[Any, ...] | None,
    final_event: Any,
    state_summary: str | None = None,
    rule_result: Any = None,
    raw_steps: list[Any] | tuple[Any, ...] | None = None,
    events: list[Any] | tuple[Any, ...] | None = None,
) -> str:
    """Build a compact lexical query for spec retrieval."""

    parts: list[str] = []
    event_plain = _to_plain(final_event)
    if isinstance(event_plain, dict):
        for key in IMPORTANT_KEYS:
            value = event_plain.get(key)
            if value not in (None, "", [], {}):
                parts.append(f"{key} {value}")
        params = event_plain.get("parameters")
        if isinstance(params, dict):
            parts.extend(str(k) for k in params.keys())
    else:
        parts.append(repr(event_plain))

    for issue in list(parse_issues or [])[:10]:
        for attr in ("kind", "message", "path"):
            value = _field(issue, attr, None)
            if value:
                parts.append(str(value))
        raw_value = _field(issue, "raw_value", None)
        if raw_value is not None:
            parts.append(_safe_json(raw_value, max_chars=240))

    if state_summary:
        parts.append(state_summary[:600])
    if rule_result is not None:
        parts.append(summarize_rule_result(rule_result, max_chars=400))
    if raw_steps or events:
        parts.append(summarize_trajectory(raw_steps, events, parse_issues, max_steps=30, max_raw_issue_chars=500)[:1600])

    query = " ".join(parts)
    return " ".join(query.split())


def format_retrieved_context(chunks: list[RetrievedChunk], max_chars: int = 5000) -> str:
    if not chunks:
        return "No spec chunks retrieved."
    lines: list[str] = []
    used = 0
    for idx, chunk in enumerate(chunks, start=1):
        header = f"[{idx}] {chunk.path} section={chunk.section} title={chunk.title} score={chunk.score}"
        text = chunk.text.strip()
        block = f"{header}\n{text}"
        remaining = max_chars - used
        if remaining <= 0:
            break
        if len(block) > remaining:
            block = block[:remaining] + "...<truncated>"
        lines.append(block)
        used += len(block) + 2
    return "\n\n".join(lines)


def build_repair_context(
    parse_issues: list[Any] | tuple[Any, ...] | None,
    final_event: Any,
    state_summary: str | None,
    rule_result: Any,
    chunks: list[RetrievedChunk],
    raw_steps: list[Any] | tuple[Any, ...] | None = None,
    events: list[Any] | tuple[Any, ...] | None = None,
    *,
    max_issues: int = 8,
    source_max_chars: int = 5200,
    trajectory_max_steps: int = 80,
    raw_issue_chars: int = 1800,
    event_max_chars: int = 1600,
    rule_max_chars: int = 1000,
    spec_max_chars: int = 5000,
) -> str:
    """Build a compact human-readable context block for the repair prompt."""

    return "\n\n".join(
        [
            "=== Parse Audit Issues ===",
            summarize_parse_issues(parse_issues, max_issues=max_issues),
            "=== Input Parser Concerns ===",
            INPUT_PARSER_CONCERNS,
            "=== Current State-Machine Code Contract ===",
            STATE_MACHINE_CONTRACT,
            "=== Current State-Machine Source Excerpts ===",
            current_state_machine_source_context(max_chars=source_max_chars),
            "=== Protocol Facts ===",
            summarize_protocol_facts(raw_steps, events),
            "=== Full Trajectory Parse Context ===",
            summarize_trajectory(
                raw_steps,
                events,
                parse_issues,
                max_steps=trajectory_max_steps,
                max_raw_issue_chars=raw_issue_chars,
            ),
            "=== Final Event As Parsed ===",
            summarize_event(final_event, max_chars=event_max_chars),
            "=== Deterministic State Summary ===",
            state_summary or "No state summary supplied.",
            "=== Deterministic Rule Result ===",
            summarize_rule_result(rule_result, max_chars=rule_max_chars),
            "=== Retrieved Spec Evidence ===",
            format_retrieved_context(chunks, max_chars=spec_max_chars),
        ]
    )

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .normalizer import (
    canonical_arg_key,
    compact_uid,
    dict_value,
    normalize_args,
    normalize_status,
    normalized_key_token,
    object_families_compatible,
    object_family_from_name,
    object_family_from_uid,
)
from .spec_docs import METHOD_NAMES, METHOD_UID_NAMES


SEVERITY_SCORE = {"high": 5, "medium": 3, "low": 1}
KNOWN_METHODS = set(METHOD_NAMES)
KNOWN_STATUSES = {
    "success",
    "not_authorized",
    "authority_locked_out",
    "invalid_parameter",
    "invalid_command",
    "insufficient_rows",
    "insufficient_columns",
    "unsupported",
    "sp_busy",
    "sp_failed",
    "sp_disabled",
    "sp_frozen",
    "no_sessions_available",
    "insufficient_space",
    "transaction_failure",
    "response_overflow",
    "tper_malfunction",
    "fail",
    "failed",
    "failure",
}
KNOWN_RESULT_TEXT = {
    "success",
    "pass",
    "passed",
    "ok",
    "fail",
    "failed",
    "failure",
    "error",
    "denied",
    "not_authorized",
    "invalid_parameter",
    "invalid_command",
    "user_data",
    "userdata",
    "mbr_shadow",
    "mbrshadow",
    "mbr_shadow_data",
    "mbrshadowdata",
    "mbr",
}

IMPORTANT_KEYS = {
    "spid",
    "write",
    "values",
    "where",
    "cellblock",
    "hostsigningauthority",
    "authority",
    "signingauthority",
    "proof",
    "hostchallenge",
    "challenge",
    "count",
    "lba",
    "pattern",
    "status",
    "statuscodes",
    "returnvalues",
    "result",
    "hostsessionid",
    "spsessionid",
}
IMPORTANT_ARG_KEYS = IMPORTANT_KEYS - {"status", "statuscodes", "returnvalues", "result"}
METHOD_META_KEYS = {"name", "uid", "args"}
EXPECTED_ARG_WRAPPERS = {"required", "optional"}

REQUIRED_PARAMS = {
    "StartSession": (("HostSessionID",), ("SPID",), ("Write",)),
    "SyncSession": (("HostSessionID",), ("SPSessionID",)),
    "Authenticate": (("HostSigningAuthority", "Authority", "SigningAuthority"),),
    "CreateRow": (("Row",),),
    "DeleteRow": (("Rows",),),
    "Random": (("Count",),),
    "Stir": (("Value",),),
}


@dataclass
class ParseIssue:
    severity: str
    kind: str
    step_index: int | None
    path: str
    message: str
    raw_value: Any = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "kind": self.kind,
            "step_index": self.step_index,
            "path": self.path,
            "message": self.message,
            "raw_value": json_safe(self.raw_value),
        }


@dataclass
class ParseAuditReport:
    issues: list[ParseIssue] = field(default_factory=list)
    risk_score: int = 0
    should_run_rag: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "issues": [issue.to_dict() for issue in self.issues],
            "risk_score": self.risk_score,
            "should_run_rag": self.should_run_rag,
        }


def json_safe(value: Any) -> Any:
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        return repr(value)


def report_to_dict(report: ParseAuditReport) -> dict[str, Any]:
    return report.to_dict()


def audit_trajectory_parse(raw_steps, events, final_result=None) -> ParseAuditReport:
    issues: list[ParseIssue] = []
    raw_list = raw_steps if isinstance(raw_steps, list) else []
    event_list = events if isinstance(events, list) else []
    max_len = max(len(raw_list), len(event_list))

    for position in range(max_len):
        raw = raw_list[position] if position < len(raw_list) else None
        event = event_list[position] if position < len(event_list) else None
        step_index = _step_index(raw, event, position)
        is_final = position == max_len - 1
        try:
            _audit_step(raw, event, step_index, is_final, issues)
        except Exception as exc:  # Defensive: audit must never affect prediction.
            issues.append(
                ParseIssue(
                    "medium",
                    "audit_exception",
                    step_index,
                    "$",
                    f"Parse audit failed on this step: {exc}",
                    repr(exc),
                )
            )

    if final_result is not None:
        _audit_final_result(final_result, issues)

    risk_score = sum(SEVERITY_SCORE.get(issue.severity, 1) for issue in issues)
    actionable_score = sum(
        SEVERITY_SCORE.get(issue.severity, 1)
        for issue in issues
        if issue.severity in {"high", "medium"}
    )
    should_run_rag = actionable_score >= 5 or any(issue.severity == "high" for issue in issues)
    return ParseAuditReport(issues=issues, risk_score=risk_score, should_run_rag=should_run_rag)


def _audit_step(raw: Any, event: Any, step_index: int | None, is_final: bool, issues: list[ParseIssue]) -> None:
    if not isinstance(raw, dict):
        issues.append(ParseIssue("high", "malformed_step", step_index, "$", "Raw step is not a JSON object.", raw))
        return
    if not isinstance(event, dict):
        issues.append(ParseIssue("high", "missing_event", step_index, "$", "Normalizer did not produce an event object.", event))
        return

    inp = dict_value(raw, "input")
    out = dict_value(raw, "output")
    inp = inp if isinstance(inp, dict) else {}
    out = out if isinstance(out, dict) else {}
    method = dict_value(inp, "method")

    if isinstance(method, dict):
        _audit_method_event(raw, inp, out, method, event, step_index, is_final, issues)
    else:
        _audit_command_event(inp, out, event, step_index, is_final, issues)

    _audit_status_text(inp, out, event, step_index, issues)
    _audit_unconsumed_important_fields(raw, event, step_index, issues)


def _audit_method_event(
    raw: dict[str, Any],
    inp: dict[str, Any],
    out: dict[str, Any],
    method: dict[str, Any],
    event: dict[str, Any],
    step_index: int | None,
    is_final: bool,
    issues: list[ParseIssue],
) -> None:
    raw_method_name = dict_value(method, "name")
    raw_method_uid = dict_value(method, "uid")
    method_uid = compact_uid(raw_method_uid)
    uid_method_name = METHOD_UID_NAMES.get(method_uid)
    parsed_method = event.get("method")

    if not parsed_method:
        severity = "high" if is_final else "medium"
        issues.append(ParseIssue(severity, "missing_method", step_index, "input.method", "Method event has no parsed method name.", method))
    elif parsed_method not in KNOWN_METHODS:
        severity = "high" if is_final or _is_success_event(event) else "medium"
        issues.append(
            ParseIssue(
                severity,
                "unknown_method",
                step_index,
                "input.method.name",
                f"Parsed method {parsed_method!r} is not in the modeled method list.",
                raw_method_name,
            )
        )

    if method_uid and uid_method_name is None:
        issues.append(
            ParseIssue(
                "medium",
                "unmapped_method_uid",
                step_index,
                "input.method.uid",
                "Method UID is present but does not map to a known MethodID.",
                raw_method_uid,
            )
        )
    name_disagrees_with_uid = (
        uid_method_name
        and raw_method_name
        and _method_name_token(raw_method_name) != _method_name_token(uid_method_name)
    )
    if name_disagrees_with_uid:
        severity = "low" if str(raw_method_name) in KNOWN_METHODS and parsed_method == raw_method_name else "high"
        issues.append(
            ParseIssue(
                severity,
                "method_uid_name_disagreement",
                step_index,
                "input.method",
                f"Method UID maps to {uid_method_name!r} but raw name is {raw_method_name!r}.",
                method,
            )
        )
    if uid_method_name and parsed_method and parsed_method != uid_method_name and not name_disagrees_with_uid:
        issues.append(
            ParseIssue(
                "high",
                "parsed_method_uid_disagreement",
                step_index,
                "input.method",
                f"Parsed method {parsed_method!r} disagrees with UID-derived method {uid_method_name!r}.",
                method,
            )
        )

    invoking = dict_value(inp, "invoking_id")
    invoking = invoking if isinstance(invoking, dict) else {}
    _audit_invoking_object(invoking, event, step_index, issues)

    args_raw = dict_value(method, "args")
    required, optional = normalize_args(args_raw)
    parameters = {}
    parameters.update(required)
    parameters.update(optional)
    _audit_flat_args(args_raw, step_index, issues)
    _audit_required_params(parsed_method, parameters, event, step_index, issues)
    _audit_method_shape(parsed_method, args_raw, parameters, event, step_index, issues)

    if not is_final and _is_success_event(event) and parsed_method not in KNOWN_METHODS:
        issues.append(
            ParseIssue(
                "high",
                "unknown_successful_history_method",
                step_index,
                "input.method.name",
                "Successful history method is not modeled and may have state effects.",
                raw_method_name,
            )
        )

    if is_final and (not parsed_method or parsed_method not in KNOWN_METHODS):
        issues.append(
            ParseIssue(
                "high",
                "unknown_final_method",
                step_index,
                "input.method.name",
                "Final method is missing or unknown; deterministic verdict likely used fallback behavior.",
                raw_method_name,
            )
        )


def _audit_command_event(
    inp: dict[str, Any],
    out: dict[str, Any],
    event: dict[str, Any],
    step_index: int | None,
    is_final: bool,
    issues: list[ParseIssue],
) -> None:
    command = dict_value(inp, "command")
    command_token = str(command or "").strip().lower().replace("-", "_")
    known_commands = {"read", "write", "if_recv", "ifrecv", "if_receive"}
    if command is None:
        severity = "high" if is_final else "medium"
        issues.append(ParseIssue(severity, "missing_command_or_method", step_index, "input", "Step has neither method nor command.", inp))
    elif command_token not in known_commands:
        severity = "medium" if is_final else "low"
        issues.append(ParseIssue(severity, "unknown_command", step_index, "input.command", "Command is not a modeled data/discovery command.", command))

    if is_final and event.get("kind") == "command":
        issues.append(
            ParseIssue(
                "medium",
                "final_command_fallback_like",
                step_index,
                "input.command",
                "Final event normalized as a generic command instead of a method/read/write/discovery event.",
                command,
            )
        )

    in_args = dict_value(inp, "args")
    if isinstance(in_args, dict):
        if event.get("kind") in {"read", "write"} and _has_key_like(in_args, "LBA") and event.get("lba") is None:
            issues.append(ParseIssue("high", "unparsed_lba", step_index, "input.args", "Raw LBA is present but normalized lba is missing.", in_args))
        if event.get("kind") in {"read", "write"} and _has_key_like(in_args, "Pattern") and event.get("pattern") is None:
            issues.append(ParseIssue("medium", "unparsed_pattern", step_index, "input.args", "Raw Pattern is present but normalized pattern is missing.", in_args))


def _audit_invoking_object(invoking: dict[str, Any], event: dict[str, Any], step_index: int | None, issues: list[ParseIssue]) -> None:
    raw_uid = dict_value(invoking, "uid")
    raw_name = dict_value(invoking, "name")
    uid = compact_uid(raw_uid)
    parsed_family = event.get("object_family")
    parsed_object = event.get("object")

    if parsed_object and parsed_family is None:
        issues.append(
            ParseIssue(
                "medium",
                "unknown_object_family",
                step_index,
                "input.invoking_id",
                "Normalizer parsed an object but could not classify its family.",
                invoking,
            )
        )

    uid_family = _family_from_uid(uid)
    name_family = _family_from_name(raw_name)
    if uid and uid_family is None and parsed_family is None:
        issues.append(
            ParseIssue(
                "medium",
                "unknown_object_uid_family",
                step_index,
                "input.invoking_id.uid",
                "Invoking UID does not match a known object family.",
                raw_uid,
            )
        )
    if uid_family and parsed_family and not _families_compatible(uid_family, parsed_family):
        issues.append(
            ParseIssue(
                "high",
                "parsed_object_family_disagreement",
                step_index,
                "input.invoking_id",
                f"UID implies family {uid_family!r} but parsed family is {parsed_family!r}.",
                invoking,
            )
        )
    if uid_family and name_family and not _families_compatible(uid_family, name_family):
        issues.append(
            ParseIssue(
                "medium",
                "uid_name_family_disagreement",
                step_index,
                "input.invoking_id",
                f"UID implies family {uid_family!r} but object name implies {name_family!r}.",
                invoking,
            )
        )


def _audit_flat_args(args_raw: Any, step_index: int | None, issues: list[ParseIssue]) -> None:
    if not isinstance(args_raw, dict):
        if isinstance(args_raw, list):
            issues.append(ParseIssue("low", "list_args_shape", step_index, "input.method.args", "Method args are a list instead of required/optional maps.", args_raw))
        elif args_raw is not None:
            issues.append(ParseIssue("medium", "malformed_args_shape", step_index, "input.method.args", "Method args are not a map or list.", args_raw))
        return

    for key, value in args_raw.items():
        token = normalized_key_token(key)
        if token in EXPECTED_ARG_WRAPPERS:
            continue
        canonical = canonical_arg_key(key)
        severity = "medium" if normalized_key_token(canonical) in IMPORTANT_ARG_KEYS else "low"
        issues.append(
            ParseIssue(
                severity,
                "raw_arg_outside_required_optional",
                step_index,
                f"input.method.args.{key}",
                "Method arg appears outside required/optional wrappers.",
                value,
            )
        )


def _audit_required_params(
    method: Any,
    parameters: dict[str, Any],
    event: dict[str, Any],
    step_index: int | None,
    issues: list[ParseIssue],
) -> None:
    if method not in REQUIRED_PARAMS:
        return
    for aliases in REQUIRED_PARAMS[method]:
        if not any(_parameter_present(parameters, alias) for alias in aliases):
            issues.append(
                ParseIssue(
                    "medium",
                    "missing_required_parameter",
                    step_index,
                    "input.method.args",
                    f"{method} is missing required parameter {'/'.join(aliases)} after parsing.",
                    {"method": method, "aliases": aliases},
                )
            )

    if method == "StartSession":
        if event.get("spid") is None and _parameter_present(parameters, "SPID"):
            issues.append(ParseIssue("high", "unparsed_spid", step_index, "input.method.args", "SPID is present but normalized spid is missing.", parameters))
        if event.get("write") is None and _parameter_present(parameters, "Write"):
            issues.append(ParseIssue("medium", "unparsed_write", step_index, "input.method.args", "Write is present but normalized write is missing.", parameters))
    if method == "Authenticate" and event.get("authority_uid") is None and any(
        _parameter_present(parameters, alias) for alias in ("HostSigningAuthority", "Authority", "SigningAuthority")
    ):
        issues.append(ParseIssue("high", "unparsed_authority", step_index, "input.method.args", "Authority is present but normalized authority UID is missing.", parameters))


def _audit_method_shape(
    method: Any,
    args_raw: Any,
    parameters: dict[str, Any],
    event: dict[str, Any],
    step_index: int | None,
    issues: list[ParseIssue],
) -> None:
    if method == "Get":
        if _parameter_present(parameters, "Cellblock") and event.get("cellblock") is None:
            issues.append(ParseIssue("medium", "unparsed_cellblock", step_index, "input.method.args", "Cellblock is present but normalized cellblock is missing.", parameters))
        if _parameter_present(parameters, "Cellblock") and event.get("cellblock_invalid"):
            issues.append(ParseIssue("medium", "malformed_cellblock", step_index, "input.method.args.Cellblock", "Cellblock shape could not be normalized cleanly.", _param_value(parameters, "Cellblock")))
    if method == "Set":
        if not _parameter_present(parameters, "Values"):
            issues.append(ParseIssue("medium", "missing_values", step_index, "input.method.args", "Set has no parsed Values parameter.", parameters))
        elif event.get("values") in (None, []):
            issues.append(ParseIssue("high", "unparsed_values", step_index, "input.method.args.Values", "Values is present but normalized values is empty.", _param_value(parameters, "Values")))
        if event.get("value_columns_invalid"):
            issues.append(ParseIssue("medium", "malformed_values_columns", step_index, "input.method.args.Values", "Values contain keys that do not map to target columns.", _param_value(parameters, "Values")))
    if method in {"CreateRow", "DeleteRow"}:
        expected = "Row" if method == "CreateRow" else "Rows"
        if _parameter_present(parameters, expected) and _param_value(parameters, expected) in (None, [], {}):
            issues.append(ParseIssue("medium", "empty_row_parameter", step_index, f"input.method.args.{expected}", f"{expected} is present but empty.", _param_value(parameters, expected)))


def _audit_status_text(inp: dict[str, Any], out: dict[str, Any], event: dict[str, Any], step_index: int | None, issues: list[ParseIssue]) -> None:
    for root_name, root in (("input", inp), ("output", out)):
        for key, value in _iter_items(root):
            token = normalized_key_token(key)
            if token in {"status", "statuscodes"}:
                normalized = normalize_status(value)
                if normalized is not None and normalized not in KNOWN_STATUSES:
                    issues.append(
                        ParseIssue(
                            "medium",
                            "unknown_status_text",
                            step_index,
                            f"{root_name}.{key}",
                            "Status text did not normalize to a known status class.",
                            value,
                        )
                    )
            elif token == "result" and isinstance(value, str):
                normalized = normalize_status(value)
                result_token = normalized_key_token(value)
                if (
                    normalized not in KNOWN_STATUSES
                    and result_token not in KNOWN_RESULT_TEXT
                    and _looks_statusish_result(value)
                ):
                    issues.append(
                        ParseIssue(
                            "low",
                            "odd_result_text",
                            step_index,
                            f"{root_name}.{key}",
                            "Result text is not a known pass/fail/data marker.",
                            value,
                        )
                    )


def _audit_unconsumed_important_fields(raw: dict[str, Any], event: dict[str, Any], step_index: int | None, issues: list[ParseIssue]) -> None:
    consumed = _consumed_tokens(event)
    for path, key, value in _iter_paths(raw):
        if _is_response_echo_path(path):
            continue
        token = normalized_key_token(key)
        if token not in IMPORTANT_KEYS:
            continue
        if _is_expected_container_path(path):
            continue
        if path == "$.output.return_values" or path.startswith("$.output.return_values."):
            continue
        if token in consumed:
            continue
        severity = "medium" if token in IMPORTANT_ARG_KEYS else "low"
        issues.append(
            ParseIssue(
                severity,
                "important_field_not_reflected_in_event",
                step_index,
                path,
                f"Important raw field {key!r} was present but not reflected in normalized event fields.",
                value,
            )
        )


def _audit_final_result(final_result: Any, issues: list[ParseIssue]) -> None:
    confidence = getattr(final_result, "confidence", None)
    if isinstance(confidence, (int, float)) and confidence < 0.75:
        issues.append(
            ParseIssue(
                "medium",
                "low_confidence_final_result",
                None,
                "final_result.confidence",
                "Final deterministic result has low confidence.",
                confidence,
            )
        )
    expected_status = getattr(final_result, "expected_status", None)
    if expected_status in {None, "unknown"}:
        issues.append(
            ParseIssue(
                "medium",
                "unknown_expected_status",
                None,
                "final_result.expected_status",
                "Final deterministic result did not produce a known expected status.",
                expected_status,
            )
        )
    coverage_status = getattr(final_result, "coverage_status", None)
    if coverage_status and coverage_status != "implemented":
        issues.append(
            ParseIssue(
                "medium",
                "partial_rule_coverage",
                None,
                "final_result.coverage_status",
                "Final deterministic result used partial or non-standard rule coverage.",
                coverage_status,
            )
        )
    spec_refs = getattr(final_result, "spec_refs", None)
    if not spec_refs:
        issues.append(
            ParseIssue(
                "low",
                "missing_spec_refs",
                None,
                "final_result.spec_refs",
                "Final deterministic result has no spec references.",
                spec_refs,
            )
        )


def _step_index(raw: Any, event: Any, fallback: int) -> int | None:
    if isinstance(event, dict) and event.get("index") is not None:
        return event.get("index")
    if isinstance(raw, dict) and raw.get("index") is not None:
        return raw.get("index")
    return fallback


def _is_success_event(event: dict[str, Any]) -> bool:
    return normalize_status(event.get("status")) == "success"


def _method_name_token(value: Any) -> str:
    return normalized_key_token(value)


def _family_from_uid(uid: str | None) -> str | None:
    return object_family_from_uid(uid)


def _family_from_name(name: Any) -> str | None:
    return object_family_from_name(name)


def _families_compatible(left: str, right: str) -> bool:
    return object_families_compatible(left, right)


def _parameter_present(parameters: dict[str, Any], name: str) -> bool:
    token = normalized_key_token(name)
    return any(normalized_key_token(key) == token for key in parameters)


def _param_value(parameters: dict[str, Any], name: str) -> Any:
    token = normalized_key_token(name)
    for key, value in parameters.items():
        if normalized_key_token(key) == token:
            return value
    return None


def _has_key_like(source: dict[str, Any], name: str) -> bool:
    token = normalized_key_token(name)
    return any(normalized_key_token(key) == token for key in source)


def _iter_items(value: Any):
    if isinstance(value, dict):
        for key, item_value in value.items():
            yield key, item_value
            yield from _iter_items(item_value)
    elif isinstance(value, list):
        for item in value:
            yield from _iter_items(item)


def _iter_paths(value: Any, prefix: str = "$"):
    if isinstance(value, dict):
        for key, item_value in value.items():
            path = f"{prefix}.{key}"
            yield path, key, item_value
            yield from _iter_paths(item_value, path)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _iter_paths(item, f"{prefix}[{index}]")


def _consumed_tokens(event: dict[str, Any]) -> set[str]:
    consumed = set()
    if event.get("spid") is not None or event.get("sp") is not None:
        consumed.add("spid")
    if event.get("write") is not None:
        consumed.add("write")
    if event.get("values") not in (None, []):
        consumed.add("values")
    if event.get("where") is not None:
        consumed.add("where")
    if event.get("cellblock") is not None:
        consumed.add("cellblock")
    if event.get("authority_uid") is not None or event.get("authority") is not None:
        consumed.update({"hostsigningauthority", "authority", "signingauthority"})
    if event.get("proof") is not None:
        consumed.update({"proof", "hostchallenge", "challenge"})
    if event.get("count") is not None:
        consumed.add("count")
    if event.get("lba") is not None:
        consumed.add("lba")
    if event.get("pattern") is not None:
        consumed.add("pattern")
    if event.get("status") is not None or event.get("input_status") is not None or event.get("output_status") is not None:
        consumed.update({"status", "statuscodes"})
    if event.get("return_columns"):
        consumed.add("returnvalues")
    if event.get("result") is not None:
        consumed.add("result")
    parameters = event.get("parameters")
    if isinstance(parameters, dict):
        for key in parameters:
            consumed.add(normalized_key_token(key))
    return consumed


def _is_expected_container_path(path: str) -> bool:
    lowered = path.lower()
    return lowered.endswith(".required") or lowered.endswith(".optional") or lowered.endswith(".args")


def _is_response_echo_path(path: str) -> bool:
    return path == "$.output.method" or path.startswith("$.output.method.")


def _looks_statusish_result(value: str) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return False
    hints = {
        "auth",
        "authoriz",
        "denied",
        "deny",
        "block",
        "lock",
        "invalid",
        "unsupported",
        "error",
        "fail",
        "success",
        "pass",
        "protect",
        "busy",
        "frozen",
        "overflow",
    }
    return any(hint in text for hint in hints)

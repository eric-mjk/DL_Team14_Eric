import re
from dataclasses import dataclass

from .normalizer import is_success_status, to_int
from .state import (
    data_command_success,
    is_error_result,
    key_generation_for_lba,
    lock_state_for_lba,
)
from .spec_docs import COLUMN_LIMITS, METHOD_NAMES, max_column_for_family, read_only_columns_for_family, refs_for, write_only_columns_for_family


AUTH_ERROR_STATUSES = {"not_authorized", "authority_locked_out"}
INVALID_STATUSES = {
    "invalid_parameter",
    "invalid_command",
    "insufficient_rows",
    "insufficient_columns",
    "unsupported",
}
RESOURCE_ERROR_STATUSES = {
    "sp_busy",
    "sp_failed",
    "sp_disabled",
    "sp_frozen",
    "no_sessions_available",
    "insufficient_space",
    "transaction_failure",
    "response_overflow",
    "tper_malfunction",
}
GENERIC_ERROR_STATUSES = {"fail", None}

@dataclass
class RuleResult:
    verdict: str
    confidence: float
    reason: str
    expected_status: str = "unknown"
    actual_status: str = "unknown"
    spec_refs: tuple = ()
    policy_source: str = "none"
    coverage_status: str = "implemented"


def spec_refs_for(*rule_keys):
    refs = []
    for key in rule_keys:
        for ref in refs_for(key):
            if ref not in refs:
                refs.append(ref)
    return tuple(refs)


def pass_result(
    reason,
    confidence=0.95,
    expected_status="unknown",
    actual_status="unknown",
    spec_refs=(),
    policy_source="none",
    coverage_status="implemented",
):
    return RuleResult(
        "pass",
        confidence,
        reason,
        expected_status,
        actual_status,
        tuple(spec_refs),
        policy_source,
        coverage_status,
    )


def fail_result(
    reason,
    confidence=0.95,
    expected_status="unknown",
    actual_status="unknown",
    spec_refs=(),
    policy_source="none",
    coverage_status="implemented",
):
    return RuleResult(
        "fail",
        confidence,
        reason,
        expected_status,
        actual_status,
        tuple(spec_refs),
        policy_source,
        coverage_status,
    )


def status_class(status):
    if is_success_status(status):
        return "success"
    if status in AUTH_ERROR_STATUSES:
        return "auth_error"
    if status in INVALID_STATUSES:
        return "invalid_parameter"
    if status in RESOURCE_ERROR_STATUSES:
        return "resource_error"
    if status in GENERIC_ERROR_STATUSES:
        return "error"
    return "error"


def actual_status_class(event):
    if event["kind"] in {"read", "write"}:
        return "data_success" if data_command_success(event) else "data_error"
    return status_class(event.get("status"))


def actual_success(event):
    if event["kind"] in {"read", "write"}:
        return data_command_success(event)
    return actual_status_class(event) == "success"


def status_matches(actual, expected):
    if isinstance(expected, (set, tuple, list)):
        return actual in expected
    if expected == "error":
        return actual not in {"success", "data_success"}
    if expected == "data_error":
        return actual == "data_error"
    if expected == "data_success":
        return actual == "data_success"
    return actual == expected


def expected_status_result(
    event,
    expected_status,
    reason,
    confidence=0.95,
    rule_key=None,
    policy_source="none",
    coverage_status="implemented",
):
    actual = actual_status_class(event)
    refs = spec_refs_for(rule_key) if rule_key else ()
    if status_matches(actual, expected_status):
        return pass_result(reason, confidence, expected_status, actual, refs, policy_source, coverage_status)
    return fail_result(reason, confidence, expected_status, actual, refs, policy_source, coverage_status)


def expected_success_result(event, expected_success, reason, confidence=0.95):
    expected = "success" if expected_success else "error"
    return expected_status_result(event, expected, reason, confidence)


def normalized_policy_text(value):
    return re.sub(r"[^0-9A-Za-z]", "", str(value or "")).lower()


def is_admin_authority(authority):
    return authority == "SID" or (isinstance(authority, str) and authority.startswith("Admin"))


def authority_records_for(state, authority):
    if not authority:
        return []
    wanted = normalized_policy_text(authority)
    rows = state.get("authority_rows") or {}
    records = []
    for key, row in rows.items():
        values = {key, row.get("name"), row.get("uid")}
        if any(wanted and wanted == normalized_policy_text(value) for value in values):
            records.append(row)
    return records


def authority_enabled(state, authority):
    if authority in {None, "Anybody"}:
        return True
    records = authority_records_for(state, authority)
    if not records:
        return True
    return any(record.get("enabled") is not False for record in records)


def authority_is_class(state, authority):
    return any(record.get("is_class") is True for record in authority_records_for(state, authority))


def authority_class_name(value):
    normalized = normalized_policy_text(value)
    if normalized == "admins":
        return "Admins"
    if normalized == "users":
        return "Users"
    if normalized == "anybody":
        return "Anybody"
    return None


def authority_classes_for(state, authority):
    classes = set()
    records = authority_records_for(state, authority)
    for record in records:
        class_name = authority_class_name(record.get("class"))
        if class_name and authority_enabled(state, class_name):
            classes.add(class_name)
    # Admin* authorities always belong to Admins class (spec opal/4.3.1.8).
    if isinstance(authority, str) and authority.startswith("Admin") and authority_enabled(state, "Admins"):
        classes.add("Admins")
    if not records:
        # Fallback for authorities not found in authority_rows.
        # User1 has Class=Null per spec opal/4.3.1.8 and must NOT be in Users.
        # Only UserMMMM (M>=2) belongs to the Users class.
        if isinstance(authority, str) and re.fullmatch(r"User[2-9]\d*|User\d{2,}", authority):
            if authority_enabled(state, "Users"):
                classes.add("Users")
    return classes


def is_authority_locked_out(state, authority):
    if not authority:
        return False
    trylimit = state.get("trylimit_by_authority", {}).get(authority)
    if trylimit is None or trylimit == 0:
        return False
    failed = state.get("failed_auth_counts", {}).get(authority, 0)
    return failed >= trylimit


def effective_session_authorities(state):
    authorities = set(state["session"].get("authorities") or set())
    return authorities


def session_has_authority(state, authority=None):
    authorities = effective_session_authorities(state)
    if authority is None:
        return bool(authorities)
    return authority in authorities


def session_has_admin_authority(state, sp=None):
    authorities = effective_session_authorities(state)
    if sp == "LockingSP":
        return any(isinstance(authority, str) and authority.startswith("Admin") for authority in authorities)
    if sp == "AdminSP":
        return any(authority == "SID" or (isinstance(authority, str) and authority.startswith("Admin")) for authority in authorities)
    return any(is_admin_authority(authority) for authority in authorities)


def session_authority_tokens(state):
    authorities = effective_session_authorities(state)
    tokens = set(authorities)
    tokens.add("Anybody")
    for authority in authorities:
        tokens.update(authority_classes_for(state, authority))
    return tokens


def boolean_atom_value(atom, tokens):
    text = str(atom or "").strip().strip("'\"")
    text = re.sub(r"\s*\*.*$", "", text).strip()
    if not text:
        return None
    normalized = normalized_policy_text(text)
    if normalized in {"true", "yes", "1"}:
        return True
    if normalized in {"false", "no", "0"}:
        return False
    if normalized == "anybody":
        return True
    if normalized == "admins":
        return "Admins" in tokens
    for token in tokens:
        if normalized == normalized_policy_text(token):
            return True
    if re.fullmatch(r"sid|admin\d+|user\d+", normalized):
        return False
    return None


def combine_boolean(op, values):
    if op == "OR":
        if any(value is True for value in values):
            return True
        if any(value is None for value in values):
            return None
        return False
    if op == "AND":
        if any(value is False for value in values):
            return False
        if any(value is None for value in values):
            return None
        return True
    return None


def evaluate_boolean_expr(expr, state):
    tokens = session_authority_tokens(state)
    if expr is None:
        return None
    if isinstance(expr, bool):
        return expr
    if isinstance(expr, dict):
        for op in ("OR", "AND", "or", "and"):
            if op in expr:
                value = expr[op]
                items = value if isinstance(value, list) else [value]
                return combine_boolean(op.upper(), [evaluate_boolean_expr(item, state) for item in items])
        for key in ("Authority", "authority", "Name", "name", "Value", "value"):
            if key in expr:
                return evaluate_boolean_expr(expr[key], state)
        return None
    if isinstance(expr, list):
        if not expr:
            return None
        op = str(expr[0]).upper()
        if op in {"OR", "AND"}:
            return combine_boolean(op, [evaluate_boolean_expr(item, state) for item in expr[1:]])
        if any(str(item).upper() == "OR" for item in expr):
            return combine_boolean("OR", [evaluate_boolean_expr(item, state) for item in expr if str(item).upper() != "OR"])
        if any(str(item).upper() == "AND" for item in expr):
            return combine_boolean("AND", [evaluate_boolean_expr(item, state) for item in expr if str(item).upper() != "AND"])
        if len(expr) == 1:
            return evaluate_boolean_expr(expr[0], state)
        return None

    text = str(expr).strip()
    if not text:
        return None
    or_parts = re.split(r"\bOR\b|\|\|", text, flags=re.IGNORECASE)
    if len(or_parts) > 1:
        return combine_boolean("OR", [evaluate_boolean_expr(part, state) for part in or_parts])
    and_parts = re.split(r"\bAND\b|&&", text, flags=re.IGNORECASE)
    if len(and_parts) > 1:
        return combine_boolean("AND", [evaluate_boolean_expr(part, state) for part in and_parts])
    return boolean_atom_value(text.strip("()[]{} "), tokens)


def uid_pattern_matches(pattern, uid):
    uid = str(uid or "").upper()
    if not pattern or not uid:
        return False
    pattern_text = str(pattern).split("*", 1)[0].split("(", 1)[0]
    tokens = re.findall(r"[0-9A-Fa-f]{2}|TT|XX|MM|NN", pattern_text)
    if not tokens:
        return False
    regex_parts = []
    for token in tokens:
        upper = token.upper()
        if upper in {"TT", "XX", "MM", "NN"}:
            regex_parts.append(r"[0-9A-F]{2}")
        else:
            regex_parts.append(upper)
    regex = "^" + "".join(regex_parts)
    return re.match(regex, uid) is not None


def access_row_matches(row, event):
    method = row.get("method")
    if method and method != event.get("method") and normalized_policy_text(method) != normalized_policy_text(event.get("method_uid")):
        return False

    invoking_uid = row.get("invoking_uid")
    invoking_name = row.get("invoking_name") or row.get("name")
    invoking_pattern = row.get("invoking_pattern") or invoking_name
    event_uid = event.get("object_uid")
    if invoking_uid:
        return invoking_uid == event_uid
    if uid_pattern_matches(invoking_pattern, event_uid):
        return True
    if not invoking_name:
        return False

    row_text = normalized_policy_text(invoking_name)
    candidates = {
        normalized_policy_text(event.get("object")),
        normalized_policy_text(event.get("object_name")),
        normalized_policy_text(event.get("object_family")),
    }
    candidates.discard("")
    return any(candidate and (candidate == row_text or candidate in row_text or row_text in candidate) for candidate in candidates)


def policy_scope_from_source(source):
    text = str(source or "")
    if text.startswith("opal/4.2"):
        return "AdminSP"
    if text.startswith("opal/4.3"):
        return "LockingSP"
    return None


def policy_scope_for_event(state, event):
    return object_sp(event) or state["session"].get("sp")


def best_scoped_policy_row(rows, target_sp, row_source=None):
    if not rows:
        return None
    if target_sp:
        scoped = [row for row in rows if policy_scope_from_source(row.get("source")) == target_sp]
        if scoped:
            return scoped[0]
    source_scope = policy_scope_from_source(row_source)
    if source_scope:
        scoped = [row for row in rows if policy_scope_from_source(row.get("source")) == source_scope]
        if scoped:
            return scoped[0]
    return rows[0]


def ace_for_ref(ace_rows, ref, target_sp=None, row_source=None):
    ref_uid = str(ref or "").upper()
    candidates = []
    if ref_uid in ace_rows:
        candidates.append(ace_rows[ref_uid])
    ref_name = normalized_policy_text(ref)
    for ace in ace_rows.values():
        if ace in candidates:
            continue
        if ref_uid and ref_uid == str(ace.get("uid") or "").upper():
            candidates.append(ace)
        elif ref_name and ref_name == normalized_policy_text(ace.get("name")):
            candidates.append(ace)
    return best_scoped_policy_row(candidates, target_sp, row_source=row_source)


def requested_policy_columns(event, write=False):
    method = event.get("method")
    if method not in {"Get", "Set"}:
        return set()
    if write:
        columns = set((event.get("value_columns") or {}).keys())
    else:
        columns = set(event.get("cellblock_columns") or [])
    return columns or None


def columns_authorized(allowed_columns, requested_columns):
    if requested_columns is None:
        return None
    if not requested_columns:
        return True
    if allowed_columns == "all":
        return True
    if allowed_columns is None:
        return None
    allowed = set(allowed_columns)
    if not allowed:
        return None
    return requested_columns.issubset(allowed)


def ace_policy_decision(state, event, write=False):
    access_rows = state.get("access_control_rows") or []
    ace_rows = state.get("ace_rows") or {}
    if not access_rows or not ace_rows:
        return None

    requested_columns = requested_policy_columns(event, write=write)
    matched_rows = [row for row in access_rows if access_row_matches(row, event)]
    if not matched_rows:
        return None
    target_sp = policy_scope_for_event(state, event)
    scoped_rows = [row for row in matched_rows if policy_scope_from_source(row.get("source")) == target_sp]
    if scoped_rows:
        matched_rows = scoped_rows

    saw_unknown = False
    saw_denied = False
    denied_source = None
    for row in matched_rows:
        refs = row.get("ace_refs") or []
        if not refs:
            saw_unknown = True
            continue
        for ref in refs:
            ace = ace_for_ref(ace_rows, ref, target_sp=target_sp, row_source=row.get("source"))
            if not ace:
                saw_unknown = True
                continue
            source_scope = policy_scope_from_source(row.get("source")) or target_sp or "unknown"
            source = f"AccessControl:{row.get('source') or row.get('name')} ACE:{ace.get('source') or ace.get('name')} scope:{source_scope}"
            allowed_by_expr = evaluate_boolean_expr(ace.get("boolean_expr"), state)
            if allowed_by_expr is True:
                allowed_by_columns = columns_authorized(ace.get("columns"), requested_columns)
                if allowed_by_columns is True:
                    return {"allowed": True, "source": source, "coverage": "implemented"}
                if allowed_by_columns is False:
                    saw_denied = True
                    denied_source = source
                else:
                    saw_unknown = True
            elif allowed_by_expr is False:
                saw_denied = True
                denied_source = source
            else:
                saw_unknown = True
    if saw_denied and not saw_unknown:
        return {"allowed": False, "source": denied_source or "AccessControl", "coverage": "implemented"}
    return None


def policy_status_result(state, event, write=False, reason="ACE/AccessControl policy matched."):
    decision = ace_policy_decision(state, event, write=write)
    if decision is None:
        return None
    target_sp = object_sp(event) or state["session"].get("sp")
    if target_sp and not session_open_for(state, target_sp, write_required=write):
        return expected_status_result(
            event,
            "auth_error",
            f"{reason} Matched policy still requires an open {'write ' if write else ''}{target_sp} session.",
            rule_key="access_control",
            policy_source=decision.get("source", "AccessControl"),
            coverage_status=decision.get("coverage", "implemented"),
        )
    expected = "success" if decision["allowed"] else "auth_error"
    return expected_status_result(
        event,
        expected,
        reason,
        rule_key="access_control",
        policy_source=decision.get("source", "AccessControl"),
        coverage_status=decision.get("coverage", "implemented"),
    )

def credential_matches(state, authority, challenge):
    if not authority:
        return True
    known = state["credentials"].get(authority)
    if known is None:
        return None
    return challenge == known


def session_open_for(state, sp=None, write_required=False):
    session = state["session"]
    if not session.get("open"):
        return False
    if sp is not None and session.get("sp") != sp:
        return False
    if write_required and not session.get("write"):
        return False
    return True


def authenticated_locking_admin_write(state):
    return (
        state.get("locking_sp_active")
        and session_open_for(state, "LockingSP", write_required=True)
        and session_has_admin_authority(state, "LockingSP")
    )


def authenticated_admin_sp_write(state):
    return session_open_for(state, "AdminSP", write_required=True) and session_has_admin_authority(state, "AdminSP")


def object_sp(event):
    family = event.get("object_family")
    uid = event.get("object_uid") or ""
    obj = event.get("object")
    if family in {"Locking", "LockingInfo", "MBRControl", "MBR", "MediaKey", "DataStore", "SecretProtect"}:
        return "LockingSP"
    if obj == "LockingSP":
        return "AdminSP"
    if obj == "AdminSP":
        return "AdminSP"
    if family in {"C_PIN", "Authority"} and len(uid) >= 12:
        if uid[8:12] in {"0001", "0003"}:
            return "LockingSP"
        if uid[8:12] == "0000":
            return "AdminSP"
    return None


def protected_columns_requested(event, public_columns=()):
    columns = set(event.get("cellblock_columns") or [])
    if not columns:
        return True
    return not columns.issubset(set(public_columns))


def invalid_cellblock(event):
    if event.get("cellblock_invalid"):
        return True
    start = event.get("cellblock_start")
    end = event.get("cellblock_end")
    if start is None and end is None:
        return False
    if start is None or end is None or start < 0 or end < 0 or start > end:
        return True
    max_column = max_column_for_family(event.get("object_family"))
    if max_column is None:
        max_column = COLUMN_LIMITS.get(event.get("object_family"))
    return max_column is not None and end > max_column


def invalid_set_columns(event):
    if event.get("value_columns_invalid"):
        return True
    columns = event.get("value_columns") or {}
    if not columns:
        return False
    if any(column < 0 for column in columns):
        return True
    max_column = max_column_for_family(event.get("object_family"))
    if max_column is None:
        max_column = COLUMN_LIMITS.get(event.get("object_family"))
    return max_column is not None and any(column > max_column for column in columns)


def read_only_set_columns(event):
    columns = set((event.get("value_columns") or {}).keys())
    if not columns:
        return set()
    return columns & read_only_columns_for_family(event.get("object_family"))


def projected_locking_bounds(state, event):
    if event.get("object_family") != "Locking":
        return None
    range_name = event.get("locking_range")
    if not range_name:
        return None
    current = dict((state.get("locking_ranges") or {}).get(range_name) or {})
    columns = event.get("value_columns") or {}
    if 3 in columns:
        current["range_start"] = columns[3]
    if 4 in columns:
        current["range_length"] = columns[4]
    start = to_int(current.get("range_start"))
    length = to_int(current.get("range_length"))
    if start is None or length is None or start < 0 or length < 0:
        return "invalid"
    if range_name == "Global" and length == 0:
        return (0, None)
    if length == 0:
        return None
    return (start, start + length - 1)


def invalid_locking_range_update(state, event):
    columns = event.get("value_columns") or {}
    if event.get("object_family") != "Locking" or not ({3, 4} & set(columns)):
        return False
    range_name = event.get("locking_range")
    bounds = projected_locking_bounds(state, event)
    if bounds == "invalid":
        return True
    if not bounds or range_name == "Global":
        return False
    start, end = bounds
    for other_name, other in (state.get("locking_ranges") or {}).items():
        if other_name in {range_name, "Global"}:
            continue
        other_start = to_int(other.get("range_start"))
        other_length = to_int(other.get("range_length"))
        if other_start is None or other_length is None or other_length <= 0:
            continue
        other_end = other_start + other_length - 1
        if start <= other_end and other_start <= end:
            return True
    return False


METHOD_FAILURE_MATRIX = {
    "Properties": {"rule_key": "properties", "target": "SessionManager"},
    "StartSession": {"rule_key": "start_session", "target": "SessionManager", "required_any": (("SPID",),)},
    "SyncSession": {"rule_key": "sync_session", "requires_session": True, "no_session_status": "error"},
    "CloseSession": {"rule_key": "close_session", "requires_session": True, "no_session_status": "error", "optional": True},
    "EndSession": {"rule_key": "close_session", "requires_session": True, "no_session_status": "error"},
    "Authenticate": {"rule_key": "authenticate", "requires_session": True, "required_any": (("HostSigningAuthority", "Authority", "SigningAuthority"),)},
    "Get": {"rule_key": "get", "requires_session": True},
    "Set": {"rule_key": "set", "requires_session": True, "requires_write": True},
    "Next": {"rule_key": "next", "requires_session": True},
    "GetFreeSpace": {"rule_key": "get", "requires_session": True},
    "GetFreeRows": {"rule_key": "get", "requires_session": True},
    "GenKey": {"rule_key": "gen_key", "requires_session": True, "requires_write": True},
    "Random": {"rule_key": "random", "requires_session": True},
    "Activate": {"rule_key": "activate", "requires_session": True, "requires_write": True, "target": "LockingSP"},
    "Revert": {"rule_key": "revert", "requires_session": True, "requires_write": True, "target_family": "SP"},
    "RevertSP": {"rule_key": "revert_sp", "requires_session": True, "requires_write": True},
}


def parameter_value(event, names):
    wanted = {name.lower() for name in names}
    for source_name in ("required_parameters", "optional_parameters", "parameters"):
        source = event.get(source_name) or {}
        if not isinstance(source, dict):
            continue
        for key, value in source.items():
            if str(key).lower() in wanted:
                return value
    return None


def parameter_present(event, names):
    wanted = {name.lower() for name in names}
    for source_name in ("required_parameters", "optional_parameters", "parameters"):
        source = event.get(source_name) or {}
        if not isinstance(source, dict):
            continue
        for key in source:
            if str(key).lower() in wanted:
                return True
    return False


def invalid_count_parameter(event):
    raw = parameter_value(event, ("Count",))
    return raw is not None and event.get("count") is None


def invalid_where_parameter(event):
    raw = parameter_value(event, ("Where",))
    return raw is not None and str(raw).strip() == ""


def method_preflight(state, event):
    method = event.get("method")
    if method not in METHOD_NAMES:
        return expected_status_result(event, "invalid_parameter", f"{method or 'Unknown'} is not a supported modeled method.", rule_key="fallback", coverage_status="partial")
    rule = METHOD_FAILURE_MATRIX.get(method, {})
    rule_key = rule.get("rule_key")

    for names in rule.get("required_any", ()):
        if not any(parameter_present(event, (name,)) for name in names):
            return expected_status_result(
                event,
                "invalid_parameter",
                f"{method} is missing required parameter {'/'.join(names)}.",
                rule_key=rule_key,
            )

    if invalid_count_parameter(event):
        return expected_status_result(event, "invalid_parameter", f"{method} Count parameter is malformed.", rule_key=rule_key)
    if invalid_where_parameter(event):
        return expected_status_result(event, "invalid_parameter", f"{method} Where parameter is malformed.", rule_key=rule_key)

    if rule.get("target") and event.get("object") != rule["target"]:
        return expected_status_result(event, "invalid_parameter", f"{method} target must be {rule['target']}.", rule_key=rule_key)
    if rule.get("target_family") and event.get("object_family") != rule["target_family"]:
        return expected_status_result(event, "invalid_parameter", f"{method} target must be a {rule['target_family']} object.", rule_key=rule_key)

    if method == "Get" and invalid_cellblock(event):
        return expected_status_result(event, "invalid_parameter", "Get Cellblock requests invalid columns.", rule_key="get")
    if method == "Set":
        raw_values = parameter_value(event, ("Values",))
        if raw_values == "":
            return expected_status_result(event, "invalid_parameter", "Set Values parameter is malformed.", rule_key="set")
        if invalid_set_columns(event):
            return expected_status_result(event, "invalid_parameter", "Set Values contain invalid columns for the target object.", rule_key="set")

    if rule.get("requires_session") and not state["session"].get("open"):
        return expected_status_result(
            event,
            rule.get("no_session_status", "auth_error"),
            f"{method} requires an open session.",
            rule_key=rule_key,
        )
    if rule.get("requires_write") and state["session"].get("open") and not state["session"].get("write"):
        return expected_status_result(event, "auth_error", f"{method} requires a write session.", rule_key=rule_key)

    return None


def judge_start_session(state, event):
    sp = event.get("sp")
    authority = event.get("authority")

    if sp is None:
        return expected_status_result(event, "invalid_parameter", "StartSession without an SPID is malformed.", rule_key="start_session")

    if state["session"].get("open"):
        return expected_status_result(
            event,
            {"resource_error", "error"},
            "StartSession while another session is open should be rejected.",
            rule_key="start_session",
        )

    if sp == "LockingSP" and not state.get("locking_sp_active"):
        return expected_status_result(
            event,
            "error",
            "LockingSP session before successful LockingSP activation should fail.",
            rule_key="start_session",
        )

    if authority and not authority_enabled(state, authority):
        return expected_status_result(
            event,
            "auth_error",
            f"StartSession authority {authority} is disabled.",
            rule_key="authority",
            policy_source="Authority.Enabled",
        )

    if is_authority_locked_out(state, authority):
        return expected_status_result(
            event,
            "auth_error",
            f"Authority {authority} is locked out after {state.get('failed_auth_counts', {}).get(authority, 0)} failed attempts (TryLimit={state.get('trylimit_by_authority', {}).get(authority)}).",
            rule_key="authenticate",
            policy_source="C_PIN.TryLimit",
        )

    match = credential_matches(state, authority, event.get("challenge"))
    if match is True:
        return expected_status_result(
            event,
            "success",
            f"StartSession challenge matches tracked credential for {authority}.",
            rule_key="start_session",
        )
    if match is False:
        return expected_status_result(
            event,
            "auth_error",
            f"StartSession challenge does not match tracked credential for {authority}.",
            rule_key="start_session",
        )

    if authority:
        if actual_status_class(event) in {"success", "auth_error"}:
            return pass_result(
                f"No tracked credential for {authority}; final authenticated StartSession is not contradicted by state.",
                0.55,
                "success_or_auth_error",
                actual_status_class(event),
                spec_refs_for("start_session"),
            )
        return fail_result(
            f"No tracked credential for {authority}; unexpected status class for authenticated StartSession.",
            0.55,
            "success_or_auth_error",
            actual_status_class(event),
            spec_refs_for("start_session"),
        )

    return expected_status_result(event, "success", "Unauthenticated StartSession should succeed when the SP is available.", rule_key="start_session")


def judge_authenticate(state, event):
    authority = event.get("authority")
    if not state["session"].get("open"):
        return expected_status_result(event, "error", "Authenticate requires an open session.", rule_key="authenticate")
    if not authority:
        return expected_status_result(event, "invalid_parameter", "Authenticate without an Authority is malformed.", rule_key="authenticate")
    if authority_is_class(state, authority):
        return expected_status_result(
            event,
            "invalid_parameter",
            f"Authenticate cannot directly authenticate class authority {authority}.",
            rule_key="authenticate",
            policy_source="Authority.IsClass",
        )
    if not authority_enabled(state, authority):
        actual = actual_status_class(event)
        auth_result = event.get("auth_result")
        refs = spec_refs_for("authenticate", "authority")
        reason = f"Authenticate authority {authority} is disabled and should return SUCCESS with result False."
        if actual == "success" and auth_result is False:
            return pass_result(reason, expected_status="success_false", actual_status=actual, spec_refs=refs, policy_source="Authority.Enabled")
        return fail_result(reason, expected_status="success_false", actual_status=actual, spec_refs=refs, policy_source="Authority.Enabled")

    if is_authority_locked_out(state, authority):
        return expected_status_result(
            event,
            "auth_error",
            f"Authority {authority} is locked out after {state.get('failed_auth_counts', {}).get(authority, 0)} failed attempts (TryLimit={state.get('trylimit_by_authority', {}).get(authority)}).",
            rule_key="authenticate",
            policy_source="C_PIN.TryLimit",
        )

    match = credential_matches(state, authority, event.get("proof"))
    actual = actual_status_class(event)
    auth_result = event.get("auth_result")

    if match is True:
        if actual == "success" and auth_result is not False:
            return pass_result(
                f"Authenticate proof matches tracked credential for {authority}.",
                expected_status="success",
                actual_status=actual,
                spec_refs=spec_refs_for("authenticate"),
            )
        return fail_result(
            f"Authenticate proof matches tracked credential for {authority}.",
            expected_status="success",
            actual_status=actual,
            spec_refs=spec_refs_for("authenticate"),
        )

    if match is False:
        if (actual == "success" and auth_result is False) or actual == "auth_error":
            return pass_result(
                f"Authenticate proof does not match tracked credential for {authority}.",
                expected_status="auth_failure",
                actual_status=actual,
                spec_refs=spec_refs_for("authenticate"),
            )
        return fail_result(
            f"Authenticate proof does not match tracked credential for {authority}.",
            expected_status="auth_failure",
            actual_status=actual,
            spec_refs=spec_refs_for("authenticate"),
        )

    if actual in {"success", "auth_error"}:
        return pass_result(
            f"No tracked credential for {authority}; Authenticate result is not contradicted by state.",
            0.55,
            "success_or_auth_error",
            actual,
            spec_refs_for("authenticate"),
        )
    return fail_result(
        f"No tracked credential for {authority}; unexpected Authenticate status class.",
        0.55,
        "success_or_auth_error",
        actual,
        spec_refs_for("authenticate"),
    )


def judge_get(state, event):
    obj = event.get("object")
    family = event.get("object_family")

    if invalid_cellblock(event):
        return expected_status_result(event, "invalid_parameter", "Get Cellblock requests invalid columns.", rule_key="get")

    if obj == "C_PIN_MSID":
        expected = session_open_for(state, "AdminSP")
        return expected_status_result(
            event,
            "success" if expected else "auth_error",
            "C_PIN_MSID Get requires an open AdminSP session.",
            rule_key="cpin",
        )

    target_sp = object_sp(event)
    if target_sp == "LockingSP" and not state.get("locking_sp_active"):
        return expected_status_result(event, "error", f"{obj} Get requires an active LockingSP.", rule_key="locking_table")

    policy_result = policy_status_result(state, event, write=False, reason="Get matched ACE/AccessControl policy.")
    if policy_result is not None:
        return policy_result

    # Enforce write-only / hidden columns (NOPIN constraint) before family-level fallback.
    # C_PIN_MSID is exempt: ACE_C_PIN_MSID_Get_PIN explicitly allows reading the PIN column.
    if family and obj != "C_PIN_MSID":
        write_only = write_only_columns_for_family(family)
        requested = set(event.get("cellblock_columns") or [])
        if write_only and requested & write_only:
            return expected_status_result(
                event,
                "auth_error",
                f"Get requesting hidden/write-only columns {sorted(requested & write_only)} "
                f"is not permitted for {family} objects (NOPIN constraint).",
                rule_key="cpin" if family == "C_PIN" else "get",
                coverage_status="implemented",
            )

    if family == "C_PIN":
        expected = session_open_for(state, target_sp) and session_has_admin_authority(state, target_sp)
        return expected_status_result(
            event,
            "success" if expected else "auth_error",
            "C_PIN credential Get is protected by the C_PIN/ACE access-control tables.",
            rule_key="cpin",
        )

    if family == "LockingInfo":
        expected = session_open_for(state, "LockingSP")
        return expected_status_result(
            event,
            "success" if expected else "auth_error",
            "LockingInfo Get requires an open LockingSP session; documented geometry columns are public within that SP.",
            rule_key="locking_info",
        )

    if family == "Locking":
        public = not protected_columns_requested(event, public_columns={0, 1, 2})
        expected = session_open_for(state, "LockingSP") and (public or session_has_admin_authority(state, "LockingSP"))
        return expected_status_result(
            event,
            "success" if expected else "auth_error",
            "Locking range Get of range/lock/key columns requires an Admin authority in the LockingSP.",
            rule_key="locking_table",
        )

    if family == "MBRControl":
        expected = session_open_for(state, "LockingSP")  # ACE_Anybody per opal/4.3.1.6 — no admin required
        return expected_status_result(
            event,
            "success" if expected else "auth_error",
            "MBRControl Get requires an open LockingSP session (ACE_Anybody).",
            rule_key="mbr_control",
        )

    if family in {"Authority", "MediaKey", "ACE", "AccessControl", "SecretProtect", "DataStore"}:
        expected = session_open_for(state, target_sp) and session_has_admin_authority(state, target_sp)
        return expected_status_result(
            event,
            "success" if expected else "auth_error",
            f"{family} Get is protected by template access-control rows.",
            rule_key="access_control",
        )

    return expected_status_result(event, "success", "Get on non-sensitive discovery object should succeed.", rule_key="get")


def judge_set(state, event):
    obj = event.get("object")
    family = event.get("object_family")

    if invalid_set_columns(event):
        return expected_status_result(event, "invalid_parameter", "Set Values contain invalid columns for the target object.", rule_key="set")

    read_only = read_only_set_columns(event)
    if read_only:
        return expected_status_result(
            event,
            {"invalid_parameter", "auth_error"},
            f"Set Values include read-only/non-modifiable columns {sorted(read_only)}.",
            rule_key="set",
            policy_source="table_schema",
            coverage_status="implemented",
        )

    if invalid_locking_range_update(state, event):
        return expected_status_result(
            event,
            "invalid_parameter",
            "Locking RangeStart/RangeLength update is negative or overlaps another configured range.",
            rule_key="locking_table",
            policy_source="table_schema",
            coverage_status="implemented",
        )

    target_sp = object_sp(event) or state["session"].get("sp")
    if target_sp == "LockingSP" and not state.get("locking_sp_active"):
        return expected_status_result(event, "error", f"{obj} Set requires an active LockingSP.", rule_key="locking_table")

    policy_result = policy_status_result(state, event, write=True, reason="Set matched ACE/AccessControl policy.")
    if policy_result is not None:
        return policy_result

    if family == "C_PIN":
        authorities = effective_session_authorities(state)
        self_authority = event.get("credential_authority")
        # C_PIN_SID in AdminSP: only SID can set its own PIN (ACE_C_PIN_SID_Set_PIN, spec opal/4.2.1.5)
        if obj == "C_PIN_SID" and target_sp == "AdminSP":
            expected = session_open_for(state, target_sp, write_required=True) and "SID" in authorities
        else:
            expected = (
                session_open_for(state, target_sp, write_required=True)
                and (session_has_admin_authority(state, target_sp) or (self_authority in authorities and 3 in (event.get("value_columns") or {})))
            )
        return expected_status_result(
            event,
            "success" if expected else "auth_error",
            "C_PIN Set requires a write session authorized by Admins or by the matching credential authority for PIN updates.",
            rule_key="cpin",
        )

    if family in {"Locking", "MBRControl", "MediaKey", "ACE", "AccessControl", "SecretProtect", "DataStore"}:
        expected = authenticated_locking_admin_write(state)
        return expected_status_result(
            event,
            "success" if expected else "auth_error",
            f"{obj} Set requires authenticated Admin1 LockingSP write session.",
            rule_key="access_control",
        )

    if family == "Authority":
        expected = session_open_for(state, target_sp, write_required=True) and session_has_admin_authority(state, target_sp)
        return expected_status_result(
            event,
            "success" if expected else "auth_error",
            "Authority Set requires an authenticated admin write session in the owning SP.",
            rule_key="authority",
        )

    expected = state["session"].get("open") and state["session"].get("write") and session_has_authority(state)
    return expected_status_result(
        event,
        "success" if expected else "auth_error",
        "Protected Set fallback requires an authenticated write session.",
        rule_key="set",
    )


def judge_activate(state, event):
    if event.get("object") != "LockingSP":
        return expected_status_result(event, "invalid_parameter", "Activate target must be the LockingSP object.", rule_key="activate")

    expected = session_open_for(state, "AdminSP", write_required=True) and session_has_authority(state, "SID")
    return expected_status_result(
        event,
        "success" if expected else "auth_error",
        "LockingSP Activate requires an authenticated SID AdminSP write session.",
        rule_key="activate",
    )


def judge_revert(state, event):
    if event.get("object_family") != "SP":
        return expected_status_result(event, "invalid_parameter", "Revert target must be an SP object in the AdminSP SP table.", rule_key="revert")
    expected = authenticated_admin_sp_write(state)
    return expected_status_result(
        event,
        "success" if expected else "auth_error",
        "Revert on an SP object requires an authenticated AdminSP owner write session.",
        rule_key="revert",
    )


def judge_revert_sp(state, event):
    sp = state["session"].get("sp")
    if sp == "LockingSP" and not state.get("locking_sp_active"):
        return expected_status_result(event, "error", "RevertSP on LockingSP requires the LockingSP to be manufactured/active.", rule_key="revert_sp")

    # spec opal/5.1.3.2: KeepGlobalRangeKey=True fails with FAIL if Global Range is both Read and Write Locked
    if event.get("keep_global_range_key"):
        global_range = (state.get("locking_ranges") or {}).get("Global") or {}
        if bool(global_range.get("read_locked")) and bool(global_range.get("write_locked")):
            return expected_status_result(
                event,
                "error",
                "RevertSP with KeepGlobalRangeKey=True fails because Global Range is both Read Locked and Write Locked.",
                rule_key="revert_sp",
            )

    expected = state["session"].get("open") and state["session"].get("write") and session_has_admin_authority(state, sp)
    return expected_status_result(
        event,
        "success" if expected else "auth_error",
        "RevertSP requires an authenticated owner/admin write session in the target SP.",
        rule_key="revert_sp",
    )


def judge_gen_key(state, event):
    family = event.get("object_family")
    target_sp = object_sp(event) or state["session"].get("sp")

    # LockingSP must be active for any GenKey that targets it
    if target_sp == "LockingSP" and not state.get("locking_sp_active"):
        return expected_status_result(event, "error", "GenKey requires an active LockingSP.", rule_key="gen_key")

    # Check ACE/AccessControl policy before family fallbacks
    policy_result = policy_status_result(state, event, write=True, reason="GenKey matched ACE/AccessControl policy.")
    if policy_result is not None:
        return policy_result

    # spec core/5.3.4.1.1.1 + opal/4.2.1.5: C_PIN GenKey has no ACE in Opal SSC → not_authorized
    if family == "C_PIN":
        return expected_status_result(
            event, "auth_error",
            "GenKey on C_PIN has no ACE in Opal SSC AccessControl — not_authorized.",
            rule_key="gen_key",
        )

    if family != "MediaKey" and not event.get("key_range"):
        return expected_status_result(event, "invalid_parameter", "GenKey target must be a media-key object.", rule_key="gen_key")

    expected = authenticated_locking_admin_write(state)
    return expected_status_result(
        event,
        "success" if expected else "auth_error",
        "GenKey requires authenticated Admin1 LockingSP write session.",
        rule_key="gen_key",
    )


def judge_random(state, event):
    count = event.get("count")
    if count is not None and count < 0:
        return expected_status_result(event, "invalid_parameter", "Random Count cannot be negative.", rule_key="random")
    target_sp = object_sp(event) or state["session"].get("sp")
    expected = state["session"].get("open") and (target_sp is None or session_open_for(state, target_sp))
    return expected_status_result(
        event,
        "success" if expected else "auth_error",
        "Random is a Crypto Template SP method and requires an open session in that SP.",
        rule_key="random",
    )


def judge_free_space_or_rows(state, event):
    target_sp = object_sp(event) or state["session"].get("sp")
    if target_sp and not session_open_for(state, target_sp):
        return expected_status_result(
            event,
            "auth_error",
            f"{event.get('method')} requires an open session for the target table/SP context.",
            rule_key="get",
            coverage_status="partial",
        )
    expected = state["session"].get("open")
    return expected_status_result(
        event,
        "success" if expected else "auth_error",
        f"{event.get('method')} requires an open session and follows table-management status classes.",
        rule_key="get",
        coverage_status="partial",
    )


def judge_next(state, event):
    count = event.get("count")
    if count is not None and count < 0:
        return expected_status_result(event, "invalid_parameter", "Next Count cannot be negative.", rule_key="next")
    target_sp = object_sp(event) or state["session"].get("sp")
    policy_result = policy_status_result(state, event, write=False, reason="Next matched ACE/AccessControl policy.")
    if policy_result is not None:
        return policy_result
    sensitive = event.get("object_family") in {"C_PIN", "Authority", "Locking", "MBRControl", "MediaKey", "ACE", "AccessControl"}
    expected = session_open_for(state, target_sp) and (not sensitive or session_has_authority(state))
    return expected_status_result(
        event,
        "success" if expected else "auth_error",
        "Next follows table access-control requirements for the target table.",
        rule_key="next",
    )


def normalized_read_result(result):
    if result is None:
        return ""
    text = str(result).strip()
    lower = text.lower()
    if lower.startswith("pattern "):
        text = text.split(None, 1)[1].strip()
    if text.lower().startswith("0x"):
        text = text[2:]
    return text.strip().upper()


def is_zero_data(result):
    text = normalized_read_result(result)
    compact = "".join(ch for ch in text if ch.isalnum())
    return bool(compact) and set(compact) <= {"0"}


def lba_overlap(left, right):
    if left is None or right is None:
        return False
    return left[0] <= right[1] and right[0] <= left[1]


def find_prior_write(state, lba):
    if lba in state["writes"]:
        return state["writes"][lba]
    for record in reversed(state.get("write_records", [])):
        if lba_overlap(record.get("lba"), lba):
            return record
    return None


def judge_read(state, event):
    lba = event.get("lba")
    lock = lock_state_for_lba(state, lba, "read")
    actual = actual_status_class(event)
    if lock.get("mixed") or lock.get("locked"):
        if actual == "data_error" or is_zero_data(event.get("result")):
            return pass_result(
                "Read intersects a locked range and returned protected-read behavior.",
                expected_status="data_error_or_zeroes",
                actual_status=actual,
                spec_refs=spec_refs_for("locking_data"),
            )
        return fail_result(
            "Read intersects a locked range but returned user data.",
            expected_status="data_error_or_zeroes",
            actual_status=actual,
            spec_refs=spec_refs_for("locking_data"),
        )

    if actual == "data_error":
        return fail_result("Read is not locked but returned an error-like data response.", expected_status="data_success", actual_status=actual, spec_refs=spec_refs_for("locking_data"))

    write = find_prior_write(state, lba)
    if not write:
        return pass_result("No prior write for this LBA and no lock violation is known; accept observed read.", 0.60, "data_success", actual, spec_refs_for("locking_data"))

    old_pattern = normalized_read_result(write.get("pattern"))
    result = normalized_read_result(event.get("result"))
    current_key_generation = key_generation_for_lba(state, lba)
    write_key_generation = write.get("key_generation", 0)

    if current_key_generation > write_key_generation:
        if result == old_pattern:
            return fail_result(
                "Read after successful GenKey returned the old written pattern.",
                expected_status="changed_data",
                actual_status=actual,
                spec_refs=spec_refs_for("gen_key", "locking_data"),
            )
        return pass_result(
            "Read after successful GenKey returned data different from the old written pattern.",
            expected_status="changed_data",
            actual_status=actual,
            spec_refs=spec_refs_for("gen_key", "locking_data"),
        )

    if result == old_pattern:
        return pass_result("Read before key change returned the prior written pattern.", expected_status="data_success", actual_status=actual, spec_refs=spec_refs_for("locking_data"))
    return fail_result("Read before key change did not return the prior written pattern.", expected_status="written_pattern", actual_status=actual, spec_refs=spec_refs_for("locking_data"))


def judge_write(state, event):
    lba = event.get("lba")
    lock = lock_state_for_lba(state, lba, "write")
    actual = actual_status_class(event)
    if lock.get("mixed") or lock.get("locked"):
        if actual == "data_error":
            return pass_result(
                "Write intersects a locked range and was rejected.",
                expected_status="data_error",
                actual_status=actual,
                spec_refs=spec_refs_for("locking_data"),
            )
        return fail_result(
            "Write intersects a locked range but succeeded.",
            expected_status="data_error",
            actual_status=actual,
            spec_refs=spec_refs_for("locking_data"),
        )

    return expected_status_result(event, "data_success", "Write is not locked and should succeed.", rule_key="locking_data")


def judge_sync_session(state, event):
    expected = state["session"].get("open")
    return expected_status_result(
        event,
        "success" if expected else "error",
        "SyncSession is part of the session-start exchange and requires a pending/open session.",
        rule_key="sync_session",
    )


def judge_close_session(state, event):
    expected = state["session"].get("open")
    return expected_status_result(
        event,
        "success" if expected else "error",
        "CloseSession/EndSession should close an open session.",
        rule_key="close_session",
    )


def fallback(event, state):
    if event["kind"] != "method":
        return expected_status_result(event, "data_success", "Non-method fallback expects a successful data command.", 0.50)

    method = event.get("method") or ""
    harmless = {"Properties"}
    if method in harmless:
        return expected_status_result(event, "success", f"{method} is a harmless discovery/helper method.", rule_key="properties")

    expected = state["session"].get("open") and (
        not method.lower().startswith(("set", "gen", "activate", "revert", "delete", "create"))
        or (state["session"].get("write") and session_has_authority(state))
    )
    return expected_status_result(
        event,
        "success" if expected else "auth_error",
        "Method-aware fallback requires session and authorization evidence for protected methods.",
        0.60,
        rule_key="fallback",
    )


def judge_final(state, event):
    if event["kind"] == "read":
        return judge_read(state, event)
    if event["kind"] == "write":
        return judge_write(state, event)
    if event["kind"] != "method":
        return fallback(event, state)

    method = event.get("method")
    preflight = method_preflight(state, event)
    if preflight is not None:
        return preflight

    if method == "Properties":
        expected = event.get("object") == "SessionManager"
        return expected_status_result(
            event,
            "success" if expected else "invalid_parameter",
            "Properties should be invoked on the Session Manager.",
            rule_key="properties",
        )
    if method == "StartSession":
        return judge_start_session(state, event)
    if method == "SyncSession":
        return judge_sync_session(state, event)
    if method == "Authenticate":
        return judge_authenticate(state, event)
    if method == "Get":
        return judge_get(state, event)
    if method == "Set":
        return judge_set(state, event)
    if method == "Next":
        return judge_next(state, event)
    if method in {"GetFreeSpace", "GetFreeRows"}:
        return judge_free_space_or_rows(state, event)
    if method == "Random":
        return judge_random(state, event)
    if method == "Activate":
        return judge_activate(state, event)
    if method == "Revert":
        return judge_revert(state, event)
    if method == "RevertSP":
        return judge_revert_sp(state, event)
    if method == "GenKey":
        return judge_gen_key(state, event)
    if method in {"EndSession", "CloseSession"}:
        return judge_close_session(state, event)

    return fallback(event, state)

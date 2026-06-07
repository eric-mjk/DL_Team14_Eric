import re
from dataclasses import dataclass

from .normalizer import compact_uid, find_named_value, is_success_status, to_bool, to_int
from .state import (
    data_command_success,
    is_error_result,
    key_generation_for_lba,
    lock_state_for_lba,
)
from .spec_docs import (
    COLUMN_LIMITS,
    METHOD_NAMES,
    NOT_READABLE_VIA_GET,
    max_column_for_family,
    read_only_columns_for_family,
    reencrypt_request_value,
    reencrypt_state_value,
    refs_for,
    write_only_columns_for_family,
)


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


def _source_matches_sp(source, sp):
    """True when a record's source is compatible with the given SP.

    spec_index authority rows carry sources like "opal/4.2.1.7" (AdminSP) or
    "opal/4.3.1.8" (LockingSP).  A blank source is treated as matching both so
    hand-seeded rows are always visible.
    """
    if not source or not sp:
        return True
    src = normalized_policy_text(source)
    sp_norm = normalized_policy_text(sp)
    if sp_norm == "adminsp":
        return "adminsp" in src or "opal42" in src
    if sp_norm == "lockingsp":
        return "lockingsp" in src or "opal43" in src
    return True


def authority_records_for(state, authority, sp=None):
    if not authority:
        return []
    wanted = normalized_policy_text(authority)
    rows = state.get("authority_rows") or {}
    records = []
    for key, row in rows.items():
        values = {key, row.get("name"), row.get("uid")}
        if any(wanted and wanted == normalized_policy_text(value) for value in values):
            records.append(row)
    if sp and records:
        sp_filtered = [r for r in records if _source_matches_sp(r.get("source"), sp)]
        if sp_filtered:
            return sp_filtered
    return records


def authority_enabled(state, authority, sp=None):
    if authority in {None, "Anybody"}:
        return True
    if sp is None:
        sp = (state.get("session") or {}).get("sp")
    records = authority_records_for(state, authority, sp=sp)
    if not records:
        return True
    return any(record.get("enabled") is not False for record in records)


def secure_messaging_required(value):
    parsed = to_int(value)
    if parsed is not None:
        return parsed != 0
    normalized = normalized_policy_text(value)
    return bool(normalized and normalized not in {"none", "null", "false", "no", "plaintext"})


def authority_requires_secure_messaging(state, authority):
    records = authority_records_for(state, authority)
    return any(secure_messaging_required(record.get("secure")) for record in records if "secure" in record)


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
    if trylimit is None:
        return False
    if not isinstance(trylimit, int):
        trylimit = to_int(trylimit)
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
        return any(
            (isinstance(authority, str) and authority.startswith("Admin"))
            or "Admins" in authority_classes_for(state, authority)
            for authority in authorities
        )
    if sp == "AdminSP":
        return any(
            authority == "SID"
            or (isinstance(authority, str) and authority.startswith("Admin"))
            or "Admins" in authority_classes_for(state, authority)
            for authority in authorities
        )
    return any(
        is_admin_authority(authority) or "Admins" in authority_classes_for(state, authority)
        for authority in authorities
    )




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
        return False  # spec core/5.3.4.3.3: empty BooleanExpr = ACE always False
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
            return False  # spec core/5.3.4.3.3: empty list BooleanExpr always False
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
    uid_prefix = row.get("uid_prefix")
    if uid_prefix and event_uid and event_uid.upper().startswith(uid_prefix.upper()):
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
                # Expression grants access but this ACE doesn't cover all requested columns.
                # Treat as unknown: another ACE in the same AccessControl row may cover the
                # remaining columns, and the hardcode fallback should arbitrate if none does.
                # Marking as saw_denied here would block legitimate admin writes on columns
                # (e.g. NextKey, ReEncryptRequest) that the spec allows but aren't enumerated
                # in any single Opal ACE (opal/4.3.1.7 Table 39 lists per-column ACEs).
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
        # If credential was invalidated by GenKey, a challenge matching the old value is wrong
        old = (state.get("invalidated_credentials") or {}).get(authority)
        if old is not None and (challenge == old or (not challenge and not old)):
            return False
        return None
    # Empty credential: None challenge or empty challenge both match
    if known == "" or known == b"":
        return challenge is None or challenge == "" or challenge == b""
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
    if event.get("object_family") in {"MBR", "DataStore"} and (event.get("cellblock_start") is not None or event.get("cellblock_end") is not None):
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
    if event.get("value_columns_duplicate"):
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
    if range_name == "Global":
        # spec opal/4.3.1.1: Global Range RangeStart and RangeLength are fixed (whole disk);
        # any attempt to Set them is INVALID_PARAMETER
        return True
    # spec core/5.7.3.7: RangeStart/RangeLength modification fails when the row is not IDLE.
    def _reencrypt_idle(rname):
        current = (state.get("locking_ranges") or {}).get(rname) or {}
        sv = reencrypt_state_value(current.get("reencrypt_state"))
        return (sv is None) or sv == 1  # None treated as IDLE
    if not _reencrypt_idle(range_name):
        return True
    # spec core/5.7.2.2.12: if Global Range is not IDLE, no range geometry change is permitted.
    if not _reencrypt_idle("Global"):
        return True
    bounds = projected_locking_bounds(state, event)
    if bounds == "invalid":
        return True
    if not bounds:
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


VALID_REENCRYPT_REQUEST_STATES = {
    1: {1},
    2: {4, 5},
    3: {5},
    4: {5},
    5: {2, 3},
}


def invalid_reencrypt_request(state, event):
    columns = event.get("value_columns") or {}
    if event.get("object_family") != "Locking" or 13 not in columns:
        return False
    request = reencrypt_request_value(columns.get(13))
    if request not in VALID_REENCRYPT_REQUEST_STATES:
        return True
    range_name = event.get("locking_range")
    current = (state.get("locking_ranges") or {}).get(range_name) or {}
    state_value = reencrypt_state_value(current.get("reencrypt_state"))
    if state_value is None:
        state_value = 1
    return state_value not in VALID_REENCRYPT_REQUEST_STATES[request]


def invalid_next_key_update(state, event):
    columns = event.get("value_columns") or {}
    if event.get("object_family") != "Locking" or 11 not in columns:
        return False
    current = (state.get("locking_ranges") or {}).get(event.get("locking_range")) or {}
    state_value = reencrypt_state_value(current.get("reencrypt_state"))
    if state_value is None:
        state_value = 1
    return state_value != 1


def invalid_locking_reencrypt_enum(event):
    columns = event.get("value_columns") or {}
    if event.get("object_family") != "Locking":
        return False
    for column in (14, 15):
        if column not in columns:
            continue
        parsed = to_int(columns[column])
        if parsed not in {0, 1}:
            return True
    return False


def invalid_data_removal_enum(event):
    if event.get("object_family") != "DataRemovalMechanism":
        return False
    columns = event.get("value_columns") or {}
    if 1 not in columns:
        return False
    val = to_int(columns[1])
    return val is not None and val not in {0, 1, 2, 5}


def byte_table_granularity(state, event):
    if event.get("object_family") not in {"MBR", "DataStore"}:
        return None
    wanted = normalized_policy_text(event.get("object") or event.get("object_family"))
    for row in (state.get("tables") or {}).values():
        values = row.get("values") or {}
        name = normalized_policy_text(values.get("Name") or row.get("name"))
        if name != wanted:
            continue
        raw = (
            values.get("MandatoryWriteGranularity")
            or values.get("MandatoryWrite")
            or values.get("mandatory_write_granularity")
            or (row.get("columns") or {}).get(13)
        )
        granularity = to_int(raw)
        if granularity and granularity > 0:
            return granularity
    return None


def invalid_byte_table_granularity(state, event):
    if event.get("method") != "Set":
        return False
    granularity = byte_table_granularity(state, event)
    if not granularity or granularity <= 1:
        return False
    offset = to_int(event.get("where"))
    length = event.get("value_byte_length")
    if offset is None or length is None:
        return False
    return offset % granularity != 0 or length % granularity != 0


METHOD_FAILURE_MATRIX = {
    "Properties": {"rule_key": "properties", "target": "SessionManager"},
    "StartSession": {"rule_key": "start_session", "target": "SessionManager", "required_any": (("HostSessionID",), ("SPID",), ("Write",))},
    "SyncSession": {"rule_key": "sync_session", "requires_session": True, "no_session_status": "error", "required_any": (("HostSessionID",), ("SPSessionID",))},
    "StartTrustedSession": {"rule_key": "trusted_session", "target": "SessionManager", "requires_session": True, "no_session_status": "error", "required_any": (("HostSessionID",), ("SPSessionID",))},
    "SyncTrustedSession": {"rule_key": "trusted_session", "target": "SessionManager", "requires_session": True, "no_session_status": "error", "required_any": (("HostSessionID",), ("SPSessionID",))},
    "CloseSession": {"rule_key": "close_session", "requires_session": True, "no_session_status": "error", "required_any": (("RemoteSessionNumber",), ("LocalSessionNumber",))},
    "EndSession": {"rule_key": "close_session", "requires_session": True, "no_session_status": "error"},
    "Authenticate": {"rule_key": "authenticate", "requires_session": True, "required_any": (("HostSigningAuthority", "Authority", "SigningAuthority"),)},
    "GetACL": {"rule_key": "meta_acl", "requires_session": True, "required_any": (("InvokingID",), ("MethodID",))},
    "AddACE": {"rule_key": "meta_acl", "requires_session": True, "requires_write": True, "required_any": (("InvokingID",), ("MethodID",), ("ACE",))},
    "RemoveACE": {"rule_key": "meta_acl", "requires_session": True, "requires_write": True, "required_any": (("InvokingID",), ("MethodID",), ("ACE",))},
    "DeleteMethod": {"rule_key": "meta_acl", "requires_session": True, "requires_write": True, "required_any": (("InvokingID",), ("MethodID",))},
    "Get": {"rule_key": "get", "requires_session": True},
    "Set": {"rule_key": "set", "requires_session": True, "requires_write": True},
    "Delete": {"rule_key": "delete", "requires_session": True, "requires_write": True},
    "Next": {"rule_key": "next", "requires_session": True},
    "CreateTable": {"rule_key": "create_table", "requires_session": True, "requires_write": True, "required_any": (("NewTableName",), ("Kind",), ("GetSetACL",), ("Columns",), ("MinSize",))},
    "CreateRow": {"rule_key": "row_management", "requires_session": True, "requires_write": True, "required_any": (("Row",),)},
    "DeleteRow": {"rule_key": "row_management", "requires_session": True, "requires_write": True, "required_any": (("Rows",),)},
    "GetFreeSpace": {"rule_key": "get", "requires_session": True},
    "GetFreeRows": {"rule_key": "get", "requires_session": True},
    "GenKey": {"rule_key": "gen_key", "requires_session": True, "requires_write": True},
    "GetPackage": {"rule_key": "get_package", "requires_session": True, "required_any": (("Purpose",),)},
    "SetPackage": {"rule_key": "set_package", "requires_session": True, "requires_write": True, "required_any": (("Value",),)},
    "DecryptInit": {"rule_key": "crypto_stream", "requires_session": True},
    "Decrypt": {"rule_key": "crypto_stream", "requires_session": True, "required_any": (("Input",),)},
    "DecryptFinalize": {"rule_key": "crypto_stream", "requires_session": True},
    "EncryptInit": {"rule_key": "crypto_stream", "requires_session": True},
    "Encrypt": {"rule_key": "crypto_stream", "requires_session": True, "required_any": (("Input",),)},
    "EncryptFinalize": {"rule_key": "crypto_stream", "requires_session": True},
    "HashInit": {"rule_key": "crypto_stream", "requires_session": True},
    "Hash": {"rule_key": "crypto_stream", "requires_session": True, "required_any": (("Input",),)},
    "HashFinalize": {"rule_key": "crypto_stream", "requires_session": True},
    "HMACInit": {"rule_key": "crypto_stream", "requires_session": True},
    "HMAC": {"rule_key": "crypto_stream", "requires_session": True, "required_any": (("Input",),)},
    "HMACFinalize": {"rule_key": "crypto_stream", "requires_session": True},
    "Sign": {"rule_key": "crypto_sign", "requires_session": True},
    "Verify": {"rule_key": "crypto_sign", "requires_session": True},
    "XOR": {"rule_key": "xor", "requires_session": True, "required_any": (("PatternInput",), ("DeletePattern",), ("Input",))},
    "Random": {"rule_key": "random", "requires_session": True, "required_any": (("Count",),)},
    "Stir": {"rule_key": "stir", "requires_session": True, "required_any": (("Value",),)},
    "GetClock": {"rule_key": "clock", "requires_session": True},
    "IncrementCounter": {"rule_key": "clock", "requires_session": True},
    "ResetClock": {"rule_key": "clock", "requires_session": True, "requires_write": True},
    "SetClockHigh": {"rule_key": "clock", "requires_session": True, "requires_write": True, "required_any": (("ExactTime",),)},
    "SetLagHigh": {"rule_key": "clock", "requires_session": True, "requires_write": True, "required_any": (("LagTime",),)},
    "SetClockLow": {"rule_key": "clock", "requires_session": True, "requires_write": True, "required_any": (("ExactTime",),)},
    "SetLagLow": {"rule_key": "clock", "requires_session": True, "requires_write": True, "required_any": (("LagTime",),)},
    "AddLog": {"rule_key": "log", "requires_session": True, "required_any": (("LogEntryName",), ("Data",))},
    "CreateLog": {"rule_key": "log", "requires_session": True, "requires_write": True, "required_any": (("NewLogTableName",), ("HighSecurity",), ("MinSize",))},
    "ClearLog": {"rule_key": "log", "requires_session": True, "requires_write": True},
    "FlushLog": {"rule_key": "log", "requires_session": True},
    "Activate": {"rule_key": "activate", "requires_session": True, "requires_write": True, "target": "LockingSP"},
    "Revert": {"rule_key": "revert", "requires_session": True, "requires_write": True, "target_family": "SP"},
    "RevertSP": {"rule_key": "revert_sp", "requires_session": True, "requires_write": True},
    "DeleteSP": {"rule_key": "delete_sp", "requires_session": True, "requires_write": True},
    "IssueSP": {"rule_key": "issue_sp", "requires_session": True, "requires_write": True, "target": "AdminSP",
                "required_any": (("SPName",), ("Size",), ("Templates",))},
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


def invalid_uinteger_parameter(event, names):
    for name in names:
        raw = parameter_value(event, (name,))
        if raw is None:
            continue
        parsed = to_int(raw)
        if parsed is None or parsed < 0:
            return True
    return False


def invalid_boolean_parameter(event, names):
    for name in names:
        raw = parameter_value(event, (name,))
        if raw is not None and to_bool(raw) is None:
            return True
    return False


def invalid_host_properties(event):
    raw = parameter_value(event, ("HostProperties",))
    if raw is None:
        return False
    if isinstance(raw, dict):
        return False
    if isinstance(raw, list):
        return not all(isinstance(item, dict) and bool(item) for item in raw)
    return True


def find_named_parameter(value, names):
    wanted = {name.lower() for name in names}
    if isinstance(value, dict):
        for key, item_value in value.items():
            if str(key).lower() in wanted:
                return item_value
            nested = find_named_parameter(item_value, names)
            if nested is not None:
                return nested
    elif isinstance(value, list):
        for item in value:
            nested = find_named_parameter(item, names)
            if nested is not None:
                return nested
    return None


def stir_internal_parameter(event):
    raw = parameter_value(event, ("Value",))
    nested = find_named_parameter(raw, {"Internal"})
    if nested is not None:
        return nested
    return parameter_value(event, ("Internal",))


def invalid_stir_internal_parameter(event):
    if event.get("method") != "Stir":
        return False
    raw = stir_internal_parameter(event)
    return raw is not None and to_bool(raw) is None


def stir_false_value(event):
    if event.get("method") != "Stir":
        return False
    raw_value = parameter_value(event, ("Value",))
    if to_bool(raw_value) is False:
        return True
    internal = stir_internal_parameter(event)
    return internal is not None and to_bool(internal) is False


def invalid_where_parameter(event):
    raw = parameter_value(event, ("Where",))
    return raw is not None and str(raw).strip() == ""


def uid_parameter_value(value):
    if isinstance(value, dict):
        for key in ("uid", "UID", "Uid"):
            if key in value:
                return value[key]
        if len(value) == 1:
            return uid_parameter_value(next(iter(value.values())))
        return None
    if isinstance(value, (list, tuple)) and len(value) == 1:
        return uid_parameter_value(value[0])
    return value


def row_parameter_value(value):
    if isinstance(value, dict):
        for key in ("row", "Row", "ROW", "offset", "Offset"):
            if key in value:
                return value[key]
        if len(value) == 1:
            return row_parameter_value(next(iter(value.values())))
        return None
    if isinstance(value, (list, tuple)) and len(value) == 1:
        return row_parameter_value(value[0])
    return value


def invalid_next_where_parameter(event):
    if event.get("method") != "Next":
        return False
    raw = parameter_value(event, ("Where",))
    if raw is None:
        return False
    uid = compact_uid(uid_parameter_value(raw))
    return uid is None or len(uid) != 16


def table_level_invocation(event):
    uid = compact_uid(event.get("object_uid"))
    return bool(uid and uid.startswith("00000001"))


def invalid_set_where_parameter(event):
    if event.get("method") != "Set":
        return False
    has_where = parameter_present(event, ("Where",))
    if event.get("object_family") in {"MBR", "DataStore"}:
        return False
    if table_level_invocation(event):
        return not has_where
    return has_where


def invalid_set_where_type(event):
    if event.get("method") != "Set":
        return False
    raw = parameter_value(event, ("Where",))
    if raw is None:
        return False
    if event.get("object_family") in {"MBR", "DataStore"}:
        # Byte-table Set Where must be a Row/offset integer, not a UID object reference.
        # If the raw Where dict contains a "uid" key it is an object reference, not a row address.
        if isinstance(raw, dict) and any(k.lower() == "uid" for k in raw):
            return True
        row = to_int(row_parameter_value(raw))
        return row is None or row < 0
    if table_level_invocation(event):
        uid = compact_uid(uid_parameter_value(raw))
        return uid is None or len(uid) != 16
    return False


def invalid_get_free_target(event):
    method = event.get("method")
    if method == "GetFreeRows":
        return not table_level_invocation(event)
    if method == "GetFreeSpace":
        family = event.get("object_family")
        return family not in {None, "SP"}
    return False


def invalid_rows_parameter(event):
    if event.get("method") != "DeleteRow":
        return False
    rows = parameter_value(event, ("Rows",))
    if not isinstance(rows, list) or not rows:
        return True
    return any(compact_uid(uid_parameter_value(row)) is None or len(compact_uid(uid_parameter_value(row))) != 16 for row in rows)


def invalid_set_values_shape(event):
    if event.get("method") != "Set":
        return False
    raw_values = parameter_value(event, ("Values",))
    if raw_values is None:
        return False
    is_byte_table = event.get("object_family") in {"MBR", "DataStore"}
    has_bytes = find_named_parameter(raw_values, {"Bytes"}) is not None
    has_columns = bool(event.get("value_columns") or {})
    if is_byte_table:
        return has_columns or not has_bytes
    return has_bytes


def create_table_kind(event):
    raw = parameter_value(event, ("Kind",))
    normalized = normalized_policy_text(raw)
    if normalized in {"byte", "bytes", "bytetable", "1"}:
        return "byte"
    if normalized in {"object", "objecttable", "0"}:
        return "object"
    return normalized or None


def invalid_create_table_parameters(event):
    if event.get("method") != "CreateTable":
        return False
    kind = create_table_kind(event)
    columns = parameter_value(event, ("Columns",))
    has_max_size = parameter_present(event, ("MaxSize",))
    if kind == "byte":
        return has_max_size or columns not in ([], (), None)
    return False


def invalid_meta_acl_parameters(event):
    if event.get("method") not in {"GetACL", "AddACE", "RemoveACE", "DeleteMethod"}:
        return False
    names = ("InvokingID", "MethodID") + (("ACE",) if event.get("method") in {"AddACE", "RemoveACE"} else ())
    for name in names:
        uid = compact_uid(uid_parameter_value(parameter_value(event, (name,))))
        if uid is None or len(uid) != 16:
            return True
    return False


def invalid_session_number_mismatch(state, event):
    method = event.get("method")
    if method not in {"SyncSession", "StartTrustedSession", "SyncTrustedSession"}:
        return False
    session = state.get("session") or {}
    host_session_id = to_int(parameter_value(event, ("HostSessionID",)))
    sp_session_id = to_int(parameter_value(event, ("SPSessionID",)))
    tracked_host = session.get("host_session_id")
    tracked_sp = session.get("sp_session_id")
    if tracked_host is not None and host_session_id is not None and host_session_id != tracked_host:
        return True
    if method in {"StartTrustedSession", "SyncTrustedSession"} and tracked_sp is not None and sp_session_id is not None and sp_session_id != tracked_sp:
        return True
    return False


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
    if invalid_uinteger_parameter(event, ("HostSessionID", "SPSessionID", "SessionTimeout", "TransTimeout", "InitialCredit", "RemoteSessionNumber", "LocalSessionNumber", "MinSize", "MaxSize", "HintSize")):
        return expected_status_result(
            event,
            "invalid_parameter",
            f"{method} includes a malformed unsigned integer session parameter.",
            rule_key=rule_key,
        )
    if invalid_session_number_mismatch(state, event):
        return expected_status_result(
            event,
            "invalid_parameter",
            f"{method} session number does not match the established session.",
            rule_key=rule_key,
        )
    if invalid_boolean_parameter(event, ("Write", "KeepGlobalRangeKey", "DeletePattern")):
        return expected_status_result(
            event,
            "invalid_parameter",
            f"{method} includes a malformed boolean parameter.",
            rule_key=rule_key,
        )
    if method == "Properties" and invalid_host_properties(event):
        return expected_status_result(
            event,
            "invalid_parameter",
            "Properties HostProperties must be a list of name/value pairs.",
            rule_key="properties",
        )
    if invalid_stir_internal_parameter(event):
        return expected_status_result(event, "invalid_parameter", "Stir Internal must be boolean when present.", rule_key="stir")
    if stir_false_value(event):
        return expected_status_result(event, "error", "Stir with a false Value/Internal parameter must return non-success.", rule_key="stir")
    if invalid_where_parameter(event):
        return expected_status_result(event, "invalid_parameter", f"{method} Where parameter is malformed.", rule_key=rule_key)
    if invalid_next_where_parameter(event):
        return expected_status_result(event, "invalid_parameter", "Next Where parameter must be a UID reference.", rule_key="next")
    if invalid_set_where_parameter(event):
        return expected_status_result(
            event,
            "invalid_parameter",
            "Set Where parameter does not match object-vs-table invocation requirements.",
            rule_key="set",
        )
    if invalid_set_where_type(event):
        return expected_status_result(
            event,
            "invalid_parameter",
            "Set Where parameter has the wrong row/UID type for the target table kind.",
            rule_key="set",
        )
    if invalid_get_free_target(event):
        return expected_status_result(
            event,
            "invalid_parameter",
            f"{method} was invoked on an incompatible target object.",
            rule_key="get",
        )
    if invalid_create_table_parameters(event):
        return expected_status_result(
            event,
            "invalid_parameter",
            "CreateTable byte-table parameters must omit MaxSize and use an empty Columns list.",
            rule_key="create_table",
        )
    if invalid_meta_acl_parameters(event):
        return expected_status_result(
            event,
            "invalid_parameter",
            f"{method} meta-ACL parameters must be UID references.",
            rule_key="meta_acl",
        )
    if invalid_rows_parameter(event):
        return expected_status_result(
            event,
            "invalid_parameter",
            "DeleteRow Rows parameter must be a non-empty list of UID references.",
            rule_key="row_management",
        )

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
        if invalid_set_values_shape(event):
            return expected_status_result(
                event,
                "error",
                "Set Values shape must match byte-table Bytes versus object-table RowValues.",
                rule_key="set",
            )
        if invalid_set_columns(event):
            return expected_status_result(event, "invalid_parameter", "Set Values contain invalid columns for the target object.", rule_key="set")
        if invalid_byte_table_granularity(state, event):
            return expected_status_result(
                event,
                "invalid_parameter",
                "Set on a byte table violates the documented MandatoryWriteGranularity.",
                rule_key="set",
                policy_source="table_schema",
            )
        if invalid_reencrypt_request(state, event):
            return expected_status_result(
                event,
                "error",
                "Locking ReEncryptRequest is not valid for the current ReEncryptState.",
                rule_key="locking_table",
                policy_source="table_schema",
            )
        if invalid_next_key_update(state, event):
            return expected_status_result(
                event,
                "error",
                "Locking NextKey is writable only while ReEncryptState is IDLE.",
                rule_key="locking_table",
                policy_source="table_schema",
            )
        if invalid_locking_reencrypt_enum(event):
            return expected_status_result(
                event,
                "invalid_parameter",
                "Locking AdvKeyMode/VerifyMode use only enumeration values 0 or 1.",
                rule_key="locking_table",
                policy_source="table_schema",
            )

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


def _check_sync_session_ids(event):
    """Return a fail_result if a successful StartSession response is missing valid session IDs.

    TCG Core spec 5.2.3.2: A successful StartSession always yields a SyncSession response
    from the TPer that MUST include HostSessionID (echoing the host's value) and SPSessionID
    (a non-zero TPer-assigned value).  A response with status=SUCCESS but absent or zero
    session IDs is a compliance failure (spec core/5.2.3.2.1, 5.2.3.2.2).
    """
    if actual_status_class(event) != "success":
        return None

    raw_record = event.get("raw") or {}
    output = raw_record.get("output") or {}
    return_values = output.get("return_values")
    if return_values is None:
        return fail_result(
            "StartSession response status=SUCCESS but SyncSession return_values are absent; "
            "HostSessionID and SPSessionID are required (spec core/5.2.3.2).",
            confidence=0.95,
            expected_status="success_with_session_ids",
            actual_status="success_no_ids",
            spec_refs=("core/5.2.3.2",),
            policy_source="SyncSession",
        )

    host_session_id = find_named_value(return_values, {"HostSessionID", "hostsessionid"})
    sp_session_id = find_named_value(return_values, {"SPSessionID", "spsessionid"})

    host_id_int = to_int(host_session_id) if host_session_id is not None else None
    sp_id_int = to_int(sp_session_id) if sp_session_id is not None else None

    missing = []
    if host_session_id is None:
        missing.append("HostSessionID")
    if sp_session_id is None:
        missing.append("SPSessionID")

    if missing:
        return fail_result(
            f"StartSession response status=SUCCESS but SyncSession is missing required session ID(s): "
            f"{', '.join(missing)} (spec core/5.2.3.2).",
            confidence=0.95,
            expected_status="success_with_session_ids",
            actual_status="success_no_ids",
            spec_refs=("core/5.2.3.2",),
            policy_source="SyncSession",
        )

    if sp_id_int == 0:
        return fail_result(
            "StartSession response status=SUCCESS but SPSessionID=0 is invalid; "
            "the TPer must assign a non-zero session number (spec core/5.2.3.2.2).",
            confidence=0.90,
            expected_status="success_with_session_ids",
            actual_status="success_zero_sp_id",
            spec_refs=("core/5.2.3.2",),
            policy_source="SyncSession",
        )

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

    # SP has been deleted (AdminSP Delete + EndSession) — no further sessions allowed.
    if sp in state.get("deleted_sps", set()):
        return expected_status_result(
            event, "error",
            f"StartSession to {sp} must fail: SP has been deleted (core/5.3.3.1.1).",
            rule_key="start_session",
        )

    _sp_lifecycle = (state.get("sp_lifecycle") or {}).get(sp, "Manufactured")
    if "Disabled" in _sp_lifecycle:
        return expected_status_result(
            event,
            "error",
            f"StartSession to {sp} must fail: SP lifecycle is {_sp_lifecycle} (spec core/4.3.6).",
            rule_key="start_session",
        )
    if "Frozen" in _sp_lifecycle:
        return expected_status_result(
            event,
            "error",
            f"StartSession to {sp} must fail: SP lifecycle is {_sp_lifecycle} (spec core/4.3.7).",
            rule_key="start_session",
        )

    if sp == "LockingSP" and not state.get("locking_sp_active"):
        return expected_status_result(
            event,
            "error",
            "LockingSP session before successful LockingSP activation should fail.",
            rule_key="start_session",
        )

    if authority_is_class(state, authority):
        return expected_status_result(
            event,
            "invalid_parameter",
            f"StartSession HostSigningAuthority {authority} is a class authority; class authorities are not valid session authorities (spec core/5.1.5.11).",
            rule_key="start_session",
        )

    _auth_operation = next((r.get("operation") for r in authority_records_for(state, authority) if "operation" in r), None)
    if _auth_operation in ("Exchange", "TPerExchange", "TPerSign"):
        return expected_status_result(
            event,
            "invalid_parameter",
            f"StartSession HostSigningAuthority {authority} has Operation={_auth_operation}; key-exchange authorities cannot be used as session authorities (spec core/5.3.4.1.3).",
            rule_key="start_session",
        )

    if authority and not authority_enabled(state, authority, sp=sp):
        return expected_status_result(
            event,
            "auth_error",
            f"StartSession authority {authority} is disabled (opal/4.2.1.7 — AdminSP Admin1 starts disabled).",
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
        id_check = _check_sync_session_ids(event)
        if id_check is not None:
            return id_check
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
            id_check = _check_sync_session_ids(event)
            if id_check is not None:
                return id_check
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

    id_check = _check_sync_session_ids(event)
    if id_check is not None:
        return id_check
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

    _auth_records = authority_records_for(state, authority)
    _auth_operation = next((r.get("operation") for r in _auth_records if "operation" in r), None)
    if _auth_operation in ("Exchange", "TPerExchange", "TPerSign"):
        # spec core/5.3.4.1.3: key-exchange authorities return SUCCESS with result=False on Authenticate
        actual = actual_status_class(event)
        auth_result = event.get("auth_result")
        refs = spec_refs_for("authenticate")
        reason = f"Authenticate on {_auth_operation} authority always returns SUCCESS with result=False (spec core/5.3.4.1.3)."
        if actual == "success" and auth_result is False:
            return pass_result(reason, expected_status="success_false", actual_status=actual, spec_refs=refs)
        return fail_result(reason, expected_status="success_false", actual_status=actual, spec_refs=refs)

    if _auth_operation in ("Sign", "SymK", "HMAC"):
        # Two-step challenge-response: first call returns SUCCESS with a challenge,
        # second call (with Proof) returns SUCCESS with result True/False.
        # The SSD must return SUCCESS for either step; INVALID_PARAMETER is never correct
        # (spec core/5.3.4.1.14).
        actual = actual_status_class(event)
        refs = spec_refs_for("authenticate")
        if actual == "success":
            return pass_result(
                f"Authenticate on {_auth_operation} authority (two-step challenge-response): SUCCESS is correct (spec core/5.3.4.1.14).",
                expected_status="success",
                actual_status=actual,
                spec_refs=refs,
            )
        return fail_result(
            f"Authenticate on {_auth_operation} authority (two-step challenge-response): SUCCESS expected but got {actual} (spec core/5.3.4.1.14).",
            expected_status="success",
            actual_status=actual,
            spec_refs=refs,
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
        # spec core/5.3.4.1.14.1 item 2: locked-out Authenticate MAY return either
        # AUTHORITY_LOCKED_OUT (auth_error) OR SUCCESS with result=False.
        actual = actual_status_class(event)
        auth_result = event.get("auth_result")
        refs = spec_refs_for("authenticate")
        reason = (
            f"Authority {authority} is locked out after "
            f"{state.get('failed_auth_counts', {}).get(authority, 0)} failed attempts "
            f"(TryLimit={state.get('trylimit_by_authority', {}).get(authority)}); "
            f"TPer may return AUTHORITY_LOCKED_OUT or SUCCESS with result=False "
            f"(core/5.3.4.1.14.1, core/5.1.5.15)."
        )
        if actual == "auth_error" or (actual == "success" and auth_result is False):
            return pass_result(reason, expected_status="auth_error_or_success_false", actual_status=actual, spec_refs=refs, policy_source="C_PIN.TryLimit")
        return fail_result(reason, expected_status="auth_error_or_success_false", actual_status=actual, spec_refs=refs, policy_source="C_PIN.TryLimit")

    if authority_requires_secure_messaging(state, authority) and not state["session"].get("trusted"):
        # spec core/5.3.4.1.14.1 item 5a: secure-messaging failure returns SUCCESS with result=False,
        # not NOT_AUTHORIZED (which would apply only to missing AccessControl authorization).
        actual = actual_status_class(event)
        auth_result_val = event.get("auth_result")
        refs = spec_refs_for("authenticate", "authority")
        reason = (
            f"Authenticate authority {authority} requires secure messaging but the current session "
            f"is not trusted; TPer must return SUCCESS with result=False (core/5.3.4.1.14.1 item 5a)."
        )
        if actual == "success" and auth_result_val is False:
            return pass_result(reason, expected_status="success_false", actual_status=actual, spec_refs=refs, policy_source="Authority.Secure")
        return fail_result(reason, expected_status="success_false", actual_status=actual, spec_refs=refs, policy_source="Authority.Secure")

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
        # spec core/5.3.4.1.14.1 item 5b: wrong password on Authenticate returns
        # SUCCESS with result=False — NOT AUTHORITY_LOCKED_OUT.
        # auth_error here means the drive returned NOT_AUTHORIZED for a non-locked-out
        # authority with wrong credential, which is non-compliant (c.f. StartSession
        # where core/5.1.5.2 mandates NOT_AUTHORIZED for wrong HostChallenge).
        if actual == "success" and auth_result is False:
            return pass_result(
                f"Authenticate proof does not match tracked credential for {authority}.",
                expected_status="success_false",
                actual_status=actual,
                spec_refs=spec_refs_for("authenticate"),
            )
        return fail_result(
            f"Authenticate proof does not match tracked credential for {authority}.",
            expected_status="success_false",
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

    # (N) columns: not readable via Get at all, regardless of ACE policy (opal/4.2.6.1).
    # When no columns are explicitly requested (whole-row Get), treat it as requesting all columns
    # including the (N) ones — the same block applies.
    if family in NOT_READABLE_VIA_GET:
        not_readable = NOT_READABLE_VIA_GET[family]
        explicit_cols = event.get("cellblock_columns")
        requested_cols = set(explicit_cols) if explicit_cols else not_readable  # no filter = all cols
        if requested_cols & not_readable:
            return expected_status_result(
                event,
                "auth_error",
                f"{family} columns {sorted(requested_cols & not_readable)} have (N) access — "
                f"not readable via Get (opal/4.2.6.1).",
                rule_key="access_control",
                coverage_status="implemented",
            )

    # spec core/5.3.4.2.2: byte tables vs object tables differ on unauthorized access.
    # byte tables (MBR, DataStore) return auth_error; object tables omit unauthorized cells and return SUCCESS.
    # Families with write-only (NOPIN) columns (C_PIN, MediaKey) keep auth_error — those columns cannot be leaked.
    _CELL_OMIT_FAMILIES = frozenset({"Authority", "ACE", "AccessControl", "SecretProtect"})
    is_byte_table = family in {"MBR", "DataStore"}

    # Locking Get is handled before the policy path so that value validation and protected-column
    # leak detection always run, regardless of whether the AccessControl policy matched.
    if family == "Locking":
        range_name = event.get("locking_range")
        session_ok = session_open_for(state, "LockingSP")
        is_admin = session_has_admin_authority(state, "LockingSP")
        if not session_ok:
            return expected_status_result(
                event,
                "auth_error",
                "Locking range Get requires an open LockingSP session.",
                rule_key="locking_table",
            )
        # Protected columns for Locking: cols 3–12 (RangeStart through ActiveKey).
        # spec opal/4.3.1.7: only Admins ACE covers these; non-admin sessions must not receive them.
        _LOCKING_PROTECTED_COLS = set(range(3, 13))
        return_cols = event.get("return_columns") or {}
        int_return_cols = {int(k): v for k, v in return_cols.items()} if return_cols else {}
        returned_protected = set(int_return_cols) & _LOCKING_PROTECTED_COLS
        if not is_admin and returned_protected:
            return fail_result(
                f"Drive returned protected Locking columns {sorted(returned_protected)} to "
                f"non-admin session — cell-omit required (opal/4.3.1.7 + core/5.3.4.2.2).",
                expected_status={"success", "auth_error"},
                actual_status=actual_status_class(event),
                spec_refs=spec_refs_for("locking_table"),
                policy_source="rule",
                coverage_status="implemented",
            )
        public = not protected_columns_requested(event, public_columns={0, 1, 2})
        if not (public or is_admin):
            # spec core/5.3.4.2.2: object table — drive should omit unauthorised cells (SUCCESS),
            # though some drives return NOT_AUTHORIZED (non-compliant but tolerated).
            return expected_status_result(
                event,
                {"success", "auth_error"},
                "Non-admin Locking range Get of protected columns: drive should omit cells and return SUCCESS (opal/4.3.1.7 + core/5.3.4.2.2).",
                rule_key="locking_table",
            )
        # Admin path: validate returned column values against tracked state.
        _LOCKING_COL_FIELDS = {5: "read_lock_enabled", 6: "write_lock_enabled", 7: "read_locked", 8: "write_locked"}
        tracked = (state.get("locking_ranges") or {}).get(range_name) if range_name else None
        if tracked:
            for col_num, field in _LOCKING_COL_FIELDS.items():
                if col_num not in int_return_cols:
                    continue
                returned_val = bool(int_return_cols[col_num])
                expected_val = bool(tracked.get(field, False))
                if returned_val != expected_val:
                    return RuleResult(
                        verdict="fail",
                        confidence=0.95,
                        reason=(
                            f"Locking GET returned {field}={int(returned_val)} for {range_name} "
                            f"but tracked state has {field}={int(expected_val)} "
                            f"(opal/4.3.1 — drive must reflect authoritative lock state)."
                        ),
                        expected_status=None,
                        actual_status=event.get("status"),
                        spec_refs=["opal/4.3.1"],
                        policy_source="rule",
                        coverage_status="implemented",
                    )

    policy_result = policy_status_result(state, event, write=False, reason="Get matched ACE/AccessControl policy.")
    if policy_result is not None:
        # For object-table Get in cell-omit families, ACE denial means cells are omitted (SUCCESS).
        # Only override when there IS an open session — no-session auth_error remains correct.
        if (family in _CELL_OMIT_FAMILIES
                and policy_result.expected_status == "auth_error"
                and session_open_for(state, target_sp or state["session"].get("sp"))):
            return expected_status_result(
                event,
                {"success", "auth_error"},
                policy_result.reason + " (core/5.3.4.2.2: unauthorized object-table cells omitted from result)",
                rule_key="access_control",
                policy_source=policy_result.policy_source,
                coverage_status=policy_result.coverage_status,
            )
        if family != "Locking":
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
        # Reached only when policy_result was None (no matching AccessControl row) and no earlier
        # check returned. Both session and value checks already ran above; just approve here.
        return expected_status_result(
            event,
            "success",
            "Locking range Get is authorized and returned values match tracked state.",
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

    if family == "MBR":
        expected = session_open_for(state, "LockingSP")
        return expected_status_result(
            event,
            "success" if expected else "auth_error",
            "MBR byte-table Get requires an open LockingSP session (ACE_Anybody).",
            rule_key="mbr_control",
        )

    if family in {"Authority", "MediaKey", "ACE", "AccessControl", "SecretProtect", "DataStore"}:
        authorized = session_open_for(state, target_sp) and session_has_admin_authority(state, target_sp)
        # spec core/5.3.4.2.2: cell-omit families return SUCCESS on unauthorized Get (cells omitted).
        # Excluded: DataStore (byte table), MediaKey (write-only key material in col 3).
        unauth_status = {"success", "auth_error"} if family in _CELL_OMIT_FAMILIES else "auth_error"
        return expected_status_result(
            event,
            "success" if authorized else unauth_status,
            f"{family} Get is protected by template access-control rows.",
            rule_key="access_control",
        )

    return expected_status_result(event, "success", "Get on non-sensitive discovery object should succeed.", rule_key="get")


def judge_set(state, event):
    obj = event.get("object")
    family = event.get("object_family")

    # PSID authority can only invoke Revert, not perform any table Set operations.
    if session_has_authority(state, "PSID") and not session_has_authority(state, "SID"):
        return expected_status_result(
            event,
            "auth_error",
            "PSID authority is restricted to Revert only; table Set operations are not permitted (Opal PSID Feature Set).",
            rule_key="psid",
        )

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

    if invalid_reencrypt_request(state, event):
        return expected_status_result(
            event,
            "error",
            "Locking ReEncryptRequest is not valid for the current ReEncryptState.",
            rule_key="locking_table",
            policy_source="table_schema",
            coverage_status="implemented",
        )

    if invalid_next_key_update(state, event):
        return expected_status_result(
            event,
            "error",
            "Locking NextKey is writable only while ReEncryptState is IDLE.",
            rule_key="locking_table",
            policy_source="table_schema",
            coverage_status="implemented",
        )

    if invalid_locking_reencrypt_enum(event):
        return expected_status_result(
            event,
            "invalid_parameter",
            "Locking AdvKeyMode/VerifyMode use only enumeration values 0 or 1.",
            rule_key="locking_table",
            policy_source="table_schema",
            coverage_status="implemented",
        )

    if invalid_data_removal_enum(event):
        return expected_status_result(
            event,
            "invalid_parameter",
            "ActiveDataRemovalMechanism reserved value is not allowed (opal/4.2.6.1).",
            rule_key="set",
            policy_source="table_schema",
            coverage_status="implemented",
        )

    target_sp = object_sp(event) or state["session"].get("sp")
    if target_sp == "LockingSP" and not state.get("locking_sp_active"):
        return expected_status_result(event, "error", f"{obj} Set requires an active LockingSP.", rule_key="locking_table")

    # C_PIN Set is handled before the generic policy path because the cached
    # ACE_C_PIN_Admins_Set_PIN entry has boolean_expr="Admins" (LockingSP version),
    # which incorrectly blocks SID from setting AdminSP C_PIN objects.
    # The AdminSP version requires boolean_expr="Admins OR SID" (opal/4.2.1.6).
    # The hardcoded rules here are authoritative for C_PIN Set in both SPs.
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

    policy_result = policy_status_result(state, event, write=True, reason="Set matched ACE/AccessControl policy.")
    if policy_result is not None:
        return policy_result

    if family == "Locking":
        # spec opal/4.3.1.7 lines 177-231: all Locking range Set ACEs use BooleanExpr=Admins.
        # ReadLocked and WriteLocked ACE rows are also Admins-only, not UserN.
        expected = authenticated_locking_admin_write(state)
        return expected_status_result(
            event,
            "success" if expected else "auth_error",
            f"{obj} Set requires an authenticated Admin LockingSP write session (opal/4.3.1.7).",
            rule_key="access_control",
        )

    if family == "MBRControl":
        # opal/4.3.1.6 + 4.3.1.7: MBRControl Set ACL = ACE_MBRControl_Admins_Set OR ACE_MBRControl_Set_DoneToDOR.
        # Both ACEs have BooleanExpr=Admins (opal/4.3.1.7 Table 39). All columns (Enable=1, Done=2,
        # DoneOnReset=3) require an Admin authority in a LockingSP write session.
        expected = authenticated_locking_admin_write(state)
        return expected_status_result(
            event,
            "success" if expected else "auth_error",
            f"{obj} Set requires authenticated Admin LockingSP write session"
            " (ACE_MBRControl_Admins_Set, BooleanExpr=Admins, opal/4.3.1.7).",
            rule_key="mbr_control",
        )

    if family in {"MBR", "MediaKey", "ACE", "AccessControl", "SecretProtect", "DataStore"}:
        # MBR byte-table Set: Admin-only per ACE_Admin (opal/4.3.1.6 InvokingID=00 00 08 04)
        expected = authenticated_locking_admin_write(state)
        return expected_status_result(
            event,
            "success" if expected else "auth_error",
            f"{obj} Set requires authenticated Admin1 LockingSP write session.",
            rule_key="access_control",
        )

    if family == "Authority":
        if target_sp == "AdminSP":
            # spec opal/4.2.1.6: ACE_Set_Enabled BooleanExpr = SID only — Admin* not authorized
            expected = session_open_for(state, target_sp, write_required=True) and session_has_authority(state, "SID")
        else:
            expected = session_open_for(state, target_sp, write_required=True) and session_has_admin_authority(state, target_sp)
        return expected_status_result(
            event,
            "success" if expected else "auth_error",
            "Authority Set requires SID in AdminSP or admin authority in LockingSP.",
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

    # spec opal/5.1.1: invocation in any non-inactive lifecycle state shall complete successfully
    # (no-op) if access control is satisfied — not INVALID_PARAMETER
    expected = session_open_for(state, "AdminSP", write_required=True) and session_has_authority(state, "SID")
    if state.get("locking_sp_active"):
        return expected_status_result(
            event,
            "success" if expected else "auth_error",
            "Activate on already-Manufactured LockingSP is a no-op if access control is satisfied (opal/5.1.1).",
            rule_key="activate",
        )

    return expected_status_result(
        event,
        "success" if expected else "auth_error",
        "LockingSP Activate requires an authenticated SID AdminSP write session.",
        rule_key="activate",
    )


def judge_revert(state, event):
    if event.get("object_family") != "SP":
        return expected_status_result(event, "invalid_parameter", "Revert target must be an SP object in the AdminSP SP table.", rule_key="revert")

    # spec opal/5.1.2: Revert SHALL NOT be permitted on issued SP objects.
    # Only AdminSP and LockingSP are known manufactured SPs in this Opal model.
    target = event.get("object")
    known_sps = {"AdminSP", "LockingSP"}
    tracked_manufactured = {
        sp for sp, lc in state.get("sp_lifecycle", {}).items()
        if lc and "manufactured" in str(lc).lower()
    }
    if target not in (known_sps | tracked_manufactured):
        return expected_status_result(
            event,
            "error",
            "Revert is not permitted on issued or unknown SP objects (opal/5.1.2).",
            rule_key="revert",
        )

    # spec opal/5.1.2: Revert requires a Read-Write session to the Admin SP authenticated
    # by SID (normal owner authority) or PSID (Physical Secure ID — Opal PSID Feature Set).
    has_sid = session_has_authority(state, "SID")
    has_psid = session_has_authority(state, "PSID")
    expected = session_open_for(state, "AdminSP", write_required=True) and (has_sid or has_psid)
    return expected_status_result(
        event,
        "success" if expected else "auth_error",
        "Revert on an SP object requires an authenticated AdminSP write session with SID or PSID authority (opal/5.1.2).",
        rule_key="revert",
    )


def judge_revert_sp(state, event):
    sp = state["session"].get("sp")
    if sp == "LockingSP" and not state.get("locking_sp_active"):
        return expected_status_result(event, "error", "RevertSP on LockingSP requires the LockingSP to be manufactured/active.", rule_key="revert_sp")

    # spec opal/5.1.3.2: KeepGlobalRangeKey=True fails with FAIL if Global Range is both Read and Write Locked.
    # This behavior is defined only for LockingSP; do not apply it to AdminSP RevertSP.
    if sp == "LockingSP" and event.get("keep_global_range_key"):
        global_range = (state.get("locking_ranges") or {}).get("Global") or {}
        if bool(global_range.get("read_locked")) and bool(global_range.get("write_locked")):
            return expected_status_result(
                event,
                "error",
                "RevertSP with KeepGlobalRangeKey=True fails because Global Range is both Read Locked and Write Locked (opal/5.1.3.2).",
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
    obj = event.get("object") or ""
    target_sp = object_sp(event) or state["session"].get("sp")

    # spec core/5.3.3.16.4: type-specific optional parameters must match the credential type.
    # PublicExponent is only valid for C_RSA_* credentials; PinLength only for C_PIN credentials.
    if parameter_present(event, ("PublicExponent",)) and not obj.startswith("C_RSA_"):
        return expected_status_result(
            event, "invalid_parameter",
            "GenKey PublicExponent is only valid for C_RSA credential objects (core/5.3.3.16.4).",
            rule_key="gen_key",
        )
    if parameter_present(event, ("PinLength",)):
        if family != "C_PIN":
            return expected_status_result(
                event, "invalid_parameter",
                "GenKey PinLength is only valid for C_PIN credential objects (core/5.3.3.16.4).",
                rule_key="gen_key",
            )

    # LockingSP must be active for any GenKey that targets it
    if target_sp == "LockingSP" and not state.get("locking_sp_active"):
        return expected_status_result(event, "error", "GenKey requires an active LockingSP.", rule_key="gen_key")

    # spec core/5.7.3.7: GenKey on a media key fails when the associated range is not IDLE.
    # Check this BEFORE the ACE policy (the range state constraint is independent of ACL).
    key_range = event.get("key_range")
    if key_range:
        current = (state.get("locking_ranges") or {}).get(key_range) or {}
        sv = reencrypt_state_value(current.get("reencrypt_state"))
        if sv is not None and sv != 1:
            return expected_status_result(
                event,
                "invalid_parameter",
                f"GenKey on {key_range} key is not permitted while re-encryption is in progress (core/5.7.3.7).",
                rule_key="gen_key",
            )

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
    if count is not None and count > 32:
        return expected_status_result(event, "invalid_parameter", "Random Count SHALL NOT exceed 32 (opal/4.2.9.1).", rule_key="random")
    target_sp = object_sp(event) or state["session"].get("sp")
    expected = state["session"].get("open") and (target_sp is None or session_open_for(state, target_sp))
    return expected_status_result(
        event,
        "success" if expected else "auth_error",
        "Random is a Crypto Template SP method and requires an open session in that SP.",
        rule_key="random",
    )


def judge_stir(state, event):
    target_sp = object_sp(event) or state["session"].get("sp")
    expected = state["session"].get("open") and (target_sp is None or session_open_for(state, target_sp))
    return expected_status_result(
        event,
        "success" if expected else "auth_error",
        "Stir adds input/internal entropy for later Random calls and requires an open session in that SP.",
        rule_key="stir",
    )


def credential_object_target(event):
    family = event.get("object_family")
    obj = event.get("object") or ""
    return family == "C_PIN" or obj.startswith(("C_RSA_", "C_AES_", "C_EC_", "C_HMAC_"))


def hash_object_target(event):
    obj = event.get("object") or ""
    return obj.startswith("H_SHA_")


def judge_get_package(state, event):
    if not credential_object_target(event):
        return expected_status_result(event, "invalid_parameter", "GetPackage target must be a credential object.", rule_key="get_package")
    target_sp = object_sp(event) or state["session"].get("sp")
    expected = session_open_for(state, target_sp) and session_has_authority(state)
    return expected_status_result(
        event,
        "success" if expected else "auth_error",
        "GetPackage requires access control on the credential object and wrapping/signing credentials.",
        rule_key="get_package",
    )


def judge_set_package(state, event):
    if not credential_object_target(event):
        return expected_status_result(event, "invalid_parameter", "SetPackage target must be a credential object.", rule_key="set_package")
    target_sp = object_sp(event) or state["session"].get("sp")
    expected = session_open_for(state, target_sp, write_required=True) and session_has_authority(state)
    return expected_status_result(
        event,
        "success" if expected else "auth_error",
        "SetPackage requires a write session and credential-object access control.",
        rule_key="set_package",
    )


def crypto_stream_key(event):
    return event.get("object_uid") or event.get("object")


def crypto_operation(method):
    if method.startswith("Encrypt"):
        return "Encrypt"
    if method.startswith("Decrypt"):
        return "Decrypt"
    if method.startswith("Hash"):
        return "Hash"
    if method.startswith("HMAC"):
        return "HMAC"
    return None


def judge_crypto_stream_method(state, event):
    method = event.get("method")
    target_ok = hash_object_target(event) if method.startswith(("Hash", "HMAC")) else credential_object_target(event)
    if not target_ok:
        return expected_status_result(event, "invalid_parameter", f"{method} target must be a credential object.", rule_key="crypto_stream")
    key = crypto_stream_key(event)
    operation = crypto_operation(method)
    stream_open = bool((state.get("crypto_streams") or {}).get((key, operation)))
    if method.endswith("Init") and stream_open:
        return expected_status_result(event, "error", f"{method} cannot open a second {operation} stream for the same credential.", rule_key="crypto_stream")
    if method in {"Encrypt", "Decrypt", "Hash", "HMAC", "EncryptFinalize", "DecryptFinalize", "HashFinalize", "HMACFinalize"} and not stream_open:
        return expected_status_result(event, "error", f"{method} requires an open {operation} stream for the invoking credential.", rule_key="crypto_stream")
    target_sp = object_sp(event) or state["session"].get("sp")
    expected = session_open_for(state, target_sp) and session_has_authority(state)
    return expected_status_result(
        event,
        "success" if expected else "auth_error",
        f"{method} requires credential-object access control in an open session.",
        rule_key="crypto_stream",
    )


def judge_crypto_sign_method(state, event):
    method = event.get("method")
    if not (credential_object_target(event) or hash_object_target(event)):
        return expected_status_result(event, "invalid_parameter", f"{method} target must be a public-key credential or hash object.", rule_key="crypto_sign")
    target_sp = object_sp(event) or state["session"].get("sp")
    expected = session_open_for(state, target_sp) and session_has_authority(state)
    return expected_status_result(
        event,
        "success" if expected else "auth_error",
        f"{method} requires access control on the invoking credential/hash object.",
        rule_key="crypto_sign",
    )


def invalid_xor_pattern_input(event):
    if event.get("method") != "XOR":
        return False
    uid = compact_uid(uid_parameter_value(parameter_value(event, ("PatternInput",))))
    return uid is None or len(uid) != 16


def judge_xor(state, event):
    if invalid_xor_pattern_input(event):
        return expected_status_result(event, "invalid_parameter", "XOR PatternInput must be a byte-table UID reference.", rule_key="xor")
    target_sp = object_sp(event) or state["session"].get("sp")
    expected = session_open_for(state, target_sp) and session_has_authority(state)
    return expected_status_result(
        event,
        "success" if expected else "auth_error",
        "XOR requires access control for the pattern/input/output references in an open session.",
        rule_key="xor",
    )


def judge_free_space_or_rows(state, event):
    method = event.get("method")
    # spec core/5.3.3.9: GetFreeSpace is an SP method — requires an open session to the SP.
    # spec core/5.3.3.10: GetFreeRows is a table method — requires an open session; no write needed.
    # Neither method requires a read-write session; a read-only session is sufficient.
    target_sp = object_sp(event) or state["session"].get("sp")
    if target_sp and not session_open_for(state, target_sp):
        return expected_status_result(
            event,
            "auth_error",
            f"{method} requires an open session for the target SP context (core/5.3.3.9, core/5.3.3.10).",
            rule_key="get",
        )
    expected = state["session"].get("open")
    reason = (
        f"{method} is an SP method that succeeds in any open session (read-only or read-write); "
        f"no authentication or write session is required (core/5.3.3.9, core/5.3.3.10)."
        if method == "GetFreeSpace"
        else
        f"{method} is a table method that succeeds in any open session on an existing object table; "
        f"no write session is required (core/5.3.3.10)."
    )
    return expected_status_result(
        event,
        "success" if expected else "auth_error",
        reason,
        rule_key="get",
    )


def judge_row_management(state, event):
    method = event.get("method")
    if not table_level_invocation(event) or event.get("object_family") in {"MBR", "DataStore"}:
        return expected_status_result(
            event,
            "invalid_parameter",
            f"{method} is a table method for object tables and is not valid on byte tables or object rows.",
            rule_key="row_management",
        )
    # spec core/5.3.3.4 / core/5.8.3: MethodID rows and Log rows are TPer-managed; the host
    # must not create or delete them via CreateRow/DeleteRow. Log entries are appended via AddLog.
    if event.get("object_family") in {"MethodID", "Log"}:
        return expected_status_result(
            event,
            "invalid_parameter",
            f"{method} on {event.get('object_family')} is not permitted; these rows are TPer-managed "
            f"and not host-creatable or host-deletable (core/5.3.3.4, core/5.8.3).",
            rule_key="row_management",
        )
    # spec core/5.7.2.2.12: CreateRow/DeleteRow on Locking family fails if Global Range is not IDLE.
    if event.get("object_family") == "Locking":
        global_range = (state.get("locking_ranges") or {}).get("Global") or {}
        sv = reencrypt_state_value(global_range.get("reencrypt_state"))
        if sv is not None and sv != 1:
            return expected_status_result(
                event,
                "invalid_parameter",
                f"{method} on Locking table is not permitted while Global Range re-encryption is in progress (core/5.7.2.2.12).",
                rule_key="row_management",
            )
    target_sp = object_sp(event) or state["session"].get("sp")
    expected = session_open_for(state, target_sp, write_required=True) and session_has_authority(state)
    return expected_status_result(
        event,
        "success" if expected else "auth_error",
        f"{method} requires authorized write access to the target object table.",
        rule_key="row_management",
    )


def judge_delete(state, event):
    if event.get("object") in {None, "SessionManager"}:
        return expected_status_result(event, "invalid_parameter", "Delete target must be an existing table/object row.", rule_key="delete")
    # spec core/5.3.3.3: TPer-managed rows (MethodID) cannot be deleted by the host.
    if event.get("object_family") == "MethodID":
        return expected_status_result(
            event, "invalid_parameter",
            "MethodID rows are TPer-managed and cannot be deleted by the host (core/5.3.3.3).",
            rule_key="delete",
        )
    target_sp = object_sp(event) or state["session"].get("sp")
    expected = session_open_for(state, target_sp, write_required=True) and session_has_authority(state)
    return expected_status_result(
        event,
        "success" if expected else "auth_error",
        "Delete requires authorized write access to the invoking object.",
        rule_key="delete",
    )


def judge_delete_sp(state, event):
    # DeleteSP is an SP method — it operates within the current session's SP and deletes that SP.
    # Do not use object_sp() here: for LockingSP the object_sp would return "AdminSP" (wrong).
    sp = state["session"].get("sp")
    expected = session_open_for(state, sp, write_required=True) and session_has_admin_authority(state, sp)
    return expected_status_result(
        event,
        "success" if expected else "auth_error",
        "DeleteSP requires an authorized admin write session in the SP being deleted (core/5.3.3.1).",
        rule_key="delete_sp",
    )


def judge_create_table(state, event):
    target_sp = object_sp(event) or state["session"].get("sp")
    expected = session_open_for(state, target_sp, write_required=True) and session_has_authority(state)
    return expected_status_result(
        event,
        "success" if expected else "auth_error",
        "CreateTable requires authorized write access in the target SP.",
        rule_key="create_table",
    )


def judge_meta_acl(state, event):
    method = event.get("method")
    if event.get("object_family") != "AccessControl":
        return expected_status_result(event, "invalid_parameter", f"{method} target must be the AccessControl table.", rule_key="meta_acl")
    target_sp = object_sp(event) or state["session"].get("sp")
    write_required = method in {"AddACE", "RemoveACE", "DeleteMethod"}
    if method == "GetACL":
        # GetACL authorization is governed by the row's GetACLACL column, which defaults to
        # ACE_Anybody in Opal SSC — any open session may call GetACL (opal/4.2.1.6, opal/4.3.1.7).
        expected = session_open_for(state, target_sp, write_required=False)
        reason = "GetACL requires an open session; GetACLACL defaults to ACE_Anybody in Opal SSC."
    else:
        expected = session_open_for(state, target_sp, write_required=write_required) and session_has_authority(state)
        reason = f"{method} requires the corresponding meta-ACL authorization on the AccessControl association."
    return expected_status_result(
        event,
        "success" if expected else "auth_error",
        reason,
        rule_key="meta_acl",
    )


def judge_increment_counter(state, event):
    if event.get("object_family") != "ClockTime":
        return expected_status_result(event, "invalid_parameter", f"{event.get('method')} target must be the ClockTime table.", rule_key="clock")
    method = event.get("method")
    if not state["session"].get("open"):
        return expected_status_result(event, "auth_error", f"{method} requires an open session on the ClockTime table.", rule_key="clock")
    if actual_status_class(event) != "success":
        return expected_status_result(event, "success", f"{method} in an open session should succeed.", rule_key="clock")
    # spec core/5.5.4.3.3: IncrementCounter must return a strictly greater MonotonicTime value.
    if method == "IncrementCounter":
        raw_record = (event.get("raw") or {})
        return_values = (raw_record.get("output") or {}).get("return_values") or {}
        from .normalizer import find_named_value
        monotonic = find_named_value(return_values, {"MonotonicTime", "monotonictime", "monotonic_time"})
        if monotonic is not None:
            current_val = to_int(monotonic)
            last_val = state.get("clock_monotonic_last")
            if last_val is not None and current_val is not None and current_val <= last_val:
                return fail_result(
                    f"IncrementCounter returned MonotonicTime={current_val} which is not strictly "
                    f"greater than the previous value {last_val} (core/5.5.4.3.3).",
                    expected_status="success_with_greater_monotonic",
                    actual_status="success_monotonic_not_incremented",
                    spec_refs=spec_refs_for("clock"),
                )
    return pass_result(
        f"{method} is permitted in a read-only session but requires an open session on the ClockTime table.",
        spec_refs=spec_refs_for("clock"),
    )


def judge_clock_mutation(state, event):
    method = event.get("method")
    if event.get("object_family") != "ClockTime":
        return expected_status_result(event, "invalid_parameter", f"{method} target must be the ClockTime table.", rule_key="clock")
    expected_lag = state.get("pending_clock_lag")
    if method in {"SetLagHigh", "SetLagLow"} and expected_lag != method:
        return expected_status_result(event, "error", f"{method} must immediately follow the matching SetClock method.", rule_key="clock")
    if method in {"SetClockHigh", "SetClockLow"} and expected_lag is not None:
        return expected_status_result(event, "error", f"{method} cannot start a new clock update before the pending SetLag method.", rule_key="clock")
    target_sp = object_sp(event) or state["session"].get("sp")
    expected = session_open_for(state, target_sp, write_required=True) and session_has_authority(state)
    return expected_status_result(
        event,
        "success" if expected else "auth_error",
        f"{method} requires authorized write access to the ClockTime table.",
        rule_key="clock",
    )


def judge_log_method(state, event):
    method = event.get("method")
    if method == "CreateLog":
        if event.get("object_family") != "LogList" or not table_level_invocation(event):
            return expected_status_result(event, "invalid_parameter", "CreateLog target must be the LogList table.", rule_key="log")
        target_sp = object_sp(event) or state["session"].get("sp")
        # spec core/5.8.4: CreateLog fails with INVALID_PARAMETER if the name already exists.
        log_name = (event.get("parameters") or {}).get("NewLogTableName")
        if log_name and str(log_name) in (state.get("log_table_names") or set()):
            return expected_status_result(
                event,
                "invalid_parameter",
                f"CreateLog duplicate name '{log_name}' must fail with INVALID_PARAMETER (core/5.8.4).",
                rule_key="log",
            )
        expected = session_open_for(state, target_sp, write_required=True) and session_has_authority(state)
        return expected_status_result(
            event,
            "success" if expected else "auth_error",
            "CreateLog requires authorized write access to the LogList table.",
            rule_key="log",
        )

    if event.get("object_family") != "Log" or not table_level_invocation(event):
        return expected_status_result(event, "invalid_parameter", f"{method} target must be a Log table.", rule_key="log")
    # spec core/5.8.3: AddLog/ClearLog/FlushLog must target a Log table that exists.
    log_uid = compact_uid(event.get("object_uid"))
    known_logs = state.get("log_tables") or set()
    if log_uid not in known_logs:
        return expected_status_result(
            event,
            "error",
            f"{method} targets log table '{log_uid}' which does not exist (core/5.8.3).",
            rule_key="log",
        )
    target_sp = object_sp(event) or state["session"].get("sp")
    write_required = method == "ClearLog"
    expected = session_open_for(state, target_sp, write_required=write_required) and session_has_authority(state)
    return expected_status_result(
        event,
        "success" if expected else "auth_error",
        f"{method} requires access to the Log table.",
        rule_key="log",
    )


def judge_next(state, event):
    count = event.get("count")
    if count is not None and count < 0:
        return expected_status_result(event, "invalid_parameter", "Next Count cannot be negative.", rule_key="next")
    if event.get("object_family") in {"MBR", "DataStore"}:
        return expected_status_result(
            event,
            "invalid_parameter",
            "Next iterates object-table UID rows and is not valid for byte tables.",
            rule_key="next",
            policy_source="table_schema",
        )
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


def _mbr_shadow_active(state):
    mbr = state.get("mbr") or {}
    return bool(mbr.get("enable")) and not bool(mbr.get("done"))


_MBR_MIN_LAST_LBA = 262143  # 128 MiB / 512 bytes - 1 (spec opal/4.3.5.4 minimum MBR size)


def _mbr_shadow_overlap(state, lba):
    """Return (overlaps, fully_in) for lba vs. the MBR shadow region [0, shadow_last_lba]."""
    if lba is None:
        return False, False
    mbr = state.get("mbr") or {}
    shadow_last_lba = mbr.get("table_size_lbas") or _MBR_MIN_LAST_LBA
    lba_start, lba_end = lba
    overlaps = lba_start <= shadow_last_lba
    fully_in = overlaps and lba_end <= shadow_last_lba
    return overlaps, fully_in


def judge_read(state, event):
    lba = event.get("lba")
    actual = actual_status_class(event)

    # spec opal/4.3.4 Table 230: when MBR shadow is active (Enable=True, Done=False),
    # reads to shadow LBAs return MBR table data; mixed-region reads return Data Protection Error.
    if _mbr_shadow_active(state):
        overlaps, fully_in = _mbr_shadow_overlap(state, lba)
        if overlaps and not fully_in:
            # Mixed: read spans shadow and user regions → Data Protection Error
            if actual == "data_error":
                return pass_result(
                    "Mixed MBR-shadow/user read correctly returned Data Protection Error (opal/4.3.4).",
                    expected_status="data_error",
                    actual_status=actual,
                    spec_refs=spec_refs_for("locking_data"),
                )
            return fail_result(
                "Read spanning MBR shadow and user regions must return Data Protection Error (opal/4.3.4).",
                expected_status="data_error",
                actual_status=actual,
                spec_refs=spec_refs_for("locking_data"),
            )
        if fully_in:
            # Fully inside shadow: drive returns MBR table data (not user data)
            if actual == "data_error":
                return fail_result(
                    "Read fully within MBR shadow region must succeed with MBR table data (opal/4.3.4).",
                    expected_status="data_success",
                    actual_status=actual,
                    spec_refs=spec_refs_for("locking_data"),
                )
            return pass_result(
                "Read within active MBR shadow region returned data (MBR table contents, opal/4.3.4).",
                0.7,
                expected_status="data_success",
                actual_status=actual,
                spec_refs=spec_refs_for("locking_data"),
            )

    lock = lock_state_for_lba(state, lba, "read")
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
    actual = actual_status_class(event)

    # spec opal/4.3.4 Table 231: when MBR shadow is active (Enable=True, Done=False),
    # writes to the shadow region must be rejected.
    if _mbr_shadow_active(state):
        overlaps, _ = _mbr_shadow_overlap(state, lba)
        if overlaps:
            if actual == "data_error":
                return pass_result(
                    "Write to active MBR shadow region was correctly rejected (opal/4.3.4).",
                    expected_status="data_error",
                    actual_status=actual,
                    spec_refs=spec_refs_for("locking_data"),
                )
            return fail_result(
                "Write to active MBR shadow region must be rejected (opal/4.3.4).",
                expected_status="data_error",
                actual_status=actual,
                spec_refs=spec_refs_for("locking_data"),
            )

    lock = lock_state_for_lba(state, lba, "write")
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


def judge_trusted_session(state, event):
    method = event.get("method")
    if method == "SyncTrustedSession":
        # spec core/5.2.3.4: SyncTrustedSession must follow a StartTrustedSession exchange.
        # If no StartTrustedSession occurred in this session, SyncTrustedSession must fail.
        expected = state["session"].get("open") and state["session"].get("pending_trusted", False)
        return expected_status_result(
            event,
            "success" if expected else "error",
            "SyncTrustedSession requires a preceding StartTrustedSession exchange (core/5.2.3.4).",
            rule_key="trusted_session",
        )
    # StartTrustedSession: session must be open.
    expected = state["session"].get("open")
    return expected_status_result(
        event,
        "success" if expected else "error",
        "StartTrustedSession must occur after the normal session-start exchange (core/5.2.3.3).",
        rule_key="trusted_session",
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


def judge_discovery(state, event):
    """Judge a Level 0 Discovery response for spec compliance (opal/3.1.1.*)."""
    TPER_CODE    = 0x0001
    LOCKING_CODE = 0x0002
    OPAL_V2_CODE = 0x0203

    features = event.get("features") or {}

    # Required descriptors must all be present.
    for code, name in ((TPER_CODE, "TPer"), (LOCKING_CODE, "Locking"), (OPAL_V2_CODE, "Opal SSC V2")):
        if code not in features:
            return fail_result(
                f"Level 0 Discovery missing required {name} descriptor (feature 0x{code:04X}) (opal/3.1.1).",
                0.95, "success", "discovery_missing_descriptor",
                spec_refs_for("discovery"), "spec", "implemented",
            )

    # TPer descriptor (opal/3.1.1.2): StreamingSupported=1, SyncSupported=1
    tper = features[TPER_CODE]
    sync_ok = to_bool(tper.get("sync_supported") if "sync_supported" in tper else tper.get("sync")) is not False
    stream_ok = to_bool(tper.get("streaming_supported") if "streaming_supported" in tper else tper.get("streaming")) is not False
    if not sync_ok:
        return fail_result(
            "TPer descriptor SyncSupported must be 1 (opal/3.1.1.2).",
            0.90, "success", "discovery_tper_sync",
            spec_refs_for("discovery"), "spec", "implemented",
        )
    if not stream_ok:
        return fail_result(
            "TPer descriptor StreamingSupported must be 1 (opal/3.1.1.2).",
            0.90, "success", "discovery_tper_streaming",
            spec_refs_for("discovery"), "spec", "implemented",
        )

    # Locking descriptor (opal/3.1.1.3): LockingSupported=1, MediaEncryption=1, MBRShadowingNotSupported=0
    locking = features[LOCKING_CODE]
    supported = to_bool(locking.get("locking_supported") if "locking_supported" in locking else locking.get("supported"))
    media_enc = to_bool(locking.get("media_encryption"))
    mbr_shadow_not = to_bool(locking.get("mbr_shadowing_not_supported") if "mbr_shadowing_not_supported" in locking else locking.get("mbr_not_supported"))
    if supported is False:
        return fail_result(
            "Locking descriptor LockingSupported must be 1 (opal/3.1.1.3).",
            0.90, "success", "discovery_locking",
            spec_refs_for("discovery"), "spec", "implemented",
        )
    if media_enc is False:
        return fail_result(
            "Locking descriptor MediaEncryption must be 1 (opal/3.1.1.3).",
            0.90, "success", "discovery_locking",
            spec_refs_for("discovery"), "spec", "implemented",
        )
    if mbr_shadow_not is True:
        return fail_result(
            "Locking descriptor MBRShadowingNotSupported must be 0 (opal/3.1.1.3).",
            0.90, "success", "discovery_locking",
            spec_refs_for("discovery"), "spec", "implemented",
        )

    # LockingEnabled must match SP lifecycle state (opal/3.1.1.3.1).
    locking_enabled_reported = to_bool(
        locking.get("locking_enabled") if "locking_enabled" in locking else locking.get("enabled")
    )
    locking_sp_active = state.get("locking_sp_active", False)
    if locking_enabled_reported is not None:
        if locking_sp_active and not locking_enabled_reported:
            return fail_result(
                "LockingEnabled must be 1 when LockingSP is active (opal/3.1.1.3.1).",
                0.90, "success", "discovery_locking_enabled",
                spec_refs_for("discovery"), "spec", "implemented",
            )
        if not locking_sp_active and locking_enabled_reported:
            return fail_result(
                "LockingEnabled must be 0 when LockingSP is inactive (opal/3.1.1.3.1).",
                0.90, "success", "discovery_locking_enabled",
                spec_refs_for("discovery"), "spec", "implemented",
            )

    # Opal SSC V2 descriptor (opal/3.1.1.5): >=4 admins, >=8 users, >=1 ComID
    opal = features[OPAL_V2_CODE]
    num_admins = to_int(opal.get("number_of_admins_supported") or opal.get("admin_auth_count") or opal.get("num_admins"))
    num_users = to_int(opal.get("number_of_users_supported") or opal.get("user_auth_count") or opal.get("num_users"))
    num_comids = to_int(opal.get("num_comids") or opal.get("number_of_comids"))
    if num_admins is not None and num_admins < 4:
        return fail_result(
            f"Opal SSC V2 must support at least 4 Locking SP admin authorities; reported {num_admins} (opal/3.1.1.5).",
            0.90, "success", "discovery_opal_v2",
            spec_refs_for("discovery"), "spec", "implemented",
        )
    if num_users is not None and num_users < 8:
        return fail_result(
            f"Opal SSC V2 must support at least 8 Locking SP user authorities; reported {num_users} (opal/3.1.1.5).",
            0.90, "success", "discovery_opal_v2",
            spec_refs_for("discovery"), "spec", "implemented",
        )
    if num_comids is not None and num_comids < 1:
        return fail_result(
            "Opal SSC V2 must have at least one ComID (opal/3.1.1.5).",
            0.90, "success", "discovery_opal_v2",
            spec_refs_for("discovery"), "spec", "implemented",
        )

    return pass_result(
        "Level 0 Discovery response is compliant: required descriptors present and field values valid (opal/3.1.1).",
        0.95, "success", "success",
        spec_refs_for("discovery"), "spec", "implemented",
    )


def judge_issue_sp(state, event):
    # spec core/5.4.3.1: IssueSP issues a new SP — requires authorized AdminSP read-write session.
    # The standard authorization is SID or Admins (ACE_SP_SID covers Activate/Revert; IssueSP
    # follows the same Admin Template access-control pattern).
    expected = session_open_for(state, "AdminSP", write_required=True) and session_has_admin_authority(state, "AdminSP")
    return expected_status_result(
        event,
        "success" if expected else "auth_error",
        "IssueSP requires an authorized read-write AdminSP session (core/5.4.3.1).",
        rule_key="issue_sp",
    )


def judge_final(state, event):
    if event["kind"] == "read":
        return judge_read(state, event)
    if event["kind"] == "write":
        return judge_write(state, event)
    if event["kind"] == "discovery":
        return judge_discovery(state, event)
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
    if method in {"StartTrustedSession", "SyncTrustedSession"}:
        return judge_trusted_session(state, event)
    if method == "Authenticate":
        return judge_authenticate(state, event)
    if method in {"GetACL", "AddACE", "RemoveACE", "DeleteMethod"}:
        return judge_meta_acl(state, event)
    if method == "Get":
        return judge_get(state, event)
    if method == "Set":
        return judge_set(state, event)
    if method == "Delete":
        return judge_delete(state, event)
    if method == "CreateTable":
        return judge_create_table(state, event)
    if method == "Next":
        return judge_next(state, event)
    if method in {"CreateRow", "DeleteRow"}:
        return judge_row_management(state, event)
    if method in {"GetFreeSpace", "GetFreeRows"}:
        return judge_free_space_or_rows(state, event)
    if method == "GetPackage":
        return judge_get_package(state, event)
    if method == "SetPackage":
        return judge_set_package(state, event)
    if method in {"EncryptInit", "Encrypt", "EncryptFinalize", "DecryptInit", "Decrypt", "DecryptFinalize", "HashInit", "Hash", "HashFinalize", "HMACInit", "HMAC", "HMACFinalize"}:
        return judge_crypto_stream_method(state, event)
    if method in {"Sign", "Verify"}:
        return judge_crypto_sign_method(state, event)
    if method == "XOR":
        return judge_xor(state, event)
    if method == "Random":
        return judge_random(state, event)
    if method == "Stir":
        return judge_stir(state, event)
    if method in {"GetClock", "IncrementCounter"}:
        return judge_increment_counter(state, event)
    if method in {"ResetClock", "SetClockHigh", "SetLagHigh", "SetClockLow", "SetLagLow"}:
        return judge_clock_mutation(state, event)
    if method in {"AddLog", "CreateLog", "ClearLog", "FlushLog"}:
        return judge_log_method(state, event)
    if method == "Activate":
        return judge_activate(state, event)
    if method == "Revert":
        return judge_revert(state, event)
    if method == "RevertSP":
        return judge_revert_sp(state, event)
    if method == "DeleteSP":
        return judge_delete_sp(state, event)
    if method == "IssueSP":
        return judge_issue_sp(state, event)
    if method == "GenKey":
        return judge_gen_key(state, event)
    if method in {"EndSession", "CloseSession"}:
        return judge_close_session(state, event)

    return fallback(event, state)

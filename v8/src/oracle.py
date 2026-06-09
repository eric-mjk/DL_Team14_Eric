import re
from dataclasses import dataclass

from .normalizer import (
    byte_length,
    compact_uid,
    find_named_value,
    is_success_status,
    object_families_compatible,
    to_bool,
    to_int,
)
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
    method_name_from_value,
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


def _return_values_empty(value):
    if value is None:
        return True
    if value == {} or value == []:
        return True
    if isinstance(value, dict):
        if set(value.keys()).issubset({"required", "optional"}):
            return all(_return_values_empty(v) for v in value.values())
        return False
    if isinstance(value, list):
        return all(_return_values_empty(item) for item in value)
    return False


def unexpected_success_return_values(event):
    if actual_status_class(event) != "success":
        return False
    raw_out = (event.get("raw") or {}).get("output") or {}
    return not _return_values_empty(raw_out.get("return_values"))


def fail_empty_success_result(event, rule_key, empty_result_ref, confidence=0.95):
    return fail_result(
        f"{event.get('method')} returns an empty result list on success; non-empty return_values are not compliant ({empty_result_ref}).",
        confidence,
        "success_empty_result",
        "success",
        spec_refs_for(rule_key),
        "return_shape",
        "implemented",
    )


_EMPTY_SUCCESS_RESULT_METHODS = {
    "Set": ("set", "core/5.3.3.7.3"),
    "Delete": ("delete", "core/5.3.3.3.1.1"),
    "DeleteRow": ("row_management", "core/5.3.3.5.2.1"),
    "DeleteMethod": ("meta_acl", "core/5.3.3.11.3.1"),
    "AddACE": ("meta_acl", "core/5.3.3.14.4.1"),
    "RemoveACE": ("meta_acl", "core/5.3.3.15.4.1"),
    "SetPackage": ("set_package", "core/5.3.3.18.4"),
    "GenKey": ("gen_key", "core/5.3.3.16.3.1"),
    "EncryptInit": ("crypto_stream", "core/5.6.4.6.2.1"),
    "DecryptInit": ("crypto_stream", "core/5.6.4.3.2.1"),
    "HashInit": ("crypto_stream", "core/5.6.4.11.2.1"),
    "HMACInit": ("crypto_stream", "core/5.6.4.14.2.1"),
    "Stir": ("stir", "core/5.6.4.2.3.1"),
    "ResetClock": ("clock", "core/5.5.4.2.1.1"),
    "SetClockHigh": ("clock", "core/5.5.4.3.2.1"),
    "SetClockLow": ("clock", "core/5.5.4.5.2.1"),
    "SetLagLow": ("clock", "core/5.5.4.6.2.1"),
    "AddLog": ("log", "core/5.8.3.1.3.1"),
    "ClearLog": ("log", "core/5.8.3.3.1.1"),
    "FlushLog": ("log", "core/5.8.3.4.1.1"),
    "Activate": ("activate", "opal/5.1.1.1"),
    "DeleteSP": ("delete_sp", "core/5.3.3.1.1.1"),
    "EndSession": ("close_session", "core/3.3.7.1.5"),
    "CloseSession": ("close_session", "core/3.3.7.1.5"),
}


_STANDARD_SINGLETON_UIDS = {
    "MBRControl": ("0000080300000001", "opal/4.3.5.3"),
}


def incompatible_object_identity_result(event):
    uid_family = event.get("object_uid_family")
    name_family = event.get("object_name_family")
    if not uid_family or not name_family:
        return None
    if object_families_compatible(uid_family, name_family):
        return None
    return expected_status_result(
        event,
        "error",
        (
            f"Invoking object name {event.get('object_name')!r} identifies {name_family}, "
            f"but UID {event.get('object_uid')} identifies {uid_family}; a method on a "
            "contradictory concrete object identity cannot succeed."
        ),
        rule_key=(event.get("method") or "").lower(),
        policy_source="object_identity",
    )


def invalid_singleton_object_row_result(event):
    family = event.get("object_family")
    expected = _STANDARD_SINGLETON_UIDS.get(family)
    if expected is None:
        return None
    expected_uid, ref = expected
    uid = compact_uid(event.get("object_uid"))
    if uid == expected_uid:
        return None
    return expected_status_result(
        event,
        "error",
        (
            f"{family} is a singleton Opal preconfigured object with UID {expected_uid}; "
            f"row UID {uid or '<missing>'} is not that object and cannot be used successfully ({ref})."
        ),
        rule_key="mbr_control" if family == "MBRControl" else (event.get("method") or "").lower(),
        policy_source="object_identity",
    )


def no_result_method_return_shape_result(event):
    entry = _EMPTY_SUCCESS_RESULT_METHODS.get(event.get("method"))
    if entry is None or not unexpected_success_return_values(event):
        return None
    rule_key, ref = entry
    return fail_empty_success_result(event, rule_key, ref)


def success_response_method_mismatch_result(event):
    if actual_status_class(event) != "success":
        return None
    method = event.get("method")
    if not method:
        return None
    raw_out = (event.get("raw") or {}).get("output") or {}
    output_method = raw_out.get("method")
    if not isinstance(output_method, dict):
        return None
    output_method_name = output_method.get("name")
    if not output_method_name:
        return None

    expected_output_method = "SyncSession" if method == "StartSession" else method
    if str(output_method_name).strip().lower() == str(expected_output_method).strip().lower():
        return None

    return fail_result(
        (
            f"{method} returned SUCCESS but output.method.name={output_method_name!r}; "
            f"expected {expected_output_method!r}."
        ),
        confidence=0.95,
        expected_status=f"success_with_{expected_output_method}_response",
        actual_status=f"success_with_{output_method_name}_response",
        spec_refs=spec_refs_for(METHOD_FAILURE_MATRIX.get(method, {}).get("rule_key") or "get"),
        policy_source="response_shape",
    )


def authenticate_success_missing_result(event):
    if event.get("method") != "Authenticate" or actual_status_class(event) != "success":
        return None
    if not parameter_present(event, ("Proof",)):
        return None
    raw_out = (event.get("raw") or {}).get("output") or {}
    raw_result = find_named_value(raw_out.get("return_values"), {"Success", "Result"})
    if raw_result is not None and to_bool(raw_result) is not None:
        return None
    return fail_result(
        "Authenticate returned SUCCESS for a Proof-bearing step without a boolean Result/Success field.",
        confidence=0.95,
        expected_status="success_with_boolean_result",
        actual_status="success_missing_result",
        spec_refs=spec_refs_for("authenticate"),
        policy_source="response_shape",
    )


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


def expected_empty_success_result(
    event,
    expected_status,
    reason,
    rule_key,
    empty_result_ref,
    confidence=0.95,
    policy_source="none",
    coverage_status="implemented",
):
    result = expected_status_result(
        event,
        expected_status,
        reason,
        confidence=confidence,
        rule_key=rule_key,
        policy_source=policy_source,
        coverage_status=coverage_status,
    )
    if result.verdict != "pass" or actual_status_class(event) != "success":
        return result
    if not status_matches("success", expected_status) or not unexpected_success_return_values(event):
        return result
    return fail_empty_success_result(event, rule_key, empty_result_ref, confidence)


def expected_exact_method_status_result(
    event,
    expected_status,
    reason,
    confidence=0.95,
    rule_key=None,
    policy_source="none",
    coverage_status="implemented",
):
    actual = event.get("status")
    refs = spec_refs_for(rule_key) if rule_key else ()
    if actual == expected_status:
        return pass_result(reason, confidence, expected_status, actual, refs, policy_source, coverage_status)
    return fail_result(reason, confidence, expected_status, actual or actual_status_class(event), refs, policy_source, coverage_status)


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


def authority_record_matches_sp(record, sp):
    if not sp:
        return True
    if not isinstance(record, dict):
        return True
    record_sp = record.get("sp")
    if record_sp:
        return str(record_sp).strip().lower() == str(sp).strip().lower()
    return _source_matches_sp(record.get("source"), sp)


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
        sp_filtered = [r for r in records if authority_record_matches_sp(r, sp)]
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


def max_authentications_limit_result(state, event):
    limit = to_int((state.get("properties") or {}).get("MaxAuthentications"))
    if limit is None or limit <= 0:
        return None
    session = state.get("session") or {}
    if not session.get("open"):
        return None
    authority = event.get("authority")
    if not authority or authority == "Anybody":
        return None
    authorities = set(session.get("authorities") or set())
    if authority in authorities:
        return None
    # Anybody is always considered authenticated in an open session and counts
    # against MaxAuthentications (core/5.3.4.1.2.1).
    if len(authorities) + 1 < limit:
        return None
    actual = actual_status_class(event)
    auth_result = event.get("auth_result")
    reason = (
        f"Authenticate for {authority} would exceed learned MaxAuthentications={limit}; "
        "TPer must return SUCCESS with result False."
    )
    refs = spec_refs_for("authenticate")
    if actual == "success" and auth_result is False:
        return pass_result(
            reason,
            expected_status="success_false",
            actual_status=actual,
            spec_refs=refs,
            policy_source="Properties.MaxAuthentications",
        )
    return fail_result(
        reason,
        expected_status="success_false",
        actual_status=actual,
        spec_refs=refs,
        policy_source="Properties.MaxAuthentications",
    )


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


def meta_acl_parameter_target(event):
    invoking = compact_uid(uid_parameter_value(parameter_value(event, ("InvokingID",))))
    method_uid = compact_uid(uid_parameter_value(parameter_value(event, ("MethodID",))))
    method_name = method_name_from_value(method_uid) if method_uid else None
    return invoking, method_name


def matching_access_control_row(state, invoking_uid, method_name, target_sp=None):
    rows = []
    for row in (state.get("access_control_rows") or []):
        if invoking_uid:
            if row.get("invoking_uid") == invoking_uid:
                pass
            elif row.get("uid_prefix") and invoking_uid.startswith(str(row.get("uid_prefix")).upper()):
                pass
            elif uid_pattern_matches(row.get("invoking_pattern"), invoking_uid):
                pass
            else:
                continue
        if method_name and row.get("method") not in {None, "", method_name}:
            continue
        rows.append(row)
    if target_sp:
        scoped = [row for row in rows if policy_scope_from_source(row.get("source")) == target_sp]
        if scoped:
            return scoped[0]
    return rows[0] if rows else None


def ace_refs_authorized(state, refs, target_sp=None, row_source=None):
    ace_rows = state.get("ace_rows") or {}
    if not refs:
        return None
    saw_unknown = False
    for ref in refs:
        ace = ace_for_ref(ace_rows, ref, target_sp=target_sp, row_source=row_source)
        if not ace:
            saw_unknown = True
            continue
        allowed = evaluate_boolean_expr(ace.get("boolean_expr"), state)
        if allowed is True:
            return True
        if allowed is None:
            saw_unknown = True
    return None if saw_unknown else False


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


def challenge_response_value(event):
    return_values = ((event.get("raw") or {}).get("output") or {}).get("return_values")
    challenge = find_named_value(return_values, {"Challenge", "challenge"})
    if challenge is not None:
        return challenge
    result = find_named_value(return_values, {"Result", "result"})
    if result is not None and to_bool(result) is None:
        return result
    return None


def success_false_result(event, reason, rule_key="authenticate", policy_source="none"):
    actual = actual_status_class(event)
    auth_result = event.get("auth_result")
    refs = spec_refs_for(rule_key)
    if actual == "success" and auth_result is False:
        return pass_result(reason, expected_status="success_false", actual_status=actual, spec_refs=refs, policy_source=policy_source)
    return fail_result(reason, expected_status="success_false", actual_status=actual, spec_refs=refs, policy_source=policy_source)


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


def issued_sp_entry_for_sp(state, sp_name):
    for _uid, entry in (state.get("issued_sps") or {}).items():
        if entry.get("sp") == sp_name or entry.get("uid") == sp_name:
            return entry
    return None


def object_sp(event):
    family = event.get("object_family")
    uid = event.get("object_uid") or ""
    obj = event.get("object")
    if family in {"Locking", "LockingInfo", "MBRControl", "MBR", "MediaKey", "DataStore", "SecretProtect"}:
        return "LockingSP"
    if family in {"TPerInfo", "DataRemovalMechanism"}:
        return "AdminSP"
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


def _get_locking_info_alignment(state):
    """Return (alignment_required, granularity, lowest_lba) from trajectory-observed LockingInfo, or None."""
    for key, row in (state.get("tables") or {}).items():
        if row.get("table") != "LockingInfo" and not (isinstance(key, str) and key.startswith("00000801")):
            continue
        cols = row.get("columns") or {}
        alignment_required = to_bool(cols.get(7))
        if alignment_required is None:
            continue
        granularity = to_int(cols.get(9))
        lowest_lba = to_int(cols.get(10)) or 0
        return (alignment_required, granularity, lowest_lba)
    return None


def _get_locking_info_geometry(state):
    """Return observed LockingInfo geometry columns for Discovery descriptor comparison."""
    for key, row in (state.get("tables") or {}).items():
        if row.get("table") != "LockingInfo" and not (isinstance(key, str) and key.startswith("00000801")):
            continue
        cols = row.get("columns") or {}
        geometry = {}
        alignment_required = to_bool(cols.get(7))
        logical_block_size = to_int(cols.get(8))
        alignment_granularity = to_int(cols.get(9))
        lowest_aligned_lba = to_int(cols.get(10))
        if alignment_required is not None:
            geometry["align"] = alignment_required
        if logical_block_size is not None:
            geometry["logical_block_size"] = logical_block_size
        if alignment_granularity is not None:
            geometry["alignment_granularity"] = alignment_granularity
        if lowest_aligned_lba is not None:
            geometry["lowest_aligned_lba"] = lowest_aligned_lba
        if geometry:
            return geometry
    return None


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
    # spec opal/4.3.5.2.1.1 + 4.3.5.2.1.2: alignment check
    alignment = _get_locking_info_alignment(state)
    if alignment:
        align_required, granularity, lowest_lba = alignment
        if align_required and granularity and granularity > 1:
            if 3 in columns:  # RangeStart alignment
                rs = to_int(columns[3]) or 0
                if rs != 0 and (rs - lowest_lba) % granularity != 0:
                    return True
            if 4 in columns:  # RangeLength alignment
                rl = to_int(columns[4]) or 0
                if rl != 0:
                    if 3 in columns:
                        rs = to_int(columns[3]) or 0
                    else:
                        rs = to_int((state.get("locking_ranges") or {}).get(range_name, {}).get("range_start")) or 0
                    length_align = (rl - lowest_lba) % granularity if rs == 0 else rl % granularity
                    if length_align != 0:
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


_LOCK_ON_RESET_NAMES = {
    "powercycle": 0, "power_cycle": 0, "powercyl": 0,
    "hardwarereset": 1, "hardware_reset": 1, "hwreset": 1,
    "programmatic": 3, "prog": 3,
}

_MANDATORY_RESET_SETS = {frozenset({0}), frozenset({0, 3})}
_OPTIONAL_RESET_SETS = {frozenset({0, 1}), frozenset({0, 1, 3})}
_ALL_SUPPORTED_RESET_SETS = _MANDATORY_RESET_SETS | _OPTIONAL_RESET_SETS


def _parse_reset_set(value):
    """Parse a LockOnReset/DoneOnReset column value to frozenset of ints, or None."""
    if value is None:
        return None
    if isinstance(value, int):
        return frozenset({value})
    if isinstance(value, (list, tuple)):
        result = set()
        for v in value:
            if isinstance(v, int):
                result.add(v)
            else:
                key = re.sub(r"[\s\-_]", "", str(v).lower())
                mapped = _LOCK_ON_RESET_NAMES.get(key)
                if mapped is None:
                    try:
                        result.add(int(v))
                    except (ValueError, TypeError):
                        return None  # unparseable element
                else:
                    result.add(mapped)
        return frozenset(result) if result is not None else None
    if isinstance(value, str):
        stripped = re.sub(r"[{}\s]", "", value)
        if not stripped:
            return None
        parts = stripped.split(",")
        result = set()
        for part in parts:
            try:
                result.add(int(part))
            except ValueError:
                key = re.sub(r"[\-_]", "", part.lower())
                mapped = _LOCK_ON_RESET_NAMES.get(key)
                if mapped is None:
                    return None  # unrecognized string
                result.add(mapped)
        return frozenset(result) if result else None
    return None


def validate_lock_on_reset_value(value):
    """Return expected status string/set for LockOnReset/DoneOnReset column value.

    Returns 'invalid_parameter' for clearly unsupported values, 'success_or_invalid'
    (as a set) for optional-support values, or None for mandatory/unknown values
    where normal auth flow should proceed.
    """
    parsed = _parse_reset_set(value)
    if parsed is None:
        return None  # unparseable — can't judge content
    if parsed in _MANDATORY_RESET_SETS:
        return None  # mandatory: must succeed if authorized — fall through to auth check
    if parsed in _OPTIONAL_RESET_SETS:
        return {"success", "invalid_parameter"}  # optional: either is acceptable
    return "invalid_parameter"  # unsupported value


def is_byte_table_event(state, event):
    if event.get("object_family") in {"MBR", "DataStore"}:
        return True
    dynamic_table = dynamic_table_record(state, event)
    return dynamic_table is not None and dynamic_table.get("kind") == "byte"


def byte_table_granularity(state, event):
    if not is_byte_table_event(state, event):
        return None
    dynamic_table = dynamic_table_record(state, event)
    if dynamic_table is not None:
        raw = (
            dynamic_table.get("mandatory_write_granularity")
            or dynamic_table.get("mandatory_write")
            or dynamic_table.get("MandatoryWriteGranularity")
            or dynamic_table.get("recommended_access_granularity")
        )
        granularity = to_int(raw)
        return granularity if granularity and granularity > 0 else None
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


_MBR_TABLE_UID = "0000000100000804"
_DATASTORE_TABLE_UID = "0000000100001001"
_BYTE_TABLE_MIN_SIZES = {
    _MBR_TABLE_UID: (0x08000000, "MBR", "opal/4.3.5.4"),
    _DATASTORE_TABLE_UID: (0x00A00000, "DataStore", "opal/4.3.8.1"),
}


def byte_table_reported_size_violation(event):
    if event.get("method") != "Get" or actual_status_class(event) != "success":
        return None
    table_uid = compact_uid(event.get("object_uid"))
    if table_uid not in _BYTE_TABLE_MIN_SIZES:
        return None
    minimum, name, spec_ref = _BYTE_TABLE_MIN_SIZES[table_uid]
    return_cols = event.get("return_columns") or {}
    raw_out = (event.get("raw") or {}).get("output") or {}
    return_values = raw_out.get("return_values")
    candidates = [
        return_cols.get(7),   # Table.Rows: byte-table size in bytes
        return_cols.get(11),  # Table.MinSize, if returned
        find_named_value(return_values, {"Rows"}),
        find_named_value(return_values, {"MinSize"}),
    ]
    for raw_size in candidates:
        size = to_int(raw_size)
        if size is not None and size < minimum:
            return (name, size, minimum, spec_ref)
    return None


_ADMIN_SP_OPAL_METHODS = {"Next", "GetACL", "Get", "Set", "Authenticate", "Revert", "Activate", "Random"}
_LOCKING_SP_METHODS = {"Next", "GetACL", "GenKey", "RevertSP", "DeleteSP", "Get", "Set", "Authenticate", "Random"}
_SESSION_MANAGER_METHODS = {
    "Properties", "StartSession", "SyncSession", "StartTrustedSession",
    "SyncTrustedSession", "CloseSession", "EndSession",
}


def sp_method_filter_result(state, event):
    method = event.get("method")
    if method in _SESSION_MANAGER_METHODS or not method:
        return None
    session_sp = state["session"].get("sp")
    sp_method = method in {"RevertSP", "DeleteSP", "IssueSP"}
    target_sp = session_sp if sp_method else (object_sp(event) or session_sp)

    if target_sp == "AdminSP" and state.get("opal_profile_confirmed") and method not in _ADMIN_SP_OPAL_METHODS:
        return expected_status_result(
            event,
            "error",
            f"{method} is not in the AdminSP supported MethodID set after Opal SSC V2 discovery (opal/4.2.1.4).",
            rule_key="method_table",
            coverage_status="implemented",
        )

    # Without explicit Opal discovery evidence, keep Core/Admin-template methods modeled elsewhere
    # in this file. The high-risk ungated AdminSP gap is accepting SUCCESS for GenKey, which has
    # no AdminSP interpretation in either the Opal table or the modeled Core template path.
    if target_sp == "AdminSP" and method == "GenKey":
        return expected_status_result(
            event,
            "error",
            f"{method} is not in the AdminSP supported MethodID set (opal/4.2.1.4).",
            rule_key="method_table",
            coverage_status="implemented",
        )
    if target_sp == "LockingSP" and method not in _LOCKING_SP_METHODS:
        return expected_status_result(
            event,
            "error",
            f"{method} is not in the LockingSP supported MethodID set (opal/4.3.1.5).",
            rule_key="method_table",
            coverage_status="implemented",
        )
    return None


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


def invalid_tperinfo_programmatic_reset_value(event):
    if event.get("method") != "Set" or event.get("object_family") != "TPerInfo":
        return False
    value_cols = event.get("value_columns") or {}
    return 8 in value_cols and to_bool(value_cols.get(8)) is None


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


def dynamic_table_record(state, event):
    uid = compact_uid(event.get("object_uid"))
    if not uid:
        return None
    return (state.get("dynamic_tables") or {}).get(uid)


def returned_free_rows(event):
    raw_out = (event.get("raw") or {}).get("output") or {}
    return_values = raw_out.get("return_values") or {}
    value = find_named_value(return_values, {"FreeRows", "Result"})
    return to_int(value)


def returned_free_space(event):
    raw_out = (event.get("raw") or {}).get("output") or {}
    return_values = raw_out.get("return_values") or {}
    value = find_named_value(return_values, {"FreeSpace", "freespace"})
    return to_int(value)


def _table_rows_items(value):
    if isinstance(value, dict):
        rows = find_named_value(value, {"Rows", "FreeRows", "TableRows"})
        uid = find_named_value(value, {"UID", "TableUID", "Table"})
        if uid is not None and rows is not None:
            return [(uid, rows)]
        result = []
        for key, item in value.items():
            if isinstance(item, (dict, list, tuple)):
                nested = _table_rows_items(item)
                if nested:
                    result.extend(nested)
                    continue
            result.append((key, item))
        return result
    if isinstance(value, (list, tuple)):
        result = []
        for item in value:
            if isinstance(item, (dict, list, tuple)):
                nested = _table_rows_items(item)
                if nested:
                    result.extend(nested)
                    continue
        if not result and len(value) >= 2:
            result.append((value[0], value[1]))
        return result
    return []


def returned_table_rows(event):
    raw_out = (event.get("raw") or {}).get("output") or {}
    return_values = raw_out.get("return_values") or {}
    table_rows = find_named_value(return_values, {"TableRows", "tablerows"})
    result = {}
    for uid_raw, rows_raw in _table_rows_items(table_rows):
        uid = compact_uid(uid_parameter_value(uid_raw))
        rows = to_int(rows_raw)
        if uid and rows is not None:
            result[uid] = rows
    return result


def returned_table_capacity(event):
    raw_out = (event.get("raw") or {}).get("output") or {}
    return_values = raw_out.get("return_values") or {}
    columns = event.get("return_columns") or {}

    def _value(column, *names):
        raw = columns.get(column)
        if raw is None:
            raw = find_named_value(return_values, set(names))
        return to_int(raw)

    return {
        "rows": _value(7, "Rows", "rows"),
        "rows_free": _value(8, "RowsFree", "rowsfree", "FreeRows"),
        "max_size": _value(12, "MaxSize", "maxsize"),
    }


def returned_output_byte_length(event, names=None):
    raw_out = (event.get("raw") or {}).get("output") or {}
    return_values = raw_out.get("return_values") or {}
    wanted = names or {
        "Random", "RandomBytes", "Bytes", "Output", "OutputBytes",
        "Data", "Result", "Hash", "HMAC", "Ciphertext", "Plaintext",
    }
    value = find_named_value(return_values, wanted)
    if value is None:
        return None
    return byte_length(value)


def buffer_out_count(event):
    return to_int(parameter_value(event, ("BufferOut", "buffer_out", "OutputBuffer", "OutputBufferSize")))


def table_capacity_consistency_result(event, source_name, policy_source):
    if actual_status_class(event) != "success":
        return None
    capacity = returned_table_capacity(event)
    rows = capacity.get("rows")
    rows_free = capacity.get("rows_free")
    max_size = capacity.get("max_size")
    if rows is None or rows_free is None or max_size is None:
        return None
    if rows < 0 or rows_free < 0 or max_size < 0:
        return fail_result(
            f"{source_name} returned negative table capacity metadata: Rows={rows}, RowsFree={rows_free}, MaxSize={max_size}.",
            expected_status="success_with_consistent_capacity",
            actual_status="success",
            spec_refs=spec_refs_for("get"),
            policy_source=policy_source,
        )
    if rows > max_size:
        return fail_result(
            f"{source_name} returned Rows={rows}, which exceeds MaxSize={max_size}.",
            expected_status="success_with_consistent_capacity",
            actual_status="success",
            spec_refs=spec_refs_for("get"),
            policy_source=policy_source,
        )
    if rows + rows_free > max_size:
        return fail_result(
            f"{source_name} returned Rows={rows} and RowsFree={rows_free}, which exceed MaxSize={max_size}.",
            expected_status="success_with_consistent_capacity",
            actual_status="success",
            spec_refs=spec_refs_for("get"),
            policy_source=policy_source,
        )
    return None


def uids_from_value(value):
    uids = []
    if isinstance(value, dict):
        for key in ("uid", "UID", "Uid", "RowUID", "Row", "Result"):
            if key in value:
                compact = compact_uid(value[key])
                if compact and len(compact) == 16 and compact not in uids:
                    uids.append(compact)
        for item in value.values():
            for uid in uids_from_value(item):
                if uid not in uids:
                    uids.append(uid)
    elif isinstance(value, (list, tuple)):
        for item in value:
            for uid in uids_from_value(item):
                if uid not in uids:
                    uids.append(uid)
    else:
        compact = compact_uid(value)
        if compact and len(compact) == 16:
            uids.append(compact)
    return uids


def returned_uids_from_event(event):
    raw_out = (event.get("raw") or {}).get("output") or {}
    return uids_from_value(raw_out.get("return_values"))


def returned_acl_refs(event):
    raw_out = (event.get("raw") or {}).get("output") or {}
    return_values = raw_out.get("return_values") or {}
    value = find_named_value(return_values, {"ACL", "Acl", "ACE", "ACEs", "ACEList", "ace_refs"})
    if value is None:
        return None
    return uids_from_value(value)


def column_number_from_key(key):
    if isinstance(key, int):
        return key
    text = str(key).strip()
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        if text.isdigit():
            return int(text, 10)
    except ValueError:
        return None
    return None


def numeric_columns_from_value(value):
    columns = set()
    wrappers = {"row", "rowvalues", "values"}
    if isinstance(value, dict):
        for key, item in value.items():
            column = column_number_from_key(key)
            if column is not None:
                columns.add(column)
            elif str(key).strip().lower() in wrappers:
                columns.update(numeric_columns_from_value(item))
    elif isinstance(value, (list, tuple)):
        for item in value:
            columns.update(numeric_columns_from_value(item))
    return columns


def comparable_column_value(value):
    if isinstance(value, dict):
        return tuple(sorted((normalized_policy_text(key), comparable_column_value(item)) for key, item in value.items()))
    if isinstance(value, (list, tuple)):
        return tuple(comparable_column_value(item) for item in value)
    uid = compact_uid(uid_parameter_value(value))
    if uid and len(uid) == 16:
        return ("uid", uid)
    return ("value", normalized_policy_text(value))


def requested_get_columns(event):
    cols = event.get("cellblock_columns")
    if not cols:
        return set()
    return {int(col) for col in cols}


def missing_success_get_columns_result(event, required_columns, rule_key, spec_ref, label):
    if actual_status_class(event) != "success":
        return None
    returned = {int(col) for col in (event.get("return_columns") or {}).keys()}
    missing = sorted(set(required_columns) - returned)
    if not missing:
        return None
    return fail_result(
        f"{label} Get succeeded but omitted requested column(s) {missing}; successful Get must return requested authorized cells ({spec_ref}).",
        expected_status="success_with_requested_columns",
        actual_status="success",
        spec_refs=spec_refs_for(rule_key),
        policy_source="return_shape",
    )


def _value_matches_int(value, expected):
    parsed = to_int(value)
    return parsed is not None and parsed == expected


def _value_matches_bool(value, expected):
    parsed_bool = to_bool(value)
    if parsed_bool is not None:
        return bool(parsed_bool) == bool(expected)
    parsed_int = to_int(value)
    if parsed_int is not None:
        return bool(parsed_int) == bool(expected)
    return normalized_policy_text(value) == normalized_policy_text(expected)


def mismatched_success_get_value_result(event, column, returned, expected, rule_key, spec_ref, label, *, kind="value"):
    if actual_status_class(event) != "success":
        return None
    if kind == "int":
        matched = _value_matches_int(returned, int(expected))
    elif kind == "bool":
        matched = _value_matches_bool(returned, bool(expected))
    else:
        matched = comparable_column_value(returned) == comparable_column_value(expected)
    if matched:
        return None
    return fail_result(
        f"{label} Get returned column {column}={returned!r}, expected {expected!r} from tracked state ({spec_ref}).",
        expected_status="success_with_tracked_value",
        actual_status="success",
        spec_refs=spec_refs_for(rule_key),
        policy_source="state",
    )


def row_column_values_from_value(value, dynamic_table=None):
    values = {}
    wrappers = {"row", "rowvalues", "values", "returnvalues"}
    name_numbers = {
        normalized_policy_text(name): number
        for name, number in ((dynamic_table or {}).get("column_name_numbers") or {}).items()
    }
    if isinstance(value, dict):
        for key, item in value.items():
            normalized_key = str(key).strip().lower()
            if normalized_key in wrappers:
                values.update(row_column_values_from_value(item, dynamic_table))
                continue
            column = column_number_from_key(key)
            if column is None:
                column = name_numbers.get(normalized_policy_text(key))
            if column is not None:
                values[column] = item
            elif isinstance(item, (dict, list, tuple)):
                values.update(row_column_values_from_value(item, dynamic_table))
    elif isinstance(value, (list, tuple)):
        for item in value:
            values.update(row_column_values_from_value(item, dynamic_table))
    return values


def dynamic_row_context(state, event):
    row_uid = compact_uid(event.get("object_uid"))
    table_uid = (state.get("dynamic_row_table") or {}).get(row_uid)
    if not row_uid or not table_uid:
        return None
    row = ((state.get("dynamic_rows") or {}).get(table_uid) or {}).get(row_uid)
    table = (state.get("dynamic_tables") or {}).get(table_uid)
    if not row or not table:
        return None
    return {"row_uid": row_uid, "table_uid": table_uid, "row": row, "table": table}


def dynamic_table_set_context(state, event):
    table = dynamic_table_record(state, event)
    if table is None or table.get("kind") == "byte":
        return None
    row_uid = compact_uid(uid_parameter_value(parameter_value(event, ("Where",))))
    if not row_uid:
        return None
    rows = (state.get("dynamic_rows") or {}).get(table.get("uid")) or {}
    return {
        "row_uid": row_uid,
        "table_uid": table.get("uid"),
        "row": rows.get(row_uid),
        "table": table,
    }


def row_record_column_values(row, dynamic_table):
    if isinstance(row, dict) and row.get("columns"):
        return dict(row.get("columns") or {})
    return row_column_values_from_value((row or {}).get("values") if isinstance(row, dict) else None, dynamic_table)


def unique_conflicts_for_values(state, dynamic_table, new_values, exclude_uid=None):
    unique_columns = set(dynamic_table.get("unique_columns") or []) - {0}
    if not unique_columns or not new_values:
        return []
    table_uid = dynamic_table.get("uid")
    known_rows = (state.get("dynamic_rows") or {}).get(table_uid) or {}
    conflicts = []
    for column in sorted(unique_columns & set(new_values)):
        new_value = comparable_column_value(new_values[column])
        for row_uid, row in known_rows.items():
            if exclude_uid and row_uid == exclude_uid:
                continue
            old_values = row_record_column_values(row, dynamic_table)
            if column in old_values and comparable_column_value(old_values[column]) == new_value:
                conflicts.append((column, row_uid))
    return conflicts


def unique_conflicts_for_create_row(state, event, dynamic_table):
    new_values = row_column_values_from_value(parameter_value(event, ("Row",)), dynamic_table)
    return unique_conflicts_for_values(state, dynamic_table, new_values)


def dynamic_getset_acl_result(state, event, table, write=False, reason=None):
    method_name = event.get("method")
    acl_row = matching_access_control_row(state, table.get("uid"), method_name, target_sp=table.get("sp") or state["session"].get("sp"))
    if acl_row is not None:
        refs = acl_row.get("ace_refs") or []
        if not refs and acl_row.get("dynamic_table_uid"):
            sp = table.get("sp") or state["session"].get("sp")
            if sp and not session_open_for(state, sp, write_required=write):
                return expected_status_result(
                    event,
                    "auth_error",
                    f"{reason or event.get('method')} matched an empty dynamic ACL and still requires an open {'write ' if write else ''}{sp} session.",
                    rule_key="access_control",
                    policy_source="dynamic_getset_acl",
                )
            return expected_status_result(
                event,
                "auth_error",
                reason or "Dynamic table AccessControl row has no ACEs for this operation.",
                rule_key="access_control",
                policy_source="dynamic_getset_acl",
            )
    else:
        refs = table.get("get_set_acl_refs") or []
    if not refs:
        return None
    sp = table.get("sp") or state["session"].get("sp")
    allowed = ace_refs_authorized(state, refs, target_sp=sp, row_source=(acl_row or table).get("source"))
    if allowed is None:
        return None
    if sp and not session_open_for(state, sp, write_required=write):
        return expected_status_result(
            event,
            "auth_error",
            f"{reason or event.get('method')} matched dynamic table GetSetACL but still requires an open {'write ' if write else ''}{sp} session.",
            rule_key="access_control",
            policy_source="dynamic_getset_acl",
        )
    return expected_status_result(
        event,
        "success" if allowed else "auth_error",
        reason or "Dynamic table GetSetACL governs this Get/Set operation.",
        rule_key="access_control",
        policy_source="dynamic_getset_acl",
    )


def dynamic_column_from_value(value, dynamic_table):
    column = column_number_from_key(value)
    if column is not None:
        return column
    return {
        normalized_policy_text(name): number
        for name, number in ((dynamic_table or {}).get("column_name_numbers") or {}).items()
    }.get(normalized_policy_text(value))


def dynamic_cellblock_columns_from_value(value, dynamic_table):
    if value is None:
        return set()
    if isinstance(value, dict):
        start = find_named_parameter(value, {"StartColumn", "Start", "startColumn"})
        end = find_named_parameter(value, {"EndColumn", "End", "endColumn"})
        start_col = dynamic_column_from_value(start, dynamic_table)
        end_col = dynamic_column_from_value(end, dynamic_table)
        if start_col is not None or end_col is not None:
            if start_col is None:
                start_col = end_col
            if end_col is None:
                end_col = start_col
            if start_col is not None and end_col is not None and start_col <= end_col:
                return set(range(start_col, end_col + 1))
            return {-1}
        columns = set()
        for item in value.values():
            columns.update(dynamic_cellblock_columns_from_value(item, dynamic_table))
        return columns
    if isinstance(value, (list, tuple)):
        columns = set()
        for item in value:
            columns.update(dynamic_cellblock_columns_from_value(item, dynamic_table))
        return columns
    column = dynamic_column_from_value(value, dynamic_table)
    return {column} if column is not None else set()


def dynamic_get_requested_columns(event, dynamic_table):
    if event.get("cellblock_columns"):
        return set(event.get("cellblock_columns") or [])
    return dynamic_cellblock_columns_from_value(event.get("cellblock"), dynamic_table)


def dynamic_set_column_values(event, dynamic_table):
    columns = dict(event.get("value_columns") or {})
    columns.update(row_column_values_from_value(parameter_value(event, ("Values",)), dynamic_table))
    return columns


def invalid_dynamic_columns(columns, dynamic_table, allow_empty=True, allow_uid=False):
    if not columns:
        return None if allow_empty else "no dynamic columns were parseable"
    known_columns = set(dynamic_table.get("column_numbers") or [])
    if not allow_uid:
        known_columns -= {0}
    supplied = set(columns)
    if 0 in supplied and not allow_uid:
        return "column 0 (UID) is not host-writable"
    if known_columns:
        unknown = supplied - known_columns
        if unknown:
            return f"unknown dynamic column(s) {sorted(unknown)}"
    return None


def dynamic_set_columns_error(state, event):
    context = dynamic_row_context(state, event)
    if context is None:
        context = dynamic_table_set_context(state, event)
    if context is None:
        return None
    columns = dynamic_set_column_values(event, context["table"])
    return invalid_dynamic_columns(columns, context["table"], allow_empty=False)


def dynamic_table_get_result(state, event):
    table = dynamic_table_record(state, event)
    if table is None:
        return None
    requested = set(event.get("cellblock_columns") or [])
    table_max = max_column_for_family("Table")
    if event.get("cellblock_invalid") or (table_max is not None and any(column < 0 or column > table_max for column in requested)):
        return expected_status_result(
            event,
            "invalid_parameter",
            "Get Cellblock requests invalid Table columns for a learned dynamic table.",
            rule_key="get",
            policy_source="dynamic_table_state",
        )
    if actual_status_class(event) == "success":
        consistency = table_capacity_consistency_result(
            event,
            f"Get on dynamic table {table.get('name')}",
            "dynamic_table_state",
        )
        if consistency is not None:
            return consistency
        raw_return_values = ((event.get("raw") or {}).get("output") or {}).get("return_values")
        return_columns = event.get("return_columns") or {}
        checks = (
            ("Rows", 7, table.get("rows")),
            ("RowsFree", 8, table.get("rows_free")),
            ("MinSize", 11, table.get("min_size")),
            ("MaxSize", 12, table.get("max_size")),
        )
        for name, column, expected_value in checks:
            if expected_value is None:
                continue
            raw = return_columns.get(column)
            if raw is None:
                raw = find_named_value(raw_return_values, {name})
            reported = to_int(raw)
            if reported is not None and reported != expected_value:
                return fail_result(
                    f"Get on dynamic table {table.get('name')} returned {name}={reported}; expected {expected_value}.",
                    expected_status=f"success_with_{name.lower()}",
                    actual_status="success",
                    spec_refs=spec_refs_for("get"),
                    policy_source="dynamic_table_state",
                )
    acl_result = dynamic_getset_acl_result(
        state,
        event,
        table,
        write=False,
        reason="Get on a learned dynamic table is governed by its CreateTable GetSetACL.",
    )
    if acl_result is not None:
        return acl_result
    sp = table.get("sp") or state["session"].get("sp")
    expected = session_open_for(state, sp)
    return expected_status_result(
        event,
        "success" if expected else "auth_error",
        "Get on a learned dynamic table row requires an open session in that table's SP.",
        rule_key="get",
        policy_source="dynamic_table_state",
    )


def dynamic_get_result(state, event):
    context = dynamic_row_context(state, event)
    if context is None:
        return None
    table = context["table"]
    requested = dynamic_get_requested_columns(event, table)
    if invalid_cellblock(event) and not requested:
        return expected_status_result(
            event,
            "invalid_parameter",
            "Get Cellblock requests invalid dynamic-table columns.",
            rule_key="get",
            policy_source="dynamic_table_state",
        )
    requested_error = invalid_dynamic_columns(requested, table, allow_empty=True, allow_uid=True)
    if requested_error:
        return expected_status_result(
            event,
            "invalid_parameter",
            f"Get requests {requested_error}.",
            rule_key="get",
            policy_source="dynamic_table_state",
        )
    if actual_status_class(event) == "success":
        raw_return_values = ((event.get("raw") or {}).get("output") or {}).get("return_values")
        returned = dict(event.get("return_columns") or {})
        returned.update(row_column_values_from_value(raw_return_values, table))
        returned_error = invalid_dynamic_columns(returned, table, allow_empty=True, allow_uid=True)
        if returned_error:
            return fail_result(
                f"Get returned {returned_error} for learned dynamic table {table.get('name')}.",
                expected_status="success_with_valid_columns",
                actual_status="success",
                spec_refs=spec_refs_for("get"),
                policy_source="dynamic_table_state",
            )
        tracked = context["row"].get("columns") or {}
        for column, returned_value in returned.items():
            if column == 0 or column not in tracked:
                continue
            if comparable_column_value(returned_value) != comparable_column_value(tracked[column]):
                return fail_result(
                    f"Get on dynamic row {context['row_uid']} returned column {column}={returned_value!r}; expected tracked value {tracked[column]!r}.",
                    expected_status="success_with_tracked_values",
                    actual_status="success",
                    spec_refs=spec_refs_for("get"),
                    policy_source="dynamic_table_state",
                )
    acl_result = dynamic_getset_acl_result(
        state,
        event,
        table,
        write=False,
        reason="Get on a learned dynamic row is governed by its table GetSetACL.",
    )
    if acl_result is not None:
        return acl_result
    sp = table.get("sp") or state["session"].get("sp")
    expected = session_open_for(state, sp)
    return expected_status_result(
        event,
        "success" if expected else "auth_error",
        "Get on a learned dynamic row requires an open session in the row's SP.",
        rule_key="get",
        policy_source="dynamic_table_state",
    )


def dynamic_set_result(state, event):
    context = dynamic_row_context(state, event)
    if context is None:
        return None
    table = context["table"]
    columns = dynamic_set_column_values(event, table)
    columns_error = invalid_dynamic_columns(columns, table, allow_empty=False)
    if columns_error:
        return expected_status_result(
            event,
            "invalid_parameter",
            f"Set Values contain {columns_error}.",
            rule_key="set",
            policy_source="dynamic_table_state",
        )
    conflicts = unique_conflicts_for_values(state, table, columns, exclude_uid=context["row_uid"])
    if conflicts:
        return expected_status_result(
            event,
            "error",
            f"Set would create dynamic unique-column conflict(s): {conflicts}.",
            rule_key="set",
            policy_source="dynamic_table_state",
        )
    acl_result = dynamic_getset_acl_result(
        state,
        event,
        table,
        write=True,
        reason="Set on a learned dynamic row is governed by its table GetSetACL.",
    )
    if acl_result is not None:
        return acl_result
    sp = table.get("sp") or state["session"].get("sp")
    expected = session_open_for(state, sp, write_required=True) and session_has_admin_authority(state, sp)
    return expected_status_result(
        event,
        "success" if expected else "auth_error",
        "Set on a learned dynamic row requires an authorized read-write session in the row's SP.",
        rule_key="set",
        policy_source="dynamic_table_state",
    )


def dynamic_table_set_result(state, event):
    context = dynamic_table_set_context(state, event)
    if context is None:
        return None
    table = context["table"]
    if table.get("row_inventory_complete") and context.get("row") is None:
        return expected_status_result(
            event,
            "error",
            f"Set targets unknown dynamic row UID {context['row_uid']}; table inventory is complete.",
            rule_key="set",
            policy_source="dynamic_table_state",
        )
    columns = dynamic_set_column_values(event, table)
    columns_error = invalid_dynamic_columns(columns, table, allow_empty=False)
    if columns_error:
        return expected_status_result(
            event,
            "invalid_parameter",
            f"Set Values contain {columns_error}.",
            rule_key="set",
            policy_source="dynamic_table_state",
        )
    conflicts = unique_conflicts_for_values(state, table, columns, exclude_uid=context["row_uid"])
    if conflicts:
        return expected_status_result(
            event,
            "error",
            f"Set would create dynamic unique-column conflict(s): {conflicts}.",
            rule_key="set",
            policy_source="dynamic_table_state",
        )
    acl_result = dynamic_getset_acl_result(
        state,
        event,
        table,
        write=True,
        reason="Table-level Set on a learned dynamic object table is governed by its table GetSetACL.",
    )
    if acl_result is not None:
        return acl_result
    sp = table.get("sp") or state["session"].get("sp")
    expected = session_open_for(state, sp, write_required=True) and session_has_admin_authority(state, sp)
    return expected_status_result(
        event,
        "success" if expected else "auth_error",
        "Table-level Set on a learned dynamic object table requires an authorized read-write session in the table's SP.",
        rule_key="set",
        policy_source="dynamic_table_state",
    )


def invalid_set_where_parameter(state, event):
    if event.get("method") != "Set":
        return False
    has_where = parameter_present(event, ("Where",))
    if is_byte_table_event(state, event):
        return False
    if table_level_invocation(event) or dynamic_table_record(state, event) is not None:
        return not has_where
    return has_where


def invalid_set_where_type(state, event):
    if event.get("method") != "Set":
        return False
    raw = parameter_value(event, ("Where",))
    if raw is None:
        return False
    if is_byte_table_event(state, event):
        # Byte-table Set Where must be a Row/offset integer, not a UID object reference.
        # If the raw Where dict contains a "uid" key it is an object reference, not a row address.
        if isinstance(raw, dict) and any(k.lower() == "uid" for k in raw):
            return True
        row = to_int(row_parameter_value(raw))
        return row is None or row < 0
    if table_level_invocation(event) or dynamic_table_record(state, event) is not None:
        uid = compact_uid(uid_parameter_value(raw))
        return uid is None or len(uid) != 16
    return False


def invalid_get_free_target(state, event):
    method = event.get("method")
    if method == "GetFreeRows":
        return not table_level_invocation(event) and dynamic_table_record(state, event) is None
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


def invalid_set_values_shape(state, event):
    if event.get("method") != "Set":
        return False
    raw_values = parameter_value(event, ("Values",))
    if raw_values is None:
        return False
    is_byte_table = is_byte_table_event(state, event)
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
    has_hint_size = parameter_present(event, ("HintSize",))
    # spec core/5.3.4.2.1: byte tables use no row-count parameters (MaxSize, HintSize) and
    # no typed column list. These are object-table-only parameters.
    if kind == "byte":
        return has_max_size or has_hint_size or columns not in ([], (), None)
    if kind == "object":
        if columns is None or columns == [] or columns == ():
            return True
        if not isinstance(columns, (list, dict)):
            return True
        if isinstance(columns, list) and not all(isinstance(item, dict) and bool(item) for item in columns):
            return True
    min_size = to_int(parameter_value(event, ("MinSize",)))
    max_size = to_int(parameter_value(event, ("MaxSize",)))
    hint_size = to_int(parameter_value(event, ("HintSize",)))
    if min_size is not None:
        if max_size is not None and max_size < min_size:
            return True
        if hint_size is not None and hint_size < min_size:
            return True
    return False


def invalid_issue_sp_parameters(event):
    if event.get("method") != "IssueSP":
        return False
    admin_template_uid = "0000020400000002"
    size = to_int(parameter_value(event, ("Size",)))
    if size is not None and size <= 0:
        return True
    templates = parameter_value(event, ("Templates",))
    if templates is not None and (not isinstance(templates, list) or not templates):
        return True
    if isinstance(templates, list):
        for template in templates:
            uid = compact_uid(uid_parameter_value(template))
            if uid is None or len(uid) != 16:
                return True
            if uid == admin_template_uid:
                return True
            name = find_named_value(template, {"Name", "TemplateName", "CommonName"})
            if name is not None and normalized_policy_text(name) == "admin":
                return True
    return False


def issue_sp_template_limit_violation(state, event):
    templates = parameter_value(event, ("Templates",))
    if not isinstance(templates, list):
        return None
    requested = {compact_uid(uid_parameter_value(template)) for template in templates}
    requested.discard(None)
    for key, row in (state.get("tables") or {}).items():
        values = row.get("values") or {}
        table_uid = compact_uid(key)
        template_uid = compact_uid(values.get("UID")) or table_uid
        if template_uid not in requested:
            continue
        instances = to_int(values.get("Instances") or (row.get("columns") or {}).get(3))
        max_instances = to_int(values.get("MaxInstances") or (row.get("columns") or {}).get(4))
        if instances is not None and max_instances is not None and instances >= max_instances:
            name = values.get("Name") or row.get("name") or template_uid
            return name, instances, max_instances
    return None


def issue_sp_template_inventory_violation(state, event):
    templates = parameter_value(event, ("Templates",))
    if not isinstance(templates, list):
        return None
    inventory = state.get("template_inventory") or {}
    if not inventory.get("complete"):
        return None
    available = set(inventory.get("available") or set())
    requested = [compact_uid(uid_parameter_value(template)) for template in templates]
    missing = [uid for uid in requested if uid and uid not in available]
    return missing or None


def invalid_meta_acl_parameters(event):
    if event.get("method") not in {"GetACL", "AddACE", "RemoveACE", "DeleteMethod"}:
        return False
    names = ("InvokingID", "MethodID") + (("ACE",) if event.get("method") in {"AddACE", "RemoveACE"} else ())
    for name in names:
        uid = compact_uid(uid_parameter_value(parameter_value(event, (name,))))
        if uid is None or len(uid) != 16:
            return True
    return False


def deleted_dynamic_object_result(state, event):
    method = event.get("method")
    uid = compact_uid(event.get("object_uid"))
    deleted_tables = state.get("deleted_dynamic_tables") or set()
    deleted_rows = state.get("deleted_dynamic_rows") or set()
    if uid in deleted_tables:
        return expected_status_result(
            event,
            "error",
            f"{method} targets deleted dynamic table UID {uid}.",
            rule_key="delete",
            policy_source="dynamic_table_state",
        )
    if uid in deleted_rows:
        return expected_status_result(
            event,
            "error",
            f"{method} targets deleted dynamic row UID {uid}.",
            rule_key="delete",
            policy_source="dynamic_table_state",
        )
    if method in {"GetACL", "AddACE", "RemoveACE", "DeleteMethod"}:
        invoking_uid, _method_name = meta_acl_parameter_target(event)
        if invoking_uid in deleted_tables or invoking_uid in deleted_rows:
            return expected_status_result(
                event,
                "error",
                f"{method} targets AccessControl for deleted dynamic UID {invoking_uid}.",
                rule_key="meta_acl",
                policy_source="dynamic_table_state",
            )
    return None


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
    if tracked_sp is not None and sp_session_id is not None and sp_session_id != tracked_sp:
        return True
    return False


def disabled_sp_reenable_set(event):
    if event.get("method") != "Set" or event.get("object_family") != "SPInfo":
        return False
    columns = event.get("value_columns") or {}
    return 6 in columns and to_bool(columns.get(6)) is True


def disabled_sp_method_preflight(state, event):
    method = event.get("method")
    session_sp = state["session"].get("sp")
    if not session_sp:
        return None
    lifecycle = (state.get("sp_lifecycle") or {}).get(session_sp, "")
    if "Disabled" not in lifecycle:
        return None
    if method in _SESSION_MANAGER_METHODS or method in {"Authenticate", "DeleteSP"}:
        return None
    if disabled_sp_reenable_set(event):
        return None
    rule_key = (METHOD_FAILURE_MATRIX.get(method) or {}).get("rule_key") or "fallback"
    return expected_exact_method_status_result(
        event,
        "sp_disabled",
        f"{method} invoked in disabled {session_sp} session must fail unless it directly re-enables the SP, authenticates, or deletes the SP (core/4.5.2, core/5.3.5.1).",
        rule_key=rule_key,
    )


def method_preflight(state, event):
    method = event.get("method")
    if method not in METHOD_NAMES:
        return expected_status_result(event, "invalid_parameter", f"{method or 'Unknown'} is not a supported modeled method.", rule_key="fallback", coverage_status="partial")
    rule = METHOD_FAILURE_MATRIX.get(method, {})
    rule_key = rule.get("rule_key")

    identity_result = incompatible_object_identity_result(event)
    if identity_result is not None:
        return identity_result

    singleton_result = invalid_singleton_object_row_result(event)
    if singleton_result is not None:
        return singleton_result

    deleted_dynamic_result = deleted_dynamic_object_result(state, event)
    if deleted_dynamic_result is not None:
        return deleted_dynamic_result

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
    if invalid_uinteger_parameter(event, ("HostSessionID", "SPSessionID", "SessionTimeout", "TransTimeout", "InitialCredit", "RemoteSessionNumber", "LocalSessionNumber", "MinSize", "MaxSize", "HintSize", "Size", "AdminExch")):
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
    if invalid_boolean_parameter(event, ("Write", "KeepGlobalRangeKey", "DeletePattern", "Enabled")):
        return expected_status_result(
            event,
            "invalid_parameter",
            f"{method} includes a malformed boolean parameter.",
            rule_key=rule_key,
        )
    if invalid_tperinfo_programmatic_reset_value(event):
        return expected_status_result(
            event,
            "invalid_parameter",
            "TPerInfo ProgrammaticResetEnable must be a boolean value (opal/4.2.3.1).",
            rule_key="set",
            coverage_status="implemented",
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
    if invalid_set_where_parameter(state, event):
        return expected_status_result(
            event,
            "invalid_parameter",
            "Set Where parameter does not match object-vs-table invocation requirements.",
            rule_key="set",
        )
    if invalid_set_where_type(state, event):
        return expected_status_result(
            event,
            "invalid_parameter",
            "Set Where parameter has the wrong row/UID type for the target table kind.",
            rule_key="set",
        )
    if invalid_get_free_target(state, event):
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
            "CreateTable parameters are inconsistent with the requested table kind or size bounds.",
            rule_key="create_table",
        )
    if invalid_issue_sp_parameters(event):
        return expected_status_result(
            event,
            "invalid_parameter",
            "IssueSP parameters are inconsistent with the required SPName/Size/Templates/AdminExch/Enabled shape.",
            rule_key="issue_sp",
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
        dynamic_context = dynamic_row_context(state, event)
        if dynamic_context is None or not dynamic_get_requested_columns(event, dynamic_context["table"]):
            return expected_status_result(event, "invalid_parameter", "Get Cellblock requests invalid columns.", rule_key="get")
    if method == "Set":
        raw_values = parameter_value(event, ("Values",))
        if raw_values == "":
            return expected_status_result(event, "invalid_parameter", "Set Values parameter is malformed.", rule_key="set")
        if invalid_set_values_shape(state, event):
            return expected_status_result(
                event,
                "error",
                "Set Values shape must match byte-table Bytes versus object-table RowValues.",
                rule_key="set",
            )
        dynamic_context = dynamic_row_context(state, event) or dynamic_table_set_context(state, event)
        dynamic_error = dynamic_set_columns_error(state, event)
        if dynamic_error is not None:
            return expected_status_result(event, "invalid_parameter", f"Set Values contain {dynamic_error}.", rule_key="set")
        if invalid_set_columns(event) and dynamic_context is None:
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

    disabled_preflight = disabled_sp_method_preflight(state, event)
    if disabled_preflight is not None:
        return disabled_preflight

    return None


def create_table_name_conflict(state, event, target_sp):
    new_name = parameter_value(event, ("NewTableName",))
    if new_name is None:
        return False
    new_common = parameter_value(event, ("CommonName",))
    new_name_norm = normalized_policy_text(new_name)
    new_common_norm = normalized_policy_text(new_common or "")
    for (sp, existing_name, existing_common), _uid in (state.get("dynamic_table_names") or {}).items():
        if target_sp and sp and sp != target_sp:
            continue
        if (
            normalized_policy_text(existing_name) == new_name_norm
            and normalized_policy_text(existing_common or "") == new_common_norm
        ):
            return True
    for row in (state.get("tables") or {}).values():
        title = str(row.get("table") or "")
        if "Table Table Preconfiguration" not in title:
            continue
        if target_sp and not _source_matches_sp(row.get("source"), target_sp):
            continue
        values = row.get("values") or {}
        existing_name = values.get("Name") if isinstance(values, dict) else None
        if existing_name is None:
            existing_name = row.get("name")
        existing_common = values.get("CommonName") if isinstance(values, dict) else None
        if (
            normalized_policy_text(existing_name) == new_name_norm
            and normalized_policy_text(existing_common or "") == new_common_norm
        ):
            return True
    return False


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

    # spec core/5.2.3.2.1: echoed HostSessionID must match what the host sent.
    input_host_id = to_int(parameter_value(event, ("HostSessionID",)))
    if input_host_id is not None and host_id_int is not None and host_id_int != input_host_id:
        return fail_result(
            f"StartSession SyncSession echoed HostSessionID={host_id_int} but host sent {input_host_id}; "
            "the TPer must echo the host's HostSessionID unmodified (spec core/5.2.3.2.1).",
            confidence=0.90,
            expected_status="success_with_session_ids",
            actual_status="success_wrong_host_id",
            spec_refs=("core/5.2.3.2.1",),
            policy_source="SyncSession",
        )

    requested_trans_timeout = to_int(parameter_value(event, ("TransTimeout",)))
    returned_trans_timeout = to_int(find_named_value(return_values, {"TransTimeout", "transtimeout"}))
    if (
        requested_trans_timeout is not None
        and returned_trans_timeout is not None
        and returned_trans_timeout < requested_trans_timeout
    ):
        return fail_result(
            f"StartSession SyncSession returned TransTimeout={returned_trans_timeout}, below the "
            f"requested StartSession TransTimeout={requested_trans_timeout} (core/5.2.3.2.1).",
            confidence=0.90,
            expected_status="success_with_valid_trans_timeout",
            actual_status="success_low_trans_timeout",
            spec_refs=("core/5.2.3.2.1",),
            policy_source="SyncSession",
        )

    return None


def sync_session_trans_timeout_violation(state, event):
    if actual_status_class(event) != "success":
        return None
    requested = (state.get("session") or {}).get("trans_timeout")
    raw_record = event.get("raw") or {}
    return_values = ((raw_record.get("output") or {}).get("return_values"))
    returned = to_int(find_named_value(return_values, {"TransTimeout", "transtimeout"}))
    properties = state.get("properties") or {}
    min_trans = properties.get("MinTransTimeout")
    max_trans = properties.get("MaxTransTimeout")
    if requested is not None and returned is not None and returned < requested:
        return fail_result(
            f"SyncSession returned TransTimeout={returned}, below the StartSession TransTimeout={requested} "
            "(core/5.2.3.2.1).",
            confidence=0.90,
            expected_status="success_with_valid_trans_timeout",
            actual_status="success_low_trans_timeout",
            spec_refs=("core/5.2.3.2.1",),
            policy_source="SyncSession",
        )
    if returned is not None and min_trans is not None and returned < min_trans:
        return fail_result(
            f"SyncSession returned TransTimeout={returned}, below MinTransTimeout={min_trans} "
            "(core/5.2.3.2.6, core/3.3.9.4).",
            confidence=0.90,
            expected_status="success_with_valid_trans_timeout",
            actual_status="success_low_trans_timeout",
            spec_refs=("core/5.2.3.2.6", "core/3.3.9.4"),
            policy_source="SyncSession",
        )
    if returned is not None and max_trans not in (None, 0) and returned > max_trans:
        return fail_result(
            f"SyncSession returned TransTimeout={returned}, above MaxTransTimeout={max_trans} "
            "(core/5.2.3.2.6, core/3.3.9.4).",
            confidence=0.90,
            expected_status="success_with_valid_trans_timeout",
            actual_status="success_high_trans_timeout",
            spec_refs=("core/5.2.3.2.6", "core/3.3.9.4"),
            policy_source="SyncSession",
        )
    return None


def start_session_timeout_bounds_violation(state, event):
    properties = state.get("properties") or {}
    session_timeout = to_int(parameter_value(event, ("SessionTimeout",)))
    trans_timeout = to_int(parameter_value(event, ("TransTimeout",)))
    sp = event.get("sp")

    if session_timeout is not None:
        min_session = properties.get("MinSessionTimeout")
        max_session = properties.get("MaxSessionTimeout")
        sp_session = (state.get("sp_session_timeouts") or {}).get(sp)
        if min_session is not None and session_timeout < min_session:
            return (
                "invalid_parameter",
                f"StartSession SessionTimeout={session_timeout} is below MinSessionTimeout={min_session}.",
            )
        if max_session not in (None, 0) and session_timeout > max_session:
            return (
                "invalid_parameter",
                f"StartSession SessionTimeout={session_timeout} exceeds MaxSessionTimeout={max_session}.",
            )
        if sp_session not in (None, 0) and session_timeout > sp_session:
            return (
                "invalid_parameter",
                f"StartSession SessionTimeout={session_timeout} exceeds {sp} SPInfo.SPSessionTimeout={sp_session}.",
            )

    if trans_timeout is not None:
        min_trans = properties.get("MinTransTimeout")
        max_trans = properties.get("MaxTransTimeout")
        if min_trans is not None and trans_timeout < min_trans:
            return (
                "invalid_parameter",
                f"StartSession TransTimeout={trans_timeout} is below MinTransTimeout={min_trans}.",
            )
        if max_trans not in (None, 0) and trans_timeout > max_trans:
            return (
                "invalid_parameter",
                f"StartSession TransTimeout={trans_timeout} exceeds MaxTransTimeout={max_trans}.",
            )
    return None


def judge_start_session(state, event):
    sp = event.get("sp")
    authority = event.get("authority")

    if sp is None:
        return expected_status_result(event, "invalid_parameter", "StartSession without an SPID is malformed.", rule_key="start_session")

    timeout_violation = start_session_timeout_bounds_violation(state, event)
    if timeout_violation is not None:
        expected_status, reason = timeout_violation
        return expected_status_result(
            event,
            expected_status,
            reason + " Out-of-limit StartSession timeout parameters must fail (core/5.2.3.1.9, core/5.2.3.1.10, opal/4.1.1.2).",
            rule_key="start_session",
        )

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
        return expected_exact_method_status_result(
            event,
            "sp_disabled",
            f"StartSession to {sp} must fail: SP lifecycle is {_sp_lifecycle} (spec core/4.3.6).",
            rule_key="start_session",
        )
    if "Frozen" in _sp_lifecycle:
        return expected_exact_method_status_result(
            event,
            "sp_frozen",
            f"StartSession to {sp} must fail: SP lifecycle is {_sp_lifecycle} (spec core/4.3.7).",
            rule_key="start_session",
        )
    if "Failed" in _sp_lifecycle:
        return expected_exact_method_status_result(
            event,
            "sp_failed",
            f"StartSession to {sp} must fail: SP lifecycle is {_sp_lifecycle} (spec core/4.5.5).",
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

    # SP-scoping: if all matching authority records have SP-discriminating sources and none match
    # the target SP, this authority does not exist in the target SP (opal/4.2.1.7, opal/4.3.1.8).
    if sp and authority:
        _sp_sourced = [r for r in authority_records_for(state, authority) if r.get("source")]
        if _sp_sourced and not any(authority_record_matches_sp(r, sp) for r in _sp_sourced):
            return expected_status_result(
                event,
                "auth_error",
                f"StartSession authority {authority} is not valid in {sp}; it is defined in a different SP only (opal/4.2.1.7, opal/4.3.1.8).",
                rule_key="start_session",
                coverage_status="implemented",
            )

    match = credential_matches(state, authority, event.get("challenge"))
    if match is True:
        if actual_status_class(event) == "success":
            id_check = _check_sync_session_ids(event)
            if id_check is not None:
                return id_check
        expected = {"success", "auth_error"} if event.get("write") is False else "success"
        return expected_status_result(
            event,
            expected,
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
            if actual_status_class(event) == "success":
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

    if actual_status_class(event) == "success":
        id_check = _check_sync_session_ids(event)
        if id_check is not None:
            return id_check
    expected = {"success", "auth_error"} if event.get("write") is False else "success"
    return expected_status_result(event, expected, "Unauthenticated StartSession should succeed when the SP is available.", rule_key="start_session")


def judge_authenticate(state, event):
    authority = event.get("authority")
    if not state["session"].get("open"):
        return expected_status_result(event, "error", "Authenticate requires an open session.", rule_key="authenticate")
    if not authority:
        return expected_status_result(event, "invalid_parameter", "Authenticate without an Authority is malformed.", rule_key="authenticate")
    missing_result = authenticate_success_missing_result(event)
    if missing_result is not None:
        return missing_result
    if authority_is_class(state, authority):
        if (state["session"].get("pending_auth_challenge") or {}).get("authority"):
            return success_false_result(
                event,
                f"Authenticate response targeted class authority {authority}; pending challenge-response authentication must resolve as SUCCESS False (core/5.3.4.1.14.1).",
                policy_source="Authority.IsClass",
            )
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
        actual = actual_status_class(event)
        auth_result = event.get("auth_result")
        refs = spec_refs_for("authenticate")

        if is_authority_locked_out(state, authority):
            reason = (
                f"Authority {authority} is locked out during challenge-response authentication; "
                "TPer may return AUTHORITY_LOCKED_OUT or SUCCESS with result=False "
                "(core/5.3.4.1.14.1, core/5.1.5.15)."
            )
            if actual == "auth_error" or (actual == "success" and auth_result is False):
                return pass_result(reason, expected_status="auth_error_or_success_false", actual_status=actual, spec_refs=refs, policy_source="C_PIN.TryLimit")
            return fail_result(reason, expected_status="auth_error_or_success_false", actual_status=actual, spec_refs=refs, policy_source="C_PIN.TryLimit")

        if not authority_enabled(state, authority):
            return success_false_result(
                event,
                f"Authenticate authority {authority} is disabled; challenge-response authentication must return SUCCESS False.",
                policy_source="Authority.Enabled",
            )

        if authority_requires_secure_messaging(state, authority) and not state["session"].get("trusted"):
            return success_false_result(
                event,
                f"Authenticate authority {authority} requires secure messaging; challenge-response authentication must return SUCCESS False.",
                policy_source="Authority.Secure",
            )

        _session_sp = state["session"].get("sp")
        if _session_sp and authority:
            _auth_sourced = [r for r in authority_records_for(state, authority) if policy_scope_from_source(r.get("source"))]
            if _auth_sourced and not any(authority_record_matches_sp(r, _session_sp) for r in _auth_sourced):
                return success_false_result(
                    event,
                    f"Authenticate authority {authority} is not valid in {_session_sp}; challenge-response authentication must return SUCCESS False.",
                )

        pending = state["session"].get("pending_auth_challenge") or {}
        proof_supplied = parameter_present(event, ("Proof", "HostChallenge", "Challenge"))
        if pending:
            if authority != pending.get("authority"):
                return success_false_result(
                    event,
                    f"Authenticate response authority {authority} does not match pending challenge authority {pending.get('authority')}; result must be False.",
                )
            if not proof_supplied:
                return success_false_result(
                    event,
                    "Second Authenticate invocation for challenge-response lacks a Proof/Challenge response; result must be False.",
                )
            limit_result = max_authentications_limit_result(state, event)
            if limit_result is not None:
                return limit_result
            if actual == "success" and auth_result in {True, False}:
                return pass_result(
                    f"Authenticate on {_auth_operation} authority resolved pending challenge-response with a boolean result.",
                    expected_status="success_bool",
                    actual_status=actual,
                    spec_refs=refs,
                )
            return fail_result(
                f"Authenticate on {_auth_operation} authority must resolve the pending challenge with SUCCESS and result True/False.",
                expected_status="success_bool",
                actual_status=actual,
                spec_refs=refs,
            )

        if proof_supplied:
            limit_result = max_authentications_limit_result(state, event)
            if limit_result is not None:
                return limit_result
            if actual == "success" and auth_result in {True, False}:
                return pass_result(
                    f"Authenticate on {_auth_operation} authority supplied a proof without a visible pending challenge; accept as an externally-started response step with boolean result.",
                    expected_status="success_bool",
                    actual_status=actual,
                    spec_refs=refs,
                    coverage_status="partial",
                )
            return fail_result(
                f"Authenticate on {_auth_operation} authority with Proof must return SUCCESS with result True/False when no pending challenge is visible.",
                expected_status="success_bool",
                actual_status=actual,
                spec_refs=refs,
                coverage_status="partial",
            )

        challenge = challenge_response_value(event)
        if actual == "success" and challenge is not None:
            if _auth_operation == "SymK":
                challenge_len = byte_length(challenge)
                if challenge_len is not None and challenge_len != 32:
                    return fail_result(
                        "Authenticate on SymK authority must return a 32-byte nonce challenge on the first invocation.",
                        expected_status="success_challenge_32",
                        actual_status=actual,
                        spec_refs=refs,
                    )
            return pass_result(
                f"Authenticate on {_auth_operation} authority started challenge-response and returned a challenge.",
                expected_status="success_challenge",
                actual_status=actual,
                spec_refs=refs,
            )
        return fail_result(
            f"Authenticate on {_auth_operation} authority first invocation must return SUCCESS with a challenge.",
            expected_status="success_challenge",
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

    # SP-scoping: if all matching authority records have SP-discriminating sources and none match
    # the current session SP, this authority does not exist in this SP.
    # Per Core/5.3.4.1.14.1: Authenticate on a non-existent authority returns SUCCESS with result=False.
    _session_sp = state["session"].get("sp")
    if _session_sp and authority:
        _auth_sourced = [r for r in authority_records_for(state, authority) if r.get("source")]
        if _auth_sourced and not any(authority_record_matches_sp(r, _session_sp) for r in _auth_sourced):
            actual = actual_status_class(event)
            auth_result_sp = event.get("auth_result")
            _sp_reason = (
                f"Authenticate authority {authority} is not valid in {_session_sp}; "
                f"TPer must return SUCCESS with result=False (core/5.3.4.1.14.1, opal/4.2, opal/4.3.1)."
            )
            _sp_refs = spec_refs_for("authenticate")
            if actual == "success" and auth_result_sp is False:
                return pass_result(_sp_reason, expected_status="success_false", actual_status=actual, spec_refs=_sp_refs)
            return fail_result(_sp_reason, expected_status="success_false", actual_status=actual, spec_refs=_sp_refs)

    limit_result = max_authentications_limit_result(state, event)
    if limit_result is not None:
        return limit_result

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

    dynamic_table_result = dynamic_table_get_result(state, event)
    if dynamic_table_result is not None:
        return dynamic_table_result

    dynamic_result = dynamic_get_result(state, event)
    if dynamic_result is not None:
        return dynamic_result

    if invalid_cellblock(event):
        return expected_status_result(event, "invalid_parameter", "Get Cellblock requests invalid columns.", rule_key="get")

    if obj == "C_PIN_MSID":
        expected = session_open_for(state, "AdminSP")
        result = expected_status_result(
            event,
            "success" if expected else "auth_error",
            "C_PIN_MSID Get requires an open AdminSP session.",
            rule_key="cpin",
        )
        if result.verdict == "pass" and actual_status_class(event) == "success":
            requested = requested_get_columns(event)
            missing = missing_success_get_columns_result(event, requested, "cpin", "opal/4.2.1.8", "C_PIN_MSID")
            if missing is not None:
                return missing
            returned = event.get("return_columns") or {}
            known_msid = (state.get("credentials") or {}).get("MSID")
            if known_msid is not None and 3 in returned:
                mismatch = mismatched_success_get_value_result(
                    event, 3, returned[3], known_msid, "cpin", "opal/4.2.1.8", "C_PIN_MSID"
                )
                if mismatch is not None:
                    return mismatch
        return result

    target_sp = object_sp(event)
    if target_sp == "LockingSP" and not state.get("locking_sp_active"):
        return expected_status_result(event, "error", f"{obj} Get requires an active LockingSP.", rule_key="locking_table")

    size_violation = byte_table_reported_size_violation(event)
    if size_violation is not None:
        table_name, reported_size, minimum_size, spec_ref = size_violation
        return fail_result(
            f"{table_name} Table row reported size {reported_size} bytes, below the required minimum "
            f"{minimum_size} bytes ({spec_ref}).",
            expected_status="success_with_minimum_size",
            actual_status=actual_status_class(event),
            spec_refs=(spec_ref,),
            policy_source="table_schema",
            coverage_status="implemented",
        )

    object_uid = compact_uid(event.get("object_uid"))
    if object_uid and object_uid.startswith("00000001"):
        consistency = table_capacity_consistency_result(
            event,
            f"Get on table UID {object_uid}",
            "table_capacity_result",
        )
        if consistency is not None:
            return consistency

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
    # Byte-tables, write-only-column families (MediaKey), and C_PIN are NOT in the omit set:
    #   - MBR, DataStore: byte tables → empty result, not cell omission
    #   - MediaKey: key material (col 3) is write-only; auth_error keeps that leak-free
    #   - C_PIN: PIN (col 3) is NOPIN; handled separately with explicit auth_error for PIN requests
    #   - Locking/MBRControl/LockingInfo/MBR: handled by their own specific branches below
    _CELL_OMIT_FAMILIES = frozenset({
        "Authority", "ACE", "AccessControl", "SecretProtect",
        "SP", "MethodID", "Column",
        "ClockTime", "TPerInfo", "DataRemovalMechanism",
        "Log", "LogList",
    })
    is_byte_table = family in {"MBR", "DataStore"}

    # SP Get: validate returned LifeCycleState (col 6) against tracked state before the policy path,
    # so content consistency is checked regardless of whether an AccessControl row was matched.
    if family == "SP":
        sp_return_cols = event.get("return_columns") or {}
        int_sp_return_cols = {int(k): v for k, v in sp_return_cols.items()} if sp_return_cols else {}
        tracked_lc = (state.get("sp_lifecycle") or {}).get(obj)
        if tracked_lc is not None and 6 in requested_get_columns(event):
            missing = missing_success_get_columns_result(event, {6}, "get", "core/5.4.2.4.7", f"SP {obj}")
            if missing is not None:
                return missing
        if 6 in int_sp_return_cols:
            returned_lc = int_sp_return_cols[6]
            if tracked_lc in ("Manufactured", "Manufactured-Inactive"):
                # Map returned value to canonical string form.
                if isinstance(returned_lc, int):
                    canonical = {8: "Manufactured-Inactive", 9: "Manufactured"}.get(returned_lc)
                else:
                    s = str(returned_lc).lower().replace("-", "").replace("_", "").replace(" ", "")
                    canonical = (
                        "Manufactured-Inactive" if "inactive" in s else
                        "Manufactured" if s == "manufactured" else
                        None
                    )
                if canonical is not None and canonical != tracked_lc:
                    return RuleResult(
                        verdict="fail",
                        confidence=0.90,
                        reason=(
                            f"SP table Get for {obj} returned LifeCycleState={returned_lc!r} "
                            f"({canonical}) but tracked state is {tracked_lc!r} "
                            f"(core/5.4.2.4.7: LifeCycleState must reflect current SP lifecycle)."
                        ),
                        expected_status=None,
                        actual_status=event.get("status"),
                        spec_refs=("core/5.4.2.4.7", "opal/5.2.2.2"),
                        policy_source="rule",
                        coverage_status="implemented",
                    )

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
        requested = requested_get_columns(event)
        missing = missing_success_get_columns_result(event, requested, "locking_table", "core/5.3.3.6.2", f"Locking {range_name}")
        if missing is not None and (public or is_admin):
            return missing
        _LOCKING_COL_FIELDS = {
            3: ("range_start", "int"),
            4: ("range_length", "int"),
            5: ("read_lock_enabled", "bool"),
            6: ("write_lock_enabled", "bool"),
            7: ("read_locked", "bool"),
            8: ("write_locked", "bool"),
        }
        tracked = (state.get("locking_ranges") or {}).get(range_name) if range_name else None
        if tracked:
            for col_num, (field, kind) in _LOCKING_COL_FIELDS.items():
                if col_num not in int_return_cols:
                    continue
                expected_val = tracked.get(field, False)
                mismatch = mismatched_success_get_value_result(
                    event,
                    col_num,
                    int_return_cols[col_num],
                    expected_val,
                    "locking_table",
                    "opal/4.3.5.2",
                    f"Locking {range_name}",
                    kind=kind,
                )
                if mismatch is not None:
                    return mismatch

    if family == "MBRControl":
        expected = session_open_for(state, "LockingSP")  # ACE_Anybody per opal/4.3.1.6
        result = expected_status_result(
            event,
            "success" if expected else "auth_error",
            "MBRControl Get requires an open LockingSP session (ACE_Anybody).",
            rule_key="mbr_control",
        )
        if result.verdict == "pass" and actual_status_class(event) == "success":
            requested = requested_get_columns(event)
            missing = missing_success_get_columns_result(event, requested, "mbr_control", "opal/4.3.5.3", "MBRControl")
            if missing is not None:
                return missing
            returned = event.get("return_columns") or {}
            mbr = state.get("mbr") or {}
            for column, field in ((1, "enable"), (2, "done")):
                if column not in returned:
                    continue
                mismatch = mismatched_success_get_value_result(
                    event,
                    column,
                    returned[column],
                    bool(mbr.get(field, False)),
                    "mbr_control",
                    "opal/4.3.5.3",
                    "MBRControl",
                    kind="bool",
                )
                if mismatch is not None:
                    return mismatch
        return result

    if family == "Authority":
        target = target_sp or state["session"].get("sp")
        authorized = session_open_for(state, target) and session_has_admin_authority(state, target)
        if authorized and actual_status_class(event) == "success":
            requested = requested_get_columns(event)
            tracked_rows = authority_records_for(state, obj, sp=target)
            if tracked_rows and 5 in requested:
                missing = missing_success_get_columns_result(event, {5}, "authority", "core/5.3.2.10.6", f"Authority {obj}")
                if missing is not None:
                    return missing
                returned = event.get("return_columns") or {}
                if 5 in returned and "enabled" in tracked_rows[0]:
                    mismatch = mismatched_success_get_value_result(
                        event,
                        5,
                        returned[5],
                        bool(tracked_rows[0].get("enabled")),
                        "authority",
                        "core/5.3.2.10.6",
                        f"Authority {obj}",
                        kind="bool",
                    )
                    if mismatch is not None:
                        return mismatch

    if family == "LockingInfo":
        expected = session_open_for(state, "LockingSP")
        result = expected_status_result(
            event,
            "success" if expected else "auth_error",
            "LockingInfo Get requires an open LockingSP session; documented geometry columns are public within that SP.",
            rule_key="locking_info",
        )
        if result.verdict == "pass" and actual_status_class(event) == "success":
            requested = requested_get_columns(event)
            if 4 in requested:
                missing = missing_success_get_columns_result(event, {4}, "locking_info", "opal/4.3.5.1", "LockingInfo")
                if missing is not None:
                    return missing
                returned = event.get("return_columns") or {}
                if 4 in returned:
                    max_ranges = to_int(returned[4])
                    if max_ranges is not None and max_ranges < 8:
                        return fail_result(
                            f"LockingInfo MaxRanges={max_ranges} is below the Opal minimum of 8 ranges (opal/4.3.5.1 Table 44 note 1).",
                            expected_status="success_with_minimum_maxranges",
                            actual_status="success",
                            spec_refs=spec_refs_for("locking_info"),
                            policy_source="table_schema",
                        )
        return result

    if family == "AccessControl":
        target = target_sp or state["session"].get("sp")
        authorized = session_open_for(state, target) and session_has_admin_authority(state, target)
        if authorized and 3 in requested_get_columns(event):
            missing = missing_success_get_columns_result(event, {3}, "access_control", "core/5.3.2.7", "AccessControl")
            if missing is not None:
                return missing

    if family == "C_PIN" and obj != "C_PIN_MSID":
        target = target_sp or state["session"].get("sp")
        authorized = session_open_for(state, target) and session_has_admin_authority(state, target)
        requested = requested_get_columns(event)
        readable_requested = requested - write_only_columns_for_family("C_PIN")
        if authorized and readable_requested:
            missing = missing_success_get_columns_result(event, readable_requested, "cpin", "core/5.3.3.6.2", f"{obj} C_PIN")
            if missing is not None:
                return missing

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
        result = expected_status_result(
            event,
            "success" if expected else "auth_error",
            "C_PIN credential Get is protected by the C_PIN/ACE access-control tables.",
            rule_key="cpin",
        )
        if result.verdict == "pass" and actual_status_class(event) == "success":
            requested = requested_get_columns(event)
            if requested:
                missing = missing_success_get_columns_result(event, requested, "cpin", "core/5.3.3.6.2", f"{obj} C_PIN")
                if missing is not None:
                    return missing
        return result

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

    _final_sp = target_sp or state["session"].get("sp")
    _session_ok = session_open_for(state, _final_sp)
    return expected_status_result(
        event,
        "success" if _session_ok else "auth_error",
        "Get on discovery/metadata object requires an open session in the target SP.",
        rule_key="get",
    )


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

    dynamic_result = dynamic_set_result(state, event)
    if dynamic_result is not None:
        return dynamic_result

    dynamic_table_result = dynamic_table_set_result(state, event)
    if dynamic_table_result is not None:
        return dynamic_table_result

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
            "Locking RangeStart/RangeLength update violates alignment, overlaps another configured range, or is negative.",
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

    # spec core/3.4.1.1: AdminSP SHALL NOT be disabled or frozen.
    # Reject Set on AdminSP's SP-table row that sets Enabled (col 6) to False or Frozen (col 7) to True.
    if event.get("object") == "AdminSP" and event.get("object_family") == "SP":
        value_cols = event.get("value_columns") or {}
        if 6 in value_cols and to_bool(value_cols[6]) is False:
            return expected_status_result(
                event, "invalid_parameter",
                "AdminSP cannot be disabled (Enabled=False); core/3.4.1.1 forbids disabling AdminSP.",
                rule_key="set",
            )
        if 7 in value_cols and to_bool(value_cols[7]) is True:
            return expected_status_result(
                event, "invalid_parameter",
                "AdminSP cannot be frozen (Frozen=True); core/3.4.1.1 forbids freezing AdminSP.",
                rule_key="set",
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
        if authenticated_locking_admin_write(state):
            # spec opal/4.3.5.2.2: LockOnReset column (9) has restricted supported values.
            # Mandatory: {0}, {0,3}. Optional: {0,1}, {0,1,3}. Others: INVALID_PARAMETER.
            value_cols = event.get("value_columns") or {}
            if 9 in value_cols:
                lor_result = validate_lock_on_reset_value(value_cols[9])
                if lor_result is not None:
                    return expected_status_result(
                        event, lor_result,
                        f"Locking LockOnReset value must be {{0}}, {{0,3}} (mandatory), "
                        f"{{0,1}}, or {{0,1,3}} (optional per opal/4.3.5.2.2).",
                        rule_key="locking_table",
                    )
            return expected_status_result(
                event, "success",
                f"{obj} Set requires an authenticated Admin LockingSP write session (opal/4.3.1.7).",
                rule_key="access_control",
            )
        return expected_status_result(
            event, "auth_error",
            f"{obj} Set requires an authenticated Admin LockingSP write session (opal/4.3.1.7).",
            rule_key="access_control",
        )

    if family == "MBRControl":
        # opal/4.3.1.6 + 4.3.1.7: MBRControl Set ACL = ACE_MBRControl_Admins_Set OR ACE_MBRControl_Set_DoneToDOR.
        # Both ACEs have BooleanExpr=Admins (opal/4.3.1.7 Table 39). All columns (Enable=1, Done=2,
        # DoneOnReset=3) require an Admin authority in a LockingSP write session.
        if authenticated_locking_admin_write(state):
            # spec opal/4.3.5.3.1: DoneOnReset column (3) has restricted supported values.
            # Mandatory: {0}, {0,3}. Optional: {0,1}, {0,1,3}. Others: INVALID_PARAMETER.
            value_cols = event.get("value_columns") or {}
            if 3 in value_cols:
                dor_result = validate_lock_on_reset_value(value_cols[3])
                if dor_result is not None:
                    return expected_status_result(
                        event, dor_result,
                        f"MBRControl DoneOnReset value must be {{0}}, {{0,3}} (mandatory), "
                        f"{{0,1}}, or {{0,1,3}} (optional per opal/4.3.5.3.1).",
                        rule_key="mbr_control",
                    )
            return expected_status_result(
                event, "success",
                f"{obj} Set requires authenticated Admin LockingSP write session"
                " (ACE_MBRControl_Admins_Set, BooleanExpr=Admins, opal/4.3.1.7).",
                rule_key="mbr_control",
            )
        return expected_status_result(
            event, "auth_error",
            f"{obj} Set requires authenticated Admin LockingSP write session"
            " (ACE_MBRControl_Admins_Set, BooleanExpr=Admins, opal/4.3.1.7).",
            rule_key="mbr_control",
        )

    if family in {"MBR", "MediaKey", "ACE", "AccessControl", "SecretProtect", "DataStore"}:
        # MBR byte-table Set: Admin-only per ACE_Admin (opal/4.3.1.6 InvokingID=00 00 08 04)
        if family == "ACE" and authenticated_locking_admin_write(state):
            # spec opal/4.3.1.7 *ACE1: ACE_C_PIN_UserMMMM_Set_PIN BooleanExpr must be only
            # "Admins" or "Admins OR UserMMMM". Any other value → INVALID_PARAMETER.
            obj_name = (obj or "").lower()
            if re.search(r"ace_c_pin_user\w+_set_pin", obj_name):
                value_cols = event.get("value_columns") or {}
                if 3 in value_cols:  # column 3 = BooleanExpr
                    raw_expr = value_cols[3]
                    expr_str = re.sub(r"[^a-zA-Z0-9\s_]", "", str(raw_expr or "")).lower().strip()
                    # Accept "admins" alone or "admins or userN" (any user number)
                    is_admins = expr_str in {"admins"}
                    is_admins_or_user = bool(re.match(r"admins\s+or\s+user\w+", expr_str))
                    if not is_admins and not is_admins_or_user:
                        return expected_status_result(
                            event, "invalid_parameter",
                            f"ACE_C_PIN_UserMMMM_Set_PIN BooleanExpr must be 'Admins' or 'Admins OR UserMMMM'; "
                            f"got {raw_expr!r} (opal/4.3.1.7 *ACE1).",
                            rule_key="ace",
                        )
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

    _set_sp = object_sp(event) or state["session"].get("sp")
    expected = (
        state["session"].get("open")
        and state["session"].get("write")
        and session_has_admin_authority(state, _set_sp)
    )
    return expected_status_result(
        event,
        "success" if expected else "auth_error",
        "Protected Set fallback requires an admin-level authenticated write session.",
        rule_key="set",
    )


def judge_activate(state, event):
    if event.get("object") != "LockingSP":
        return expected_status_result(event, "invalid_parameter", "Activate target must be the LockingSP object.", rule_key="activate")

    # spec opal/5.1.1: invocation in any non-inactive lifecycle state shall complete successfully
    # (no-op) if access control is satisfied — not INVALID_PARAMETER
    expected = session_open_for(state, "AdminSP", write_required=True) and session_has_authority(state, "SID")
    if state.get("locking_sp_active"):
        return expected_empty_success_result(
            event,
            "success" if expected else "auth_error",
            "Activate on already-Manufactured LockingSP is a no-op if access control is satisfied (opal/5.1.1).",
            rule_key="activate",
            empty_result_ref="opal/5.1.1.1",
        )

    return expected_empty_success_result(
        event,
        "success" if expected else "auth_error",
        "LockingSP Activate requires an authenticated SID AdminSP write session.",
        rule_key="activate",
        empty_result_ref="opal/5.1.1.1",
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
        pin_length_val = to_int(parameter_value(event, ("PinLength",)))
        if pin_length_val is not None and pin_length_val > 32:
            return expected_status_result(
                event, "invalid_parameter",
                f"GenKey PinLength {pin_length_val} exceeds the maximum of 32 (core/5.3.3.16.2).",
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
        if policy_result.verdict == "pass" and actual_status_class(event) == "success" and unexpected_success_return_values(event):
            return fail_empty_success_result(event, "gen_key", "core/5.3.3.16.3.1")
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
    return expected_empty_success_result(
        event,
        "success" if expected else "auth_error",
        "GenKey requires authenticated Admin1 LockingSP write session.",
        rule_key="gen_key",
        empty_result_ref="core/5.3.3.16.3.1",
    )


def judge_random(state, event):
    count = event.get("count")
    if count is not None and count < 0:
        return expected_status_result(event, "invalid_parameter", "Random Count cannot be negative.", rule_key="random")
    if count is not None and count > 32:
        return expected_status_result(event, "invalid_parameter", "Random Count SHALL NOT exceed 32 (opal/4.2.9.1).", rule_key="random")
    target_sp = object_sp(event) or state["session"].get("sp")
    expected = state["session"].get("open") and (target_sp is None or session_open_for(state, target_sp))
    result = expected_status_result(
        event,
        "success" if expected else "auth_error",
        "Random is a Crypto Template SP method and requires an open session in that SP.",
        rule_key="random",
    )
    if result.verdict == "pass" and actual_status_class(event) == "success" and count is not None:
        output_len = returned_output_byte_length(event, {"Random", "RandomBytes", "Bytes", "Output", "Data", "Result"})
        if output_len is not None and output_len != count:
            return fail_result(
                f"Random Count={count} returned {output_len} byte(s); successful Random must return exactly Count bytes when output bytes are present.",
                expected_status="success_with_count_bytes",
                actual_status="success",
                spec_refs=spec_refs_for("random"),
                policy_source="return_shape",
            )
    return result


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


def credential_like_name(value):
    text = str(value or "").strip()
    normalized = normalized_policy_text(text)
    return normalized.startswith(("cpin", "crsa", "caes", "cec", "chmac"))


def invalid_package_key_parameter(event):
    for name in ("WrappingKey", "SigningKey"):
        if not parameter_present(event, (name,)):
            continue
        raw = parameter_value(event, (name,))
        value = uid_parameter_value(raw)
        text = str(value or "").strip()
        is_uid_text = bool(re.fullmatch(r"(?:0x)?[0-9A-Fa-f\s\-]+", text)) if text else False
        uid = compact_uid(value) if is_uid_text else None
        if uid is not None:
            if len(uid) != 16:
                return True
            continue
        if value is not None and not credential_like_name(value):
            return True
    return False


def judge_get_package(state, event):
    if invalid_package_key_parameter(event):
        return expected_status_result(
            event,
            "invalid_parameter",
            "GetPackage WrappingKey/SigningKey parameters must be credential UID references when present.",
            rule_key="get_package",
        )
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
    if invalid_package_key_parameter(event):
        return expected_status_result(
            event,
            "invalid_parameter",
            "SetPackage WrappingKey/SigningKey parameters must be credential UID references when present.",
            rule_key="set_package",
        )
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
    result = expected_status_result(
        event,
        "success" if expected else "auth_error",
        f"{method} requires credential-object access control in an open session.",
        rule_key="crypto_stream",
    )
    if (
        result.verdict == "pass"
        and actual_status_class(event) == "success"
        and method in {"Encrypt", "Decrypt", "Hash", "HMAC", "EncryptFinalize", "DecryptFinalize", "HashFinalize", "HMACFinalize"}
    ):
        limit = buffer_out_count(event)
        output_len = returned_output_byte_length(event)
        if limit is not None and limit >= 0 and output_len is not None and output_len > limit:
            return fail_result(
                f"{method} returned {output_len} output byte(s), exceeding BufferOut={limit}.",
                expected_status="success_with_bufferout_bound",
                actual_status="success",
                spec_refs=spec_refs_for("crypto_stream"),
                policy_source="return_shape",
            )
    return result


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
    result = expected_status_result(
        event,
        "success" if expected else "auth_error",
        "XOR requires access control for the pattern/input/output references in an open session.",
        rule_key="xor",
    )
    if result.verdict == "pass" and actual_status_class(event) == "success":
        limit = buffer_out_count(event)
        output_len = returned_output_byte_length(event)
        if limit is not None and limit >= 0 and output_len is not None and output_len > limit:
            return fail_result(
                f"XOR returned {output_len} output byte(s), exceeding BufferOut={limit}.",
                expected_status="success_with_bufferout_bound",
                actual_status="success",
                spec_refs=spec_refs_for("xor"),
                policy_source="return_shape",
            )
    return result


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
    if method == "GetFreeRows" and expected:
        dynamic_table = dynamic_table_record(state, event)
        if dynamic_table is not None and dynamic_table.get("row_inventory_complete"):
            expected_rows = dynamic_table.get("rows_free")
            reported_rows = returned_free_rows(event)
            if actual_status_class(event) == "success" and expected_rows is not None and reported_rows != expected_rows:
                return fail_result(
                    f"GetFreeRows on dynamic table {dynamic_table.get('name')} returned {reported_rows}; expected {expected_rows} from tracked row inventory.",
                    expected_status="success_freerows",
                    actual_status="success",
                    spec_refs=spec_refs_for("get"),
                    policy_source="dynamic_table_state",
                )
        capacity = (state.get("table_capacity") or {}).get(compact_uid(event.get("object_uid")))
        if capacity is not None:
            expected_rows = capacity.get("rows_free")
            reported_rows = returned_free_rows(event)
            if actual_status_class(event) == "success" and expected_rows is not None and reported_rows is not None and reported_rows != expected_rows:
                return fail_result(
                    f"GetFreeRows on learned table {event.get('object_uid')} returned {reported_rows}; expected {expected_rows} from tracked Table.RowsFree.",
                    expected_status="success_freerows",
                    actual_status="success",
                    spec_refs=spec_refs_for("get"),
                    policy_source="table_capacity_state",
                )
    if method == "GetFreeSpace" and expected and actual_status_class(event) == "success":
        free_space = returned_free_space(event)
        if free_space is not None and free_space < 0:
            return fail_result(
                f"GetFreeSpace returned negative FreeSpace={free_space}; FreeSpace is an approximate byte count and cannot be negative.",
                expected_status="success_nonnegative_freespace",
                actual_status="success",
                spec_refs=spec_refs_for("get"),
                policy_source="get_free_space_result",
            )
        issued_entry = issued_sp_entry_for_sp(state, target_sp or state["session"].get("sp"))
        issued_size = to_int((issued_entry or {}).get("size"))
        if free_space is not None and issued_size is not None and free_space > issued_size:
            return fail_result(
                f"GetFreeSpace returned FreeSpace={free_space}, exceeding concrete issued SP Size={issued_size}.",
                expected_status="success_with_bounded_freespace",
                actual_status="success",
                spec_refs=spec_refs_for("get"),
                policy_source="issued_sp_state",
            )
        reported_table_rows = returned_table_rows(event)
        if reported_table_rows:
            for table_uid, dynamic_table in (state.get("dynamic_tables") or {}).items():
                if target_sp and dynamic_table.get("sp") not in {None, target_sp}:
                    continue
                if not dynamic_table.get("row_inventory_complete"):
                    continue
                expected_rows = dynamic_table.get("rows_free")
                reported_rows = reported_table_rows.get(table_uid)
                if expected_rows is not None and reported_rows is not None and reported_rows != expected_rows:
                    return fail_result(
                        f"GetFreeSpace TableRows for dynamic table {dynamic_table.get('name')} returned {reported_rows}; expected {expected_rows} from tracked row inventory.",
                        expected_status="success_tablerows",
                        actual_status="success",
                        spec_refs=spec_refs_for("get"),
                        policy_source="dynamic_table_state",
                    )
            for table_uid, capacity in (state.get("table_capacity") or {}).items():
                expected_rows = capacity.get("rows_free")
                reported_rows = reported_table_rows.get(table_uid)
                if expected_rows is not None and reported_rows is not None and reported_rows != expected_rows:
                    return fail_result(
                        f"GetFreeSpace TableRows for learned table {table_uid} returned {reported_rows}; expected {expected_rows} from tracked Table.RowsFree.",
                        expected_status="success_tablerows",
                        actual_status="success",
                        spec_refs=spec_refs_for("get"),
                        policy_source="table_capacity_state",
                    )
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
    dynamic_table = dynamic_table_record(state, event)
    if (not table_level_invocation(event) and dynamic_table is None) or event.get("object_family") in {"MBR", "DataStore"}:
        return expected_status_result(
            event,
            "invalid_parameter",
            f"{method} is a table method for object tables and is not valid on byte tables or object rows.",
            rule_key="row_management",
        )
    if dynamic_table is not None and dynamic_table.get("kind") == "byte":
        return expected_status_result(
            event,
            "invalid_parameter",
            f"{method} is not valid on dynamic byte table {dynamic_table.get('name')}.",
            rule_key="row_management",
        )
    if method == "DeleteRow" and dynamic_table is not None and dynamic_table.get("row_inventory_complete"):
        table_uid = compact_uid(event.get("object_uid"))
        known_rows = (state.get("dynamic_rows") or {}).get(table_uid) or {}
        requested = uids_from_value(parameter_value(event, ("Rows",)))
        missing = [uid for uid in requested if uid not in known_rows]
        if missing:
            return expected_status_result(
                event,
                "error",
                f"DeleteRow targets unknown dynamic row UID(s) {missing}; deletion must fail without removing other rows.",
                rule_key="row_management",
            )
    if method == "CreateRow" and dynamic_table is not None:
        known_columns = set(dynamic_table.get("column_numbers") or []) - {0}
        supplied_column_values = row_column_values_from_value(parameter_value(event, ("Row",)), dynamic_table)
        supplied_columns = set(supplied_column_values) or numeric_columns_from_value(parameter_value(event, ("Row",)))
        if known_columns and supplied_columns:
            unknown = supplied_columns - known_columns
            missing = known_columns - supplied_columns if dynamic_table.get("schema_complete") else set()
            if unknown or missing:
                return expected_status_result(
                    event,
                    "invalid_parameter",
                    f"CreateRow Row columns do not match the dynamic table schema; missing={sorted(missing)} unknown={sorted(unknown)}.",
                    rule_key="row_management",
                )
        unique_conflicts = unique_conflicts_for_create_row(state, event, dynamic_table)
        if unique_conflicts:
            return expected_status_result(
                event,
                "error",
                f"CreateRow conflicts with dynamic unique column value(s): {unique_conflicts}.",
                rule_key="row_management",
            )
        if dynamic_table.get("rows_free") == 0:
            sp = dynamic_table.get("sp") or state["session"].get("sp")
            if session_open_for(state, sp, write_required=True) and session_has_authority(state):
                return expected_exact_method_status_result(
                    event,
                    "insufficient_rows",
                    f"CreateRow cannot succeed because dynamic table {dynamic_table.get('name')} has concrete RowsFree=0.",
                    rule_key="row_management",
                    policy_source="dynamic_table_state",
                )
        if actual_status_class(event) == "success":
            returned = returned_uids_from_event(event)
            if not returned:
                return fail_result(
                    "CreateRow on a dynamic object table returned SUCCESS without a row UID result (core/5.3.3.4.2.1).",
                    expected_status="success_with_row_uid",
                    actual_status="success",
                    spec_refs=spec_refs_for("row_management"),
                )
            table_uid = compact_uid(event.get("object_uid"))
            known_rows = (state.get("dynamic_rows") or {}).get(table_uid) or {}
            duplicates = [uid for uid in returned if uid in known_rows]
            if duplicates:
                return expected_status_result(
                    event,
                    "error",
                    f"CreateRow returned duplicate dynamic row UID(s) {duplicates}; row UIDs must be unique.",
                    rule_key="row_management",
                )
            max_size = dynamic_table.get("max_size")
            current_rows = dynamic_table.get("rows") or 0
            if max_size is not None and current_rows + len(returned) > max_size:
                return expected_status_result(
                    event,
                    "error",
                    f"CreateRow would exceed dynamic table MaxSize={max_size}.",
                    rule_key="row_management",
                )
    if method == "CreateRow" and dynamic_table is None:
        capacity = (state.get("table_capacity") or {}).get(compact_uid(event.get("object_uid")))
        if capacity is not None and capacity.get("rows_free") == 0:
            target_sp = object_sp(event) or state["session"].get("sp")
            if session_open_for(state, target_sp, write_required=True) and session_has_authority(state):
                return expected_exact_method_status_result(
                    event,
                    "insufficient_rows",
                    f"CreateRow cannot succeed because learned Table.RowsFree for {event.get('object_uid')} is 0.",
                    rule_key="row_management",
                    policy_source="table_capacity_state",
                )
    # spec core/5.3.3.4 / core/5.8.3: these rows are TPer-managed; the host must not
    # create or delete them directly via CreateRow/DeleteRow.
    if event.get("object_family") in {"AccessControl", "Column", "Log", "LogList", "MethodID"}:
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
    # spec core/5.3.3.3: TPer-managed rows cannot be deleted directly by the host.
    if event.get("object_family") in {"AccessControl", "Column", "LogList", "MethodID"}:
        return expected_status_result(
            event, "invalid_parameter",
            f"{event.get('object_family')} rows are TPer-managed and cannot be deleted directly by the host (core/5.3.3.3).",
            rule_key="delete",
        )
    # spec core/3.4.1.1: AdminSP SHALL NOT be deleted.
    if event.get("object") == "AdminSP":
        return expected_status_result(
            event, "invalid_parameter",
            "AdminSP cannot be deleted; it is a mandatory singleton (core/3.4.1.1).",
            rule_key="delete",
        )
    # spec core/5.7.2.2.12: Delete on a Locking-family row fails if Global Range is not IDLE.
    if event.get("object_family") == "Locking":
        global_range = (state.get("locking_ranges") or {}).get("Global") or {}
        sv = reencrypt_state_value(global_range.get("reencrypt_state"))
        if sv is not None and sv != 1:
            return expected_status_result(
                event,
                "invalid_parameter",
                "Delete on a Locking row is not permitted while Global Range re-encryption is in progress (core/5.7.2.2.12).",
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
    # spec core/3.4.1.1: AdminSP SHALL NOT be deleted.
    if sp == "AdminSP":
        return expected_status_result(
            event, "invalid_parameter",
            "AdminSP cannot be deleted via DeleteSP; it is a mandatory singleton (core/3.4.1.1).",
            rule_key="delete_sp",
        )
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
    if expected and create_table_name_conflict(state, event, target_sp):
        return expected_status_result(
            event,
            "invalid_parameter",
            "CreateTable NewTableName/CommonName conflicts with an existing table in the target SP.",
            rule_key="create_table",
        )
    if expected:
        table_capacity = (state.get("table_capacity") or {}).get("0000000100000001")
        if table_capacity is not None and table_capacity.get("rows_free") == 0:
            return expected_exact_method_status_result(
                event,
                "insufficient_rows",
                "CreateTable cannot succeed because learned Table.RowsFree for the Table table is 0.",
                rule_key="create_table",
                policy_source="table_capacity_state",
            )
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
    invoking_uid, method_name = meta_acl_parameter_target(event)
    row = matching_access_control_row(state, invoking_uid, method_name, target_sp=target_sp)
    if method == "GetACL":
        expected = session_open_for(state, target_sp, write_required=False)
        reason = "GetACL requires an open session; GetACLACL defaults to ACE_Anybody in Opal SSC."
        if row is not None and row.get("get_acl_acl_refs"):
            authorized = ace_refs_authorized(
                state,
                row.get("get_acl_acl_refs"),
                target_sp=target_sp,
                row_source=row.get("source"),
            )
            if authorized is not None:
                expected = expected and authorized
                reason = "GetACL is governed by the target AccessControl row's GetACLACL."
        if expected and actual_status_class(event) == "success" and row is not None and row.get("dynamic_table_uid"):
            reported_refs = returned_acl_refs(event)
            if reported_refs is not None:
                expected_refs = row.get("ace_refs") or []
                if sorted(reported_refs) != sorted(expected_refs):
                    return fail_result(
                        f"Dynamic GetACL returned ACL refs {reported_refs}; expected {expected_refs} from the concrete dynamic AccessControl row.",
                        expected_status="success_acl_refs",
                        actual_status="success",
                        spec_refs=spec_refs_for("meta_acl"),
                        policy_source="dynamic_access_control_state",
                    )
    else:
        expected = session_open_for(state, target_sp, write_required=write_required) and session_has_authority(state)
        reason = f"{method} requires the corresponding meta-ACL authorization on the AccessControl association."
        field_by_method = {
            "AddACE": "add_ace_acl_refs",
            "RemoveACE": "remove_ace_acl_refs",
            "DeleteMethod": "delete_method_acl_refs",
        }
        refs_field = field_by_method.get(method)
        if row is not None and refs_field and row.get(refs_field):
            authorized = ace_refs_authorized(
                state,
                row.get(refs_field),
                target_sp=target_sp,
                row_source=row.get("source"),
            )
            if authorized is not None:
                expected = session_open_for(state, target_sp, write_required=write_required) and authorized
                reason = f"{method} is governed by the target AccessControl row's {refs_field}."
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
    dynamic_table = dynamic_table_record(state, event)
    if event.get("object_family") in {"MBR", "DataStore"} or (
        dynamic_table is not None and dynamic_table.get("kind") == "byte"
    ):
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
            result_text = str(event.get("result") or "").strip().lower()
            if "user_data" in result_text or "userdata" in result_text:
                return fail_result(
                    "Read within active MBR shadow region returned user data instead of MBR table data (opal/4.3.4).",
                    expected_status="data_success_mbr_data",
                    actual_status="data_success_user_data",
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
    violation = sync_session_trans_timeout_violation(state, event) if expected else None
    if violation is not None:
        return violation
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
    return expected_empty_success_result(
        event,
        "success" if expected else "error",
        "CloseSession/EndSession should close an open session.",
        rule_key="close_session",
        empty_result_ref="core/3.3.7.1.5",
    )


def fallback(event, state):
    if event["kind"] != "method":
        return expected_status_result(event, "data_success", "Non-method fallback expects a successful data command.", 0.50)

    method = event.get("method") or ""
    harmless = {"Properties"}
    if method in harmless:
        return expected_status_result(event, "success", f"{method} is a harmless discovery/helper method.", rule_key="properties")

    _fb_sp = state["session"].get("sp")
    expected = state["session"].get("open") and (
        not method.lower().startswith(("set", "gen", "activate", "revert", "delete", "create"))
        or (state["session"].get("write") and session_has_admin_authority(state, _fb_sp))
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
    feature_codes = event.get("feature_codes") or []
    duplicates = event.get("duplicate_feature_codes") or []
    header = event.get("discovery_header") or {}

    header_reserved = to_int(header.get("reserved"))
    if header_reserved is not None and header_reserved != 0:
        return fail_result(
            f"Level 0 Discovery header reserved bytes 8-15 must be zero; reported 0x{header_reserved:X}.",
            0.90, "success", "discovery_header_reserved",
            spec_refs_for("discovery"), "spec", "implemented",
        )

    header_major = to_int(header.get("major_version"))
    if header_major is not None and header_major != 0:
        return fail_result(
            f"Level 0 Discovery header MajorVersion must be 0x0000; reported 0x{header_major:04X}.",
            0.90, "success", "discovery_header_version",
            spec_refs_for("discovery"), "spec", "implemented",
        )

    header_minor = to_int(header.get("minor_version"))
    if header_minor is not None and header_minor != 1:
        return fail_result(
            f"Level 0 Discovery header MinorVersion must be 0x0001; reported 0x{header_minor:04X}.",
            0.90, "success", "discovery_header_version",
            spec_refs_for("discovery"), "spec", "implemented",
        )

    if duplicates:
        duplicate_text = ", ".join(f"0x{code:04X}" for code in duplicates)
        return fail_result(
            f"Level 0 Discovery contains duplicate feature descriptor code(s): {duplicate_text}.",
            0.90, "success", "discovery_duplicate_descriptor",
            spec_refs_for("discovery"), "spec", "implemented",
        )

    if feature_codes and feature_codes != sorted(feature_codes):
        return fail_result(
            "Level 0 Discovery feature descriptors must appear in increasing feature-code order.",
            0.90, "success", "discovery_descriptor_order",
            spec_refs_for("discovery"), "spec", "implemented",
        )

    def _feature_int(feature, *names):
        for name in names:
            value = feature.get(name) if isinstance(feature, dict) else None
            parsed = to_int(value)
            if parsed is not None:
                return parsed
        return None

    def _reserved_nonzero(feature, *names):
        if not isinstance(feature, dict):
            return None
        for name in names:
            if name not in feature:
                continue
            parsed = to_int(feature.get(name))
            if parsed is not None and parsed != 0:
                return name, parsed
        return None

    # Required descriptors must all be present.
    for code, name in ((TPER_CODE, "TPer"), (LOCKING_CODE, "Locking"), (OPAL_V2_CODE, "Opal SSC V2")):
        if code not in features:
            return fail_result(
                f"Level 0 Discovery missing required {name} descriptor (feature 0x{code:04X}) (opal/3.1.1).",
                0.95, "success", "discovery_missing_descriptor",
                spec_refs_for("discovery"), "spec", "implemented",
            )

    for code, feature in features.items():
        length = _feature_int(feature, "length", "Length", "feature_length", "FeatureLength")
        if length is not None and length % 4 != 0:
            return fail_result(
                f"Level 0 Discovery descriptor 0x{code:04X} has Length={length}; descriptor Length must be a multiple of 4 (core/3.3.6.3.1.3).",
                0.90, "success", "discovery_descriptor_length",
                spec_refs_for("discovery"), "spec", "implemented",
            )

    expected_lengths = {
        TPER_CODE: (0x0C, "TPer"),
        LOCKING_CODE: (0x0C, "Locking"),
        OPAL_V2_CODE: (0x10, "Opal SSC V2"),
    }
    for code, (expected_length, name) in expected_lengths.items():
        length = _feature_int(features[code], "length", "Length", "feature_length", "FeatureLength")
        if length is not None and length != expected_length:
            return fail_result(
                f"{name} descriptor Length must be 0x{expected_length:02X}; reported 0x{length:02X}.",
                0.90, "success", "discovery_descriptor_length",
                spec_refs_for("discovery"), "spec", "implemented",
            )

    optional_expected_lengths = {
        0x0003: (0x1C, "Geometry"),
        0x0404: (0x20, "Data Removal"),
    }
    for code, (expected_length, name) in optional_expected_lengths.items():
        feature = features.get(code)
        if not isinstance(feature, dict):
            continue
        length = _feature_int(feature, "length", "Length", "feature_length", "FeatureLength")
        if length is not None and length != expected_length:
            return fail_result(
                f"{name} descriptor Length must be 0x{expected_length:02X}; reported 0x{length:02X}.",
                0.90, "success", "discovery_descriptor_length",
                spec_refs_for("discovery"), "spec", "implemented",
            )

    header_length = to_int(header.get("length_of_parameter_data"))
    if header_length is not None:
        descriptor_lengths = []
        for code in feature_codes:
            feature = features.get(code)
            length = _feature_int(feature, "length", "Length", "feature_length", "FeatureLength")
            if length is None:
                descriptor_lengths = []
                break
            descriptor_lengths.append(length)
        if descriptor_lengths:
            min_parameter_bytes = 44 + sum(4 + length for length in descriptor_lengths)
            truncated = to_bool(header.get("truncated")) is True
            complete = to_bool(header.get("complete")) is True
            if not truncated and header_length < min_parameter_bytes:
                return fail_result(
                    f"Level 0 Discovery LengthOfParameterData={header_length} is too short for the concrete returned descriptors; minimum is {min_parameter_bytes} bytes.",
                    0.90, "success", "discovery_total_length",
                    spec_refs_for("discovery"), "spec", "implemented",
                )
            if complete and header_length != min_parameter_bytes:
                return fail_result(
                    f"Complete Level 0 Discovery LengthOfParameterData={header_length} must equal the concrete descriptor payload size {min_parameter_bytes} bytes.",
                    0.90, "success", "discovery_total_length",
                    spec_refs_for("discovery"), "spec", "implemented",
                )

    for code, name, reserved_names in (
        (TPER_CODE, "TPer", ("reserved", "Reserved", "reserved_bits", "reserved_byte4", "reserved_5_15", "reserved_bytes_5_15")),
        (LOCKING_CODE, "Locking", ("reserved", "Reserved", "reserved_bits", "reserved_5_15", "reserved_bytes_5_15")),
        (OPAL_V2_CODE, "Opal SSC V2", ("reserved", "Reserved", "reserved_bits", "reserved_common", "reserved_future_common", "reserved_15_19", "reserved_bytes_15_19")),
    ):
        bad_reserved = _reserved_nonzero(features.get(code), *reserved_names)
        if bad_reserved is not None:
            field_name, value = bad_reserved
            return fail_result(
                f"{name} descriptor reserved field {field_name} must be zero; reported 0x{value:X}.",
                0.90, "success", "discovery_reserved_field",
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

    # Geometry descriptor (0x0003) is optional, but when present it must mirror
    # the observed LockingInfo geometry fields (opal/3.1.1.4.2-.5).
    geometry_descriptor = features.get(0x0003)
    locking_info_geometry = _get_locking_info_geometry(state)
    if isinstance(geometry_descriptor, dict) and locking_info_geometry:
        reported_align = to_bool(
            geometry_descriptor.get("align")
            if "align" in geometry_descriptor
            else geometry_descriptor.get("alignment_required")
        )
        if reported_align is not None and "align" in locking_info_geometry:
            if reported_align != locking_info_geometry["align"]:
                return fail_result(
                    "Geometry descriptor ALIGN bit must match LockingInfo.AlignmentRequired (opal/3.1.1.4.2).",
                    0.90, "success", "discovery_geometry",
                    spec_refs_for("discovery"), "spec", "implemented",
                )

        for field, names, title, ref in (
            (
                "logical_block_size",
                ("logical_block_size", "logicalblocksize", "LogicalBlockSize"),
                "LogicalBlockSize",
                "opal/3.1.1.4.3",
            ),
            (
                "alignment_granularity",
                ("alignment_granularity", "alignmentgranularity", "AlignmentGranularity"),
                "AlignmentGranularity",
                "opal/3.1.1.4.4",
            ),
            (
                "lowest_aligned_lba",
                ("lowest_aligned_lba", "lowestalignedlba", "LowestAlignedLBA"),
                "LowestAlignedLBA",
                "opal/3.1.1.4.5",
            ),
        ):
            expected_value = locking_info_geometry.get(field)
            if expected_value is None:
                continue
            reported_value = _feature_int(geometry_descriptor, *names)
            if reported_value is not None and reported_value != expected_value:
                return fail_result(
                    f"Geometry descriptor {title} must match LockingInfo.{title}; reported {reported_value}, expected {expected_value} ({ref}).",
                    0.90, "success", "discovery_geometry",
                    spec_refs_for("discovery"), "spec", "implemented",
                )

    # Opal SSC V2 descriptor (opal/3.1.1.5): >=4 admins, >=8 users, >=1 ComID
    opal = features[OPAL_V2_CODE]
    num_admins = to_int(opal.get("number_of_admins_supported") or opal.get("admin_auth_count") or opal.get("num_admins"))
    num_users = to_int(opal.get("number_of_users_supported") or opal.get("user_auth_count") or opal.get("num_users"))
    num_comids = to_int(opal.get("num_comids") or opal.get("number_of_comids"))
    initial_sid_indicator = _feature_int(
        opal,
        "initial_c_pin_sid_pin_indicator",
        "initial_cpin_sid_pin_indicator",
        "initial_sid_pin_indicator",
        "initial_sid_indicator",
    )
    revert_sid_indicator = _feature_int(
        opal,
        "c_pin_sid_pin_revert_behavior",
        "cpin_sid_pin_revert_behavior",
        "sid_pin_revert_behavior",
        "revert_sid_indicator",
    )
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
    if initial_sid_indicator is not None and 0x01 <= initial_sid_indicator <= 0xFE:
        return fail_result(
            f"Opal SSC V2 Initial C_PIN_SID PIN Indicator value 0x{initial_sid_indicator:02X} is reserved; only 0x00 or 0xFF are defined (opal/3.1.1.5).",
            0.90, "success", "discovery_opal_v2",
            spec_refs_for("discovery"), "spec", "implemented",
        )
    if revert_sid_indicator is not None and 0x01 <= revert_sid_indicator <= 0xFE:
        return fail_result(
            f"Opal SSC V2 C_PIN_SID PIN revert behavior value 0x{revert_sid_indicator:02X} is reserved; only 0x00 or 0xFF are defined (opal/3.1.1.5).",
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
    if expected:
        sp_name = parameter_value(event, ("SPName",))
        known_names = set(state.get("sp_names") or set())
        known_names.update(normalized_policy_text(name) for name in (state.get("issued_sp_names") or set()))
        for row in (state.get("tables") or {}).values():
            title = str(row.get("table") or "")
            if "SP Table Preconfiguration" not in title:
                continue
            values = row.get("values") or {}
            known = values.get("Name") if isinstance(values, dict) else row.get("name")
            if known:
                known_names.add(normalized_policy_text(known))
        if sp_name is not None and normalized_policy_text(sp_name) in known_names:
            return expected_status_result(
                event,
                "error",
                f"IssueSP SPName {sp_name!r} conflicts with an existing known SP name.",
                rule_key="issue_sp",
                policy_source="sp_state",
            )
        template_limit = issue_sp_template_limit_violation(state, event)
        if template_limit is not None:
            template_name, instances, max_instances = template_limit
            return expected_status_result(
                event,
                "error",
                f"IssueSP template {template_name!r} is already at MaxInstances ({instances}/{max_instances}).",
                rule_key="issue_sp",
                policy_source="template_state",
            )
        missing_templates = issue_sp_template_inventory_violation(state, event)
        if missing_templates is not None:
            return expected_status_result(
                event,
                "error",
                f"IssueSP requested template UID(s) {missing_templates} that are absent from the complete learned Template table inventory.",
                rule_key="issue_sp",
                policy_source="template_inventory_state",
            )
        requested_size = to_int(parameter_value(event, ("Size",)))
        issuance_free = to_int((state.get("sp_issuance_space") or {}).get("free"))
        if issuance_free is not None and requested_size is not None and requested_size > issuance_free:
            return expected_exact_method_status_result(
                event,
                "insufficient_space",
                f"IssueSP requested Size={requested_size} exceeds learned TPerInfo.SpaceForIssuance={issuance_free}.",
                rule_key="issue_sp",
                policy_source="TPerInfo.SpaceForIssuance",
            )
        if actual_status_class(event) == "success":
            raw_out = (event.get("raw") or {}).get("output") or {}
            return_values = raw_out.get("return_values") or {}
            returned_size = to_int(find_named_value(return_values, {"Size"}))
            if returned_size is not None and requested_size is not None and returned_size < requested_size:
                return fail_result(
                    f"IssueSP returned Size={returned_size}, below requested Size={requested_size}; inability to allocate requested size must fail.",
                    expected_status="success_with_allocated_size",
                    actual_status="success",
                    spec_refs=spec_refs_for("issue_sp"),
                )
            if issuance_free is not None and returned_size is not None and returned_size > issuance_free:
                return fail_result(
                    f"IssueSP returned allocated Size={returned_size}, above learned TPerInfo.SpaceForIssuance={issuance_free}.",
                    expected_status="success_with_available_size",
                    actual_status="success",
                    spec_refs=spec_refs_for("issue_sp"),
                    policy_source="TPerInfo.SpaceForIssuance",
                )
            returned_uid = find_named_value(return_values, {"UID", "SPID", "SPUID"})
            if returned_uid is not None:
                compact = compact_uid(uid_parameter_value(returned_uid))
                if compact is None or len(compact) != 16:
                    return fail_result(
                        f"IssueSP returned malformed UID {returned_uid!r}.",
                        expected_status="success_with_valid_uid",
                        actual_status="success",
                        spec_refs=spec_refs_for("issue_sp"),
                    )
                if compact in (state.get("issued_sps") or {}):
                    return fail_result(
                        f"IssueSP returned duplicate issued SP UID {compact}; issued SP UIDs must be unique.",
                        expected_status="success_with_unique_sp_uid",
                        actual_status="success",
                        spec_refs=spec_refs_for("issue_sp"),
                        policy_source="issued_sp_state",
                    )
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

    identity_result = incompatible_object_identity_result(event)
    if identity_result is not None:
        return identity_result

    singleton_result = invalid_singleton_object_row_result(event)
    if singleton_result is not None:
        return singleton_result

    method_filter = sp_method_filter_result(state, event)
    if method_filter is not None:
        return method_filter

    response_mismatch = success_response_method_mismatch_result(event)
    if response_mismatch is not None:
        return response_mismatch

    no_result_shape = no_result_method_return_shape_result(event)
    if no_result_shape is not None:
        return no_result_shape

    if method == "Properties":
        expected = event.get("object") == "SessionManager"
        if not expected:
            return expected_status_result(
                event,
                "invalid_parameter",
                "Properties should be invoked on the Session Manager.",
                rule_key="properties",
            )
        # spec core/5.2.2.2 Table 167 and opal/4.1.1.1 Table 17: validate
        # mandatory TPer property minimums when an explicit TPerProperties map is returned.
        raw_out = (event.get("raw") or {}).get("output") or {}
        return_vals = raw_out.get("return_values") or []
        tper_props = find_named_value(return_vals, {"Properties", "TPerProperties"})
        if isinstance(tper_props, dict) and actual_status_class(event) == "success":
            def _prop_int(props, name):
                v = props.get(name)
                if v is None:
                    return None
                if isinstance(v, int):
                    return v
                try:
                    return int(str(v), 16) if str(v).startswith(("0x", "0X")) or (len(str(v)) > 2 and all(c in "0123456789abcdefABCDEF" for c in str(v))) else int(v)
                except (ValueError, TypeError):
                    return None
            opal_mandatory = {
                "MaxComPacketSize": 2048,
                "MaxResponseComPacketSize": 2048,
                "MaxPacketSize": 2028,
                "MaxIndTokenSize": 1992,
                "MaxPackets": 1,
                "MaxSubpackets": 1,
                "MaxMethods": 1,
                "MaxSessions": 1,
                "MaxAuthentications": 2,
                "MaxTransactionLimit": 1,
            }
            missing = [name for name in (*opal_mandatory.keys(), "DefSessionTimeout") if name not in tper_props]
            if missing:
                return RuleResult(
                    verdict="fail",
                    confidence=0.95,
                    reason=(
                        "Properties response included explicit TPerProperties but omitted mandatory Opal "
                        f"{', '.join(missing)} field(s) (opal/4.1.1.1 Table 17)."
                    ),
                    expected_status=None,
                    actual_status=event.get("status"),
                    spec_refs=("opal/4.1.1.1",),
                    policy_source="rule",
                    coverage_status="implemented",
                )
            for name, minimum in opal_mandatory.items():
                value = _prop_int(tper_props, name)
                if value is None or value == 0 or value >= minimum:
                    continue
                return RuleResult(
                    verdict="fail",
                    confidence=0.95,
                    reason=f"Properties response {name}={value} is below the Opal minimum of {minimum} (opal/4.1.1.1 Table 17).",
                    expected_status=None,
                    actual_status=event.get("status"),
                    spec_refs=("opal/4.1.1.1",),
                    policy_source="rule",
                    coverage_status="implemented",
                )
        return expected_status_result(
            event,
            "success",
            "Properties is a discovery method on the Session Manager.",
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

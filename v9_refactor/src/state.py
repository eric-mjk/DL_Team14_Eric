from copy import deepcopy
import re

from .normalizer import (
    canonical_sp,
    compact_uid,
    credentials_equal,
    find_named_value,
    is_success_status,
    to_bool,
    to_int,
)
from .spec_docs import (
    column_list_from_value,
    default_access_policy,
    default_locking_ranges,
    default_mbr_control,
    default_table_rows,
    exact_uid_or_none,
    METHOD_NAMES,
    method_name_from_value,
    normalize_authority_name,
    normalized_column_name,
    reencrypt_request_value,
    reencrypt_state_value,
)


LOCKING_COLUMNS = {
    3: "range_start",
    4: "range_length",
    5: "read_lock_enabled",
    6: "write_lock_enabled",
    7: "read_locked",
    8: "write_locked",
    9: "lock_on_reset",
    10: "active_key",
    11: "next_key",
    12: "reencrypt_state",
    13: "reencrypt_request",
    14: "adv_key_mode",
    15: "verify_mode",
    16: "cont_on_reset",
    17: "last_reencrypt_lba",
    18: "last_reenc_stat",
    19: "general_status",
}

MBR_COLUMNS = {
    1: "enable",
    2: "done",
    3: "done_on_reset",
}


def empty_session():
    return {
        "open": False,
        "sp": None,
        "authority": None,
        "authorities": set(),
        "write": False,
        "had_failure": False,
        "trusted": False,
        "host_session_id": None,
        "sp_session_id": None,
        "pending_auth_challenge": None,
    }


def fresh_access_policy():
    return deepcopy(default_access_policy())


def initial_state():
    locking_ranges = default_locking_ranges()
    access_policy = fresh_access_policy()
    state = {
        "session": empty_session(),
        "credentials": {
            "SID": None,
            "MSID": None,
            "Admin1": None,
            # spec opal/4.3.1.9: LockingSP C_PIN preconfiguration — initial PIN = "" (empty)
            "Admin2": "",
            "Admin3": "",
            "Admin4": "",
            "User1": "",
            # spec opal/4.3.1.8: User2-User8 shall be implemented; initially disabled with empty PINs
            "User2": "",
            "User3": "",
            "User4": "",
            "User5": "",
            "User6": "",
            "User7": "",
            "User8": "",
        },
        "sp_lifecycle": {
            "AdminSP": "Manufactured",
            "LockingSP": "Manufactured-Inactive",
        },
        "sp_names": {
            "adminsp": "AdminSP",
            "lockingsp": "LockingSP",
        },
        "locking_sp_active": False,
        "opal_profile_confirmed": False,
        # opal/3.1.1.5 Range Crossing Behavior bit; None until discovery exposes it.
        "range_crossing_behavior": None,
        # opal/3.1.1.5: Initial C_PIN_SID PIN Indicator (0x00 -> SID PIN starts as
        # MSID; 0xFF -> vendor unique) and Behavior of C_PIN_SID PIN upon TPer
        # Revert (same encoding). None until discovery exposes them.
        "initial_sid_pin_is_msid": None,
        "revert_sid_pin_is_msid": None,
        # Speculative credential values (e.g. "SID may initially equal MSID").
        # A challenge matching a candidate authenticates; a mismatch is UNKNOWN,
        # not wrong — the real value may be vendor unique (public tc3-tc20
        # evidence: the initial SID PIN is VU and does not equal MSID).
        "credential_candidates": {},
        "deleted_sps": set(),
        "pending_sp_deletions": set(),
        "properties": {},
        "sp_session_timeouts": {},
        "sp_byte_space": {},
        "sp_issuance_space": {"free": None, "source": None},
        "locking_ranges": locking_ranges,
        "mbr": default_mbr_control(),
        "tables": default_table_rows(),
        "table_capacity": {},
        "template_inventory": {"complete": False, "available": set(), "source": None},
        "dynamic_tables": {},
        "dynamic_table_names": {},
        "dynamic_rows": {},
        "dynamic_row_table": {},
        "deleted_dynamic_tables": set(),
        "deleted_dynamic_rows": set(),
        "issued_sp_names": set(),
        "issued_sps": {},
        "ace_rows": access_policy.get("ace_rows", {}),
        "access_control_rows": access_policy.get("access_control_rows", []),
        "authority_rows": access_policy.get("authority_rows", {}),
        "credential_to_authority": access_policy.get("credential_to_authority", {}),
        "authenticated_history": set(),
        "key_generations": {},
        "key_generations_by_range": {},
        "trylimit_by_authority": {},
        "failed_auth_counts": {},
        "writes": {},
        "write_records": [],
        # Non-overlapping byte-range view of successful data writes. Newer writes
        # clip older segments, so partial-overlap reads can be judged per segment.
        "write_segments": [],
        "reads": [],
        "crypto_streams": {},
        "pending_clock_lag": None,
        "history": [],
        # spec core/5.8.3: log tables that exist; pre-seeded with the default Log template UID.
        # AddLog/ClearLog/FlushLog on a UID not in this set is an error.
        "log_tables": {"0000000100000A01"},
        "log_table_names": set(),
    }
    # spec opal/4.3.1.8: User2-User8 shall be implemented and are initially disabled.
    # authority_enabled() returns True for unknown rows, so we must seed explicit disabled entries.
    # Class must be "Users" so authority_classes_for() correctly places them in the Users class
    # for ACE BooleanExpression evaluation.
    for _n in range(2, 9):
        _user = f"User{_n}"
        state["authority_rows"].setdefault(_user, {
            "name": _user,
            "enabled": False,
            "is_class": False,
            "class": "Users",
            "operation": "Password",
            "source": "LockingSP",
        })
    return state


def normalized_result_text(result):
    if result is None:
        return ""
    return str(result).strip()


def is_error_result(result):
    text = normalized_result_text(result).lower().replace("_", " ")
    if not text:
        return False
    return any(
        marker in text
        for marker in (
            "fail",
            "failed",
            "error",
            "denied",
            "not authorized",
            "protected",
            "locked",
        )
    )


def data_command_success(event):
    status = event.get("status")
    result = event.get("result")
    if status is not None:
        return is_success_status(status)
    text = normalized_result_text(result).lower()
    if event.get("kind") == "write":
        if not text:
            return True
        if text in {"pass", "passed", "success", "successful", "ok"}:
            return True
        return not is_error_result(result)
    if event.get("kind") == "read":
        return result is not None and not is_error_result(result)
    return status in {None, "success"} and not is_error_result(result)


def success_like(event):
    if event["kind"] in {"read", "write", "command"}:
        return data_command_success(event)
    return is_success_status(event.get("status"))


def add_credential_candidate(state, authority, value):
    """Record a speculative credential value (initial/copied PIN defaults)."""
    if not authority or value is None:
        return
    candidates = state.setdefault("credential_candidates", {}).setdefault(authority, [])
    if not any(credentials_equal(value, existing) for existing in candidates):
        candidates.append(value)


def clear_credential_candidates(state, authority):
    (state.get("credential_candidates") or {}).pop(authority, None)


def candidate_credential_match(state, authority, proof):
    """True when the proof matches a speculative candidate; None when
    candidates exist but none match (value may be vendor unique)."""
    candidates = (state.get("credential_candidates") or {}).get(authority) or []
    if not candidates:
        return None
    if any(credentials_equal(proof, candidate) for candidate in candidates):
        return True
    return None


def credential_matches(state, authority, proof):
    if not authority:
        return True
    known = state["credentials"].get(authority)
    if known is None:
        return candidate_credential_match(state, authority, proof)
    # Encoding-tolerant comparison: the trace may encode the same PIN bytes as
    # raw hex, 0x/space-formatted hex, plain text, or an atom-wrapped value.
    return credentials_equal(proof, known)


def add_authenticated_authority(state, authority):
    if not authority:
        return
    session = state["session"]
    session["authority"] = authority
    session["authorities"].add(authority)
    state.setdefault("authenticated_history", set()).add(authority)


def remember_successful_start_session(state, event):
    authority = event.get("authority")
    challenge = event.get("challenge")
    sp = event.get("sp")
    parameters = event.get("parameters") or {}

    state["session"] = empty_session()
    state["session"].update(
        {
            "open": True,
            "sp": sp,
            "authority": authority,
            "write": bool(event.get("write")),
            "host_session_id": to_int(parameters.get("HostSessionID")),
            "session_timeout": to_int(parameters.get("SessionTimeout")),
            "trans_timeout": to_int(parameters.get("TransTimeout")),
        }
    )
    raw_out = (event.get("raw") or {}).get("output") or {}
    return_values = raw_out.get("return_values")
    returned_host_session_id = to_int(find_named_value(return_values, {"HostSessionID", "hostsessionid"}))
    returned_sp_session_id = to_int(find_named_value(return_values, {"SPSessionID", "spsessionid"}))
    if returned_host_session_id is not None:
        state["session"]["host_session_id"] = returned_host_session_id
    if returned_sp_session_id is not None:
        state["session"]["sp_session_id"] = returned_sp_session_id
    if authority:
        state["session"]["authorities"].add(authority)
        state.setdefault("authenticated_history", set()).add(authority)

    if authority and challenge is not None and state["credentials"].get(authority) is None:
        state["credentials"][authority] = challenge
        clear_credential_candidates(state, authority)
    # Successful authenticated session resets Tries counter for that authority
    if authority:
        state.setdefault("failed_auth_counts", {}).pop(authority, None)


def remember_successful_sync_session(state, event):
    parameters = event.get("parameters") or {}
    host_session_id = to_int(parameters.get("HostSessionID"))
    sp_session_id = to_int(parameters.get("SPSessionID"))
    trans_timeout = to_int(parameters.get("TransTimeout"))
    if host_session_id is not None:
        state["session"]["host_session_id"] = host_session_id
    if sp_session_id is not None:
        state["session"]["sp_session_id"] = sp_session_id
    if trans_timeout is not None:
        state["session"]["trans_timeout"] = trans_timeout


def property_int(value):
    if isinstance(value, int):
        return value
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        if len(text) > 2 and re.fullmatch(r"[0-9A-Fa-f]+", text):
            return int(text, 16)
        return int(text, 10)
    except (TypeError, ValueError):
        return None


def apply_successful_properties(state, event):
    raw_out = (event.get("raw") or {}).get("output") or {}
    return_values = raw_out.get("return_values") or []
    tper_props = find_named_value(return_values, {"Properties", "TPerProperties"})
    if not isinstance(tper_props, dict):
        return
    tracked = (
        "MinSessionTimeout",
        "MaxSessionTimeout",
        "DefSessionTimeout",
        "MinTransTimeout",
        "MaxTransTimeout",
        "DefTransTimeout",
        "MaxAuthentications",
    )
    properties = state.setdefault("properties", {})
    for name in tracked:
        value = property_int(tper_props.get(name))
        if value is not None:
            properties[name] = value


def crypto_stream_key(event):
    return event.get("object_uid") or event.get("object")


def apply_successful_crypto_stream_method(state, event):
    key = crypto_stream_key(event)
    if not key:
        return
    method = event.get("method")
    streams = state.setdefault("crypto_streams", {})
    if method == "EncryptInit":
        streams[(key, "Encrypt")] = True
    elif method == "DecryptInit":
        streams[(key, "Decrypt")] = True
    elif method == "HashInit":
        streams[(key, "Hash")] = True
    elif method == "HMACInit":
        streams[(key, "HMAC")] = True
    elif method == "EncryptFinalize":
        streams.pop((key, "Encrypt"), None)
    elif method == "DecryptFinalize":
        streams.pop((key, "Decrypt"), None)
    elif method == "HashFinalize":
        streams.pop((key, "Hash"), None)
    elif method == "HMACFinalize":
        streams.pop((key, "HMAC"), None)


def _apply_successful_create_log(state, event):
    name = (event.get("parameters") or {}).get("NewLogTableName")
    if name:
        state.setdefault("log_table_names", set()).add(str(name))
    # If the drive returns a UID for the new table, track it too.
    ret = event.get("return_columns") or {}
    new_uid = ret.get("uid") or ret.get(0)
    if new_uid:
        from .normalizer import compact_uid
        state.setdefault("log_tables", set()).add(compact_uid(str(new_uid)))


def apply_successful_clock_method(state, event):
    method = event.get("method")
    if method == "SetClockHigh":
        state["pending_clock_lag"] = "SetLagHigh"
    elif method == "SetClockLow":
        state["pending_clock_lag"] = "SetLagLow"
    elif method in {"SetLagHigh", "SetLagLow"}:
        state["pending_clock_lag"] = None
    else:
        state["pending_clock_lag"] = None


def remember_successful_authenticate(state, event):
    if not state["session"].get("open"):
        return

    authority = event.get("authority")
    proof = event.get("proof")
    if not authority:
        return

    operation = authority_operation(state, authority)
    if operation in {"Sign", "SymK", "HMAC"}:
        pending = state["session"].get("pending_auth_challenge")
        auth_result = event.get("auth_result")
        if pending:
            state["session"]["pending_auth_challenge"] = None
            if pending.get("authority") == authority and auth_result is True:
                add_authenticated_authority(state, authority)
                state.setdefault("failed_auth_counts", {}).pop(authority, None)
                # Track accepted (challenge, proof) pairs: an identical proof
                # later accepted for a *different* challenge is a replay.
                if proof is not None and pending.get("challenge") is not None:
                    state.setdefault("auth_proof_history", []).append(
                        {
                            "authority": authority,
                            "operation": operation,
                            "challenge": pending.get("challenge"),
                            "proof": proof,
                        }
                    )
            return
        if proof is not None:
            if auth_result is True:
                add_authenticated_authority(state, authority)
                state.setdefault("failed_auth_counts", {}).pop(authority, None)
            return
        if proof is None:
            challenge = authenticate_response_challenge(event)
            if challenge is not None:
                state["session"]["pending_auth_challenge"] = {
                    "authority": authority,
                    "operation": operation,
                    "challenge": challenge,
                    "sp": state["session"].get("sp"),
                    "host_session_id": state["session"].get("host_session_id"),
                    "sp_session_id": state["session"].get("sp_session_id"),
                }
        return

    auth_result = event.get("auth_result")
    match = credential_matches(state, authority, proof)
    if auth_result is True or (auth_result is None and match is True):
        add_authenticated_authority(state, authority)
        if proof is not None and state["credentials"].get(authority) is None:
            state["credentials"][authority] = proof
            clear_credential_candidates(state, authority)
        # Successful authentication resets Tries counter (spec core/3.3.7.4)
        state.setdefault("failed_auth_counts", {}).pop(authority, None)


def remember_failed_authenticate(state, event):
    authority = event.get("authority")
    if not authority:
        return
    counts = state.setdefault("failed_auth_counts", {})
    next_count = counts.get(authority, 0) + 1
    trylimit = state.get("trylimit_by_authority", {}).get(authority)
    if isinstance(trylimit, int) and trylimit > 0:
        next_count = min(next_count, trylimit)
    counts[authority] = next_count


def authority_operation(state, authority):
    wanted = normalize_authority_name(authority) or authority
    wanted_norm = normalized_policy_name(wanted)
    for key, row in (state.get("authority_rows") or {}).items():
        values = {key, row.get("name"), row.get("uid")}
        if any(wanted_norm and wanted_norm == normalized_policy_name(value) for value in values):
            return row.get("operation")
    return None


def authenticate_response_challenge(event):
    return_values = ((event.get("raw") or {}).get("output") or {}).get("return_values")
    challenge = find_named_value(return_values, {"Challenge", "challenge"})
    if challenge is not None:
        return challenge
    result = find_named_value(return_values, {"Result", "result"})
    if result is not None and to_bool(result) is None:
        return result
    return None


def normalize_column_value(column, value):
    if column in {5, 6, 7, 8}:
        parsed = to_bool(value)
        return parsed if parsed is not None else value
    if column in {3, 4, 12, 13, 14, 15, 17, 18, 19}:
        parsed = to_int(value)
        return parsed if parsed is not None else value
    return value


def apply_reencrypt_request(current, request):
    request_value = reencrypt_request_value(request)
    state_value = reencrypt_state_value(current.get("reencrypt_state"))
    if state_value is None:
        state_value = 1

    if request_value == 1 and state_value == 1:
        current["reencrypt_state"] = 2
        current["columns"][12] = 2
    elif request_value == 2 and state_value in {4, 5}:
        current["reencrypt_state"] = 1
        current["columns"][12] = 1
        current["active_key"] = current.get("next_key")
        current["active_key_uid"] = current.get("next_key_uid")
        current["next_key"] = None
        current["next_key_uid"] = None
        current["columns"][10] = current.get("active_key")
        current["columns"][11] = None
    elif request_value == 3 and state_value == 5:
        current["reencrypt_state"] = 1
        current["columns"][12] = 1
    elif request_value == 4 and state_value == 5:
        current["reencrypt_state"] = 2
        current["columns"][12] = 2
    elif request_value == 5 and state_value in {2, 3}:
        current["reencrypt_state"] = 5
        current["columns"][12] = 5


def default_locking_range(name):
    entry = {
        "name": name,
        "columns": {},
        "range_start": 0,
        "range_length": 0,
        "read_lock_enabled": False,
        "write_lock_enabled": False,
        "read_locked": False,
        "write_locked": False,
        "reencrypt_state": 1,
    }
    return entry


def merge_locking_columns(state, range_name, columns):
    if not range_name:
        return
    current = state["locking_ranges"].setdefault(range_name, default_locking_range(range_name))
    for column, value in columns.items():
        current["columns"][column] = value
        name = LOCKING_COLUMNS.get(column)
        if not name:
            continue
        normalized = normalize_column_value(column, value)
        current[name] = normalized
        if name in {"active_key", "next_key"}:
            current[f"{name}_uid"] = compact_uid(value)
        if name == "reencrypt_request":
            apply_reencrypt_request(current, normalized)


def merge_mbr_columns(state, columns):
    for column, value in columns.items():
        state["mbr"][column] = value
        name = MBR_COLUMNS.get(column)
        if name:
            parsed = to_bool(value) if column in {1, 2} else value
            state["mbr"][name] = parsed if parsed is not None else value


def merge_table_columns(state, event, columns):
    if not columns:
        return
    key = event.get("object_uid") or event.get("object")
    if not key:
        return
    current = state["tables"].setdefault(
        key,
        {
            "source": "trajectory",
            "table": event.get("object_family"),
            "name": event.get("object"),
            "values": {},
            "columns": {},
        },
    )
    current.setdefault("columns", {}).update(columns)
    current.setdefault("values", {}).update({str(column): value for column, value in columns.items()})
    is_get = event.get("method") == "Get"
    if event.get("object_family") == "SPInfo" and is_get and 5 in columns:
        timeout = to_int(columns.get(5))
        if timeout is not None:
            sp = state.get("session", {}).get("sp")
            if sp:
                state.setdefault("sp_session_timeouts", {})[sp] = timeout
    if event.get("object_family") == "SPInfo" and is_get and (3 in columns or 4 in columns):
        sp = state.get("session", {}).get("sp")
        if sp:
            byte_space = state.setdefault("sp_byte_space", {}).setdefault(
                sp,
                {"sp": sp, "source": "SPInfo.Get"},
            )
            size = to_int(columns.get(3)) if 3 in columns else None
            size_in_use = to_int(columns.get(4)) if 4 in columns else None
            if size is not None and size >= 0:
                byte_space["size"] = size
            if size_in_use is not None and size_in_use >= 0:
                byte_space["size_in_use"] = size_in_use
            learned_size = to_int(byte_space.get("size"))
            learned_used = to_int(byte_space.get("size_in_use"))
            if learned_size is not None and learned_used is not None and learned_used <= learned_size:
                byte_space["free"] = learned_size - learned_used
            elif learned_size is not None and learned_used is not None:
                byte_space.pop("free", None)
    if event.get("object_family") == "SPInfo" and 6 in columns:
        sp = state.get("session", {}).get("sp")
        enabled = to_bool(columns.get(6))
        if sp and enabled is not None:
            apply_sp_enabled_state(state, sp, enabled)
    if event.get("object_family") == "ClockTime" and 13 in columns:
        # core/5.5.3.1.14: TrustMode column; tracked only when the trace shows a
        # recognizable enumeration text (numeric encodings are unspecified).
        trust_text = str(columns.get(13) or "").strip().lower()
        if trust_text in {"low", "high", "both", "none"}:
            state["clock_trust_mode"] = trust_text
    if event.get("object_family") == "TPerInfo" and 7 in columns:
        free = to_int(columns.get(7))
        if free is not None:
            state["sp_issuance_space"] = {
                "free": free,
                "source": "TPerInfo.SpaceForIssuance",
            }
    table_uid = compact_uid(event.get("object_uid"))
    if event.get("object_family") == "Table" or (table_uid and table_uid.startswith("00000001")):
        if table_uid:
            capacity = state.setdefault("table_capacity", {}).setdefault(
                table_uid,
                {"uid": table_uid, "source": "Table.Get"},
            )
            if 7 in columns:
                rows = to_int(columns.get(7))
                if rows is not None:
                    capacity["rows"] = rows
            if 8 in columns:
                rows_free = to_int(columns.get(8))
                if rows_free is not None:
                    capacity["rows_free"] = rows_free
            if 12 in columns:
                max_size = to_int(columns.get(12))
                if max_size is not None:
                    capacity["max_size"] = max_size
            # Evidence-first MBR shadow size: the MBR byte table's observed size
            # (Table.Rows = bytes for byte tables) overrides the 128 MiB default
            # used by the shadow-region overlap rule (opal/4.3.5.4).
            if table_uid == "0000000100000804":
                mbr_bytes = to_int(columns.get(7))
                if mbr_bytes is None:
                    mbr_bytes = to_int(columns.get(12))
                if mbr_bytes is not None and mbr_bytes >= 512:
                    state.setdefault("mbr", {})["table_size_lbas"] = mbr_bytes // 512 - 1


def policy_scope_from_source(source):
    text = str(source or "")
    if text.startswith("opal/4.2"):
        return "AdminSP"
    if text.startswith("opal/4.3"):
        return "LockingSP"
    return None


def policy_row_scope(row):
    return row.get("sp") or policy_scope_from_source(row.get("source"))


def credential_mapping_scope(uid):
    uid = compact_uid(uid)
    if not uid or not uid.startswith("0000000B") or len(uid) < 12:
        return None
    if uid[8:12] in {"0001", "0003"}:
        return "LockingSP"
    if uid[8:12] == "0000":
        return "AdminSP"
    return None


def reset_access_policy_scope(state, sp=None):
    policy = fresh_access_policy()
    if sp is None:
        state["ace_rows"] = policy.get("ace_rows", {})
        state["access_control_rows"] = policy.get("access_control_rows", [])
        state["authority_rows"] = policy.get("authority_rows", {})
        state["credential_to_authority"] = policy.get("credential_to_authority", {})
        return

    state["ace_rows"] = {
        key: row
        for key, row in (state.get("ace_rows") or {}).items()
        if policy_row_scope(row) != sp
    }
    state["ace_rows"].update({
        key: row
        for key, row in (policy.get("ace_rows") or {}).items()
        if policy_row_scope(row) == sp
    })
    state["access_control_rows"] = [
        row
        for row in (state.get("access_control_rows") or [])
        if policy_row_scope(row) != sp
    ] + [
        row
        for row in (policy.get("access_control_rows") or [])
        if policy_row_scope(row) == sp
    ]
    state["authority_rows"] = {
        key: row
        for key, row in (state.get("authority_rows") or {}).items()
        if policy_row_scope(row) != sp
    }
    state["authority_rows"].update({
        key: row
        for key, row in (policy.get("authority_rows") or {}).items()
        if policy_row_scope(row) == sp
    })
    state["credential_to_authority"] = {
        key: value
        for key, value in (state.get("credential_to_authority") or {}).items()
        if credential_mapping_scope(key) != sp
    }
    state["credential_to_authority"].update({
        key: value
        for key, value in (policy.get("credential_to_authority") or {}).items()
        if credential_mapping_scope(key) == sp
    })


def normalized_policy_name(value):
    return re.sub(r"[^0-9A-Za-z]", "", str(value or "")).lower()


def policy_object_key(event):
    uid = compact_uid(event.get("object_uid"))
    if uid:
        return uid
    name = event.get("object")
    normalized = normalized_policy_name(name)
    return normalized or None


def ace_refs_from_value(value):
    raw_items = value if isinstance(value, list) else [value]
    refs = []
    for item in raw_items:
        item_text = str(item or "").strip()
        compact = exact_uid_or_none(item_text)
        ref = compact if compact else normalized_column_name(item_text)
        if ref:
            refs.append(ref)
    return refs


def apply_ace_columns(state, event, columns):
    key = policy_object_key(event)
    if not key:
        return
    row = state.setdefault("ace_rows", {}).setdefault(
        key,
        {
            "uid": compact_uid(event.get("object_uid")),
            "name": event.get("object"),
            "source": "trajectory",
            "sp": state["session"].get("sp"),
        },
    )
    if 3 in columns:
        row["boolean_expr"] = columns[3]
    if 4 in columns:
        row["columns"] = column_list_from_value(columns[4])
    row.setdefault("source", "trajectory")
    row.setdefault("sp", state["session"].get("sp"))


def apply_access_control_columns(state, event, columns):
    key = policy_object_key(event)
    if not key:
        return
    rows = state.setdefault("access_control_rows", [])
    row = next((item for item in rows if item.get("uid") == key or normalized_policy_name(item.get("name")) == key), None)
    if row is None:
        row = {
            "uid": compact_uid(event.get("object_uid")),
            "name": event.get("object"),
            "source": "trajectory",
            "sp": state["session"].get("sp"),
            "ace_refs": [],
        }
        rows.append(row)
    if 1 in columns:
        invoking = columns[1]
        row["invoking_uid"] = exact_uid_or_none(invoking)
        row["invoking_pattern"] = str(invoking or "")
        row["invoking_name"] = invoking
    elif 3 in columns and exact_uid_or_none(columns[3]):
        invoking = columns[3]
        row["invoking_uid"] = exact_uid_or_none(invoking)
        row["invoking_pattern"] = str(invoking or "")
        row["invoking_name"] = invoking
    if 2 in columns:
        row["method"] = method_name_from_value(columns[2])
    elif 4 in columns and str(columns[4]) in METHOD_NAMES:
        row["method"] = method_name_from_value(columns[4])
    if 3 in columns:
        row["common_name"] = columns[3]
    if 4 in columns and str(columns[4]) not in METHOD_NAMES:
        row["ace_refs"] = ace_refs_from_value(columns[4])
    elif 5 in columns:
        row["ace_refs"] = ace_refs_from_value(columns[5])
    if 6 in columns:
        row["add_ace_acl_refs"] = ace_refs_from_value(columns[6])
    if 7 in columns:
        row["remove_ace_acl_refs"] = ace_refs_from_value(columns[7])
    if 8 in columns:
        row["get_acl_acl_refs"] = ace_refs_from_value(columns[8])
    if 9 in columns:
        row["delete_method_acl_refs"] = ace_refs_from_value(columns[9])
    row.setdefault("source", "trajectory")
    row.setdefault("sp", state["session"].get("sp"))


def apply_authority_columns(state, event, columns):
    key = normalize_authority_name(event.get("object_uid") or event.get("object")) or policy_object_key(event)
    if not key:
        return
    row = state.setdefault("authority_rows", {}).setdefault(
        key,
        {
            "uid": compact_uid(event.get("object_uid")),
            "name": event.get("object"),
            "source": "trajectory",
            "sp": state["session"].get("sp"),
        },
    )
    if 4 in columns:
        parsed = to_bool(columns[4])
        if parsed is None:
            row["class"] = normalize_authority_name(columns[4]) or columns[4]
        elif 5 not in columns:
            row["enabled"] = parsed
    if 5 in columns:
        parsed = to_bool(columns[5])
        row["enabled"] = parsed if parsed is not None else bool(columns[5])
    if 6 in columns:
        row["secure"] = columns[6]
    if 9 in columns:
        row["operation"] = columns[9]
    if 10 in columns:
        row["credential"] = compact_uid(columns[10])
        row["credential_name"] = columns[10]
    elif 5 in columns and compact_uid(columns[5]) and to_bool(columns[5]) is None:
        row["credential"] = compact_uid(columns[5])
        row["credential_name"] = columns[5]
    row.setdefault("source", "trajectory")
    row.setdefault("sp", state["session"].get("sp"))


def apply_cpin_policy_columns(state, event, columns):
    uid = compact_uid(event.get("object_uid"))
    authority = event.get("credential_authority") or normalize_authority_name(event.get("object"))
    if uid and authority:
        state.setdefault("credential_to_authority", {})[uid] = authority


def apply_policy_table_columns(state, event, columns):
    family = event.get("object_family")
    if family == "ACE":
        apply_ace_columns(state, event, columns)
    elif family == "AccessControl":
        apply_access_control_columns(state, event, columns)
    elif family == "Authority":
        apply_authority_columns(state, event, columns)
    elif family == "C_PIN":
        apply_cpin_policy_columns(state, event, columns)


def apply_successful_get(state, event):
    target = event.get("object")
    columns = event.get("return_columns") or {}
    credential_authority = event.get("credential_authority")
    merge_table_columns(state, event, columns)
    raw_return_values = ((event.get("raw") or {}).get("output") or {}).get("return_values")
    _merge_dynamic_row_columns(state, event, columns, raw_return_values)
    _merge_dynamic_table_column_metadata(state, event, columns, raw_return_values)
    apply_policy_table_columns(state, event, columns)

    # Capture TryLimit (col 5) for lockout tracking.
    # Always store as int so is_authority_locked_out can compare without TypeError.
    if credential_authority and 5 in columns:
        parsed = to_int(columns[5])
        state.setdefault("trylimit_by_authority", {})[credential_authority] = (
            parsed if parsed is not None else columns[5]
        )

    if credential_authority and 3 in columns:
        state["credentials"][credential_authority] = columns[3]
        clear_credential_candidates(state, credential_authority)
        # opal/3.1.1.5 Initial C_PIN_SID PIN Indicator: 0x00 -> initial SID PIN
        # equals MSID; 0xFF -> vendor unique. Public tc3-tc20 use a VU initial
        # SID PIN, so without discovery evidence MSID is only a *candidate*.
        if credential_authority == "MSID" and state["credentials"].get("SID") is None:
            if state.get("initial_sid_pin_is_msid") is True:
                state["credentials"]["SID"] = columns[3]
            elif state.get("initial_sid_pin_is_msid") is None:
                add_credential_candidate(state, "SID", columns[3])
        return

    if event.get("object_family") == "SP":
        # Observed lifecycle evidence from a successful Get is authoritative
        # device-confirmed state (opal/5.2.3 enumeration).
        apply_sp_lifecycle_columns(state, event, columns)
        return

    if event.get("object_family") == "Locking":
        merge_locking_columns(state, event.get("locking_range"), columns)
        return

    if target == "MBRControl":
        merge_mbr_columns(state, columns)


# opal/5.2.3 Table 49: life_cycle_state enumeration. Values 0/1 are left to the
# legacy boolean path below because bare 0/1 in traces usually encode Enabled.
_LIFE_CYCLE_STATE_BY_NUMBER = {
    2: "Issued-Frozen",
    3: "Issued-Disabled-Frozen",
    4: "Failed",
    8: "Manufactured-Inactive",
    9: "Manufactured",
    10: "Issued-Disabled",
    11: "Issued-Frozen",
    12: "Issued-Disabled-Frozen",
    13: "Failed",
}

_LIFE_CYCLE_STATE_BY_TOKEN = {
    "issued": "Issued",
    "issueddisabled": "Issued-Disabled",
    "issuedfrozen": "Issued-Frozen",
    "issueddisabledfrozen": "Issued-Disabled-Frozen",
    "issuedfailed": "Failed",
    "manufacturedinactive": "Manufactured-Inactive",
    "manufactured": "Manufactured",
    "manufactureddisabled": "Issued-Disabled",
    "manufacturedfrozen": "Issued-Frozen",
    "manufactureddisabledfrozen": "Issued-Disabled-Frozen",
    "manufacturedfailed": "Failed",
}


def canonical_life_cycle_state(value):
    """Map a life_cycle_state cell (numeric enum or text) to the tracked
    canonical lifecycle string, or None when ambiguous/unrecognized."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return _LIFE_CYCLE_STATE_BY_NUMBER.get(value)
    text = str(value or "").strip()
    if text.isdigit():
        return _LIFE_CYCLE_STATE_BY_NUMBER.get(int(text))
    token = re.sub(r"[^0-9a-z]", "", text.lower())
    return _LIFE_CYCLE_STATE_BY_TOKEN.get(token)


def apply_sp_lifecycle_columns(state, event, columns):
    uid = compact_uid(event.get("object_uid"))
    sp_name = canonical_sp(uid) if uid else None
    if not sp_name or (sp_name not in ("AdminSP", "LockingSP") and not str(sp_name).startswith("SP_")):
        return
    lifecycle = state.setdefault("sp_lifecycle", {})
    if 6 in columns:
        # Full enumeration values (numeric or spelled-out state names) are
        # authoritative device-confirmed lifecycle evidence (opal/5.2.3).
        canonical = canonical_life_cycle_state(columns[6])
        if canonical is not None:
            lifecycle[sp_name] = canonical
            if sp_name == "LockingSP":
                state["locking_sp_active"] = canonical == "Manufactured"
            return
        text = str(columns[6] or "").lower().replace("-", "").replace("_", "").replace(" ", "")
        if "failed" in text or "spfail" in text:
            lifecycle[sp_name] = "Failed"
            return
        val = to_bool(columns[6])
        if val is False:
            current = lifecycle.get(sp_name, "Manufactured")
            if "Frozen" in current:
                lifecycle[sp_name] = "Issued-Disabled-Frozen"
            else:
                lifecycle[sp_name] = "Issued-Disabled"
        elif val is True:
            current = lifecycle.get(sp_name, "Manufactured")
            if "Frozen" in current:
                lifecycle[sp_name] = "Issued-Frozen"
            elif "Inactive" not in current:
                lifecycle[sp_name] = "Manufactured"
    if 7 in columns:
        val = to_bool(columns[7])
        if val is True:
            current = lifecycle.get(sp_name, "Manufactured")
            if "Disabled" in current:
                lifecycle[sp_name] = "Issued-Disabled-Frozen"
            else:
                lifecycle[sp_name] = "Issued-Frozen"
        elif val is False:
            current = lifecycle.get(sp_name, "Manufactured")
            if "Disabled" in current:
                lifecycle[sp_name] = "Issued-Disabled"
            elif "Inactive" not in current:
                lifecycle[sp_name] = "Manufactured"


def apply_sp_enabled_state(state, sp_name, enabled):
    if not sp_name:
        return
    lifecycle = state.setdefault("sp_lifecycle", {})
    current = lifecycle.get(sp_name, "Issued")
    if enabled is False:
        if "Frozen" in current:
            lifecycle[sp_name] = "Issued-Disabled-Frozen"
        else:
            lifecycle[sp_name] = "Issued-Disabled"
        return
    if "Disabled" in current and "Frozen" in current:
        lifecycle[sp_name] = "Issued-Frozen"
    elif "Disabled" in current:
        lifecycle[sp_name] = "Issued"


def issue_sp_template_uid(value):
    if isinstance(value, dict):
        found = find_named_value(value, {"UID", "TemplateID", "Template"})
        if found is not None:
            return compact_uid(_uid_value(found))
        if len(value) == 1:
            return issue_sp_template_uid(next(iter(value.values())))
        return None
    if isinstance(value, (list, tuple)) and len(value) == 1:
        return issue_sp_template_uid(value[0])
    return compact_uid(_uid_value(value))


def _uid_value(value):
    if isinstance(value, dict):
        for key in ("uid", "UID", "Uid"):
            if key in value:
                return _uid_value(value[key])
        if len(value) == 1:
            return _uid_value(next(iter(value.values())))
        return None
    if isinstance(value, (list, tuple)) and len(value) == 1:
        return _uid_value(value[0])
    return value


def issue_sp_size_bytes(size_blocks):
    parsed = to_int(size_blocks)
    if parsed is None or parsed < 0:
        return None
    return parsed * 512


def issue_sp_size_blocks(size_value):
    parsed = to_int(size_value)
    if parsed is None or parsed < 0:
        return None
    return parsed


def remove_sp_name(state, sp_name):
    if not sp_name:
        return
    key = re.sub(r"[^0-9A-Za-z]", "", str(sp_name or "")).lower()
    names = state.setdefault("sp_names", {})
    for name_key, value in list(names.items()):
        if name_key == key or value == sp_name:
            names.pop(name_key, None)


def issued_sp_entry_for_sp(state, sp_name):
    for uid, entry in (state.get("issued_sps") or {}).items():
        if entry.get("sp") == sp_name or entry.get("uid") == sp_name:
            return uid, entry
    return None, None


def release_issued_sp_template_instances(state, entry):
    if not entry or entry.get("template_instances_released"):
        return
    templates = {compact_uid(template) for template in (entry.get("templates") or [])}
    templates.discard(None)
    if not templates:
        return
    released = False
    for key, row in (state.get("tables") or {}).items():
        values = row.get("values") or {}
        template_uid = compact_uid(values.get("UID")) or compact_uid(key)
        if template_uid not in templates:
            continue
        columns = row.setdefault("columns", {})
        current = to_int(values.get("Instances") or columns.get(3))
        if current is None or current <= 0:
            continue
        values["Instances"] = current - 1
        columns[3] = current - 1
        released = True
    if released:
        entry["template_instances_released"] = True


def mark_issued_sp_deleted(state, sp_name, deleted_by):
    uid, entry = issued_sp_entry_for_sp(state, sp_name)
    if entry is None:
        return
    already_deleted = entry.get("deleted") is True
    entry["deleted"] = True
    entry["deleted_by"] = deleted_by
    entry["lifecycle"] = "Deleted"
    if not already_deleted:
        release_issued_sp_template_instances(state, entry)
    state.setdefault("sp_lifecycle", {})[entry.get("sp") or sp_name] = "Deleted"
    if uid:
        state.setdefault("deleted_sps", set()).add(entry.get("sp") or sp_name)


def apply_successful_issue_sp(state, event):
    raw_out = (event.get("raw") or {}).get("output") or {}
    return_values = raw_out.get("return_values") or {}
    parameters = event.get("parameters") or {}
    issuance_space = state.get("sp_issuance_space") or {}
    free = to_int(issuance_space.get("free"))
    returned_size = to_int(find_named_value(return_values, {"Size"}))
    requested_size = to_int(find_named_value(parameters, {"Size"}))
    allocated_size = returned_size if returned_size is not None else requested_size
    allocated_size_bytes = issue_sp_size_bytes(allocated_size)
    size_evidence = "returned_size" if returned_size is not None else "requested_size_blocks"
    # Compatibility: some generated legacy traces omit IssueSP's returned
    # Size and encode a request exactly equal to the learned byte budget.  The
    # spec says Size is in 512-byte blocks, so all explicit returned sizes are
    # block-converted. Public generated legacy traces omit returned Size and
    # treat the request value as the only byte-bound for later GetFreeSpace
    # checks; keep that compatibility bound visibly non-exact.
    if (
        returned_size is None
        and requested_size is not None
        and requested_size >= 512
        and (free is None or requested_size == free)
    ):
        allocated_size_bytes = requested_size
        size_evidence = "legacy_request_bound"
    allocated_size_blocks = issue_sp_size_blocks(allocated_size)
    if free is not None and allocated_size_bytes is not None:
        issuance_space["free"] = max(0, free - allocated_size_bytes)
        issuance_space.setdefault("source", "TPerInfo.SpaceForIssuance")
        state["sp_issuance_space"] = issuance_space
    templates = find_named_value(parameters, {"Templates"})
    requested_templates = {
        issue_sp_template_uid(template)
        for template in templates
    } if isinstance(templates, list) else set()
    requested_templates.discard(None)
    for key, row in (state.get("tables") or {}).items():
        values = row.get("values") or {}
        template_uid = compact_uid(values.get("UID")) or compact_uid(key)
        if template_uid not in requested_templates:
            continue
        current = to_int(values.get("Instances") or (row.get("columns") or {}).get(3))
        maximum = to_int(values.get("MaxInstances") or (row.get("columns") or {}).get(4))
        if current is None or (maximum is not None and current >= maximum):
            continue
        values["Instances"] = current + 1
        row.setdefault("columns", {})[3] = current + 1
    sp_uid = (
        compact_uid(_uid_value(find_named_value(return_values, {"UID", "SPID", "SPUID"})))
        or compact_uid(_uid_value(find_named_value(parameters, {"UID", "SPID", "SPUID"})))
    )
    sp_name = canonical_sp(sp_uid)
    issued_name = find_named_value(parameters, {"SPName"})
    if issued_name is not None:
        name_key = re.sub(r"[^0-9A-Za-z]", "", str(issued_name or "")).lower()
        state.setdefault("sp_names", {})[name_key] = sp_name or f"SPName:{issued_name}"
    if not sp_name or (sp_name not in ("AdminSP", "LockingSP") and not str(sp_name).startswith("SP_")):
        return
    enabled = to_bool(find_named_value(parameters, {"Enabled"}))
    state.setdefault("sp_lifecycle", {})[sp_name] = "Issued-Disabled" if enabled is False else "Issued"
    name = find_named_value(parameters, {"SPName"})
    if name is not None:
        state.setdefault("issued_sp_names", set()).add(str(name))
    state.setdefault("issued_sps", {})[sp_uid] = {
        "uid": sp_uid,
        "sp": sp_name,
        "name": str(name) if name is not None else None,
        "size": allocated_size_bytes,
        "size_blocks": allocated_size_blocks,
        "requested_size_blocks": requested_size,
        "size_evidence": size_evidence,
        "size_is_exact": returned_size is not None,
        "templates": sorted(requested_templates),
        "enabled": enabled,
        "source": "IssueSP",
    }


def _returned_uid_from_event(event, *names):
    def _uid(value):
        if isinstance(value, dict):
            for key in ("uid", "UID", "Uid"):
                if key in value:
                    return _uid(value[key])
            if len(value) == 1:
                return _uid(next(iter(value.values())))
            return None
        if isinstance(value, (list, tuple)) and len(value) == 1:
            return _uid(value[0])
        compact = compact_uid(value)
        return compact if compact and len(compact) == 16 else None

    ret = event.get("return_columns") or {}
    uid = _uid(ret.get("uid") or ret.get("UID") or ret.get(0))
    if uid:
        return uid
    raw_out = (event.get("raw") or {}).get("output") or {}
    return_values = raw_out.get("return_values") or {}
    return _uid(find_named_value(return_values, set(names) | {"UID", "TableUID"}))


def _column_number_from_definition(item, implicit_index=None):
    if not isinstance(item, dict):
        return implicit_index
    raw = find_named_value(item, {"ColumnNumber", "ColumnNo", "Column", "Number"})
    parsed = to_int(raw)
    if parsed is not None:
        return parsed
    return implicit_index


def _column_names_from_definition(item):
    names = []
    if not isinstance(item, dict):
        return names
    for key in ("Name", "CommonName"):
        value = find_named_value(item, {key})
        if value is None:
            continue
        text = normalized_column_name(value)
        if text and text not in names:
            names.append(text)
    return names


def _is_unique_column_definition(item):
    if not isinstance(item, dict):
        return False
    raw = find_named_value(item, {"IsUnique", "Unique", "is_unique"})
    return raw is not None and to_bool(raw) is True


def _column_type_from_definition(item):
    if not isinstance(item, dict):
        return None
    raw = find_named_value(item, {"Type", "ColumnType", "DataType"})
    return str(raw) if raw is not None else None


def _create_table_column_metadata(columns):
    numbers = []
    unique_columns = []
    name_numbers = {}
    column_types = {}

    def add_definition(item, implicit_index=None):
        column = _column_number_from_definition(item, implicit_index)
        if column is None:
            parsed = column_list_from_value(item)
            if isinstance(parsed, list) and len(parsed) == 1:
                column = parsed[0]
        if column is None:
            return
        if column not in numbers:
            numbers.append(column)
        if _is_unique_column_definition(item) and column not in unique_columns:
            unique_columns.append(column)
        for name in _column_names_from_definition(item):
            name_numbers[name] = column
        column_type = _column_type_from_definition(item)
        if column_type is not None:
            column_types[column] = column_type

    if isinstance(columns, list):
        for index, item in enumerate(columns, start=1):
            if isinstance(item, dict):
                add_definition(item, index)
        return {
            "column_numbers": numbers,
            "unique_columns": unique_columns,
            "column_name_numbers": name_numbers,
            "column_types": column_types,
        }
    if isinstance(columns, dict):
        definition_keys = {
            "columnnumber", "columnno", "column", "number",
            "isunique", "unique", "is_unique", "name", "commonname", "type",
        }
        if any(str(key).strip().lower() in definition_keys for key in columns):
            add_definition(columns)
            return {
                "column_numbers": numbers,
                "unique_columns": unique_columns,
                "column_name_numbers": name_numbers,
                "column_types": column_types,
            }
        nested = find_named_value(columns, {"Columns", "ColumnList"})
        if nested is not None and nested is not columns:
            return _create_table_column_metadata(nested)
        add_definition(columns)
    return {
        "column_numbers": numbers,
        "unique_columns": unique_columns,
        "column_name_numbers": name_numbers,
        "column_types": column_types,
    }


def _create_table_column_numbers(columns):
    return _create_table_column_metadata(columns)["column_numbers"]


def _dynamic_table_uid_from_column_metadata(state, values):
    dynamic_tables = state.get("dynamic_tables") or {}
    if not dynamic_tables:
        return None
    explicit = find_named_value(values, {
        "TableUID", "TableID", "Table", "TableName", "ParentTable",
        "ParentTableUID", "ObjectTable", "Object",
    })
    explicit_uid = compact_uid(explicit)
    if explicit_uid in dynamic_tables:
        return explicit_uid
    if explicit is not None:
        explicit_name = normalized_column_name(explicit)
        matches = [
            table_uid
            for table_uid, table in dynamic_tables.items()
            if explicit_name and explicit_name in {
                normalized_column_name(table_uid),
                normalized_column_name(table.get("name")),
                normalized_column_name(table.get("common_name")),
            }
        ]
        if len(matches) == 1:
            return matches[0]
    return None


def apply_successful_create_table(state, event):
    table_uid = _returned_uid_from_event(event, "NewTableUID", "TableUID")
    if not table_uid:
        return
    params = event.get("parameters") or {}
    table_name = find_named_value(params, {"NewTableName"})
    if table_name is None:
        table_name = params.get("NewTableName")
    common_name = find_named_value(params, {"CommonName"})
    kind_raw = find_named_value(params, {"Kind"})
    kind = str(kind_raw).strip().lower() if kind_raw is not None else None
    if kind in {"0", "objecttable", "object_table"}:
        kind = "object"
    elif kind in {"1", "bytetable", "byte_table", "bytes"}:
        kind = "byte"
    sp = state.get("session", {}).get("sp")
    columns = find_named_value(params, {"Columns"})
    get_set_acl_refs = ace_refs_from_value(find_named_value(params, {"GetSetACL"}))
    min_size = to_int(find_named_value(params, {"MinSize"}))
    max_size = to_int(find_named_value(params, {"MaxSize"}))
    hint_size = to_int(find_named_value(params, {"HintSize"}))
    column_metadata = _create_table_column_metadata(columns)
    record = {
        "uid": table_uid,
        "name": str(table_name) if table_name is not None else None,
        "common_name": "" if common_name is None else str(common_name),
        "sp": sp,
        "source": _trajectory_source(state),
        "kind": kind,
        "columns_parameter": columns,
        "get_set_acl_refs": get_set_acl_refs,
        "column_numbers": column_metadata["column_numbers"],
        "unique_columns": column_metadata["unique_columns"],
        "column_name_numbers": column_metadata["column_name_numbers"],
        "column_types": column_metadata["column_types"],
        "schema_complete": columns is not None,
        "schema_source": "CreateTable.Columns",
        "min_size": min_size,
        "max_size": max_size,
        "hint_size": hint_size,
        "rows": 0,
        "rows_free": min_size,
        "row_inventory_complete": True,
    }
    state.setdefault("dynamic_tables", {})[table_uid] = record
    state.setdefault("dynamic_table_names", {})[(sp, record["name"], record["common_name"])] = table_uid
    state.setdefault("tables", {})[table_uid] = {
        "source": record["source"],
        "sp": sp,
        "table": "Dynamic Table",
        "name": record["name"],
        "common_name": record["common_name"],
        "kind": kind,
        "values": {
            "UID": table_uid,
            "Name": record["name"],
            "CommonName": record["common_name"],
            "Kind": kind,
            "MinSize": min_size,
            "MaxSize": max_size,
            "GetSetACL": get_set_acl_refs,
            "Rows": 0,
            "RowsFree": min_size,
        },
        "columns": {
            0: table_uid,
            1: record["name"],
            2: record["common_name"],
            4: kind,
            5: record["column_numbers"],
            6: get_set_acl_refs,
            7: 0,
            8: min_size,
            11: min_size,
            12: max_size,
        },
    }
    for method_name in ("Get", "Set"):
        state.setdefault("access_control_rows", []).append({
            "uid": None,
            "name": f"{record['name'] or table_uid}_{method_name}_ACL",
            "invoking_uid": table_uid,
            "invoking_name": record["name"] or table_uid,
            "method": method_name,
            "ace_refs": list(get_set_acl_refs),
            "add_ace_acl_refs": ["0000000800000002"],
            "remove_ace_acl_refs": ["0000000800000002"],
            "delete_method_acl_refs": ["0000000800000002"],
            "get_acl_acl_refs": ["0000000800000001"],
            "source": record["source"],
            "sp": sp,
            "dynamic_table_uid": table_uid,
        })
    table_capacity = (state.get("table_capacity") or {}).get("0000000100000001")
    if table_capacity is not None:
        rows = to_int(table_capacity.get("rows"))
        rows_free = to_int(table_capacity.get("rows_free"))
        if rows is not None:
            table_capacity["rows"] = rows + 1
        if rows_free is not None:
            table_capacity["rows_free"] = max(0, rows_free - 1)


def _sync_dynamic_table_column_state(state, table_uid):
    table = (state.get("dynamic_tables") or {}).get(table_uid)
    table_row = (state.get("tables") or {}).get(table_uid)
    if not table or not table_row:
        return
    numbers = list(table.get("column_numbers") or [])
    table_row.setdefault("columns", {})[5] = numbers
    table_row.setdefault("values", {})["Column"] = numbers


def _merge_dynamic_table_column_metadata(state, event, columns, return_values):
    if event.get("object_family") != "Column":
        return
    table_uid = _dynamic_table_uid_from_column_metadata(state, return_values)
    if not table_uid:
        return
    table = (state.get("dynamic_tables") or {}).get(table_uid)
    if table is None:
        return

    column = to_int((columns or {}).get(5))
    if column is None:
        column = to_int(find_named_value(return_values, {"ColumnNumber", "ColumnNo", "Column", "Number"}))
    if column is None:
        return

    numbers = table.setdefault("column_numbers", [])
    if column not in numbers:
        numbers.append(column)

    names = table.setdefault("column_name_numbers", {})
    for raw_name in ((columns or {}).get(1), (columns or {}).get(2)):
        text = normalized_column_name(raw_name)
        if text:
            names[text] = column
    for raw_name in _column_names_from_definition(return_values):
        names[raw_name] = column

    unique = to_bool((columns or {}).get(4))
    if unique is None:
        unique = to_bool(find_named_value(return_values, {"IsUnique", "Unique", "is_unique"}))
    if unique is True:
        unique_columns = table.setdefault("unique_columns", [])
        if column not in unique_columns:
            unique_columns.append(column)

    column_type = (columns or {}).get(3)
    if column_type is None:
        column_type = find_named_value(return_values, {"Type", "ColumnType", "DataType"})
    if column_type is not None:
        table.setdefault("column_types", {})[column] = str(column_type)

    table.setdefault("schema_complete", False)
    table["schema_source"] = "Column.Get"
    table.setdefault("column_rows", {})[compact_uid(event.get("object_uid")) or f"column:{column}"] = {
        "column_number": column,
        "name": (columns or {}).get(1) or find_named_value(return_values, {"Name"}),
        "common_name": (columns or {}).get(2) or find_named_value(return_values, {"CommonName"}),
        "type": column_type,
        "is_unique": unique,
        "source": "Column.Get",
    }
    _sync_dynamic_table_column_state(state, table_uid)


def _uids_from_value(value):
    uids = []
    if isinstance(value, dict):
        for key in ("uid", "UID", "Uid", "RowUID", "Row", "Result"):
            if key in value:
                compact = compact_uid(value[key])
                if compact and len(compact) == 16 and compact not in uids:
                    uids.append(compact)
        for item in value.values():
            for uid in _uids_from_value(item):
                if uid not in uids:
                    uids.append(uid)
    elif isinstance(value, (list, tuple)):
        for item in value:
            for uid in _uids_from_value(item):
                if uid not in uids:
                    uids.append(uid)
    else:
        compact = compact_uid(value)
        if compact and len(compact) == 16:
            uids.append(compact)
    return uids


def _returned_uids_from_event(event):
    raw_out = (event.get("raw") or {}).get("output") or {}
    return _uids_from_value(raw_out.get("return_values"))


def _dynamic_table_uid(event):
    uid = compact_uid(event.get("object_uid"))
    return uid if uid else None


def _column_number_from_key(key):
    if isinstance(key, int):
        return key
    text = str(key).strip()
    if not text:
        return None
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        if text.isdigit():
            return int(text, 10)
    except ValueError:
        return None
    return None


def _row_column_values_from_value(value, table=None):
    columns = {}
    wrappers = {"row", "rowvalues", "values", "returnvalues"}
    name_numbers = {
        normalized_column_name(name): number
        for name, number in ((table or {}).get("column_name_numbers") or {}).items()
    }
    if isinstance(value, dict):
        for key, item in value.items():
            normalized_key = str(key).strip().lower()
            if normalized_key in wrappers:
                columns.update(_row_column_values_from_value(item, table))
                continue
            column = _column_number_from_key(key)
            if column is None:
                column = name_numbers.get(normalized_column_name(key))
            if column is not None:
                columns[column] = item
            elif isinstance(item, (dict, list, tuple)):
                columns.update(_row_column_values_from_value(item, table))
    elif isinstance(value, (list, tuple)):
        for item in value:
            columns.update(_row_column_values_from_value(item, table))
    return columns


def _dynamic_row_context(state, event):
    row_uid = compact_uid(event.get("object_uid"))
    table_uid = (state.get("dynamic_row_table") or {}).get(row_uid)
    if not table_uid:
        candidate_table_uid = _dynamic_table_uid(event)
        if candidate_table_uid in (state.get("dynamic_tables") or {}):
            where_uids = _uids_from_value((event.get("parameters") or {}).get("Where"))
            row_uid = where_uids[0] if where_uids else None
            table_uid = candidate_table_uid if row_uid else None
    if not row_uid or not table_uid:
        return None, None, None
    row = ((state.get("dynamic_rows") or {}).get(table_uid) or {}).get(row_uid)
    table = (state.get("dynamic_tables") or {}).get(table_uid)
    if not row or not table:
        return None, None, None
    return row_uid, row, table


def _merge_dynamic_row_columns(state, event, columns, raw_values):
    row_uid, row, table = _dynamic_row_context(state, event)
    if not row:
        return
    merged = dict(row.get("columns") or {})
    merged.update(columns or {})
    merged.update(_row_column_values_from_value(raw_values, table))
    if merged:
        row["columns"] = merged
        row["values"] = {str(column): value for column, value in sorted(merged.items())}


def _adjust_dynamic_table_counts(state, table_uid, row_delta):
    table = (state.get("dynamic_tables") or {}).get(table_uid)
    if not table:
        return
    rows = table.get("rows")
    rows_free = table.get("rows_free")
    if rows is not None:
        table["rows"] = max(0, rows + row_delta)
    if rows_free is not None:
        table["rows_free"] = max(0, rows_free - row_delta)
    table_row = (state.get("tables") or {}).get(table_uid) or {}
    cols = table_row.setdefault("columns", {})
    vals = table_row.setdefault("values", {})
    if rows is not None:
        cols[7] = table["rows"]
        vals["Rows"] = table["rows"]
    if rows_free is not None:
        cols[8] = table["rows_free"]
        vals["RowsFree"] = table["rows_free"]


def apply_successful_create_row(state, event):
    table_uid = _dynamic_table_uid(event)
    if table_uid not in (state.get("dynamic_tables") or {}):
        return
    row_uids = _returned_uids_from_event(event)
    if not row_uids:
        state["dynamic_tables"][table_uid]["row_inventory_complete"] = False
        return
    row_value = (event.get("parameters") or {}).get("Row")
    rows = state.setdefault("dynamic_rows", {}).setdefault(table_uid, {})
    created = 0
    for row_uid in row_uids:
        if row_uid in rows:
            continue
        rows[row_uid] = {
            "uid": row_uid,
            "table_uid": table_uid,
            "values": row_value,
            "columns": _row_column_values_from_value(row_value, state["dynamic_tables"].get(table_uid)),
            "source": _trajectory_source(state),
        }
        state.setdefault("dynamic_row_table", {})[row_uid] = table_uid
        created += 1
    if created:
        _adjust_dynamic_table_counts(state, table_uid, created)


def apply_successful_next(state, event):
    template_table_uid = "0000000100000204"
    table_uid = compact_uid(event.get("object_uid"))
    if table_uid != template_table_uid:
        return
    returned = _returned_uids_from_event(event)
    if not returned:
        return
    inventory = state.setdefault("template_inventory", {"complete": False, "available": set(), "source": None})
    inventory.setdefault("available", set()).update(returned)
    inventory["source"] = "Template.Next"
    capacity = (state.get("table_capacity") or {}).get(template_table_uid) or {}
    rows = to_int(capacity.get("rows"))
    requested = to_int((event.get("parameters") or {}).get("Count"))
    if rows is not None and requested is not None and requested >= rows and len(inventory.get("available") or set()) >= rows:
        inventory["complete"] = True


def apply_successful_delete_row(state, event):
    table_uid = _dynamic_table_uid(event)
    rows = (state.get("dynamic_rows") or {}).get(table_uid)
    if not rows:
        return
    requested = _uids_from_value((event.get("parameters") or {}).get("Rows"))
    table = (state.get("dynamic_tables") or {}).get(table_uid)
    if table and table.get("row_inventory_complete") and any(row_uid not in rows for row_uid in requested):
        return
    deleted = 0
    for row_uid in requested:
        if row_uid in rows:
            rows.pop(row_uid, None)
            state.setdefault("dynamic_row_table", {}).pop(row_uid, None)
            state.setdefault("deleted_dynamic_rows", set()).add(row_uid)
            deleted += 1
    if deleted:
        _adjust_dynamic_table_counts(state, table_uid, -deleted)


def apply_successful_dynamic_delete(state, event):
    uid = compact_uid(event.get("object_uid"))
    if not uid:
        return
    table_uid = (state.get("dynamic_row_table") or {}).pop(uid, None)
    if table_uid:
        rows = (state.get("dynamic_rows") or {}).get(table_uid) or {}
        if uid in rows:
            rows.pop(uid, None)
            state.setdefault("deleted_dynamic_rows", set()).add(uid)
            _adjust_dynamic_table_counts(state, table_uid, -1)
        return
    if uid in (state.get("dynamic_tables") or {}):
        for row_uid in list((state.get("dynamic_rows") or {}).get(uid, {}).keys()):
            state.setdefault("dynamic_row_table", {}).pop(row_uid, None)
            state.setdefault("deleted_dynamic_rows", set()).add(row_uid)
        state.setdefault("dynamic_rows", {}).pop(uid, None)
        table = state.setdefault("dynamic_tables", {}).pop(uid, None)
        if table:
            state.setdefault("dynamic_table_names", {}).pop((table.get("sp"), table.get("name"), table.get("common_name")), None)
        state.setdefault("tables", {}).pop(uid, None)
        state.setdefault("deleted_dynamic_tables", set()).add(uid)
        table_capacity = (state.get("table_capacity") or {}).get("0000000100000001")
        if table_capacity is not None:
            rows = to_int(table_capacity.get("rows"))
            rows_free = to_int(table_capacity.get("rows_free"))
            if rows is not None:
                table_capacity["rows"] = max(0, rows - 1)
            if rows_free is not None:
                table_capacity["rows_free"] = rows_free + 1
        state["access_control_rows"] = [
            row for row in (state.get("access_control_rows") or [])
            if row.get("dynamic_table_uid") != uid
        ]


def apply_successful_set(state, event):
    target = event.get("object")
    columns = event.get("value_columns") or {}
    credential_authority = event.get("credential_authority")
    merge_table_columns(state, event, columns)
    values = (event.get("parameters") or {}).get("Values")
    _merge_dynamic_row_columns(state, event, columns, values)
    _merge_dynamic_table_column_metadata(state, event, columns, values)
    apply_policy_table_columns(state, event, columns)

    # Capture TryLimit (col 5) for lockout tracking.
    # Always store as int so is_authority_locked_out can compare without TypeError.
    if credential_authority and 5 in columns:
        parsed = to_int(columns[5])
        state.setdefault("trylimit_by_authority", {})[credential_authority] = (
            parsed if parsed is not None else columns[5]
        )

    # spec core/3.3.7.4: Set of Tries (col 6) to 0 resets the failed-auth counter/lockout.
    if credential_authority and 6 in columns:
        tries_val = to_int(columns[6])
        if tries_val == 0:
            state.setdefault("failed_auth_counts", {}).pop(credential_authority, None)

    if credential_authority and 3 in columns:
        state["credentials"][credential_authority] = columns[3]
        clear_credential_candidates(state, credential_authority)
        state.setdefault("failed_auth_counts", {}).pop(credential_authority, None)
        # Note: a post-Activate SID change does NOT propagate to Admin1 — the
        # opal/5.1.1.2 copy happens only at Activate (cross_fail_05 evidence).
        return

    if event.get("object_family") == "SP":
        apply_sp_lifecycle_columns(state, event, columns)
        return

    if event.get("object_family") == "Locking":
        merge_locking_columns(state, event.get("locking_range"), columns)
        return

    if target == "MBRControl":
        merge_mbr_columns(state, columns)


def apply_successful_activate(state, event):
    if event.get("object") != "LockingSP":
        return
    already_active = state.get("locking_sp_active", False)
    state["locking_sp_active"] = True
    state["sp_lifecycle"]["LockingSP"] = "Manufactured"
    # spec opal/5.1.1.2 (SHALL): SID → Admin1 copy happens on first Activate
    # (transition out of Inactive) and the labeled suites treat the copy as
    # authoritative (cross_fail_05, opal_fail_79, tc5 mutation). A repeat
    # Activate is a no-op; do not re-copy. When SID itself is only known as a
    # candidate, the copy is also only a candidate.
    if not already_active:
        sid_value = state["credentials"].get("SID")
        if sid_value is not None:
            state["credentials"]["Admin1"] = sid_value
            clear_credential_candidates(state, "Admin1")
        else:
            for sid_candidate in (state.get("credential_candidates") or {}).get("SID", []):
                add_credential_candidate(state, "Admin1", sid_candidate)


def bump_key_generation_for_range(state, range_name):
    if not range_name:
        return
    current = state["key_generations_by_range"].get(range_name, 0)
    state["key_generations_by_range"][range_name] = current + 1


def apply_successful_gen_key(state, event):
    key = event.get("object") or "unknown"
    state["key_generations"][key] = state["key_generations"].get(key, 0) + 1

    key_range = event.get("key_range")
    if key_range:
        bump_key_generation_for_range(state, key_range)

    # spec core/5.3.4.1.1.1: GenKey on C_PIN generates a new PIN — credential is now unknown
    if event.get("object_family") == "C_PIN":
        authority = event.get("credential_authority")
        if authority and authority in state["credentials"]:
            old_val = state["credentials"][authority]
            state["credentials"][authority] = None
            if old_val is not None:
                # Remember the old value so the oracle can reject it if used after GenKey
                state.setdefault("invalidated_credentials", {})[authority] = old_val
            state.setdefault("failed_auth_counts", {}).pop(authority, None)


def reset_locking_sp(state, preserve_global_key=False):
    # spec opal/5.1.2.2: user-data removal and key eradication only when LockingSP was active;
    # Revert on an already-inactive LockingSP has no effect on user data or media keys.
    locking_was_active = state.get("locking_sp_active", False)
    previous_ranges = set(state.get("locking_ranges", {})) or {"Global"}
    default_ranges = default_locking_ranges()
    affected_ranges = previous_ranges | set(default_ranges) | {"Global"}
    if locking_was_active:
        for range_name in affected_ranges:
            if preserve_global_key and range_name == "Global":
                continue
            bump_key_generation_for_range(state, range_name)

    state["locking_sp_active"] = False
    state["sp_lifecycle"]["LockingSP"] = "Manufactured-Inactive"
    state["locking_ranges"] = default_ranges
    state["mbr"] = default_mbr_control()
    # Restore LockingSP credentials to factory defaults (spec opal/4.3.1.9 Table 41).
    # Admin1 PIN is unknown until next Activate (set from SID at that point).
    # Admin2-4 and User1-8 all reset to empty string per OFS.
    state["credentials"]["Admin1"] = None
    state["credentials"]["Admin2"] = ""
    state["credentials"]["Admin3"] = ""
    state["credentials"]["Admin4"] = ""
    for _n in range(1, 9):
        state["credentials"][f"User{_n}"] = ""
    # Failed-auth counters and TryLimit overrides revert to OFS (all zero) with the SP.
    # Only clear entries that belong to LockingSP authorities; AdminSP counters are unaffected.
    _locking_auths = {"Admin1", "Admin2", "Admin3", "Admin4"} | {f"User{n}" for n in range(1, 9)}
    for _auth in _locking_auths:
        state.setdefault("failed_auth_counts", {}).pop(_auth, None)
        state.setdefault("trylimit_by_authority", {}).pop(_auth, None)
        state.setdefault("invalidated_credentials", {}).pop(_auth, None)
        clear_credential_candidates(state, _auth)
    reset_access_policy_scope(state, "LockingSP")
    # spec opal/4.3.1.8: ensure User2-User8 are restored to disabled OFS after reset.
    # reset_access_policy_scope only affects rows whose source matches "opal/4.3.*" scope;
    # synthetic User2-User8 rows use source="LockingSP" (not an opal/ prefix) so they
    # survive the scope-filtered reset. Re-seed them explicitly.
    for _n in range(2, 9):
        _user = f"User{_n}"
        state["authority_rows"][_user] = {
            "name": _user,
            "enabled": False,
            "is_class": False,
            "class": "Users",
            "operation": "Password",
            "source": "LockingSP",
        }


def reset_admin_sp_credentials(state):
    # spec opal/5.1.2.2.1: if SID was ever authenticated, the SID PIN resets to
    # the MSID PIN when the discovery "Behavior upon TPer Revert" field is 0x00,
    # and to a vendor-unique value when it is 0xFF; without discovery evidence
    # the MSID value is only a candidate.
    sid_was_authenticated = "SID" in state.get("authenticated_history", set())
    if sid_was_authenticated:
        msid_value = state["credentials"].get("MSID")
        clear_credential_candidates(state, "SID")
        if state.get("revert_sid_pin_is_msid") is True:
            state["credentials"]["SID"] = msid_value
        else:
            state["credentials"]["SID"] = None
            if state.get("revert_sid_pin_is_msid") is None and msid_value is not None:
                add_credential_candidate(state, "SID", msid_value)
    state["credentials"]["MSID"] = None
    state["credentials"]["Admin1"] = None
    clear_credential_candidates(state, "Admin1")
    # Clear history so a subsequent Revert uses the post-factory-reset baseline
    state["authenticated_history"] = set()
    reset_access_policy_scope(state, "AdminSP")


def apply_successful_revert(state, event):
    target = event.get("object")
    if target == "LockingSP":
        reset_locking_sp(state)
    elif target == "AdminSP":
        # spec opal/5.2.2.2: full TPer factory reset — LockingSP returns to OFS (Manufactured-Inactive)
        reset_locking_sp(state)
        reset_admin_sp_credentials(state)
        state["sp_lifecycle"]["AdminSP"] = "Manufactured"
        # All per-session policy and lockout state goes back to factory defaults
        state["tables"] = default_table_rows()
        state["trylimit_by_authority"] = {}
        state["failed_auth_counts"] = {}
        # All media encryption keys were eradicated — named key generation tracking resets
        state["key_generations"] = {}
        state["writes"] = {}
        state["write_records"] = []
        state["write_segments"] = []
    state["session"] = empty_session()


def apply_successful_revert_sp(state, event):
    sp = state["session"].get("sp") or event.get("object")
    # spec opal/5.1.3.2-5.1.3.3: KeepGlobalRangeKey is defined only for LockingSP RevertSP
    preserve_global = bool(event.get("keep_global_range_key")) and sp == "LockingSP"
    if sp == "LockingSP":
        reset_locking_sp(state, preserve_global_key=preserve_global)
    elif sp == "AdminSP":
        reset_locking_sp(state, preserve_global_key=False)
        reset_admin_sp_credentials(state)
        state["sp_lifecycle"]["AdminSP"] = "Manufactured"
        state["tables"] = default_table_rows()
        state["trylimit_by_authority"] = {}
        state["failed_auth_counts"] = {}
    state["session"] = empty_session()


def reset_like_command(event):
    text = f"{event.get('command') or ''} {event.get('result') or ''}".lower()
    return any(marker in text for marker in ("reset", "reboot", "power cycle", "powercycle"))


def reset_flag_enabled(value):
    if isinstance(value, (list, tuple, set)):
        return len(value) > 0
    parsed = to_bool(value)
    if parsed is not None:
        return parsed
    text = str(value or "").strip().lower()
    return text not in {"", "none", "false", "0", "no"}


def _done_on_reset_fires(value):
    """Return True when DoneOnReset encodes a set that contains the Power Cycle type.

    The spec stores this as a list/set of reset-type enumerals or a descriptive
    string like "Power Cycle *MC1".  to_bool() fails on that string, so we
    check for the Power Cycle token explicitly (spec opal/4.3.5.3 Table 46).
    """
    if value is None:
        return False
    if isinstance(value, (list, tuple, set)):
        return len(value) > 0
    parsed = to_bool(value)
    if parsed is not None:
        return parsed
    return "power cycle" in str(value).lower() or "powercycle" in str(value).lower()


def apply_reset_like_event(state, event):
    # spec core/5.7.2.2.10: LockOnReset unconditionally sets ReadLocked/WriteLocked to True.
    # ReadLockEnabled/WriteLockEnabled only gate I/O enforcement, not the column write on reset.
    for entry in state.get("locking_ranges", {}).values():
        if not reset_flag_enabled(entry.get("lock_on_reset")):
            continue
        entry["read_locked"] = True
        entry["write_locked"] = True
    # spec opal/4.3.5.3 + opal/3.2.3: MBRControl.Done is reset to False on power cycle
    # when DoneOnReset contains the Power Cycle reset type (default for all Opal drives).
    mbr = state.get("mbr") or {}
    if _done_on_reset_fires(mbr.get("done_on_reset")):
        mbr["done"] = False
        mbr[2] = False
    # spec core/5.3.4.1.1.2: C_PIN.Tries resets to 0 on power cycle when Persistence=False.
    # All Opal C_PIN objects default to Persistence=False, so clear all tracked counters.
    state["failed_auth_counts"] = {}
    # spec opal/3.2.3 + 3.3.5.1: any reset aborts all open sessions and clears transient state.
    state["session"] = empty_session()
    state["pending_clock_lag"] = None
    state["crypto_streams"] = {}


def range_bounds(entry):
    start = to_int(entry.get("range_start"))
    length = to_int(entry.get("range_length"))
    if start is None:
        start = 0
    if length is None:
        length = 0
    if entry.get("name") == "Global" and length == 0:
        return (0, None)
    if length <= 0:
        return None
    return (start, start + length - 1)


def covers_lba(entry, lba):
    bounds = range_bounds(entry)
    if bounds is None or lba is None:
        return False
    start, end = bounds
    lba_start, lba_end = lba
    if end is None:
        return start <= lba_start
    return start <= lba_start and lba_end <= end


def overlaps_lba(entry, lba):
    bounds = range_bounds(entry)
    if bounds is None or lba is None:
        return False
    start, end = bounds
    lba_start, lba_end = lba
    if end is None:
        return lba_end >= start
    return start <= lba_end and lba_start <= end


def selected_locking_range(state, lba):
    ranges = list(state.get("locking_ranges", {}).values())
    covering = [entry for entry in ranges if covers_lba(entry, lba)]
    non_global = [entry for entry in covering if entry.get("name") != "Global"]
    if non_global:
        return sorted(non_global, key=lambda entry: to_int(entry.get("range_length")) or 0)[0]
    for entry in covering:
        if entry.get("name") == "Global":
            return entry
    return None


def lock_state_for_lba(state, lba, mode):
    entry = selected_locking_range(state, lba)
    overlapping = [item for item in state.get("locking_ranges", {}).values() if overlaps_lba(item, lba)]
    non_global_overlaps = [item for item in overlapping if item.get("name") != "Global"]
    mixed = bool(
        (entry and any(item is not entry for item in non_global_overlaps))
        or (not entry and len(non_global_overlaps) > 1)
        or (entry and entry.get("name") == "Global" and non_global_overlaps)
    )
    enabled_key = "read_lock_enabled" if mode == "read" else "write_lock_enabled"
    locked_key = "read_locked" if mode == "read" else "write_locked"

    def _entry_locked(item):
        return bool(item.get(locked_key)) if bool(item.get(enabled_key)) else False

    any_overlap_locked = any(_entry_locked(item) for item in overlapping)
    if not entry:
        return {
            "known": mixed,
            "range": None,
            "enabled": False,
            "locked": False,
            "mixed": mixed,
            "any_overlap_locked": any_overlap_locked,
        }

    enabled = bool(entry.get(enabled_key))
    locked = _entry_locked(entry)
    return {
        "known": True,
        "range": entry.get("name"),
        "enabled": enabled,
        "locked": locked,
        "mixed": mixed,
        "any_overlap_locked": any_overlap_locked,
    }


def key_range_for_lba(state, lba):
    entry = selected_locking_range(state, lba)
    if entry:
        return entry.get("name")
    return None


def key_generation_for_lba(state, lba):
    key_range = key_range_for_lba(state, lba)
    if key_range:
        return state["key_generations_by_range"].get(key_range, 0)
    return 0


def record_write_segment(state, record):
    """Maintain the non-overlapping write-segment map: the new write clips any
    previously written segments it overlaps, so each LBA maps to the pattern and
    key generation of the most recent write covering it."""
    start, end = record["lba"]
    if end < start:
        start, end = end, start
    updated = []
    for seg in state.setdefault("write_segments", []):
        if seg["end"] < start or seg["start"] > end:
            updated.append(seg)
            continue
        if seg["start"] < start:
            left = dict(seg)
            left["end"] = start - 1
            updated.append(left)
        if seg["end"] > end:
            right = dict(seg)
            right["start"] = end + 1
            updated.append(right)
    updated.append(
        {
            "start": start,
            "end": end,
            "pattern": record.get("pattern"),
            "key_range": record.get("key_range"),
            "key_generation": record.get("key_generation"),
        }
    )
    updated.sort(key=lambda seg: seg["start"])
    state["write_segments"] = updated


def snapshot_key_generations(state):
    return {
        "objects": deepcopy(state["key_generations"]),
        "ranges": deepcopy(state["key_generations_by_range"]),
    }


def _trajectory_source(state):
    sp = (state.get("session") or {}).get("sp")
    if sp == "LockingSP":
        return "opal/4.3-trajectory"
    if sp == "AdminSP":
        return "opal/4.2-trajectory"
    return "trajectory"


def _meta_acl_uids(event):
    params = event.get("parameters") or {}
    invoking = compact_uid(params.get("InvokingID"))
    method_uid = compact_uid(params.get("MethodID"))
    ace_uid = compact_uid(params.get("ACE"))
    method_name = method_name_from_value(method_uid) if method_uid else None
    return invoking, method_name, ace_uid


def _find_acl_row(state, invoking_uid, method_name):
    for row in (state.get("access_control_rows") or []):
        if row.get("invoking_uid") != invoking_uid:
            continue
        if method_name is None or row.get("method") == method_name:
            return row
    return None


def _apply_successful_add_ace(state, event):
    invoking, method_name, ace_uid = _meta_acl_uids(event)
    if not invoking or not ace_uid:
        return
    row = _find_acl_row(state, invoking, method_name)
    if row is None:
        row = {
            "uid": None,
            "name": None,
            "invoking_uid": invoking,
            "invoking_name": invoking,
            "method": method_name or "",
            "ace_refs": [],
            "source": _trajectory_source(state),
        }
        state.setdefault("access_control_rows", []).append(row)
    refs = row.setdefault("ace_refs", [])
    if ace_uid not in refs:
        refs.append(ace_uid)


def _apply_successful_remove_ace(state, event):
    invoking, method_name, ace_uid = _meta_acl_uids(event)
    if not invoking or not ace_uid:
        return
    row = _find_acl_row(state, invoking, method_name)
    if row is not None and ace_uid in (row.get("ace_refs") or []):
        row["ace_refs"].remove(ace_uid)


def _apply_successful_delete_method(state, event):
    invoking, method_name, _ = _meta_acl_uids(event)
    if not invoking:
        return
    kept = []
    for row in (state.get("access_control_rows") or []):
        matched = (
            row.get("invoking_uid") == invoking
            and (not method_name or row.get("method") == method_name)
        )
        if not matched:
            kept.append(row)
            continue
        if row.get("dynamic_table_uid"):
            row["ace_refs"] = []
            row["method_deleted"] = True
            kept.append(row)
    state["access_control_rows"] = kept


def apply_event(state, event):
    state["history"].append(
        {
            "index": event.get("index"),
            "kind": event.get("kind"),
            "method": event.get("method"),
            "object": event.get("object"),
            "status": event.get("status"),
        }
    )

    if not success_like(event):
        if event["kind"] == "method" and state["session"].get("open") and event.get("method") != "EndSession":
            state["session"]["had_failure"] = True
        # Track failed explicit and implicit authentication attempts for TryLimit/lockout.
        if event["kind"] == "method" and event.get("method") in {"Authenticate", "StartSession"}:
            if event.get("method") == "Authenticate" and state["session"].get("pending_auth_challenge"):
                state["session"]["pending_auth_challenge"] = None
                return
            remember_failed_authenticate(state, event)
        return

    if event["kind"] == "discovery":
        features = event.get("features") or {}
        if 0x0203 in features:
            state["opal_profile_confirmed"] = True
            # opal/3.1.1.5: Range Crossing Behavior bit selects how unlocked
            # range-crossing reads/writes behave (see opal/4.3.7).
            raw_crossing = find_named_value(
                features[0x0203],
                {
                    "range_crossing",
                    "rangecrossing",
                    "range_crossing_behavior",
                    "rangecrossingbehavior",
                    "range crossing behavior",
                    "range crossing",
                },
            )
            if raw_crossing is not None:
                parsed_crossing = to_bool(raw_crossing)
                if parsed_crossing is None:
                    parsed_int = to_int(raw_crossing)
                    parsed_crossing = bool(parsed_int) if parsed_int is not None else None
                if parsed_crossing is not None:
                    state["range_crossing_behavior"] = parsed_crossing
            # opal/3.1.1.5: SID PIN indicator fields (0x00 -> MSID, 0xFF -> VU).
            for field_names, state_key in (
                (
                    {
                        "initial_c_pin_sid_pin_indicator",
                        "initialcpinsidpinindicator",
                        "initial c_pin_sid pin indicator",
                        "initial_sid_pin_indicator",
                        "initial sid pin indicator",
                    },
                    "initial_sid_pin_is_msid",
                ),
                (
                    {
                        "behavior_of_c_pin_sid_pin_upon_tper_revert",
                        "behaviorofcpinsidpinupontperrevert",
                        "behavior of c_pin_sid pin upon tper revert",
                        "sid_pin_revert_behavior",
                    },
                    "revert_sid_pin_is_msid",
                ),
            ):
                raw_value = find_named_value(features[0x0203], field_names)
                parsed_value = to_int(raw_value)
                if parsed_value == 0:
                    state[state_key] = True
                elif parsed_value == 0xFF:
                    state[state_key] = False
        return

    if event["kind"] == "method":
        method = event.get("method")
        if method not in {"SetClockHigh", "SetClockLow", "SetLagHigh", "SetLagLow"}:
            state["pending_clock_lag"] = None
        if method == "StartSession":
            remember_successful_start_session(state, event)
        elif method == "Properties":
            apply_successful_properties(state, event)
        elif method == "SyncSession":
            remember_successful_sync_session(state, event)
        elif method in {"EndSession", "CloseSession"}:
            # Apply any pending SP deletion before closing the session (core/5.3.3.1.1):
            # an AdminSP Delete on an SP row takes deferred effect on session close.
            for sp_name in list(state.get("pending_sp_deletions", set())):
                if sp_name == "LockingSP":
                    state["locking_sp_active"] = False
                    state["sp_lifecycle"]["LockingSP"] = "Manufactured-Inactive"
                state.setdefault("deleted_sps", set()).add(sp_name)
                mark_issued_sp_deleted(state, sp_name, "AdminSP.Delete")
                remove_sp_name(state, sp_name)
            state["pending_sp_deletions"] = set()
            state["session"] = empty_session()
        elif method == "StartTrustedSession":
            remember_successful_sync_session(state, event)
            # Mark that a StartTrustedSession exchange is pending; SyncTrustedSession must follow.
            state["session"]["pending_trusted"] = True
        elif method == "SyncTrustedSession":
            remember_successful_sync_session(state, event)
            state["session"]["trusted"] = True
            state["session"]["pending_trusted"] = False
        elif method == "Authenticate":
            if event.get("auth_result") is False:
                if state["session"].get("pending_auth_challenge"):
                    state["session"]["pending_auth_challenge"] = None
                remember_failed_authenticate(state, event)
                return
            remember_successful_authenticate(state, event)
        elif method == "Get":
            apply_successful_get(state, event)
        elif method == "Next":
            apply_successful_next(state, event)
        elif method == "Set":
            apply_successful_set(state, event)
        elif method == "CreateTable":
            apply_successful_create_table(state, event)
        elif method == "CreateRow":
            apply_successful_create_row(state, event)
        elif method == "DeleteRow":
            apply_successful_delete_row(state, event)
        elif method == "Activate":
            apply_successful_activate(state, event)
        elif method == "GenKey":
            apply_successful_gen_key(state, event)
        elif method == "SetPackage":
            # spec core/5.3.4.1.1.2: successful SetPackage on a C_PIN object modifies the PIN
            # column and therefore resets the Tries column to 0 (same rule as GenKey / Set).
            if event.get("object_family") == "C_PIN":
                authority = event.get("credential_authority")
                if authority:
                    state.setdefault("failed_auth_counts", {}).pop(authority, None)
        elif method in {"EncryptInit", "DecryptInit", "HashInit", "HMACInit", "EncryptFinalize", "DecryptFinalize", "HashFinalize", "HMACFinalize"}:
            apply_successful_crypto_stream_method(state, event)
            state["pending_clock_lag"] = None
        elif method in {"ResetClock", "SetClockHigh", "SetLagHigh", "SetClockLow", "SetLagLow", "GetClock", "IncrementCounter"}:
            apply_successful_clock_method(state, event)
            if method == "IncrementCounter":
                ret = event.get("return_columns") or {}
                # The MonotonicTime return value may be in return_columns or raw return_values.
                from .normalizer import find_named_value
                raw_rv = ((event.get("raw") or {}).get("output") or {}).get("return_values") or {}
                mono = find_named_value(raw_rv, {"MonotonicTime", "monotonictime", "monotonic_time"})
                if mono is not None:
                    val = to_int(mono)
                    if val is not None:
                        state["clock_monotonic_last"] = val
        elif method == "Revert":
            state["pending_clock_lag"] = None
            apply_successful_revert(state, event)
        elif method == "RevertSP":
            apply_successful_revert_sp(state, event)
        elif method == "CreateLog":
            _apply_successful_create_log(state, event)
        elif method == "AddACE":
            _apply_successful_add_ace(state, event)
        elif method == "RemoveACE":
            _apply_successful_remove_ace(state, event)
        elif method == "DeleteMethod":
            _apply_successful_delete_method(state, event)
        elif method == "Delete":
            apply_successful_dynamic_delete(state, event)
            # spec core/5.3.3.1.1: Delete on an SP object in an AdminSP session schedules deferred
            # deletion; the SP is removed after the session closes successfully.
            if event.get("object_family") == "SP" and state["session"].get("sp") == "AdminSP":
                sp_name = event.get("object")
                if sp_name and sp_name not in {"AdminSP"}:
                    state.setdefault("pending_sp_deletions", set()).add(sp_name)
        elif method == "DeleteSP":
            # spec core/5.3.3.1: DeleteSP deletes the SP in which it was invoked.
            sp_name = state["session"].get("sp")
            if sp_name and sp_name != "AdminSP":
                state.setdefault("deleted_sps", set()).add(sp_name)
                if sp_name == "LockingSP":
                    state["locking_sp_active"] = False
                    state["sp_lifecycle"]["LockingSP"] = "Manufactured-Inactive"
                mark_issued_sp_deleted(state, sp_name, "DeleteSP")
                remove_sp_name(state, sp_name)
                state["session"] = empty_session()
        elif method == "IssueSP":
            apply_successful_issue_sp(state, event)
        return

    if event["kind"] == "command" and reset_like_command(event):
        apply_reset_like_event(state, event)
        return

    if event["kind"] == "write":
        if event.get("lba") is not None:
            record = {
                "lba": event["lba"],
                "pattern": event.get("pattern"),
                "key_range": key_range_for_lba(state, event["lba"]),
                "key_generation": key_generation_for_lba(state, event["lba"]),
                "key_generations": snapshot_key_generations(state),
            }
            state["writes"][event["lba"]] = record
            state["write_records"].append(record)
            record_write_segment(state, record)
        return

    if event["kind"] == "read":
        state["reads"].append(
            {
                "lba": event.get("lba"),
                "result": event.get("result"),
                "key_range": key_range_for_lba(state, event.get("lba")),
                "key_generation": key_generation_for_lba(state, event.get("lba")),
                "key_generations": snapshot_key_generations(state),
            }
        )


def track_state(events):
    state = initial_state()
    for event in events:
        apply_event(state, event)
    return state

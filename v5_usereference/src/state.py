from copy import deepcopy
import re

from .normalizer import compact_uid, is_success_status, to_bool, to_int
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
    }


def fresh_access_policy():
    return deepcopy(default_access_policy())


def initial_state():
    locking_ranges = default_locking_ranges()
    access_policy = fresh_access_policy()
    return {
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
        },
        "sp_lifecycle": {
            "AdminSP": "Manufactured",
            "LockingSP": "Manufactured-Inactive",
        },
        "locking_sp_active": False,
        "locking_ranges": locking_ranges,
        "mbr": default_mbr_control(),
        "tables": default_table_rows(),
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
        "reads": [],
        "crypto_streams": {},
        "pending_clock_lag": None,
        "history": [],
    }


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


def credential_matches(state, authority, proof):
    if not authority:
        return True
    known = state["credentials"].get(authority)
    if known is None:
        return None
    return proof == known


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
        }
    )
    if authority:
        state["session"]["authorities"].add(authority)
        state.setdefault("authenticated_history", set()).add(authority)

    if authority and challenge is not None and state["credentials"].get(authority) is None:
        state["credentials"][authority] = challenge
    # Successful authenticated session resets Tries counter for that authority
    if authority:
        state.setdefault("failed_auth_counts", {}).pop(authority, None)


def remember_successful_sync_session(state, event):
    parameters = event.get("parameters") or {}
    host_session_id = to_int(parameters.get("HostSessionID"))
    sp_session_id = to_int(parameters.get("SPSessionID"))
    if host_session_id is not None:
        state["session"]["host_session_id"] = host_session_id
    if sp_session_id is not None:
        state["session"]["sp_session_id"] = sp_session_id


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

    auth_result = event.get("auth_result")
    match = credential_matches(state, authority, proof)
    if auth_result is True or (auth_result is None and match is True):
        add_authenticated_authority(state, authority)
        if proof is not None and state["credentials"].get(authority) is None:
            state["credentials"][authority] = proof
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
    apply_policy_table_columns(state, event, columns)

    # Capture TryLimit (col 5) for lockout tracking
    if credential_authority and 5 in columns:
        state.setdefault("trylimit_by_authority", {})[credential_authority] = columns[5]

    if credential_authority and 3 in columns:
        state["credentials"][credential_authority] = columns[3]
        # spec opal/4.2.1.8: initial C_PIN_SID PIN = C_PIN_MSID PIN on most devices.
        # When we first observe MSID and SID is still unknown, seed SID with MSID value.
        if credential_authority == "MSID" and state["credentials"].get("SID") is None:
            state["credentials"]["SID"] = columns[3]
        return

    if event.get("object_family") == "Locking":
        merge_locking_columns(state, event.get("locking_range"), columns)
        return

    if target == "MBRControl":
        merge_mbr_columns(state, columns)


def apply_successful_set(state, event):
    target = event.get("object")
    columns = event.get("value_columns") or {}
    credential_authority = event.get("credential_authority")
    merge_table_columns(state, event, columns)
    apply_policy_table_columns(state, event, columns)

    # Capture TryLimit (col 5) for lockout tracking
    if credential_authority and 5 in columns:
        state.setdefault("trylimit_by_authority", {})[credential_authority] = columns[5]

    if credential_authority and 3 in columns:
        state["credentials"][credential_authority] = columns[3]
        state.setdefault("failed_auth_counts", {}).pop(credential_authority, None)
        if (
            credential_authority == "SID"
            and state["locking_sp_active"]
            and state["credentials"].get("Admin1") is None
        ):
            state["credentials"]["Admin1"] = columns[3]
        return

    if event.get("object_family") == "Locking":
        merge_locking_columns(state, event.get("locking_range"), columns)
        return

    if target == "MBRControl":
        merge_mbr_columns(state, columns)


def apply_successful_activate(state, event):
    if event.get("object") != "LockingSP":
        return
    state["locking_sp_active"] = True
    state["sp_lifecycle"]["LockingSP"] = "Manufactured"
    sid_value = state["credentials"].get("SID")
    if sid_value is not None:
        state["credentials"]["Admin1"] = sid_value  # Always overwrite per spec opal/5.1.1.2


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
    previous_ranges = set(state.get("locking_ranges", {})) or {"Global"}
    default_ranges = default_locking_ranges()
    affected_ranges = previous_ranges | set(default_ranges) | {"Global"}
    for range_name in affected_ranges:
        if preserve_global_key and range_name == "Global":
            continue
        bump_key_generation_for_range(state, range_name)

    state["locking_sp_active"] = False
    state["sp_lifecycle"]["LockingSP"] = "Manufactured-Inactive"
    state["locking_ranges"] = default_ranges
    state["mbr"] = default_mbr_control()
    # Restore LockingSP credentials to factory defaults (spec opal/4.3.1.9)
    state["credentials"]["Admin1"] = None
    state["credentials"]["Admin2"] = ""
    state["credentials"]["Admin3"] = ""
    state["credentials"]["Admin4"] = ""
    state["credentials"]["User1"] = ""
    reset_access_policy_scope(state, "LockingSP")


def reset_admin_sp_credentials(state):
    # spec opal/5.1.2.2.1: if SID was ever authenticated, reset SID PIN to MSID PIN value
    sid_was_authenticated = "SID" in state.get("authenticated_history", set())
    if sid_was_authenticated:
        state["credentials"]["SID"] = state["credentials"].get("MSID")
    state["credentials"]["MSID"] = None
    state["credentials"]["Admin1"] = None
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
    state["session"] = empty_session()


def apply_successful_revert_sp(state, event):
    sp = state["session"].get("sp") or event.get("object")
    preserve_global = bool(event.get("keep_global_range_key"))
    if sp == "LockingSP":
        reset_locking_sp(state, preserve_global_key=preserve_global)
    elif sp == "AdminSP":
        reset_locking_sp(state, preserve_global_key=preserve_global)
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


def apply_reset_like_event(state, event):
    for entry in state.get("locking_ranges", {}).values():
        if not reset_flag_enabled(entry.get("lock_on_reset")):
            continue
        if entry.get("read_lock_enabled"):
            entry["read_locked"] = True
        if entry.get("write_lock_enabled"):
            entry["write_locked"] = True
    done_on_reset = state.get("mbr", {}).get("done_on_reset")
    if done_on_reset is not None:
        parsed = to_bool(done_on_reset)
        # DoneOnReset=True means Done is reset to False on power cycle (spec opal/4.3.1.6)
        if parsed:
            state["mbr"]["done"] = False
            state["mbr"][2] = False


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
    if not entry:
        return {
            "known": mixed,
            "range": None,
            "enabled": False,
            "locked": False,
            "mixed": mixed,
        }

    enabled_key = "read_lock_enabled" if mode == "read" else "write_lock_enabled"
    locked_key = "read_locked" if mode == "read" else "write_locked"
    enabled = bool(entry.get(enabled_key))
    locked = bool(entry.get(locked_key)) if enabled else False
    return {
        "known": True,
        "range": entry.get("name"),
        "enabled": enabled,
        "locked": locked,
        "mixed": mixed,
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


def snapshot_key_generations(state):
    return {
        "objects": deepcopy(state["key_generations"]),
        "ranges": deepcopy(state["key_generations_by_range"]),
    }


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
            remember_failed_authenticate(state, event)
        return

    if event["kind"] == "method":
        method = event.get("method")
        if method not in {"SetClockHigh", "SetClockLow", "SetLagHigh", "SetLagLow"}:
            state["pending_clock_lag"] = None
        if method == "StartSession":
            remember_successful_start_session(state, event)
        elif method == "SyncSession":
            remember_successful_sync_session(state, event)
        elif method in {"EndSession", "CloseSession"}:
            state["session"] = empty_session()
        elif method in {"StartTrustedSession", "SyncTrustedSession"}:
            remember_successful_sync_session(state, event)
            state["session"]["trusted"] = True
        elif method == "Authenticate":
            if event.get("auth_result") is False:
                remember_failed_authenticate(state, event)
                return
            remember_successful_authenticate(state, event)
        elif method == "Get":
            apply_successful_get(state, event)
        elif method == "Set":
            apply_successful_set(state, event)
        elif method == "Activate":
            apply_successful_activate(state, event)
        elif method == "GenKey":
            apply_successful_gen_key(state, event)
        elif method in {"EncryptInit", "DecryptInit", "HashInit", "HMACInit", "EncryptFinalize", "DecryptFinalize", "HashFinalize", "HMACFinalize"}:
            apply_successful_crypto_stream_method(state, event)
            state["pending_clock_lag"] = None
        elif method in {"ResetClock", "SetClockHigh", "SetLagHigh", "SetClockLow", "SetLagLow", "GetClock", "IncrementCounter"}:
            apply_successful_clock_method(state, event)
        elif method == "Revert":
            state["pending_clock_lag"] = None
            apply_successful_revert(state, event)
        elif method == "RevertSP":
            apply_successful_revert_sp(state, event)
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

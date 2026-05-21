from copy import deepcopy

from .normalizer import compact_uid, is_success_status, to_bool, to_int
from .spec_docs import default_locking_ranges, default_mbr_control, default_table_rows


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
    }


def initial_state():
    locking_ranges = default_locking_ranges()
    return {
        "session": empty_session(),
        "credentials": {
            "SID": None,
            "MSID": None,
            "Admin1": None,
        },
        "sp_lifecycle": {
            "AdminSP": "Manufactured",
            "LockingSP": "Manufactured-Inactive",
        },
        "locking_sp_active": False,
        "locking_ranges": locking_ranges,
        "mbr": default_mbr_control(),
        "tables": default_table_rows(),
        "key_generations": {},
        "key_generations_by_range": {},
        "writes": {},
        "write_records": [],
        "reads": [],
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


def remember_successful_start_session(state, event):
    authority = event.get("authority")
    challenge = event.get("challenge")
    sp = event.get("sp")

    state["session"] = empty_session()
    state["session"].update(
        {
            "open": True,
            "sp": sp,
            "authority": authority,
            "write": bool(event.get("write")),
        }
    )
    if authority:
        state["session"]["authorities"].add(authority)

    if authority and challenge and state["credentials"].get(authority) is None:
        state["credentials"][authority] = challenge


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
        if proof and state["credentials"].get(authority) is None:
            state["credentials"][authority] = proof


def normalize_column_value(column, value):
    if column in {5, 6, 7, 8}:
        parsed = to_bool(value)
        return parsed if parsed is not None else value
    if column in {3, 4}:
        parsed = to_int(value)
        return parsed if parsed is not None else value
    return value


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


def apply_successful_get(state, event):
    target = event.get("object")
    columns = event.get("return_columns") or {}
    credential_authority = event.get("credential_authority")
    merge_table_columns(state, event, columns)

    if credential_authority and 3 in columns:
        state["credentials"][credential_authority] = columns[3]
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

    if credential_authority and 3 in columns:
        state["credentials"][credential_authority] = columns[3]
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
    if sid_value is not None and state["credentials"].get("Admin1") is None:
        state["credentials"]["Admin1"] = sid_value


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
    state["credentials"]["Admin1"] = None


def reset_admin_sp_credentials(state):
    state["credentials"]["SID"] = None
    state["credentials"]["MSID"] = None
    state["credentials"]["Admin1"] = None


def apply_successful_revert(state, event):
    target = event.get("object")
    if target == "LockingSP":
        reset_locking_sp(state)
    elif target == "AdminSP":
        reset_locking_sp(state)
        reset_admin_sp_credentials(state)
        state["sp_lifecycle"]["AdminSP"] = "Manufactured"
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
    state["session"] = empty_session()


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
    mixed = bool(entry and any(item is not entry and item.get("name") != "Global" for item in overlapping))
    if not entry:
        return {
            "known": False,
            "range": None,
            "enabled": False,
            "locked": False,
            "mixed": False,
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
        return

    if event["kind"] == "method":
        method = event.get("method")
        if method == "StartSession":
            remember_successful_start_session(state, event)
        elif method in {"EndSession", "CloseSession"}:
            state["session"] = empty_session()
        elif method == "Authenticate":
            remember_successful_authenticate(state, event)
        elif method == "Get":
            apply_successful_get(state, event)
        elif method == "Set":
            apply_successful_set(state, event)
        elif method == "Activate":
            apply_successful_activate(state, event)
        elif method == "GenKey":
            apply_successful_gen_key(state, event)
        elif method == "Revert":
            apply_successful_revert(state, event)
        elif method == "RevertSP":
            apply_successful_revert_sp(state, event)
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

from copy import deepcopy

from .normalizer import is_success_status


def initial_state():
    return {
        "session": {
            "open": False,
            "sp": None,
            "authority": None,
            "write": False,
        },
        "credentials": {
            "SID": None,
            "MSID": None,
            "Admin1": None,
        },
        "locking_sp_active": False,
        "locking_ranges": {},
        "mbr": {},
        "key_generations": {},
        "writes": {},
        "reads": [],
        "history": [],
    }


def success_like(event):
    if event["kind"] == "write":
        return True
    if event["kind"] in {"read", "command"}:
        return event.get("status") in {None, "success"}
    return is_success_status(event.get("status"))


def remember_successful_start_session(state, event):
    authority = event.get("authority")
    challenge = event.get("challenge")
    sp = event.get("sp")

    state["session"] = {
        "open": True,
        "sp": sp,
        "authority": authority,
        "write": bool(event.get("write")),
    }

    if authority and challenge and state["credentials"].get(authority) is None:
        state["credentials"][authority] = challenge


def apply_successful_set(state, event):
    target = event.get("object")
    value = event.get("set_column_3")
    credential_authority = event.get("credential_authority")

    if credential_authority and value is not None:
        state["credentials"][credential_authority] = value
        if (
            credential_authority == "SID"
            and state["locking_sp_active"]
            and state["credentials"].get("Admin1") is None
        ):
            state["credentials"]["Admin1"] = value
        return

    if target == "Locking_Range1":
        current = state["locking_ranges"].setdefault("Range1", {})
        for item in event.get("values") or []:
            if isinstance(item, dict):
                current.update({str(k): v for k, v in item.items()})
        return

    if target == "MBRControl":
        for item in event.get("values") or []:
            if isinstance(item, dict):
                state["mbr"].update({str(k): v for k, v in item.items()})


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
        return

    if event["kind"] == "method":
        method = event.get("method")
        if method == "StartSession":
            remember_successful_start_session(state, event)
        elif method == "EndSession":
            state["session"] = {
                "open": False,
                "sp": None,
                "authority": None,
                "write": False,
            }
        elif method == "Get":
            if event.get("object") == "C_PIN_MSID" and event.get("return_column_3") is not None:
                state["credentials"]["MSID"] = event["return_column_3"]
        elif method == "Set":
            apply_successful_set(state, event)
        elif method == "Activate" and event.get("object") == "LockingSP":
            state["locking_sp_active"] = True
            sid_value = state["credentials"].get("SID")
            if sid_value is not None and state["credentials"].get("Admin1") is None:
                state["credentials"]["Admin1"] = sid_value
        elif method == "GenKey":
            key = event.get("object") or "unknown"
            state["key_generations"][key] = state["key_generations"].get(key, 0) + 1
        return

    if event["kind"] == "write":
        if event.get("lba") is not None:
            state["writes"][event["lba"]] = {
                "pattern": event.get("pattern"),
                "key_generations": deepcopy(state["key_generations"]),
            }
        return

    if event["kind"] == "read":
        state["reads"].append(
            {
                "lba": event.get("lba"),
                "result": event.get("result"),
                "key_generations": deepcopy(state["key_generations"]),
            }
        )


def track_state(events):
    state = initial_state()
    for event in events:
        apply_event(state, event)
    return state

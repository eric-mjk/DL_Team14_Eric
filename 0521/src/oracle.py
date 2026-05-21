from dataclasses import dataclass

from .normalizer import is_success_status
from .state import (
    data_command_success,
    is_error_result,
    key_generation_for_lba,
    lock_state_for_lba,
)
from .spec_docs import COLUMN_LIMITS, refs_for


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


def spec_refs_for(*rule_keys):
    refs = []
    for key in rule_keys:
        for ref in refs_for(key):
            if ref not in refs:
                refs.append(ref)
    return tuple(refs)


def pass_result(reason, confidence=0.95, expected_status="unknown", actual_status="unknown", spec_refs=()):
    return RuleResult("pass", confidence, reason, expected_status, actual_status, tuple(spec_refs))


def fail_result(reason, confidence=0.95, expected_status="unknown", actual_status="unknown", spec_refs=()):
    return RuleResult("fail", confidence, reason, expected_status, actual_status, tuple(spec_refs))


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


def expected_status_result(event, expected_status, reason, confidence=0.95, rule_key=None):
    actual = actual_status_class(event)
    refs = spec_refs_for(rule_key) if rule_key else ()
    if status_matches(actual, expected_status):
        return pass_result(reason, confidence, expected_status, actual, refs)
    return fail_result(reason, confidence, expected_status, actual, refs)


def expected_success_result(event, expected_success, reason, confidence=0.95):
    expected = "success" if expected_success else "error"
    return expected_status_result(event, expected, reason, confidence)


def session_has_authority(state, authority=None):
    authorities = state["session"].get("authorities") or set()
    if authority is None:
        return bool(authorities)
    return authority in authorities


def is_admin_authority(authority):
    return authority == "SID" or (isinstance(authority, str) and authority.startswith("Admin"))


def session_has_admin_authority(state, sp=None):
    authorities = state["session"].get("authorities") or set()
    if sp == "LockingSP":
        return any(isinstance(authority, str) and authority.startswith("Admin") for authority in authorities)
    if sp == "AdminSP":
        return any(authority == "SID" or (isinstance(authority, str) and authority.startswith("Admin")) for authority in authorities)
    return any(is_admin_authority(authority) for authority in authorities)


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
    start = event.get("cellblock_start")
    end = event.get("cellblock_end")
    if start is None and end is None:
        return False
    if start is None or end is None or start < 0 or end < 0 or start > end:
        return True
    max_column = COLUMN_LIMITS.get(event.get("object_family"))
    return max_column is not None and end > max_column


def invalid_set_columns(event):
    columns = event.get("value_columns") or {}
    if not columns:
        return False
    if any(column < 0 for column in columns):
        return True
    max_column = COLUMN_LIMITS.get(event.get("object_family"))
    return max_column is not None and any(column > max_column for column in columns)


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
        expected = session_open_for(state, "LockingSP") and session_has_admin_authority(state, "LockingSP")
        return expected_status_result(
            event,
            "success" if expected else "auth_error",
            "MBRControl Get is protected by LockingSP access control.",
            rule_key="mbr_control",
        )

    if family in {"Authority", "MediaKey", "ACE", "AccessControl", "SecretProtect"}:
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

    target_sp = object_sp(event) or state["session"].get("sp")
    if target_sp == "LockingSP" and not state.get("locking_sp_active"):
        return expected_status_result(event, "error", f"{obj} Set requires an active LockingSP.", rule_key="locking_table")

    if family == "C_PIN":
        authorities = state["session"].get("authorities") or set()
        self_authority = event.get("credential_authority")
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

    if family in {"Locking", "MBRControl", "MediaKey", "ACE", "AccessControl", "SecretProtect"}:
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
    expected = state["session"].get("open") and state["session"].get("write") and session_has_admin_authority(state, sp)
    return expected_status_result(
        event,
        "success" if expected else "auth_error",
        "RevertSP requires an authenticated owner/admin write session in the target SP.",
        rule_key="revert_sp",
    )


def judge_gen_key(state, event):
    if event.get("object_family") != "MediaKey" and not event.get("key_range"):
        return expected_status_result(event, "invalid_parameter", "GenKey target must be a media-key object.", rule_key="gen_key")
    if not state.get("locking_sp_active"):
        return expected_status_result(event, "error", "GenKey requires an active LockingSP.", rule_key="gen_key")
    expected = authenticated_locking_admin_write(state)
    return expected_status_result(
        event,
        "success" if expected else "auth_error",
        "GenKey requires authenticated Admin1 LockingSP write session.",
        rule_key="gen_key",
    )


def judge_random(state, event):
    target_sp = object_sp(event) or state["session"].get("sp")
    expected = state["session"].get("open") and (target_sp is None or session_open_for(state, target_sp))
    return expected_status_result(
        event,
        "success" if expected else "auth_error",
        "Random is a Crypto Template SP method and requires an open session in that SP.",
        rule_key="random",
    )


def judge_next(state, event):
    count = event.get("count")
    if count is not None and count < 0:
        return expected_status_result(event, "invalid_parameter", "Next Count cannot be negative.", rule_key="next")
    target_sp = object_sp(event) or state["session"].get("sp")
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
        expected = state["session"].get("open")
        return expected_status_result(
            event,
            "success" if expected else "auth_error",
            f"{method} requires an open session and follows table-management status classes.",
            rule_key="get",
        )
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

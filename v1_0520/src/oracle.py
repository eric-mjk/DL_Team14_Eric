from dataclasses import dataclass

from .normalizer import is_success_status


@dataclass
class RuleResult:
    verdict: str
    confidence: float
    reason: str


def pass_result(reason, confidence=0.95):
    return RuleResult("pass", confidence, reason)


def fail_result(reason, confidence=0.95):
    return RuleResult("fail", confidence, reason)


def actual_success(event):
    if event["kind"] in {"read", "write"}:
        return True
    return is_success_status(event.get("status"))


def expected_status_result(event, expected_success, reason):
    if actual_success(event) == expected_success:
        return pass_result(reason)
    return fail_result(reason)


def credential_matches(state, authority, challenge):
    if not authority:
        return True
    known = state["credentials"].get(authority)
    if known is None:
        return None
    return challenge == known


def judge_start_session(state, event):
    sp = event.get("sp")
    authority = event.get("authority")

    if sp == "LockingSP" and not state.get("locking_sp_active"):
        return expected_status_result(
            event,
            False,
            "LockingSP session before successful LockingSP activation should fail.",
        )

    match = credential_matches(state, authority, event.get("challenge"))
    if match is True:
        return expected_status_result(
            event,
            True,
            f"StartSession challenge matches tracked credential for {authority}.",
        )
    if match is False:
        return expected_status_result(
            event,
            False,
            f"StartSession challenge does not match tracked credential for {authority}.",
        )

    if authority:
        return expected_status_result(
            event,
            True,
            f"First observed authenticated StartSession for {authority}; accept actual success as credential evidence.",
        )

    return expected_status_result(event, True, "Unauthenticated StartSession should succeed for known public flows.")


def judge_get(state, event):
    obj = event.get("object")
    if obj == "C_PIN_MSID":
        expected = state["session"].get("open") and state["session"].get("sp") == "AdminSP"
        return expected_status_result(event, bool(expected), "C_PIN_MSID Get requires an open AdminSP session.")

    if obj in {"Locking_Global", "Locking_Range1", "MBRControl", "LockingInfo"}:
        expected = state["session"].get("open") and state["session"].get("sp") == "LockingSP"
        return expected_status_result(event, bool(expected), f"{obj} Get requires an open LockingSP session.")

    return expected_status_result(event, True, "Known Get fallback expects success.")


def judge_set(state, event):
    obj = event.get("object")
    session = state["session"]

    if obj and obj.startswith("C_PIN_"):
        expected = session.get("open") and session.get("write") and session.get("authority") is not None
        return expected_status_result(event, bool(expected), "C_PIN Set requires an authenticated write session.")

    if obj and obj.startswith("Authority_"):
        expected = (
            session.get("open")
            and session.get("sp") == "LockingSP"
            and session.get("authority") == "Admin1"
            and session.get("write")
        )
        return expected_status_result(event, bool(expected), "Authority Set requires authenticated Admin1 LockingSP write session.")

    if obj in {"Locking_Range1", "MBRControl"}:
        expected = (
            session.get("open")
            and session.get("sp") == "LockingSP"
            and session.get("authority") == "Admin1"
            and session.get("write")
        )
        return expected_status_result(event, bool(expected), f"{obj} Set requires authenticated Admin1 LockingSP write session.")

    return expected_status_result(event, True, "Known Set fallback expects success.")


def judge_activate(state, event):
    expected = (
        event.get("object") == "LockingSP"
        and state["session"].get("open")
        and state["session"].get("sp") == "AdminSP"
        and state["session"].get("authority") == "SID"
        and state["session"].get("write")
    )
    return expected_status_result(event, bool(expected), "Only the LockingSP object can be activated from an authenticated SID AdminSP write session.")


def judge_gen_key(state, event):
    expected = (
        event.get("object") == "Range1_Key"
        and state["session"].get("open")
        and state["session"].get("sp") == "LockingSP"
        and state["session"].get("authority") == "Admin1"
        and state["session"].get("write")
    )
    return expected_status_result(event, bool(expected), "Range1 GenKey requires authenticated Admin1 LockingSP write session.")


def normalized_read_result(result):
    if result is None:
        return ""
    text = str(result).strip()
    lower = text.lower()
    if lower.startswith("pattern "):
        return text.split(None, 1)[1].strip()
    return text


def judge_read(state, event):
    lba = event.get("lba")
    write = state["writes"].get(lba)
    if not write:
        return pass_result("No prior write for this LBA; accept observed read.", 0.60)

    old_pattern = write.get("pattern")
    result = normalized_read_result(event.get("result"))
    current_key_generation = state["key_generations"].get("Range1_Key", 0)
    write_key_generation = write.get("key_generations", {}).get("Range1_Key", 0)

    if current_key_generation > write_key_generation:
        if result == old_pattern:
            return fail_result("Read after successful GenKey returned the old written pattern.")
        return pass_result("Read after successful GenKey returned data different from the old written pattern.")

    if result == old_pattern:
        return pass_result("Read before key change returned the prior written pattern.")
    return fail_result("Read before key change did not return the prior written pattern.")


def fallback(event):
    if actual_success(event):
        return pass_result("Fallback: success-like final response.", 0.50)
    return fail_result("Fallback: error-like final response.", 0.50)


def judge_final(state, event):
    if event["kind"] == "read":
        return judge_read(state, event)
    if event["kind"] == "write":
        return pass_result("Write command has no error status in the dataset.")
    if event["kind"] != "method":
        return fallback(event)

    method = event.get("method")
    if method == "Properties":
        return expected_status_result(event, True, "Properties on Session Manager should succeed.")
    if method == "StartSession":
        return judge_start_session(state, event)
    if method == "Get":
        return judge_get(state, event)
    if method == "Set":
        return judge_set(state, event)
    if method == "Activate":
        return judge_activate(state, event)
    if method == "GenKey":
        return judge_gen_key(state, event)
    if method == "EndSession":
        return expected_status_result(event, True, "EndSession should succeed for known flows.")

    return fallback(event)

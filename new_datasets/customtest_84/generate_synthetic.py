#!/usr/bin/env python3
"""
Synthetic TCG/Opal trajectory generator.

Produces pass/fail test cases in the same JSON format as tc1.json-tc20.json,
based on real workflow patterns from TCG Opal spec and the opal-toolset reference.

Usage:
    python generate_synthetic.py           # writes to synthetic_testcases/
    python generate_synthetic.py --check   # also runs local solver and prints accuracy
    python generate_synthetic.py --check-only
                                          # checks existing generated cases/labels
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

CUSTOMTEST_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CUSTOMTEST_DIR.parent
SYNTHETIC_DIR = CUSTOMTEST_DIR / "synthetic_testcases"
SYNTHETIC_LABELS = CUSTOMTEST_DIR / "synthetic_labels.jsonl"

# ---- UID constants -------------------------------------------------------
ADMIN_SP      = "0000020500000001"
LOCKING_SP    = "0000020500000002"
SID_UID       = "0000000900000006"
ADMIN1_UID    = "0000000900010001"
ADMIN2_UID    = "0000000900010002"
USER1_UID     = "0000000900030001"
USER2_UID     = "0000000900030002"
ANYBODY_UID   = "0000000900000001"
ADMINS_UID    = "0000000900000002"
USERS_UID     = "0000000900030000"
C_PIN_MSID    = "0000000B00008402"
C_PIN_SID     = "0000000B00000001"
C_PIN_ADMIN1  = "0000000B00010001"
C_PIN_ADMIN2  = "0000000B00010002"
C_PIN_USER1   = "0000000B00030001"
C_PIN_USER2   = "0000000B00030002"
GLOBAL_RANGE  = "0000080200000001"
RANGE1        = "0000080200030001"
K_AES_GLOBAL  = "0000080500000001"
K_AES_RANGE1  = "0000080500030001"
MBRCONTROL    = "0000080300000001"
LOG_TABLE_UID        = "0000000100000A01"  # default pre-existing Log table (template UID)
LOG_LIST_UID         = "0000000100000A02"  # LogList table (for CreateLog)
LOG_FAKE_UID         = "0000000100000A05"  # non-existent log UID (never created)
ACCESS_CONTROL_TABLE_UID = "0000000100000007"  # AccessControl table (target for AddACE/RemoveACE)
ACE_ANYBODY_UID      = "0000000800000001"  # ACE_Anybody: BooleanExpr=Anybody, columns=all
SET_METHOD_UID       = "0000000600000017"  # Method UID for Set
TPERINFO_UID         = "0000020100030001"  # TPerInfo object (AdminSP)
DATARMV_UID          = "0000110100000001"  # DataRemovalMechanism object (AdminSP)

# ---- Low-level step builders ---------------------------------------------

_idx = [0]

def _next_idx():
    _idx[0] += 1
    return _idx[0]

def _reset_idx():
    _idx[0] = 0


def _object_name_for_uid(uid: str) -> str:
    """Return the canonical object name for a given UID prefix."""
    u = uid.replace(" ", "").replace("0x", "").upper()
    if u.startswith("0000000B"):
        return "C_PIN"
    if u.startswith("00000802"):
        return "Locking"
    if u.startswith("00000803"):
        return "MBRControl"
    if u.startswith("00000805") or u.startswith("00000806"):
        return "MediaKey"
    if u.startswith("00000009"):
        return "Authority"
    if u.startswith("00000205"):
        return "SP"
    if u.startswith("00000801"):
        return "LockingInfo"
    return uid


def make_step(
    method_name: str,
    invoking_uid: str,
    required_args: dict,
    optional_args: dict,
    output_status: str,
    return_values: Any = None,
    output_method_name: str | None = None,
    invoking_name: str | None = None,
) -> dict:
    obj_name = invoking_name or _object_name_for_uid(invoking_uid)
    step = {
        "index": _next_idx(),
        "input": {
            "method": {
                "name": method_name,
                "uid": "00 00 00 06 00 00 00 16",
                "args": {
                    "required": required_args,
                    "optional": optional_args,
                },
            },
            "invoking_id": {
                "uid": invoking_uid,
                "name": obj_name,
                "type": None,
            },
            "status_codes": output_status,
        },
        "output": {
            "method": {
                "name": output_method_name or method_name,
                "uid": "00 00 00 06 00 00 00 16",
                "args": {"required": {}, "optional": {}},
            },
            "return_values": return_values if return_values is not None else {},
            "status_codes": output_status,
        },
    }
    return step


def start_session(
    spid: str,
    write: int = 1,
    authority: str | None = None,
    challenge: str | None = None,
    status: str = "SUCCESS",
) -> dict:
    optional: dict = {}
    if authority:
        optional["HostSigningAuthority"] = authority
    if challenge is not None:
        optional["HostChallenge"] = challenge
    required = {"HostSessionID": 1, "SPID": spid, "Write": write}
    rv = {"required": {"HostSessionID": "00000001", "SPSessionID": "00006572"}, "optional": {}}
    return make_step(
        "StartSession", "0000000000000001",
        required, optional,
        status,
        return_values=rv,
        output_method_name="SyncSession",
        invoking_name="Session Manager UID",
    )


def end_session(status: str = "SUCCESS") -> dict:
    return make_step("EndSession", "0000000000000001", {}, {}, status, return_values={}, invoking_name="Session Manager UID")


def get_cpin(cpin_uid: str, status: str = "SUCCESS", pin_value: str | None = None) -> dict:
    rv = [[{"3": pin_value}]] if pin_value is not None else {}
    return make_step(
        "Get", cpin_uid,
        {"Cellblock": [{"startColumn": 3}, {"endColumn": 3}]},
        {},
        status,
        return_values=rv,
    )


def set_cpin(cpin_uid: str, new_pin: str, status: str = "SUCCESS") -> dict:
    return make_step(
        "Set", cpin_uid,
        {},                          # required: empty
        {"Values": [{"3": new_pin}]},  # optional: Values
        status,
    )


def activate(target_uid: str, status: str = "SUCCESS") -> dict:
    return make_step("Activate", target_uid, {}, {}, status, invoking_name="SP")


def get_locking(range_uid: str, start_col: int, end_col: int,
                status: str = "SUCCESS", values: dict | None = None) -> dict:
    rv = [[values]] if values else {}
    return make_step(
        "Get", range_uid,
        {"Cellblock": [{"startColumn": start_col}, {"endColumn": end_col}]},
        {},
        status,
        return_values=rv,
    )


def set_locking(range_uid: str, values: dict, status: str = "SUCCESS") -> dict:
    return make_step("Set", range_uid, {}, {"Values": [values]}, status)


def set_authority(auth_uid: str, enabled: bool, status: str = "SUCCESS") -> dict:
    return make_step("Set", auth_uid, {}, {"Values": [{"5": int(enabled)}]}, status)


def set_authority_operation(auth_uid: str, operation: str, status: str = "SUCCESS") -> dict:
    """Set an authority's Operation column (column 9) to a given value."""
    return make_step("Set", auth_uid, {}, {"Values": [{9: operation}]}, status)


def authenticate_step(authority_uid: str, proof: str | None = None,
                      auth_result: bool | None = None, status: str = "SUCCESS") -> dict:
    """Authenticate step inside an open session."""
    optional: dict = {"Authority": authority_uid}
    if proof is not None:
        optional["Proof"] = proof
    rv: dict = {}
    if auth_result is not None:
        rv["Result"] = auth_result
    return make_step("Authenticate", "0000000000000001", {}, optional, status,
                     return_values=rv, invoking_name="Session Manager UID")


def add_ace_step(invoking_uid: str, method_uid: str, ace_uid: str, status: str = "SUCCESS") -> dict:
    """AddACE on the AccessControl table: grants ace_uid authority over invoking_uid.method_uid."""
    return make_step("AddACE", ACCESS_CONTROL_TABLE_UID, {},
                     {"InvokingID": invoking_uid, "MethodID": method_uid, "ACE": ace_uid},
                     status, invoking_name="AccessControl")


def gen_key(target_uid: str, status: str = "SUCCESS", invoking_name: str = "K_AES_256") -> dict:
    """GenKey on a K_AES_256 (range key) or C_PIN object."""
    return make_step("GenKey", target_uid, {}, {}, status, invoking_name=invoking_name)


def get_mbr(status: str = "SUCCESS", values: dict | None = None) -> dict:
    rv = [[values]] if values else {}
    return make_step(
        "Get", MBRCONTROL,
        {"Cellblock": [{"startColumn": 1}, {"endColumn": 3}]},
        {},
        status,
        return_values=rv,
    )


def set_mbr(values: dict, status: str = "SUCCESS") -> dict:
    return make_step("Set", MBRCONTROL, {}, {"Values": [values]}, status)


def properties_step(status: str = "SUCCESS") -> dict:
    rv = {"required": {}, "optional": {"MaxPackets": 1, "MaxSubpackets": 1, "MaxMethods": 1}}
    return make_step("Properties", "0000000000000001", {}, {}, status, return_values=rv, invoking_name="Session Manager UID")


def write_step(lba: str, pattern: str, interface_result: str = "PASS") -> dict:
    """Write step — uses 'command' field (not 'method') matching real tc format."""
    return {
        "index": _next_idx(),
        "input": {
            "command": "Write",
            "args": {"LBA": lba, "pattern": pattern},
        },
        "output": {
            "command": "Write",
            "result": interface_result,
            "args": {"result": interface_result},
        },
    }


def read_step(lba: str, result: str, interface_result: str = "PASS") -> dict:
    """Read step — uses 'command' field (not 'method') matching real tc format."""
    return {
        "index": _next_idx(),
        "input": {
            "command": "Read",
            "args": {"LBA": lba},
        },
        "output": {
            "command": "Read",
            "result": interface_result,
            "args": {"result": result},
        },
    }


def revert_sp(target_uid: str, status: str = "SUCCESS", keep_global: bool = False) -> dict:
    optional = {}
    if keep_global:
        optional["KeepGlobalRangeKey"] = 1
    return make_step("RevertSP", target_uid, {}, optional, status, invoking_name="SP")


# ---- Higher-level workflow helpers ---------------------------------------

def setup_tper(msid_pin: str, new_sid_pin: str):
    """AdminSP session: read MSID, then set SID PIN."""
    return [
        start_session(ADMIN_SP),                  # unauthenticated
        get_cpin(C_PIN_MSID, pin_value=msid_pin), # learn MSID
        end_session(),
        start_session(ADMIN_SP, authority=SID_UID, challenge=msid_pin),
        set_cpin(C_PIN_SID, new_sid_pin),         # set SID PIN
        end_session(),
    ]


def activate_locking_sp(sid_pin: str):
    """Activate LockingSP using SID."""
    return [
        start_session(ADMIN_SP, authority=SID_UID, challenge=sid_pin),
        activate(LOCKING_SP),
        end_session(),
    ]


def setup_user(admin1_pin: str, user1_pin: str):
    """Set User1 PIN and enable User1 authority."""
    return [
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=admin1_pin),
        set_cpin(C_PIN_USER1, user1_pin),
        set_authority(USER1_UID, enabled=True),
        end_session(),
    ]


def setup_range(admin1_pin: str, start: int, length: int):
    """Configure Range1 with start/length."""
    return [
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=admin1_pin),
        set_locking(RANGE1, {"3": start, "4": length, "5": 1, "6": 1}),
        end_session(),
    ]


# ---- Scenario builders --------------------------------------------------

def tc_properties_pass() -> tuple[list[dict], str]:
    """Properties returns SUCCESS with non-empty values → PASS."""
    _reset_idx()
    return [properties_step("SUCCESS")], "pass"


def tc_properties_fail() -> tuple[list[dict], str]:
    """Properties returns FAIL → FAIL."""
    _reset_idx()
    return [properties_step("FAIL")], "fail"


def tc_start_session_unauthenticated_pass() -> tuple[list[dict], str]:
    """Unauthenticated StartSession in AdminSP → SUCCESS is PASS."""
    _reset_idx()
    steps = [start_session(ADMIN_SP, authority=None, status="SUCCESS")]
    return steps, "pass"


def tc_start_session_unauthenticated_fail() -> tuple[list[dict], str]:
    """Unauthenticated StartSession returns FAIL → FAIL."""
    _reset_idx()
    steps = [start_session(ADMIN_SP, authority=None, status="FAIL")]
    return steps, "fail"


def tc_start_session_sid_correct_pass() -> tuple[list[dict], str]:
    """StartSession with correct SID challenge → SUCCESS is PASS."""
    _reset_idx()
    msid = "MSID_INITIAL_VALUE"
    steps = setup_tper(msid, "NEW_SID_PIN") + [
        start_session(ADMIN_SP, authority=SID_UID, challenge="NEW_SID_PIN", status="SUCCESS")
    ]
    return steps, "pass"


def tc_start_session_sid_wrong_fail() -> tuple[list[dict], str]:
    """StartSession with wrong SID challenge → NOT_AUTHORIZED is PASS, SUCCESS is FAIL."""
    _reset_idx()
    msid = "MSID_INITIAL_VALUE"
    steps = setup_tper(msid, "CORRECT_PIN") + [
        start_session(ADMIN_SP, authority=SID_UID, challenge="WRONG_PIN", status="SUCCESS")
    ]
    return steps, "fail"


def tc_start_session_sid_wrong_pass() -> tuple[list[dict], str]:
    """StartSession with wrong SID challenge → NOT_AUTHORIZED is PASS."""
    _reset_idx()
    msid = "MSID_INITIAL_VALUE"
    steps = setup_tper(msid, "CORRECT_PIN") + [
        start_session(ADMIN_SP, authority=SID_UID, challenge="WRONG_PIN", status="NOT_AUTHORIZED")
    ]
    return steps, "pass"


def tc_activate_locking_sp_pass() -> tuple[list[dict], str]:
    """Activate LockingSP returns SUCCESS → PASS."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + [
        start_session(ADMIN_SP, authority=SID_UID, challenge=sid),
        activate(LOCKING_SP, status="SUCCESS"),
        end_session(),
        # Final: StartSession in LockingSP with Admin1 (which gets SID PIN on activation)
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid, status="SUCCESS"),
    ]
    return steps[:-1], "pass"  # final step is the last activate + end


def tc_activate_locking_sp_already_active_fail() -> tuple[list[dict], str]:
    """Trying to activate LockingSP when already active → FAIL."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    prefix = setup_tper(msid, sid) + activate_locking_sp(sid)
    steps = prefix + [
        # Try to activate again (should fail)
        start_session(ADMIN_SP, authority=SID_UID, challenge=sid),
        activate(LOCKING_SP, status="SUCCESS"),  # SSD returns SUCCESS but this is wrong behavior
    ]
    return steps, "fail"


def tc_user1_session_after_setup_pass() -> tuple[list[dict], str]:
    """User1 session with correct PIN → SUCCESS is PASS."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    u1_pin = "USER1PIN"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + setup_user(sid, u1_pin) + [
        start_session(LOCKING_SP, authority=USER1_UID, challenge=u1_pin, status="SUCCESS"),
    ]
    return steps, "pass"


def tc_user1_session_wrong_pin_fail() -> tuple[list[dict], str]:
    """User1 session with wrong PIN → NOT_AUTHORIZED is PASS; SSD returns SUCCESS = FAIL."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    u1_pin = "USER1PIN"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + setup_user(sid, u1_pin) + [
        start_session(LOCKING_SP, authority=USER1_UID, challenge="WRONGPIN", status="SUCCESS"),
    ]
    return steps, "fail"


def tc_user1_session_wrong_pin_pass() -> tuple[list[dict], str]:
    """User1 session with wrong PIN → NOT_AUTHORIZED is PASS."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    u1_pin = "USER1PIN"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + setup_user(sid, u1_pin) + [
        start_session(LOCKING_SP, authority=USER1_UID, challenge="WRONGPIN", status="NOT_AUTHORIZED"),
    ]
    return steps, "pass"


def tc_user1_empty_pin_session_pass() -> tuple[list[dict], str]:
    """User1 still has empty PIN (never set); StartSession with no challenge → SUCCESS is PASS."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + [
        # Enable User1 but don't set its PIN
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid),
        set_authority(USER1_UID, enabled=True),
        end_session(),
        # Now User1 has empty PIN; session without challenge should succeed
        start_session(LOCKING_SP, authority=USER1_UID, status="SUCCESS"),
    ]
    return steps, "pass"


def tc_user1_empty_pin_session_fail() -> tuple[list[dict], str]:
    """User1 has empty PIN; StartSession with non-matching challenge → NOT_AUTHORIZED is PASS; SUCCESS = FAIL."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + [
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid),
        set_authority(USER1_UID, enabled=True),
        end_session(),
        # Wrong: return SUCCESS when challenge != empty credential
        start_session(LOCKING_SP, authority=USER1_UID, challenge="WRONGPIN", status="SUCCESS"),
    ]
    return steps, "fail"


def tc_genkey_read_old_data_fail() -> tuple[list[dict], str]:
    """GenKey then Read: old plaintext should not be readable → reading old data = FAIL."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + [
        # Write some data first
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid),
        set_locking(RANGE1, {"3": 0, "4": 1048576, "5": 1, "6": 1}),
        end_session(),
    ] + [
        write_step("0-1023", "PLAINTEXT_DATA"),
        # Now do GenKey
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid),
        gen_key(K_AES_RANGE1, status="SUCCESS"),
        end_session(),
        # Read: old data should not be accessible (FAIL since GenKey changed key)
        read_step("0-1023", "PLAINTEXT_DATA", interface_result="PASS"),
    ]
    return steps, "fail"


def tc_genkey_read_new_data_pass() -> tuple[list[dict], str]:
    """GenKey then Read returns different (encrypted) data → PASS."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + [
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid),
        set_locking(RANGE1, {"3": 0, "4": 1048576, "5": 1, "6": 1}),
        end_session(),
    ] + [
        write_step("0-1023", "PLAINTEXT_DATA"),
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid),
        gen_key(K_AES_RANGE1, status="SUCCESS"),
        end_session(),
        # Read: returns different data (after key change)
        read_step("0-1023", "GARBLED_DATA_AFTER_GENKEY", interface_result="PASS"),
    ]
    return steps, "pass"


def tc_locking_get_mbrcontrol_pass() -> tuple[list[dict], str]:
    """Get MBRControl in authenticated LockingSP admin session → SUCCESS is PASS."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + [
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid),
        get_mbr(status="SUCCESS", values={"1": 0, "2": 0, "3": 0}),
    ]
    return steps, "pass"


def tc_locking_get_mbrcontrol_unauth_pass2() -> tuple[list[dict], str]:
    """Get MBRControl without auth returns SUCCESS → PASS (MBRControl is ACE_Anybody readable)."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + [
        start_session(LOCKING_SP),  # unauthenticated — Anybody can read MBRControl
        get_mbr(status="SUCCESS", values={"1": 0, "2": 0, "3": 0}),
    ]
    return steps, "pass"


def tc_locking_get_mbrcontrol_unauth_wrong_fail() -> tuple[list[dict], str]:
    """Get MBRControl without auth returns NOT_AUTHORIZED → FAIL (spec says ACE_Anybody)."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + [
        start_session(LOCKING_SP),
        get_mbr(status="NOT_AUTHORIZED"),  # wrong: should allow Anybody
    ]
    return steps, "fail"


def tc_set_locking_range_pass() -> tuple[list[dict], str]:
    """Set Locking range ReadLocked/WriteLocked by Admin1 → SUCCESS is PASS."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + [
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid),
        set_locking(RANGE1, {"3": 0, "4": 1048576, "5": 1, "6": 1}),
        end_session(),
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid),
        set_locking(RANGE1, {"7": 1, "8": 1}, status="SUCCESS"),
    ]
    return steps, "pass"


def tc_set_locking_range_unauth_fail() -> tuple[list[dict], str]:
    """Set Locking range without auth → SUCCESS is FAIL."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + [
        start_session(LOCKING_SP),  # no auth
        set_locking(RANGE1, {"7": 1, "8": 1}, status="SUCCESS"),  # should be NOT_AUTHORIZED
    ]
    return steps, "fail"


def tc_cpin_get_msid_unauthenticated_pass() -> tuple[list[dict], str]:
    """MSID PIN is readable by Anybody (no auth) → SUCCESS is PASS."""
    _reset_idx()
    steps = [
        start_session(ADMIN_SP),
        get_cpin(C_PIN_MSID, status="SUCCESS", pin_value="MSID_VALUE"),
    ]
    return steps, "pass"


def tc_cpin_get_sid_unauthenticated_fail() -> tuple[list[dict], str]:
    """SID C_PIN col 3 read without auth → SUCCESS is FAIL (should be NOT_AUTHORIZED)."""
    _reset_idx()
    steps = [
        start_session(ADMIN_SP),
        get_cpin(C_PIN_SID, status="SUCCESS", pin_value="SOME_PIN"),
    ]
    return steps, "fail"


def tc_cpin_get_sid_unauthenticated_pass() -> tuple[list[dict], str]:
    """SID C_PIN col 3 read without auth returns NOT_AUTHORIZED → PASS."""
    _reset_idx()
    steps = [
        start_session(ADMIN_SP),
        get_cpin(C_PIN_SID, status="NOT_AUTHORIZED"),
    ]
    return steps, "pass"


def tc_set_locking_range_read_lock_enables_fail() -> tuple[list[dict], str]:
    """Set ReadLockEnabled=1 then verify locking range Get returns correct values."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + [
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid),
        # Set ReadLockEnabled=1, ReadLocked=1 successfully
        set_locking(RANGE1, {"5": 1, "7": 1}),
        # Get: should show ReadLocked=1, but returns ReadLocked=0 → FAIL
        get_locking(RANGE1, 7, 8, status="SUCCESS",
                    values={"7": 0, "8": 0}),  # Wrong: ReadLocked should be 1
    ]
    return steps, "fail"


def tc_set_locking_range_read_lock_enables_pass() -> tuple[list[dict], str]:
    """Set ReadLocked=1 then Get returns ReadLocked=1 → PASS."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + [
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid),
        set_locking(RANGE1, {"5": 1, "7": 1}),
        get_locking(RANGE1, 7, 8, status="SUCCESS",
                    values={"7": 1, "8": 0}),  # Correct: ReadLocked=1
    ]
    return steps, "pass"


def tc_revertsp_then_session_pass() -> tuple[list[dict], str]:
    """After RevertSP of LockingSP, StartSession in LockingSP should fail → NOT_AUTHORIZED is PASS."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + [
        # Revert the LockingSP
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid),
        revert_sp(LOCKING_SP, status="SUCCESS"),
        # Try to open LockingSP session → should fail since LockingSP is now inactive
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid, status="NOT_AUTHORIZED"),
    ]
    return steps, "pass"


def tc_revertsp_then_session_fail() -> tuple[list[dict], str]:
    """After RevertSP, LockingSP session opens as if nothing happened → FAIL."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + [
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid),
        revert_sp(LOCKING_SP, status="SUCCESS"),
        # Wrong: LockingSP session opens after RevertSP
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid, status="SUCCESS"),
    ]
    return steps, "fail"


def tc_credential_update_latest_wins_pass() -> tuple[list[dict], str]:
    """SID credential updated twice; last update wins → session with last PIN = PASS."""
    _reset_idx()
    msid = "MSIDVAL"
    steps = [
        start_session(ADMIN_SP),
        get_cpin(C_PIN_MSID, pin_value=msid),
        end_session(),
        start_session(ADMIN_SP, authority=SID_UID, challenge=msid),
        set_cpin(C_PIN_SID, "FIRST_NEW_PIN"),
        end_session(),
        start_session(ADMIN_SP, authority=SID_UID, challenge="FIRST_NEW_PIN"),
        set_cpin(C_PIN_SID, "SECOND_NEW_PIN"),
        end_session(),
        # Session with second PIN → SUCCESS is PASS
        start_session(ADMIN_SP, authority=SID_UID, challenge="SECOND_NEW_PIN", status="SUCCESS"),
    ]
    return steps, "pass"


def tc_credential_update_old_fails() -> tuple[list[dict], str]:
    """After updating SID PIN, old PIN no longer valid; SSD returns SUCCESS with old PIN = FAIL."""
    _reset_idx()
    msid = "MSIDVAL"
    steps = [
        start_session(ADMIN_SP),
        get_cpin(C_PIN_MSID, pin_value=msid),
        end_session(),
        start_session(ADMIN_SP, authority=SID_UID, challenge=msid),
        set_cpin(C_PIN_SID, "UPDATED_PIN"),
        end_session(),
        # Old PIN should be rejected; returning SUCCESS is wrong
        start_session(ADMIN_SP, authority=SID_UID, challenge=msid, status="SUCCESS"),
    ]
    return steps, "fail"


def tc_locking_get_unauthenticated_pass() -> tuple[list[dict], str]:
    """Get Locking range admin-only columns in unauthenticated session → NOT_AUTHORIZED = PASS.
    Per spec, ACE_Locking_Range1_Get_RangeStartToActiveKey requires Admins for columns 3-10."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + [
        start_session(LOCKING_SP),  # unauthenticated (Anybody)
        get_locking(RANGE1, 5, 8, status="NOT_AUTHORIZED"),
    ]
    return steps, "pass"


def tc_locking_get_unauthenticated_fail() -> tuple[list[dict], str]:
    """Get Locking range admin columns in unauthenticated session → SUCCESS is FAIL.
    Only Admins may read RangeStart..ActiveKey; Anybody session should get NOT_AUTHORIZED."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + [
        start_session(LOCKING_SP),  # unauthenticated (Anybody)
        get_locking(RANGE1, 5, 8, status="SUCCESS",
                    values={"5": 0, "6": 0, "7": 0, "8": 0}),
    ]
    return steps, "fail"


def tc_admin2_empty_pin_session_pass() -> tuple[list[dict], str]:
    """Admin2 has empty PIN; StartSession with no challenge → SUCCESS is PASS."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + [
        # Enable Admin2 (without setting a PIN → empty PIN)
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid),
        set_authority(ADMIN2_UID, enabled=True),
        end_session(),
        # StartSession as Admin2 without challenge (empty PIN)
        start_session(LOCKING_SP, authority=ADMIN2_UID, status="SUCCESS"),
    ]
    return steps, "pass"


def tc_disabled_user1_session_fail() -> tuple[list[dict], str]:
    """User1 is disabled; StartSession as User1 → NOT_AUTHORIZED is PASS; SUCCESS = FAIL."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + [
        # User1 is disabled by default (not enabled), so session should fail
        start_session(LOCKING_SP, authority=USER1_UID, status="SUCCESS"),
    ]
    return steps, "fail"


def tc_disabled_user1_session_pass() -> tuple[list[dict], str]:
    """User1 is disabled; StartSession as User1 → NOT_AUTHORIZED is PASS."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + [
        start_session(LOCKING_SP, authority=USER1_UID, status="NOT_AUTHORIZED"),
    ]
    return steps, "pass"


def tc_set_locking_global_range_start_fail() -> tuple[list[dict], str]:
    """Set RangeStart/RangeLength on GlobalRange → INVALID_PARAMETER is PASS; SUCCESS = FAIL."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + [
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid),
        # Cannot set RangeStart on Global Range; SUCCESS is wrong
        set_locking(GLOBAL_RANGE, {"3": 1024, "4": 2048}, status="SUCCESS"),
    ]
    return steps, "fail"


def tc_set_locking_global_range_start_pass() -> tuple[list[dict], str]:
    """Set RangeStart on GlobalRange → INVALID_PARAMETER is PASS."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + [
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid),
        set_locking(GLOBAL_RANGE, {"3": 1024, "4": 2048}, status="INVALID_PARAMETER"),
    ]
    return steps, "pass"


def tc_locking_sp_not_activated_get_fail() -> tuple[list[dict], str]:
    """Get Locking range when LockingSP not activated → NOT_AUTHORIZED is PASS; SUCCESS = FAIL."""
    _reset_idx()
    steps = [
        # No activate step
        start_session(LOCKING_SP),
        get_locking(RANGE1, 5, 8, status="SUCCESS",
                    values={"5": 0, "6": 0, "7": 0, "8": 0}),
    ]
    return steps, "fail"


def tc_genkey_changes_admin1_cred_pass() -> tuple[list[dict], str]:
    """GenKey on C_PIN_Admin1 invalidates Admin1 credential; next session fails → NOT_AUTHORIZED is PASS."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + [
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid),
        gen_key(C_PIN_ADMIN1, status="SUCCESS", invoking_name="C_PIN"),
        end_session(),
        # Admin1 PIN is now unknown; session with old PIN should fail
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid, status="NOT_AUTHORIZED"),
    ]
    return steps, "pass"


def tc_genkey_changes_admin1_cred_fail() -> tuple[list[dict], str]:
    """GenKey on C_PIN_Admin1 then session with old PIN → SUCCESS is FAIL."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + [
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid),
        gen_key(C_PIN_ADMIN1, status="SUCCESS", invoking_name="C_PIN"),
        end_session(),
        # Wrong: old PIN should not work after GenKey
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid, status="SUCCESS"),
    ]
    return steps, "fail"


def tc_mbr_control_set_pass() -> tuple[list[dict], str]:
    """Set MBRControl Enable=1 by Admin1 → SUCCESS is PASS."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + [
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid),
        set_mbr({"1": 1, "2": 0}, status="SUCCESS"),
    ]
    return steps, "pass"


def tc_mbr_control_set_no_locking_sp_fail() -> tuple[list[dict], str]:
    """Set MBRControl without LockingSP active → NOT_AUTHORIZED is PASS; SUCCESS = FAIL."""
    _reset_idx()
    # No activate step
    steps = [
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge="PIN"),
        set_mbr({"1": 1, "2": 0}, status="SUCCESS"),
    ]
    return steps, "fail"


def tc_cpin_get_sid_authenticated_pass() -> tuple[list[dict], str]:
    """SID tries to read C_PIN_SID col 3 → SSD correctly returns NOT_AUTHORIZED = PASS.
    Per spec: ACE_C_PIN_SID_Get_NOPIN covers only non-PIN columns; PIN column has no read ACE."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + [
        start_session(ADMIN_SP, authority=SID_UID, challenge=sid),
        get_cpin(C_PIN_SID, status="NOT_AUTHORIZED"),
    ]
    return steps, "pass"


def tc_cpin_get_sid_wrong_auth_fail() -> tuple[list[dict], str]:
    """Non-SID authority tries to read C_PIN_SID col 3 → SUCCESS is FAIL (NOT_AUTHORIZED expected)."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + [
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid),
        # Admin1 in LockingSP cannot read C_PIN_SID (AdminSP object)
        get_cpin(C_PIN_SID, status="SUCCESS", pin_value=sid),
    ]
    return steps, "fail"


def tc_cpin_get_admin1_authenticated_pass() -> tuple[list[dict], str]:
    """Admin1 tries to read C_PIN_Admin1 col 3 → SSD correctly returns NOT_AUTHORIZED = PASS.
    Per spec: ACE_C_PIN_Admins_Get_All_NOPIN covers only non-PIN columns in LockingSP."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + [
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid),
        get_cpin(C_PIN_ADMIN1, status="NOT_AUTHORIZED"),
    ]
    return steps, "pass"


def tc_cpin_get_user1_own_pin_pass() -> tuple[list[dict], str]:
    """User1 tries to read C_PIN_User1 col 3 → SSD correctly returns NOT_AUTHORIZED = PASS.
    Per spec: No ACE in LockingSP grants Users PIN column read access."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    u1_pin = "USER1PIN"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + setup_user(sid, u1_pin) + [
        start_session(LOCKING_SP, authority=USER1_UID, challenge=u1_pin),
        get_cpin(C_PIN_USER1, status="NOT_AUTHORIZED"),
    ]
    return steps, "pass"


def tc_cpin_get_user1_by_admin1_fail() -> tuple[list[dict], str]:
    """Admin1 tries to read User1's C_PIN col 3 → NOT_AUTHORIZED is PASS; SUCCESS = FAIL."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    u1_pin = "USER1PIN"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + setup_user(sid, u1_pin) + [
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid),
        # Admin1 cannot read User1's PIN
        get_cpin(C_PIN_USER1, status="SUCCESS", pin_value=u1_pin),
    ]
    return steps, "fail"


def tc_cpin_get_admin1_not_authorized_pass() -> tuple[list[dict], str]:
    """Admin1 tries to read User1's C_PIN col 3 → SSD correctly returns NOT_AUTHORIZED = PASS."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    u1_pin = "USER1PIN"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + setup_user(sid, u1_pin) + [
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid),
        get_cpin(C_PIN_USER1, status="NOT_AUTHORIZED"),
    ]
    return steps, "pass"


def tc_cpin_get_sid_own_pin_success_fail() -> tuple[list[dict], str]:
    """SSD wrongly returns SUCCESS when SID reads C_PIN_SID col 3 → FAIL.
    Per spec PIN column has no read ACE for C_PIN_SID — NOT_AUTHORIZED should be returned."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + [
        start_session(ADMIN_SP, authority=SID_UID, challenge=sid),
        get_cpin(C_PIN_SID, status="SUCCESS", pin_value=sid),
    ]
    return steps, "fail"


def tc_cpin_get_admin1_own_pin_success_fail() -> tuple[list[dict], str]:
    """SSD wrongly returns SUCCESS when Admin1 reads C_PIN_Admin1 col 3 → FAIL.
    Per spec ACE_C_PIN_Admins_Get_All_NOPIN excludes PIN column in LockingSP."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + [
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid),
        get_cpin(C_PIN_ADMIN1, status="SUCCESS", pin_value=sid),
    ]
    return steps, "fail"


def tc_write_read_no_genkey_pass() -> tuple[list[dict], str]:
    """Write then Read without GenKey → old data is still readable = PASS."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + [
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid),
        set_locking(RANGE1, {"3": 0, "4": 1048576, "5": 1, "6": 1}),
        end_session(),
        write_step("0-1023", "PLAINTEXT_DATA"),
        read_step("0-1023", "PLAINTEXT_DATA"),
    ]
    return steps, "pass"


def tc_write_read_no_genkey_different_fail() -> tuple[list[dict], str]:
    """Write PATTERN_A then Read returns PATTERN_B (without GenKey) → FAIL."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + [
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid),
        set_locking(RANGE1, {"3": 0, "4": 1048576, "5": 1, "6": 1}),
        end_session(),
        write_step("0-1023", "PATTERN_A"),
        # Read returns different data without GenKey → FAIL
        read_step("0-1023", "PATTERN_B"),
    ]
    return steps, "fail"


def tc_activate_locked_sp_fail() -> tuple[list[dict], str]:
    """StartSession to LockingSP before Activate → NOT_AUTHORIZED is PASS; SUCCESS = FAIL."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + [
        # No Activate step — LockingSP not active
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid, status="SUCCESS"),
    ]
    return steps, "fail"


def tc_activate_locked_sp_pass() -> tuple[list[dict], str]:
    """StartSession to LockingSP before Activate → NOT_AUTHORIZED is PASS."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + [
        # No Activate step — LockingSP not active
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid, status="NOT_AUTHORIZED"),
    ]
    return steps, "pass"


def tc_activate_with_wrong_authority_fail() -> tuple[list[dict], str]:
    """Activate LockingSP with non-SID authority (Admin1 in AdminSP) → SUCCESS = FAIL."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    # Need to authenticate as some non-SID authority in AdminSP - use default MSID (trick: pretend we know MSID as Admin1)
    # Actually, set up a scenario where we're in AdminSP but NOT as SID
    steps = [
        # Read MSID, authenticate as SID (to set up state), but then try Activate as Anybody
        start_session(ADMIN_SP),  # Anybody (unauthenticated)
        # Trying to Activate when not SID — but we are in AdminSP (Anybody)
        activate(LOCKING_SP, status="SUCCESS"),  # SSD incorrectly accepts
    ]
    return steps, "fail"


def tc_activate_with_wrong_authority_pass() -> tuple[list[dict], str]:
    """Activate LockingSP without SID auth → NOT_AUTHORIZED is PASS."""
    _reset_idx()
    steps = [
        start_session(ADMIN_SP),  # Anybody (unauthenticated)
        activate(LOCKING_SP, status="NOT_AUTHORIZED"),  # Correctly rejects non-SID
    ]
    return steps, "pass"


def tc_activate_wrong_uid_fail() -> tuple[list[dict], str]:
    """Activate wrong UID → SUCCESS = FAIL (should be FAIL/NOT_AUTHORIZED from SSD)."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    # Activate a non-existent SP UID (0000010500000004 like in tc15)
    steps = setup_tper(msid, sid) + [
        start_session(ADMIN_SP, authority=SID_UID, challenge=sid),
        # Wrong target UID - should not succeed
        make_step("Activate", "0000010500000004", {}, {}, "SUCCESS", invoking_name="SP"),
    ]
    return steps, "fail"


# ---- D-P2: Log table existence and CreateLog uniqueness ------------------

def tc_addlog_default_exists_pass() -> tuple[list[dict], str]:
    """AddLog to default pre-existing Log table → SUCCESS is PASS (table exists)."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    # Final step is AddLog; no end_session so it is the judged event.
    steps = setup_tper(msid, sid) + [
        start_session(ADMIN_SP, authority=SID_UID, challenge=sid),
        make_step("AddLog", LOG_TABLE_UID, {"LogEntryName": "entry1", "Data": "test entry"}, {}, "SUCCESS", invoking_name="Log"),
    ]
    return steps, "pass"


def tc_addlog_nonexistent_fail() -> tuple[list[dict], str]:
    """AddLog to non-existent log UID → SUCCESS is FAIL (table was never created)."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    # LOG_FAKE_UID is template-level (starts "00000001") but not seeded in log_tables.
    steps = setup_tper(msid, sid) + [
        start_session(ADMIN_SP, authority=SID_UID, challenge=sid),
        make_step("AddLog", LOG_FAKE_UID, {"LogEntryName": "entry1", "Data": "test entry"}, {}, "SUCCESS", invoking_name="Log"),
    ]
    return steps, "fail"


def tc_createlog_duplicate_fail() -> tuple[list[dict], str]:
    """CreateLog same name twice; second returns SUCCESS → FAIL (duplicate not rejected)."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    # First CreateLog is a prefix event (succeeds). Final step is the duplicate attempt.
    steps = setup_tper(msid, sid) + [
        start_session(ADMIN_SP, authority=SID_UID, challenge=sid),
        make_step("CreateLog", LOG_LIST_UID, {"NewLogTableName": "AuditLog"}, {}, "SUCCESS", invoking_name="LogList"),
        end_session(),
        start_session(ADMIN_SP, authority=SID_UID, challenge=sid),
        make_step("CreateLog", LOG_LIST_UID, {"NewLogTableName": "AuditLog"}, {}, "SUCCESS", invoking_name="LogList"),
    ]
    return steps, "fail"


def tc_createlog_duplicate_pass() -> tuple[list[dict], str]:
    """CreateLog same name twice; second returns INVALID_PARAMETER → PASS (correctly rejected)."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + [
        start_session(ADMIN_SP, authority=SID_UID, challenge=sid),
        make_step("CreateLog", LOG_LIST_UID, {"NewLogTableName": "AuditLog"}, {}, "SUCCESS", invoking_name="LogList"),
        end_session(),
        start_session(ADMIN_SP, authority=SID_UID, challenge=sid),
        make_step("CreateLog", LOG_LIST_UID, {"NewLogTableName": "AuditLog"}, {}, "INVALID_PARAMETER", invoking_name="LogList"),
    ]
    return steps, "pass"


# ---- D-P1: Re-encryption range geometry and key restrictions -------------

def tc_reencrypt_set_geometry_fail() -> tuple[list[dict], str]:
    """Set RangeStart while re-encryption pending → SUCCESS = FAIL (non-IDLE range)."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    admin1 = "ADMIN1PIN"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + [
        # Move Range1 to non-IDLE state: ReEncryptRequest=1 (StartReq) from IDLE → Pending
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=admin1),
        set_locking(RANGE1, {13: 1}),   # col 13 = ReEncryptRequest=1 → triggers Pending state
        end_session(),
        # Final step: try to change geometry while non-IDLE — drive incorrectly succeeds
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=admin1),
        set_locking(RANGE1, {3: 100}),  # col 3 = RangeStart — forbidden while non-IDLE
    ]
    return steps, "fail"


def tc_reencrypt_genkey_fail() -> tuple[list[dict], str]:
    """GenKey on a range key while re-encryption pending → SUCCESS = FAIL."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    admin1 = "ADMIN1PIN"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + [
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=admin1),
        set_locking(RANGE1, {13: 1}),   # ReEncryptRequest=1 → Range1 non-IDLE
        end_session(),
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=admin1),
        gen_key(K_AES_RANGE1, status="SUCCESS"),  # GenKey while non-IDLE — must fail
    ]
    return steps, "fail"


def tc_reencrypt_idle_set_ok() -> tuple[list[dict], str]:
    """Set RangeStart when range is IDLE → SUCCESS = PASS (normal case)."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    admin1 = "ADMIN1PIN"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + [
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=admin1),
        set_locking(RANGE1, {3: 100, 4: 1024}),  # RangeStart + RangeLength — IDLE → allowed
    ]
    return steps, "pass"


# ---- E-P1: Reset events must abort sessions ------------------------------

def _power_cycle_step() -> dict:
    """Synthesize a Power Cycle command event."""
    return {
        "index": _next_idx(),
        "input": {"command": "Power Cycle", "args": {}},
        "output": {"result": "pass"},
    }


def tc_reset_session_survives_fail() -> tuple[list[dict], str]:
    """Open session → Power Cycle → Get that requires the session returns SUCCESS = FAIL."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + [
        # Open AdminSP session as SID
        start_session(ADMIN_SP, authority=SID_UID, challenge=sid),
        # Power cycle — must abort the session
        _power_cycle_step(),
        # Get on C_PIN_MSID: only needs open AdminSP session (Anybody).
        # After reset the session is gone; drive incorrectly returns SUCCESS.
        make_step("Get", C_PIN_MSID, {"Cellblock": [{"startColumn": 0}, {"endColumn": 2}]}, {}, "SUCCESS", invoking_name="C_PIN"),
    ]
    return steps, "fail"


def tc_reset_session_aborted_pass() -> tuple[list[dict], str]:
    """Open session → Power Cycle → Get returns NOT_AUTHORIZED = PASS (session correctly aborted)."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + [
        start_session(ADMIN_SP, authority=SID_UID, challenge=sid),
        _power_cycle_step(),
        make_step("Get", C_PIN_MSID, {"Cellblock": [{"startColumn": 0}, {"endColumn": 2}]}, {}, "NOT_AUTHORIZED", invoking_name="C_PIN"),
    ]
    return steps, "pass"


# ---- C-P0-1: Two-step Authenticate (Sign/SymK/HMAC challenge-response) ----

def tc_sign_auth_proof_pass() -> tuple[list[dict], str]:
    """Sign authority Authenticate with proof returning SUCCESS → PASS (core/5.3.4.1.14)."""
    _reset_idx()
    steps = [
        start_session(ADMIN_SP),
        # Enable User1 and set operation=Sign (columns 5=enabled, 9=operation)
        make_step("Set", USER1_UID, {}, {"Values": [{5: 1, 9: "Sign"}]}, "SUCCESS"),
        # Final: second-step Authenticate, proof provided, SSD returns SUCCESS with result=True
        authenticate_step(USER1_UID, proof="testproof", auth_result=True, status="SUCCESS"),
    ]
    return steps, "pass"


def tc_sign_auth_proof_inv_param_fail() -> tuple[list[dict], str]:
    """Sign authority Authenticate with proof returning INVALID_PARAMETER → FAIL (core/5.3.4.1.14)."""
    _reset_idx()
    steps = [
        start_session(ADMIN_SP),
        make_step("Set", USER1_UID, {}, {"Values": [{5: 1, 9: "Sign"}]}, "SUCCESS"),
        authenticate_step(USER1_UID, proof="testproof", auth_result=None, status="INVALID_PARAMETER"),
    ]
    return steps, "fail"


# ---- A-P1: SP Disabled/Frozen lifecycle state blocks StartSession -----------

def tc_disabled_sp_session_fail() -> tuple[list[dict], str]:
    """Disable LockingSP then StartSession to it returns SUCCESS → FAIL (core/4.3.6)."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + [
        # In AdminSP, set LockingSP row column 6 (lifecycle/enabled) = 0 (disabled)
        start_session(ADMIN_SP, authority=SID_UID, challenge=sid),
        make_step("Set", LOCKING_SP, {}, {"Values": [{6: 0}]}, "SUCCESS", invoking_name="SP"),
        end_session(),
        # StartSession to disabled LockingSP → SSD incorrectly returns SUCCESS → FAIL
        start_session(LOCKING_SP, status="SUCCESS"),
    ]
    return steps, "fail"


def tc_disabled_sp_session_pass() -> tuple[list[dict], str]:
    """Disable LockingSP then StartSession to it returns SP_DISABLED → PASS (core/4.3.6)."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + [
        start_session(ADMIN_SP, authority=SID_UID, challenge=sid),
        make_step("Set", LOCKING_SP, {}, {"Values": [{6: 0}]}, "SUCCESS", invoking_name="SP"),
        end_session(),
        # StartSession to disabled LockingSP → SSD correctly returns SP_DISABLED → PASS
        start_session(LOCKING_SP, status="SP_DISABLED"),
    ]
    return steps, "pass"


# ---- C-P0-5: AddACE/RemoveACE/DeleteMethod ACL state mutations ---------------

def tc_add_ace_grants_anyone_set_pass() -> tuple[list[dict], str]:
    """AddACE(Range1, Set, ACE_Anybody) then unauthenticated Set → SUCCESS = PASS."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    admin1 = "ADMIN1PIN"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + [
        # Admin1 grants Anybody access to Range1 Set
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=admin1),
        add_ace_step(RANGE1, SET_METHOD_UID, ACE_ANYBODY_UID),
        end_session(),
        # Unauthenticated write session to LockingSP
        start_session(LOCKING_SP),
        # Final: unauthenticated Set on Range1 → SUCCESS (ACE_Anybody grants access) → PASS
        set_locking(RANGE1, {5: 1}),
    ]
    return steps, "pass"


def tc_add_ace_grants_anyone_set_fail() -> tuple[list[dict], str]:
    """AddACE(Range1, Set, ACE_Anybody) then unauthenticated Set returns AUTH_ERROR → FAIL."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    admin1 = "ADMIN1PIN"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + [
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=admin1),
        add_ace_step(RANGE1, SET_METHOD_UID, ACE_ANYBODY_UID),
        end_session(),
        start_session(LOCKING_SP),
        # Final: AUTH_ERROR even though ACE_Anybody should authorize → FAIL
        set_locking(RANGE1, {5: 1}, status="NOT_AUTHORIZED"),
    ]
    return steps, "fail"


def tc_read_locked_range_fail() -> tuple[list[dict], str]:
    """ReadLocked range read returns data (not error) → FAIL."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + [
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid),
        set_locking(RANGE1, {"3": 0, "4": 1048576, "5": 1, "6": 1, "7": 1}),
        end_session(),
        # ReadLocked=1, reading should fail but returns data
        read_step("0-1023", "SOME_DATA", interface_result="PASS"),
    ]
    return steps, "fail"


def tc_read_locked_range_pass() -> tuple[list[dict], str]:
    """ReadLocked range read returns error → PASS."""
    _reset_idx()
    msid = "MSIDVAL"
    sid = "SIDVAL"
    steps = setup_tper(msid, sid) + activate_locking_sp(sid) + [
        start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid),
        set_locking(RANGE1, {"3": 0, "4": 1048576, "5": 1, "6": 1, "7": 1}),
        end_session(),
        # ReadLocked=1, read should fail
        read_step("0-1023", "DATA_PROTECTION_ERROR", interface_result="FAIL"),
    ]
    return steps, "pass"


# ---- F-P0: TPerInfo ProgrammaticResetEnable column is SID-only writable -----

def tc_tperinfo_set_admin1_fail() -> tuple[list[dict], str]:
    """Admin1 (not SID) Set on TPerInfo col-8 returning SUCCESS → FAIL (SID only per opal/4.2.3.1)."""
    _reset_idx()
    steps = [
        # AdminSP session as Admin1 (not SID)
        start_session(ADMIN_SP, authority=ADMIN1_UID, challenge="ADMIN1PIN"),
        # Final: Set TPerInfo column 8 (ProgrammaticResetEnable) → SUCCESS
        make_step("Set", TPERINFO_UID, {}, {"Values": [{8: True}]}, "SUCCESS", invoking_name="TPerInfo"),
    ]
    return steps, "fail"


def tc_tperinfo_set_admin1_pass() -> tuple[list[dict], str]:
    """Admin1 Set on TPerInfo col-8 returning NOT_AUTHORIZED → PASS (SID only; Admin1 correctly rejected)."""
    _reset_idx()
    steps = [
        start_session(ADMIN_SP, authority=ADMIN1_UID, challenge="ADMIN1PIN"),
        make_step("Set", TPERINFO_UID, {}, {"Values": [{8: True}]}, "NOT_AUTHORIZED", invoking_name="TPerInfo"),
    ]
    return steps, "pass"


def tc_datarmv_reserved_enum_fail() -> tuple[list[dict], str]:
    """Set DataRemovalMechanism col-1 with reserved value 3 returning SUCCESS → FAIL (opal/4.2.6.1)."""
    _reset_idx()
    steps = [
        start_session(ADMIN_SP, authority=SID_UID, challenge="SIDPIN"),
        # Final: Set ActiveDataRemovalMechanism = 3 (reserved) → SUCCESS (wrong; should be INVALID_PARAMETER)
        make_step("Set", DATARMV_UID, {}, {"Values": [{1: 3}]}, "SUCCESS", invoking_name="DataRemovalMechanism"),
    ]
    return steps, "fail"


def tc_datarmv_reserved_enum_pass() -> tuple[list[dict], str]:
    """Set DataRemovalMechanism col-1 with reserved value 3 returning INVALID_PARAMETER → PASS (opal/4.2.6.1)."""
    _reset_idx()
    steps = [
        start_session(ADMIN_SP, authority=SID_UID, challenge="SIDPIN"),
        # Final: INVALID_PARAMETER for reserved value 3 → correct SSD behavior → PASS
        make_step("Set", DATARMV_UID, {}, {"Values": [{1: 3}]}, "INVALID_PARAMETER",
                  invoking_name="DataRemovalMechanism"),
    ]
    return steps, "pass"


# ---- F-P0: AccessControl (N) columns (InvokingID=1, MethodID=2, ACL=4, GetACLACL=8) ----

AC_ROW_UID = "0000000700000001"  # a generic AccessControl row UID (normalizes to "AccessControl")
GET_METHOD_UID = "0000000600000006"  # Method UID for Get


def tc_access_control_get_n_col_pass() -> tuple[list[dict], str]:
    """Get on AccessControl row with ACL column (col 4, (N)) returns NOT_AUTHORIZED → PASS."""
    _reset_idx()
    steps = [
        start_session(ADMIN_SP),
        # Final: Get on AccessControl row requesting ACL col (4) — (N) means not readable via Get
        make_step(
            "Get", AC_ROW_UID,
            {"Cellblock": [{"startColumn": 4}, {"endColumn": 4}]},
            {},
            "NOT_AUTHORIZED",
            invoking_name="AccessControl",
        ),
    ]
    return steps, "pass"


def tc_access_control_get_n_col_fail() -> tuple[list[dict], str]:
    """Get on AccessControl row with ACL column (col 4, (N)) returns SUCCESS → FAIL."""
    _reset_idx()
    steps = [
        start_session(ADMIN_SP),
        # Final: Get on AccessControl row requesting ACL col (4) — device incorrectly returns SUCCESS
        make_step(
            "Get", AC_ROW_UID,
            {"Cellblock": [{"startColumn": 4}, {"endColumn": 4}]},
            {},
            "SUCCESS",
            invoking_name="AccessControl",
        ),
    ]
    return steps, "fail"


def tc_getacl_unauth_pass() -> tuple[list[dict], str]:
    """GetACL in unauthenticated AdminSP session returns SUCCESS → PASS (GetACLACL=ACE_Anybody)."""
    _reset_idx()
    steps = [
        start_session(ADMIN_SP),
        # Final: GetACL — GetACLACL defaults to ACE_Anybody so any open session may call it
        make_step(
            "GetACL", ACCESS_CONTROL_TABLE_UID,
            {},
            {"InvokingID": RANGE1, "MethodID": SET_METHOD_UID},
            "SUCCESS",
            invoking_name="AccessControl",
        ),
    ]
    return steps, "pass"


def tc_getacl_unauth_fail() -> tuple[list[dict], str]:
    """GetACL in unauthenticated AdminSP session returns NOT_AUTHORIZED → FAIL (wrongly rejected)."""
    _reset_idx()
    steps = [
        start_session(ADMIN_SP),
        # Final: GetACL returns NOT_AUTHORIZED — wrong; device should allow it via ACE_Anybody
        make_step(
            "GetACL", ACCESS_CONTROL_TABLE_UID,
            {},
            {"InvokingID": RANGE1, "MethodID": SET_METHOD_UID},
            "NOT_AUTHORIZED",
            invoking_name="AccessControl",
        ),
    ]
    return steps, "fail"


# ---- E-P1: Level 0 Discovery (IF_RECV) normalization and judging ----------

def _compliant_features(locking_enabled: int = 0, num_admins: int = 4, num_users: int = 8) -> list:
    return [
        {"feature_code": 1, "sync_supported": 1, "streaming_supported": 1},
        {
            "feature_code": 2, "locking_supported": 1, "locking_enabled": locking_enabled,
            "locked": 0, "media_encryption": 1, "mbr_shadowing_not_supported": 0,
            "mbr_enabled": 0, "mbr_done": 0,
        },
        {"feature_code": 515, "num_comids": 1, "num_admins": num_admins, "num_users": num_users},
    ]


def discovery_step(features: list, result: str = "pass") -> dict:
    return {
        "index": _next_idx(),
        "input": {
            "command": "IF_RECV",
            "args": {"SecurityProtocol": "01", "SecurityProtocolSpecific": "0001"},
        },
        "output": {
            "command": "IF_RECV",
            "result": result,
            "discovery": {"features": features},
        },
    }


def tc_discovery_compliant_pass() -> tuple[list[dict], str]:
    """Compliant Level 0 Discovery (inactive LockingSP) returns pass → PASS."""
    _reset_idx()
    steps = [discovery_step(_compliant_features(locking_enabled=0))]
    return steps, "pass"


def tc_discovery_missing_opal_v2_fail() -> tuple[list[dict], str]:
    """Level 0 Discovery missing Opal SSC V2 descriptor → FAIL (opal/3.1.1)."""
    _reset_idx()
    features = [
        {"feature_code": 1, "sync_supported": 1, "streaming_supported": 1},
        {"feature_code": 2, "locking_supported": 1, "locking_enabled": 0, "media_encryption": 1},
        # Opal SSC V2 (code 515) intentionally absent
    ]
    steps = [discovery_step(features)]
    return steps, "fail"


def tc_discovery_locking_enabled_before_activation_fail() -> tuple[list[dict], str]:
    """Discovery reports LockingEnabled=1 but LockingSP not yet activated → FAIL (opal/3.1.1.3.1)."""
    _reset_idx()
    steps = [
        discovery_step(_compliant_features(locking_enabled=1)),
    ]
    return steps, "fail"


def tc_discovery_too_few_admins_fail() -> tuple[list[dict], str]:
    """Discovery reports only 2 admin authorities (< 4 required) → FAIL (opal/3.1.1.5)."""
    _reset_idx()
    steps = [discovery_step(_compliant_features(num_admins=2))]
    return steps, "fail"


# ---- All scenarios -------------------------------------------------------

SCENARIOS = [
    ("syn_pass_01_properties",                tc_properties_pass),
    ("syn_fail_01_properties",                tc_properties_fail),
    ("syn_pass_02_unauth_session",            tc_start_session_unauthenticated_pass),
    ("syn_fail_02_unauth_session",            tc_start_session_unauthenticated_fail),
    ("syn_pass_03_sid_correct",               tc_start_session_sid_correct_pass),
    ("syn_fail_03_sid_wrong",                 tc_start_session_sid_wrong_fail),
    ("syn_pass_04_sid_wrong_rejected",        tc_start_session_sid_wrong_pass),
    ("syn_pass_05_user1_correct",             tc_user1_session_after_setup_pass),
    ("syn_fail_05_user1_wrong",               tc_user1_session_wrong_pin_fail),
    ("syn_pass_06_user1_wrong_rejected",      tc_user1_session_wrong_pin_pass),
    ("syn_pass_07_user1_empty_pin",           tc_user1_empty_pin_session_pass),
    ("syn_fail_07_user1_empty_pin_wrong",     tc_user1_empty_pin_session_fail),
    ("syn_fail_08_genkey_read_old",           tc_genkey_read_old_data_fail),
    ("syn_pass_08_genkey_read_new",           tc_genkey_read_new_data_pass),
    ("syn_pass_09_mbrcontrol_auth",            tc_locking_get_mbrcontrol_pass),
    ("syn_pass_10_mbrcontrol_unauth_ok",       tc_locking_get_mbrcontrol_unauth_pass2),
    ("syn_fail_10_mbrcontrol_unauth_rejected", tc_locking_get_mbrcontrol_unauth_wrong_fail),
    ("syn_pass_11_locking_range_set",         tc_set_locking_range_pass),
    ("syn_fail_11_locking_range_unauth",      tc_set_locking_range_unauth_fail),
    ("syn_pass_12_msid_read",                 tc_cpin_get_msid_unauthenticated_pass),
    ("syn_fail_12_sid_read_unauth",           tc_cpin_get_sid_unauthenticated_fail),
    ("syn_pass_13_sid_read_rejected",         tc_cpin_get_sid_unauthenticated_pass),
    ("syn_fail_14_locking_get_wrong_values",  tc_set_locking_range_read_lock_enables_fail),
    ("syn_pass_14_locking_get_correct",       tc_set_locking_range_read_lock_enables_pass),
    ("syn_pass_15_revertsp_session_fails",    tc_revertsp_then_session_pass),
    ("syn_fail_15_revertsp_session_opens",    tc_revertsp_then_session_fail),
    ("syn_pass_16_cred_update_latest",        tc_credential_update_latest_wins_pass),
    ("syn_fail_16_cred_update_old_pin",       tc_credential_update_old_fails),
    ("syn_pass_17_locking_get_unauth",        tc_locking_get_unauthenticated_pass),
    ("syn_fail_17_locking_get_unauth",        tc_locking_get_unauthenticated_fail),
    ("syn_pass_18_admin2_empty_pin",          tc_admin2_empty_pin_session_pass),
    ("syn_fail_19_disabled_user1",            tc_disabled_user1_session_fail),
    ("syn_pass_19_disabled_user1",            tc_disabled_user1_session_pass),
    ("syn_fail_20_global_range_start",        tc_set_locking_global_range_start_fail),
    ("syn_pass_20_global_range_start",        tc_set_locking_global_range_start_pass),
    ("syn_fail_21_locking_not_active",        tc_locking_sp_not_activated_get_fail),
    ("syn_pass_22_genkey_cpin_auth_fails",    tc_genkey_changes_admin1_cred_pass),
    ("syn_fail_22_genkey_cpin_auth_ok",       tc_genkey_changes_admin1_cred_fail),
    ("syn_pass_23_mbr_control_set",           tc_mbr_control_set_pass),
    ("syn_fail_24_mbr_no_locking",            tc_mbr_control_set_no_locking_sp_fail),
    # C_PIN col 3 access control (only MSID PIN is readable; all other PINs are NOT readable)
    ("syn_pass_25_sid_cpin_na",               tc_cpin_get_sid_authenticated_pass),     # SSD returns NOT_AUTH = PASS
    ("syn_fail_25_sid_reads_sid_cpin",        tc_cpin_get_sid_own_pin_success_fail),   # SSD returns SUCCESS = FAIL
    ("syn_fail_25b_admin1_reads_sid_cpin",    tc_cpin_get_sid_wrong_auth_fail),        # wrong SP, SUCCESS = FAIL
    ("syn_pass_26_admin1_cpin_na",            tc_cpin_get_admin1_authenticated_pass),  # SSD returns NOT_AUTH = PASS
    ("syn_fail_26_admin1_reads_own_cpin",     tc_cpin_get_admin1_own_pin_success_fail),# SSD returns SUCCESS = FAIL
    ("syn_pass_27_user1_cpin_na",             tc_cpin_get_user1_own_pin_pass),         # SSD returns NOT_AUTH = PASS
    ("syn_fail_27_admin1_reads_user1_cpin",   tc_cpin_get_user1_by_admin1_fail),
    ("syn_pass_27b_admin1_reads_user1_cpin_na", tc_cpin_get_admin1_not_authorized_pass),
    # Read/Write consistency
    ("syn_pass_28_write_read_same",           tc_write_read_no_genkey_pass),
    ("syn_fail_28_write_read_different",      tc_write_read_no_genkey_different_fail),
    # LockingSP not activated
    ("syn_fail_29_session_before_activate",   tc_activate_locked_sp_fail),
    ("syn_pass_29_session_before_activate",   tc_activate_locked_sp_pass),
    # Read-locked range
    ("syn_fail_30_read_locked",               tc_read_locked_range_fail),
    ("syn_pass_30_read_locked_error",         tc_read_locked_range_pass),
    # Activate authority checks
    ("syn_fail_31_activate_no_sid",           tc_activate_with_wrong_authority_fail),
    ("syn_pass_31_activate_rejected",         tc_activate_with_wrong_authority_pass),
    ("syn_fail_32_activate_wrong_uid",        tc_activate_wrong_uid_fail),
    # D-P2: Log table existence and CreateLog uniqueness
    ("syn_pass_33_addlog_default",            tc_addlog_default_exists_pass),
    ("syn_fail_33_addlog_nonexistent",        tc_addlog_nonexistent_fail),
    ("syn_fail_34_createlog_duplicate",       tc_createlog_duplicate_fail),
    ("syn_pass_34_createlog_duplicate_ok",    tc_createlog_duplicate_pass),
    # D-P1: Re-encryption range geometry and key restrictions
    ("syn_fail_35_reencrypt_set_geometry",    tc_reencrypt_set_geometry_fail),
    ("syn_fail_36_reencrypt_genkey",          tc_reencrypt_genkey_fail),
    ("syn_pass_35_reencrypt_idle_set",        tc_reencrypt_idle_set_ok),
    # E-P1: Reset events must abort sessions
    ("syn_fail_37_reset_session_survives",    tc_reset_session_survives_fail),
    ("syn_pass_37_reset_session_aborted",     tc_reset_session_aborted_pass),
    # C-P0-1: Two-step Authenticate (Sign/SymK/HMAC challenge-response)
    ("syn_pass_38_sign_auth_proof",           tc_sign_auth_proof_pass),
    ("syn_fail_38_sign_auth_inv_param",       tc_sign_auth_proof_inv_param_fail),
    # A-P1: SP Disabled lifecycle blocks StartSession
    ("syn_fail_39_disabled_sp_session",       tc_disabled_sp_session_fail),
    ("syn_pass_39_disabled_sp_session",       tc_disabled_sp_session_pass),
    # C-P0-5: AddACE/RemoveACE/DeleteMethod ACL state mutations
    ("syn_pass_40_addace_anybody_set",        tc_add_ace_grants_anyone_set_pass),
    ("syn_fail_40_addace_anybody_set",        tc_add_ace_grants_anyone_set_fail),
    # F-P0: TPerInfo ProgrammaticResetEnable is SID-only writable
    ("syn_fail_41_tperinfo_admin1_set",       tc_tperinfo_set_admin1_fail),
    ("syn_pass_41_tperinfo_admin1_rejected",  tc_tperinfo_set_admin1_pass),
    # F-P0: DataRemovalMechanism ActiveDataRemovalMechanism reserved enum validation
    ("syn_fail_42_datarmv_reserved_enum",     tc_datarmv_reserved_enum_fail),
    ("syn_pass_42_datarmv_reserved_enum",     tc_datarmv_reserved_enum_pass),
    # F-P0: AccessControl (N) columns — not readable via Get; GetACL uses GetACLACL (ACE_Anybody)
    ("syn_pass_43_ac_get_n_col",              tc_access_control_get_n_col_pass),
    ("syn_fail_43_ac_get_n_col",              tc_access_control_get_n_col_fail),
    ("syn_pass_44_getacl_unauth",             tc_getacl_unauth_pass),
    ("syn_fail_44_getacl_unauth",             tc_getacl_unauth_fail),
    # E-P1: Level 0 Discovery normalization and judging
    ("syn_pass_45_discovery_compliant",       tc_discovery_compliant_pass),
    ("syn_fail_45_discovery_missing_v2",      tc_discovery_missing_opal_v2_fail),
    ("syn_fail_46_discovery_locking_enabled", tc_discovery_locking_enabled_before_activation_fail),
    ("syn_fail_47_discovery_few_admins",      tc_discovery_too_few_admins_fail),
]


def write_case(name: str, steps: list[dict]) -> Path:
    path = SYNTHETIC_DIR / f"{name}.json"
    path.write_text(json.dumps(steps, indent=2) + "\n")
    return path


def generate_all() -> list[tuple[str, str]]:
    SYNTHETIC_DIR.mkdir(exist_ok=True)
    labels: list[tuple[str, str]] = []
    for name, builder in SCENARIOS:
        steps, verdict = builder()
        write_case(name, steps)
        labels.append((f"{name}.json", verdict))
    # Write labels
    with SYNTHETIC_LABELS.open("w") as f:
        for filename, label in labels:
            f.write(json.dumps({"filename": filename, "label": label}) + "\n")
    return labels


def check_accuracy() -> None:
    if not SYNTHETIC_DIR.is_dir():
        raise SystemExit(f"Missing synthetic testcase directory: {SYNTHETIC_DIR}")
    if not SYNTHETIC_LABELS.is_file():
        raise SystemExit(f"Missing synthetic labels file: {SYNTHETIC_LABELS}")

    sys.path.insert(0, str(PROJECT_ROOT))
    from src.solver import Solver

    solver = Solver()
    dataset = [
        {"id": path.name, "steps": json.loads(path.read_text())}
        for path in sorted(SYNTHETIC_DIR.glob("syn_*.json"))
    ]
    labels = {}
    with SYNTHETIC_LABELS.open() as f:
        for line in f:
            rec = json.loads(line)
            labels[rec["filename"]] = rec["label"]

    predictions = solver.predict(dataset)
    correct = total = 0
    wrongs: list[str] = []
    for item in dataset:
        cid = item["id"]
        pred = predictions.get(cid, "fail")
        ans = labels.get(cid, "?")
        total += 1
        if pred == ans:
            correct += 1
        else:
            wrongs.append(f"  {cid}: predicted={pred!r} expected={ans!r}")

    print(f"Synthetic dataset accuracy: {correct}/{total} ({100.0*correct/total:.1f}%)")
    if wrongs:
        print("Wrong predictions:")
        for w in wrongs:
            print(w)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic TCG/Opal test cases")
    parser.add_argument("--check", action="store_true", help="Check solver accuracy on generated cases")
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Check solver accuracy using existing synthetic_testcases and synthetic_labels.jsonl",
    )
    args = parser.parse_args()

    if args.check_only:
        check_accuracy()
        return

    labels = generate_all()
    pass_count = sum(1 for _, v in labels if v == "pass")
    fail_count = sum(1 for _, v in labels if v == "fail")
    print(f"Generated {len(labels)} cases ({pass_count} pass, {fail_count} fail)")
    print(f"  → {SYNTHETIC_DIR}/")
    print(f"  → {SYNTHETIC_LABELS}")

    if args.check:
        check_accuracy()


if __name__ == "__main__":
    main()

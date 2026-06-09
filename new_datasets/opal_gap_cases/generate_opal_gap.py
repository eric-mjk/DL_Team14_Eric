#!/usr/bin/env python3
"""Generate Opal SSC gap cases in the project JSON trajectory format."""
from __future__ import annotations

import argparse
from copy import deepcopy
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


ROOT = Path(__file__).resolve().parents[2]
CUSTOM = ROOT / "new_datasets" / "customtest_84"
if str(CUSTOM) not in sys.path:
    sys.path.insert(0, str(CUSTOM))

from generate_synthetic import (  # noqa: E402
    ACCESS_CONTROL_TABLE_UID,
    ACE_ANYBODY_UID,
    ADMIN1_UID,
    ADMIN2_UID,
    ADMIN_SP,
    C_PIN_ADMIN1,
    C_PIN_ADMIN2,
    C_PIN_SID,
    C_PIN_USER1,
    DATARMV_UID,
    GLOBAL_RANGE,
    K_AES_RANGE1,
    LOCKING_SP,
    MBRCONTROL,
    RANGE1,
    SET_METHOD_UID,
    SID_UID,
    USER1_UID,
    USERS_UID,
    activate,
    activate_locking_sp,
    add_ace_step,
    authenticate_step,
    end_session,
    gen_key,
    get_cpin,
    get_locking,
    get_mbr,
    make_step,
    read_step,
    revert_sp,
    set_authority,
    set_cpin,
    set_locking,
    set_mbr,
    setup_tper,
    setup_user,
    start_session,
    write_step,
)


OUT_DIR = Path(__file__).resolve().parent
TESTCASE_DIR = OUT_DIR / "testcases"
LABELS = OUT_DIR / "label.jsonl"
MANIFEST = OUT_DIR / "manifest.json"

SID = "SIDVAL"
MSID = "MSIDVAL"
USER_PIN = "USER1PIN"
ADMIN1_NEW = "ADMIN1NEW"

ADMINS_UID = "0000000900000002"
ADMIN_SP_ADMIN1_UID = "0000000900000201"
LOCKING_TABLE_UID = "0000000100000802"
MBR_TABLE_UID = "0000000100000804"
DATASTORE_TABLE_UID = "0000000100001001"
AC_ROW_UID = "0000000700000001"
FAKE_SP_UID = "00000205000000AA"


@dataclass(frozen=True)
class Scenario:
    name: str
    label: str
    steps: list[dict]
    concept: str
    refs: tuple[str, ...]


def scen(name: str, label: str, steps: list[dict], concept: str, *refs: str) -> Scenario:
    normalized = deepcopy(steps)
    for index, step in enumerate(normalized, start=1):
        if isinstance(step, dict):
            step["index"] = index
    return Scenario(name, label, normalized, concept, tuple(refs))


def sid_admin_session(*, write: int = 1, sid: str = SID) -> list[dict]:
    return setup_tper(MSID, sid) + [
        start_session(ADMIN_SP, write=write, authority=SID_UID, challenge=sid),
    ]


def active_locking_prefix(sid: str = SID) -> list[dict]:
    return setup_tper(MSID, sid) + activate_locking_sp(sid)


def locking_admin_session(*, write: int = 1, sid: str = SID) -> list[dict]:
    return active_locking_prefix(sid) + [
        start_session(LOCKING_SP, write=write, authority=ADMIN1_UID, challenge=sid),
    ]


def power_cycle_step() -> dict:
    return {
        "index": 0,
        "input": {"command": "Power Cycle", "args": {}},
        "output": {"result": "pass"},
    }


def discovery_features(*, locking_enabled: int = 0, admins: int = 4, users: int = 8) -> list[dict]:
    return [
        {"feature_code": 1, "sync_supported": 1, "streaming_supported": 1},
        {
            "feature_code": 2,
            "locking_supported": 1,
            "locking_enabled": locking_enabled,
            "locked": 0,
            "media_encryption": 1,
            "mbr_shadowing_not_supported": 0,
            "mbr_enabled": 0,
            "mbr_done": 0,
        },
        {"feature_code": 515, "num_comids": 1, "num_admins": admins, "num_users": users},
    ]


def discovery_step(features: list[dict]) -> dict:
    return {
        "index": 0,
        "input": {
            "command": "IF_RECV",
            "args": {"SecurityProtocol": "01", "SecurityProtocolSpecific": "0001"},
        },
        "output": {
            "command": "IF_RECV",
            "result": "pass",
            "discovery": {"features": features},
        },
    }


def revert(target_uid: str = LOCKING_SP, status: str = "SUCCESS") -> dict:
    return make_step("Revert", target_uid, {}, {}, status, invoking_name="SP")


def mbr_byte_set(status: str = "SUCCESS", *, where=None, values=None) -> dict:
    optional = {"Values": {"Bytes": "AABBCCDD"} if values is None else values}
    if where is not None:
        optional["Where"] = where
    return make_step("Set", MBR_TABLE_UID, {}, optional, status, invoking_name="MBR")


def datastore_byte_set(status: str = "SUCCESS", *, where=None, values=None) -> dict:
    optional = {"Values": {"Bytes": "AABBCCDD"} if values is None else values}
    if where is not None:
        optional["Where"] = where
    return make_step("Set", DATASTORE_TABLE_UID, {}, optional, status, invoking_name="DataStore")


def get_acl(status: str = "SUCCESS") -> dict:
    return make_step(
        "GetACL",
        ACCESS_CONTROL_TABLE_UID,
        {},
        {"InvokingID": RANGE1, "MethodID": SET_METHOD_UID},
        status,
        invoking_name="AccessControl",
    )


def remove_ace(status: str = "SUCCESS") -> dict:
    return make_step(
        "RemoveACE",
        ACCESS_CONTROL_TABLE_UID,
        {},
        {"InvokingID": RANGE1, "MethodID": SET_METHOD_UID, "ACE": ACE_ANYBODY_UID},
        status,
        invoking_name="AccessControl",
    )


def data_removal_set(columns: dict, status: str = "SUCCESS") -> dict:
    return make_step("Set", DATARMV_UID, {}, {"Values": [columns]}, status, invoking_name="DataRemovalMechanism")


def table_set(target_uid: str, columns: dict, status: str = "SUCCESS", invoking_name: str = "Table") -> dict:
    return make_step("Set", target_uid, {}, {"Values": [columns]}, status, invoking_name=invoking_name)


PairBuilder = Callable[[], tuple[list[dict], list[dict]]]


def pair_scenarios(num: int, slug: str, concept: str, refs: tuple[str, ...], builder: PairBuilder) -> list[Scenario]:
    pass_steps, fail_steps = builder()
    return [
        scen(f"opal_pass_{num:02d}_{slug}", "pass", pass_steps, concept, *refs),
        scen(f"opal_fail_{num:02d}_{slug}", "fail", fail_steps, concept, *refs),
    ]


def scenarios() -> list[Scenario]:
    out: list[Scenario] = []
    add = out.extend

    add(pair_scenarios(1, "activate_sid_adminsp", "Activate requires authenticated SID AdminSP write session.", ("opal/5.1.1", "opal/4.2.1.5"), lambda: (
        sid_admin_session() + [activate(LOCKING_SP, "SUCCESS")],
        sid_admin_session() + [activate(LOCKING_SP, "NOT_AUTHORIZED")],
    )))
    add(pair_scenarios(2, "activate_unauth_rejected", "Unauthenticated AdminSP session cannot activate LockingSP.", ("opal/5.1.1", "opal/4.2.1.5"), lambda: (
        setup_tper(MSID, SID) + [start_session(ADMIN_SP), activate(LOCKING_SP, "NOT_AUTHORIZED")],
        setup_tper(MSID, SID) + [start_session(ADMIN_SP), activate(LOCKING_SP, "SUCCESS")],
    )))
    add(pair_scenarios(3, "activate_readonly_rejected", "Activate requires a read-write AdminSP session.", ("opal/5.1.1", "opal/4.1.1.2"), lambda: (
        sid_admin_session(write=0) + [activate(LOCKING_SP, "NOT_AUTHORIZED")],
        sid_admin_session(write=0) + [activate(LOCKING_SP, "SUCCESS")],
    )))
    add(pair_scenarios(4, "activate_wrong_uid", "Activate targets manufactured SP objects, specifically LockingSP here.", ("opal/5.1.1",), lambda: (
        sid_admin_session() + [make_step("Activate", FAKE_SP_UID, {}, {}, "INVALID_PARAMETER", invoking_name="SP")],
        sid_admin_session() + [make_step("Activate", FAKE_SP_UID, {}, {}, "SUCCESS", invoking_name="SP")],
    )))
    add(pair_scenarios(5, "activate_repeat_noop", "Repeat Activate on an already-Manufactured LockingSP completes as an authorized no-op.", ("opal/5.1.1", "opal/5.2.2.3.2"), lambda: (
        active_locking_prefix() + [start_session(ADMIN_SP, authority=SID_UID, challenge=SID), activate(LOCKING_SP, "SUCCESS")],
        active_locking_prefix() + [start_session(ADMIN_SP, authority=SID_UID, challenge=SID), activate(LOCKING_SP, "INVALID_PARAMETER")],
    )))
    add(pair_scenarios(6, "activate_copies_sid_to_admin1", "First activation copies SID PIN into LockingSP Admin1.", ("opal/5.1.1.2", "opal/4.3.1.9"), lambda: (
        active_locking_prefix() + [start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=SID, status="SUCCESS")],
        active_locking_prefix() + [start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=SID, status="NOT_AUTHORIZED")],
    )))
    add(pair_scenarios(7, "repeat_activate_no_recopysid", "Repeat Activate does not overwrite an initialized Admin1 PIN.", ("opal/5.1.1", "opal/5.1.1.2"), lambda: (
        active_locking_prefix() + [
            start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=SID),
            set_cpin(C_PIN_ADMIN1, ADMIN1_NEW),
            end_session(),
            start_session(ADMIN_SP, authority=SID_UID, challenge=SID),
            set_cpin(C_PIN_SID, "SID2"),
            activate(LOCKING_SP),
            end_session(),
            start_session(LOCKING_SP, authority=ADMIN1_UID, challenge="SID2", status="NOT_AUTHORIZED"),
        ],
        active_locking_prefix() + [
            start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=SID),
            set_cpin(C_PIN_ADMIN1, ADMIN1_NEW),
            end_session(),
            start_session(ADMIN_SP, authority=SID_UID, challenge=SID),
            set_cpin(C_PIN_SID, "SID2"),
            activate(LOCKING_SP),
            end_session(),
            start_session(LOCKING_SP, authority=ADMIN1_UID, challenge="SID2", status="SUCCESS"),
        ],
    )))
    add(pair_scenarios(8, "lockingsp_before_activation", "Manufactured-Inactive LockingSP rejects StartSession.", ("opal/5.2.2.3.1", "opal/4.1.1.2"), lambda: (
        setup_tper(MSID, SID) + [start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=SID, status="NOT_AUTHORIZED")],
        setup_tper(MSID, SID) + [start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=SID, status="SUCCESS")],
    )))
    add(pair_scenarios(9, "revert_lockingsp_inactive", "Revert on LockingSP returns it to Manufactured-Inactive.", ("opal/5.1.2", "opal/5.2.2.2.2"), lambda: (
        active_locking_prefix() + [start_session(ADMIN_SP, authority=SID_UID, challenge=SID), revert(LOCKING_SP), start_session(LOCKING_SP, status="NOT_AUTHORIZED")],
        active_locking_prefix() + [start_session(ADMIN_SP, authority=SID_UID, challenge=SID), revert(LOCKING_SP), start_session(LOCKING_SP, status="SUCCESS")],
    )))
    add(pair_scenarios(10, "revert_requires_sid", "Revert requires SID or PSID in an AdminSP read-write session.", ("opal/5.1.2", "opal/4.2.1.5"), lambda: (
        active_locking_prefix() + [start_session(ADMIN_SP), revert(LOCKING_SP, "NOT_AUTHORIZED")],
        active_locking_prefix() + [start_session(ADMIN_SP), revert(LOCKING_SP, "SUCCESS")],
    )))
    add(pair_scenarios(11, "revert_unknown_sp", "Revert is not permitted on issued or unknown SP objects.", ("opal/5.1.2",), lambda: (
        sid_admin_session() + [revert(FAKE_SP_UID, "FAIL")],
        sid_admin_session() + [revert(FAKE_SP_UID, "SUCCESS")],
    )))
    add(pair_scenarios(12, "revertsp_admin_success", "RevertSP succeeds in an authenticated LockingSP admin write session.", ("opal/5.1.3", "opal/4.3.1.6"), lambda: (
        locking_admin_session() + [revert_sp(LOCKING_SP, "SUCCESS")],
        locking_admin_session() + [revert_sp(LOCKING_SP, "NOT_AUTHORIZED")],
    )))
    add(pair_scenarios(13, "revertsp_unauth_rejected", "RevertSP requires an admin/owner authority in the target SP.", ("opal/5.1.3", "opal/4.3.1.6"), lambda: (
        active_locking_prefix() + [start_session(LOCKING_SP), revert_sp(LOCKING_SP, "NOT_AUTHORIZED")],
        active_locking_prefix() + [start_session(LOCKING_SP), revert_sp(LOCKING_SP, "SUCCESS")],
    )))
    add(pair_scenarios(14, "revertsp_keep_global_ok", "KeepGlobalRangeKey is valid for LockingSP RevertSP when the global range is not locked.", ("opal/5.1.3.2",), lambda: (
        locking_admin_session() + [revert_sp(LOCKING_SP, "SUCCESS", keep_global=True)],
        locking_admin_session() + [revert_sp(LOCKING_SP, "NOT_AUTHORIZED", keep_global=True)],
    )))
    add(pair_scenarios(15, "revertsp_keep_global_locked", "KeepGlobalRangeKey fails when the global range is read-locked and write-locked.", ("opal/5.1.3.2", "opal/4.3.5.2"), lambda: (
        locking_admin_session() + [set_locking(GLOBAL_RANGE, {7: 1, 8: 1}), revert_sp(LOCKING_SP, "FAIL", keep_global=True)],
        locking_admin_session() + [set_locking(GLOBAL_RANGE, {7: 1, 8: 1}), revert_sp(LOCKING_SP, "SUCCESS", keep_global=True)],
    )))
    add(pair_scenarios(16, "revertsp_session_aborts", "After successful RevertSP, LockingSP sessions fail until reactivation.", ("opal/5.1.3.3", "opal/5.2.2.3.1"), lambda: (
        locking_admin_session() + [revert_sp(LOCKING_SP), start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=SID, status="NOT_AUTHORIZED")],
        locking_admin_session() + [revert_sp(LOCKING_SP), start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=SID, status="SUCCESS")],
    )))
    add(pair_scenarios(17, "revertsp_resets_admin1_pin", "RevertSP resets LockingSP C_PIN values before reactivation copies SID again.", ("opal/5.1.3.3", "opal/4.3.1.9", "opal/5.1.1.2"), lambda: (
        active_locking_prefix() + [
            start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=SID),
            set_cpin(C_PIN_ADMIN1, ADMIN1_NEW),
            revert_sp(LOCKING_SP),
            start_session(ADMIN_SP, authority=SID_UID, challenge=SID),
            activate(LOCKING_SP),
            end_session(),
            start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=SID, status="SUCCESS"),
        ],
        active_locking_prefix() + [
            start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=SID),
            set_cpin(C_PIN_ADMIN1, ADMIN1_NEW),
            revert_sp(LOCKING_SP),
            start_session(ADMIN_SP, authority=SID_UID, challenge=SID),
            activate(LOCKING_SP),
            end_session(),
            start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=SID, status="NOT_AUTHORIZED"),
        ],
    )))
    add(pair_scenarios(18, "adminsp_manufactured_session", "Manufactured AdminSP accepts unauthenticated sessions.", ("opal/5.2.2.3.2", "opal/4.1.1.2"), lambda: (
        [start_session(ADMIN_SP, status="SUCCESS")],
        [start_session(ADMIN_SP, status="NOT_AUTHORIZED")],
    )))
    add(pair_scenarios(19, "lockingsp_manufactured_session", "Manufactured LockingSP accepts sessions after activation.", ("opal/5.2.2.3.2",), lambda: (
        active_locking_prefix() + [start_session(LOCKING_SP, status="SUCCESS")],
        active_locking_prefix() + [start_session(LOCKING_SP, status="NOT_AUTHORIZED")],
    )))
    add(pair_scenarios(20, "disabled_lockingsp_session", "Disabled LockingSP rejects StartSession.", ("opal/5.2.2.1", "opal/5.2.2.3.2"), lambda: (
        active_locking_prefix() + [start_session(ADMIN_SP, authority=SID_UID, challenge=SID), table_set(LOCKING_SP, {6: 0}, "SUCCESS", "SP"), end_session(), start_session(LOCKING_SP, status="SP_DISABLED")],
        active_locking_prefix() + [start_session(ADMIN_SP, authority=SID_UID, challenge=SID), table_set(LOCKING_SP, {6: 0}, "SUCCESS", "SP"), end_session(), start_session(LOCKING_SP, status="SUCCESS")],
    )))

    add(pair_scenarios(21, "locking_admin_set_flags", "LockingSP admins can set RangeStart, RangeLength, and lock flags.", ("opal/4.3.5.2", "opal/4.3.1.7"), lambda: (
        locking_admin_session() + [set_locking(RANGE1, {3: 2048, 4: 4096, 5: 1, 6: 1, 7: 1, 8: 1}, "SUCCESS")],
        locking_admin_session() + [set_locking(RANGE1, {3: 2048, 4: 4096, 5: 1, 6: 1, 7: 1, 8: 1}, "NOT_AUTHORIZED")],
    )))
    add(pair_scenarios(22, "locking_unauth_set_rejected", "Unauthenticated sessions cannot mutate locking range columns.", ("opal/4.3.1.7", "opal/4.3.5.2"), lambda: (
        active_locking_prefix() + [start_session(LOCKING_SP), set_locking(RANGE1, {7: 1}, "NOT_AUTHORIZED")],
        active_locking_prefix() + [start_session(LOCKING_SP), set_locking(RANGE1, {7: 1}, "SUCCESS")],
    )))
    add(pair_scenarios(23, "locking_readonly_set_rejected", "Read-only sessions cannot mutate locking range columns.", ("opal/4.1.1.2", "opal/4.3.1.7"), lambda: (
        locking_admin_session(write=0) + [set_locking(RANGE1, {7: 1}, "NOT_AUTHORIZED")],
        locking_admin_session(write=0) + [set_locking(RANGE1, {7: 1}, "SUCCESS")],
    )))
    add(pair_scenarios(24, "global_range_geometry_rejected", "Global RangeStart and RangeLength are not host-modifiable geometry.", ("opal/4.3.5.2.1.1", "opal/4.3.5.2.1.2"), lambda: (
        locking_admin_session() + [set_locking(GLOBAL_RANGE, {3: 1024, 4: 2048}, "INVALID_PARAMETER")],
        locking_admin_session() + [set_locking(GLOBAL_RANGE, {3: 1024, 4: 2048}, "SUCCESS")],
    )))
    add(pair_scenarios(25, "negative_range_geometry", "RangeStart and RangeLength updates cannot be negative.", ("opal/4.3.5.2.1.1", "opal/4.3.5.2.1.2"), lambda: (
        locking_admin_session() + [set_locking(RANGE1, {3: -1, 4: 2048}, "INVALID_PARAMETER")],
        locking_admin_session() + [set_locking(RANGE1, {3: -1, 4: 2048}, "SUCCESS")],
    )))
    add(pair_scenarios(26, "locking_get_reflects_state", "Locking Get must reflect tracked ReadLocked and WriteLocked state.", ("opal/4.3.5.2", "opal/4.3.1.7"), lambda: (
        locking_admin_session() + [set_locking(RANGE1, {5: 1, 6: 1, 7: 1, 8: 0}), get_locking(RANGE1, 7, 8, "SUCCESS", {"7": 1, "8": 0})],
        locking_admin_session() + [set_locking(RANGE1, {5: 1, 6: 1, 7: 1, 8: 0}), get_locking(RANGE1, 7, 8, "SUCCESS", {"7": 0, "8": 0})],
    )))
    add(pair_scenarios(27, "locking_get_protected_cols", "Non-admin Locking Get must not return protected range columns.", ("opal/4.3.1.7", "opal/4.3.5.2"), lambda: (
        active_locking_prefix() + [start_session(LOCKING_SP), get_locking(RANGE1, 5, 8, "NOT_AUTHORIZED")],
        active_locking_prefix() + [start_session(LOCKING_SP), get_locking(RANGE1, 5, 8, "SUCCESS", {"5": 0, "6": 0, "7": 0, "8": 0})],
    )))
    add(pair_scenarios(28, "lockinginfo_public_in_sp", "LockingInfo geometry columns are readable inside an active LockingSP session.", ("opal/4.3.5.1",), lambda: (
        active_locking_prefix() + [start_session(LOCKING_SP), make_step("Get", "0000080100000001", {"Cellblock": [{"startColumn": 7}, {"endColumn": 9}]}, {}, "SUCCESS", invoking_name="LockingInfo")],
        active_locking_prefix() + [start_session(LOCKING_SP), make_step("Get", "0000080100000001", {"Cellblock": [{"startColumn": 7}, {"endColumn": 9}]}, {}, "NOT_AUTHORIZED", invoking_name="LockingInfo")],
    )))
    add(pair_scenarios(29, "locking_get_before_active", "Locking range access requires an active LockingSP.", ("opal/5.2.2.3.1", "opal/4.3.5.2"), lambda: (
        [start_session(ADMIN_SP), get_locking(RANGE1, 5, 8, "FAIL")],
        [start_session(ADMIN_SP), get_locking(RANGE1, 5, 8, "SUCCESS", {"5": 0})],
    )))

    add(pair_scenarios(30, "mbrcontrol_admin_set", "MBRControl Enable/Done/DoneOnReset are admin-controlled.", ("opal/4.3.5.3", "opal/4.3.1.7"), lambda: (
        locking_admin_session() + [set_mbr({1: 1, 2: 0, 3: "Power Cycle"}, "SUCCESS")],
        locking_admin_session() + [set_mbr({1: 1, 2: 0, 3: "Power Cycle"}, "NOT_AUTHORIZED")],
    )))
    add(pair_scenarios(31, "mbrcontrol_unauth_set", "Unauthenticated sessions cannot write MBRControl.", ("opal/4.3.5.3", "opal/4.3.1.7"), lambda: (
        active_locking_prefix() + [start_session(LOCKING_SP), set_mbr({1: 1}, "NOT_AUTHORIZED")],
        active_locking_prefix() + [start_session(LOCKING_SP), set_mbr({1: 1}, "SUCCESS")],
    )))
    add(pair_scenarios(32, "mbrcontrol_anybody_get", "MBRControl Get is available to Anybody inside LockingSP.", ("opal/4.3.1.6", "opal/4.3.5.3"), lambda: (
        active_locking_prefix() + [start_session(LOCKING_SP), get_mbr("SUCCESS", {"1": 0, "2": 0, "3": 0})],
        active_locking_prefix() + [start_session(LOCKING_SP), get_mbr("NOT_AUTHORIZED")],
    )))
    add(pair_scenarios(33, "mbr_shadow_read", "When MBR shadowing is active, reads inside the shadow region return MBR table data.", ("opal/4.3.5.4", "opal/4.3.4", "opal/4.3.7"), lambda: (
        locking_admin_session() + [set_mbr({1: 1, 2: 0}, "SUCCESS"), end_session(), read_step("0-1023", "MBR_DATA", "PASS")],
        locking_admin_session() + [set_mbr({1: 1, 2: 0}, "SUCCESS"), end_session(), read_step("0-1023", "DATA_PROTECTION_ERROR", "FAIL")],
    )))
    add(pair_scenarios(34, "mbr_shadow_write", "Writes to the active MBR shadow region must be rejected.", ("opal/4.3.5.4", "opal/4.3.7"), lambda: (
        locking_admin_session() + [set_mbr({1: 1, 2: 0}, "SUCCESS"), end_session(), write_step("0-1023", "BOOT", "FAIL")],
        locking_admin_session() + [set_mbr({1: 1, 2: 0}, "SUCCESS"), end_session(), write_step("0-1023", "BOOT", "PASS")],
    )))
    add(pair_scenarios(35, "mbr_shadow_mixed_read", "Reads spanning MBR shadow and user data must fail.", ("opal/4.3.5.4", "opal/4.3.7"), lambda: (
        locking_admin_session() + [set_mbr({1: 1, 2: 0}, "SUCCESS"), end_session(), read_step("0-300000", "DATA_PROTECTION_ERROR", "FAIL")],
        locking_admin_session() + [set_mbr({1: 1, 2: 0}, "SUCCESS"), end_session(), read_step("0-300000", "USER_DATA", "PASS")],
    )))
    add(pair_scenarios(36, "admin2_disabled", "LockingSP Admin2 is disabled by default.", ("opal/4.3.1.8", "opal/4.3.1.9"), lambda: (
        active_locking_prefix() + [start_session(LOCKING_SP, authority=ADMIN2_UID, status="NOT_AUTHORIZED")],
        active_locking_prefix() + [start_session(LOCKING_SP, authority=ADMIN2_UID, status="SUCCESS")],
    )))
    add(pair_scenarios(37, "admin2_empty_pin_enabled", "Enabled Admin2 has the factory empty PIN until changed.", ("opal/4.3.1.8", "opal/4.3.1.9"), lambda: (
        locking_admin_session() + [set_authority(ADMIN2_UID, True), end_session(), start_session(LOCKING_SP, authority=ADMIN2_UID, status="SUCCESS")],
        locking_admin_session() + [set_authority(ADMIN2_UID, True), end_session(), start_session(LOCKING_SP, authority=ADMIN2_UID, status="NOT_AUTHORIZED")],
    )))
    add(pair_scenarios(38, "user1_disabled", "LockingSP User1 is disabled by default.", ("opal/4.3.1.8",), lambda: (
        active_locking_prefix() + [start_session(LOCKING_SP, authority=USER1_UID, status="NOT_AUTHORIZED")],
        active_locking_prefix() + [start_session(LOCKING_SP, authority=USER1_UID, status="SUCCESS")],
    )))
    add(pair_scenarios(39, "user1_empty_pin_enabled", "Enabled User1 has an empty PIN until changed.", ("opal/4.3.1.8", "opal/4.3.1.9"), lambda: (
        locking_admin_session() + [set_authority(USER1_UID, True), end_session(), start_session(LOCKING_SP, authority=USER1_UID, status="SUCCESS")],
        locking_admin_session() + [set_authority(USER1_UID, True), end_session(), start_session(LOCKING_SP, authority=USER1_UID, status="NOT_AUTHORIZED")],
    )))
    add(pair_scenarios(40, "user1_pin_auth", "Admin1 can enable User1 and set a User1 PIN for later authentication.", ("opal/4.3.1.7", "opal/4.3.1.8", "opal/4.3.1.9"), lambda: (
        active_locking_prefix() + setup_user(SID, USER_PIN) + [start_session(LOCKING_SP, authority=USER1_UID, challenge=USER_PIN, status="SUCCESS")],
        active_locking_prefix() + setup_user(SID, USER_PIN) + [start_session(LOCKING_SP, authority=USER1_UID, challenge=USER_PIN, status="NOT_AUTHORIZED")],
    )))
    add(pair_scenarios(41, "user1_wrong_pin", "User1 authentication fails with a wrong PIN.", ("opal/4.3.1.8", "opal/4.3.1.9"), lambda: (
        active_locking_prefix() + setup_user(SID, USER_PIN) + [start_session(LOCKING_SP, authority=USER1_UID, challenge="WRONG", status="NOT_AUTHORIZED")],
        active_locking_prefix() + setup_user(SID, USER_PIN) + [start_session(LOCKING_SP, authority=USER1_UID, challenge="WRONG", status="SUCCESS")],
    )))
    add(pair_scenarios(42, "user1_self_pin_set", "A User authority can set its own PIN when authorized by the C_PIN ACE.", ("opal/4.3.1.7", "opal/4.3.1.9"), lambda: (
        active_locking_prefix() + setup_user(SID, USER_PIN) + [start_session(LOCKING_SP, authority=USER1_UID, challenge=USER_PIN), set_cpin(C_PIN_USER1, "USER1NEW", "SUCCESS")],
        active_locking_prefix() + setup_user(SID, USER_PIN) + [start_session(LOCKING_SP, authority=USER1_UID, challenge=USER_PIN), set_cpin(C_PIN_USER1, "USER1NEW", "NOT_AUTHORIZED")],
    )))
    add(pair_scenarios(43, "users_class_not_authority", "Users class UID is not a valid StartSession authority.", ("opal/4.3.1.8", "core/5.3.4.1.2"), lambda: (
        active_locking_prefix() + [start_session(LOCKING_SP, authority=USERS_UID, status="INVALID_PARAMETER")],
        active_locking_prefix() + [start_session(LOCKING_SP, authority=USERS_UID, status="SUCCESS")],
    )))
    add(pair_scenarios(44, "admins_class_not_authority", "Admins class UID is not a valid StartSession authority.", ("opal/4.3.1.8", "core/5.3.4.1.2"), lambda: (
        active_locking_prefix() + [start_session(LOCKING_SP, authority=ADMINS_UID, status="INVALID_PARAMETER")],
        active_locking_prefix() + [start_session(LOCKING_SP, authority=ADMINS_UID, status="SUCCESS")],
    )))
    add(pair_scenarios(45, "authority_set_by_admin", "LockingSP Admin1 may enable User authorities.", ("opal/4.3.1.7", "opal/4.3.1.8"), lambda: (
        locking_admin_session() + [set_authority(USER1_UID, True, "SUCCESS")],
        locking_admin_session() + [set_authority(USER1_UID, True, "NOT_AUTHORIZED")],
    )))
    add(pair_scenarios(46, "authority_set_unauth", "Unauthenticated sessions cannot mutate Authority rows.", ("opal/4.3.1.7", "opal/4.3.1.8"), lambda: (
        active_locking_prefix() + [start_session(LOCKING_SP), set_authority(USER1_UID, True, "NOT_AUTHORIZED")],
        active_locking_prefix() + [start_session(LOCKING_SP), set_authority(USER1_UID, True, "SUCCESS")],
    )))
    add(pair_scenarios(47, "adminsp_admin1_disabled", "AdminSP Admin1 starts disabled and cannot authenticate by default.", ("opal/4.2.1.7",), lambda: (
        [start_session(ADMIN_SP, authority=ADMIN_SP_ADMIN1_UID, challenge="PIN", status="NOT_AUTHORIZED")],
        [start_session(ADMIN_SP, authority=ADMIN_SP_ADMIN1_UID, challenge="PIN", status="SUCCESS")],
    )))
    add(pair_scenarios(48, "cpin_pin_not_readable", "C_PIN PIN columns other than MSID are not readable via Get.", ("opal/4.2.1.8", "opal/4.3.1.9"), lambda: (
        sid_admin_session() + [get_cpin(C_PIN_SID, "NOT_AUTHORIZED")],
        sid_admin_session() + [get_cpin(C_PIN_SID, "SUCCESS", SID)],
    )))
    add(pair_scenarios(49, "admin1_pin_not_readable", "LockingSP Admin1 cannot read its own C_PIN PIN column.", ("opal/4.3.1.7", "opal/4.3.1.9"), lambda: (
        locking_admin_session() + [get_cpin(C_PIN_ADMIN1, "NOT_AUTHORIZED")],
        locking_admin_session() + [get_cpin(C_PIN_ADMIN1, "SUCCESS", SID)],
    )))
    add(pair_scenarios(50, "authenticate_wrong_pin", "Authenticate returns result false on a wrong tracked password.", ("opal/4.3.1.8", "core/5.3.4.1.14"), lambda: (
        active_locking_prefix() + setup_user(SID, USER_PIN) + [start_session(LOCKING_SP), authenticate_step(USER1_UID, proof="WRONG", auth_result=False, status="SUCCESS")],
        active_locking_prefix() + setup_user(SID, USER_PIN) + [start_session(LOCKING_SP), authenticate_step(USER1_UID, proof="WRONG", auth_result=True, status="SUCCESS")],
    )))

    add(pair_scenarios(51, "accesscontrol_n_get", "AccessControl special columns are not readable with Get.", ("opal/4.2.1.5", "opal/4.3.1.6"), lambda: (
        [start_session(ADMIN_SP), make_step("Get", AC_ROW_UID, {"Cellblock": [{"startColumn": 4}, {"endColumn": 4}]}, {}, "NOT_AUTHORIZED", invoking_name="AccessControl")],
        [start_session(ADMIN_SP), make_step("Get", AC_ROW_UID, {"Cellblock": [{"startColumn": 4}, {"endColumn": 4}]}, {}, "SUCCESS", invoking_name="AccessControl")],
    )))
    add(pair_scenarios(52, "getacl_anybody", "GetACL is allowed where GetACLACL is ACE_Anybody.", ("opal/4.2.1.5", "opal/4.3.1.6"), lambda: (
        [start_session(ADMIN_SP), get_acl("SUCCESS")],
        [start_session(ADMIN_SP), get_acl("NOT_AUTHORIZED")],
    )))
    add(pair_scenarios(53, "addace_grants_anybody_set", "AddACE can grant ACE_Anybody to a target method.", ("opal/4.3.1.6", "opal/4.3.1.7"), lambda: (
        locking_admin_session() + [add_ace_step(RANGE1, SET_METHOD_UID, ACE_ANYBODY_UID), end_session(), start_session(LOCKING_SP), set_locking(RANGE1, {5: 1}, "SUCCESS")],
        locking_admin_session() + [add_ace_step(RANGE1, SET_METHOD_UID, ACE_ANYBODY_UID), end_session(), start_session(LOCKING_SP), set_locking(RANGE1, {5: 1}, "NOT_AUTHORIZED")],
    )))
    add(pair_scenarios(54, "removeace_revokes_anybody_set", "RemoveACE revokes a previously added ACE.", ("opal/4.3.1.6", "opal/4.3.1.7"), lambda: (
        locking_admin_session() + [add_ace_step(RANGE1, SET_METHOD_UID, ACE_ANYBODY_UID), remove_ace(), end_session(), start_session(LOCKING_SP), set_locking(RANGE1, {5: 1}, "NOT_AUTHORIZED")],
        locking_admin_session() + [add_ace_step(RANGE1, SET_METHOD_UID, ACE_ANYBODY_UID), remove_ace(), end_session(), start_session(LOCKING_SP), set_locking(RANGE1, {5: 1}, "SUCCESS")],
    )))
    add(pair_scenarios(55, "addace_unauth_rejected", "Unauthenticated sessions cannot mutate AccessControl ACLs.", ("opal/4.3.1.6", "opal/4.3.1.7"), lambda: (
        active_locking_prefix() + [start_session(LOCKING_SP), add_ace_step(RANGE1, SET_METHOD_UID, ACE_ANYBODY_UID, "NOT_AUTHORIZED")],
        active_locking_prefix() + [start_session(LOCKING_SP), add_ace_step(RANGE1, SET_METHOD_UID, ACE_ANYBODY_UID, "SUCCESS")],
    )))

    add(pair_scenarios(56, "dataremoval_valid_value", "ActiveDataRemovalMechanism accepts defined values.", ("opal/4.2.6.1", "opal/4.2.6.1.2"), lambda: (
        sid_admin_session() + [data_removal_set({1: 1}, "SUCCESS")],
        sid_admin_session() + [data_removal_set({1: 1}, "NOT_AUTHORIZED")],
    )))
    add(pair_scenarios(57, "dataremoval_reserved_value", "ActiveDataRemovalMechanism rejects reserved values.", ("opal/4.2.6.1", "opal/4.2.6.1.2"), lambda: (
        sid_admin_session() + [data_removal_set({1: 3}, "INVALID_PARAMETER")],
        sid_admin_session() + [data_removal_set({1: 3}, "SUCCESS")],
    )))
    add(pair_scenarios(58, "dataremoval_uid_readonly", "DataRemovalMechanism UID is read-only.", ("opal/4.2.6.1.1",), lambda: (
        sid_admin_session() + [data_removal_set({0: "0000110100000002"}, "INVALID_PARAMETER")],
        sid_admin_session() + [data_removal_set({0: "0000110100000002"}, "SUCCESS")],
    )))

    add(pair_scenarios(59, "mbr_byte_set_bytes", "MBR byte-table Set uses Bytes values.", ("opal/5.3", "opal/5.3.1.1.2"), lambda: (
        locking_admin_session() + [mbr_byte_set("SUCCESS", where=0)],
        locking_admin_session() + [mbr_byte_set("INVALID_PARAMETER", where=0)],
    )))
    add(pair_scenarios(60, "mbr_byte_set_rowvalues", "MBR byte-table Set rejects object-table RowValues.", ("opal/5.3", "opal/5.3.1.1.2"), lambda: (
        locking_admin_session() + [mbr_byte_set("INVALID_PARAMETER", values=[{1: 1}])],
        locking_admin_session() + [mbr_byte_set("SUCCESS", values=[{1: 1}])],
    )))
    add(pair_scenarios(61, "mbr_byte_set_uid_where", "Byte-table Set Where is a row offset, not a UID object reference.", ("opal/5.3", "opal/5.3.1.1.2"), lambda: (
        locking_admin_session() + [mbr_byte_set("INVALID_PARAMETER", where={"uid": MBR_TABLE_UID})],
        locking_admin_session() + [mbr_byte_set("SUCCESS", where={"uid": MBR_TABLE_UID})],
    )))
    add(pair_scenarios(62, "datastore_byte_set_auth", "DataStore byte-table writes require LockingSP admin authority.", ("opal/4.3.8.1", "opal/5.3.1.1.2"), lambda: (
        active_locking_prefix() + [start_session(LOCKING_SP), datastore_byte_set("NOT_AUTHORIZED", where=0)],
        active_locking_prefix() + [start_session(LOCKING_SP), datastore_byte_set("SUCCESS", where=0)],
    )))

    add(pair_scenarios(63, "read_locked_range", "ReadLocked ranges block reads when ReadLockEnabled is set.", ("opal/4.3.7", "opal/4.3.5.2"), lambda: (
        locking_admin_session() + [set_locking(RANGE1, {3: 0, 4: 4096, 5: 1, 7: 1}), end_session(), read_step("0-1023", "DATA_PROTECTION_ERROR", "FAIL")],
        locking_admin_session() + [set_locking(RANGE1, {3: 0, 4: 4096, 5: 1, 7: 1}), end_session(), read_step("0-1023", "USER_DATA", "PASS")],
    )))
    add(pair_scenarios(64, "write_locked_range", "WriteLocked ranges block writes when WriteLockEnabled is set.", ("opal/4.3.7", "opal/4.3.5.2"), lambda: (
        locking_admin_session() + [set_locking(RANGE1, {3: 0, 4: 4096, 6: 1, 8: 1}), end_session(), write_step("0-1023", "USER_DATA", "FAIL")],
        locking_admin_session() + [set_locking(RANGE1, {3: 0, 4: 4096, 6: 1, 8: 1}), end_session(), write_step("0-1023", "USER_DATA", "PASS")],
    )))
    add(pair_scenarios(65, "zero_length_range_no_lock", "A non-global zero-length range does not lock data.", ("opal/4.3.5.2", "opal/4.3.7"), lambda: (
        locking_admin_session() + [set_locking(RANGE1, {3: 0, 4: 0, 5: 1, 7: 1}), end_session(), read_step("0-1023", "USER_DATA", "PASS")],
        locking_admin_session() + [set_locking(RANGE1, {3: 0, 4: 0, 5: 1, 7: 1}), end_session(), read_step("0-1023", "DATA_PROTECTION_ERROR", "FAIL")],
    )))
    add(pair_scenarios(66, "lockonreset_locks_range", "LockOnReset sets ReadLocked and WriteLocked on reset.", ("opal/4.3.5.2.2", "opal/3.3.5.1"), lambda: (
        locking_admin_session() + [set_locking(RANGE1, {3: 0, 4: 4096, 5: 1, 6: 1, 9: "Power Cycle"}), end_session(), power_cycle_step(), read_step("0-1023", "DATA_PROTECTION_ERROR", "FAIL")],
        locking_admin_session() + [set_locking(RANGE1, {3: 0, 4: 4096, 5: 1, 6: 1, 9: "Power Cycle"}), end_session(), power_cycle_step(), read_step("0-1023", "USER_DATA", "PASS")],
    )))
    add(pair_scenarios(67, "reset_aborts_session", "TPER reset style events abort open sessions.", ("opal/3.2.3", "opal/3.3.5.1"), lambda: (
        sid_admin_session() + [power_cycle_step(), get_cpin(C_PIN_SID, "NOT_AUTHORIZED")],
        sid_admin_session() + [power_cycle_step(), get_cpin(C_PIN_SID, "SUCCESS", SID)],
    )))
    add(pair_scenarios(68, "genkey_changes_range_data", "GenKey on a range key changes subsequent data reads for that range.", ("opal/4.3.5.5", "opal/4.3.7"), lambda: (
        locking_admin_session() + [set_locking(RANGE1, {3: 0, 4: 4096, 5: 1, 6: 1}), end_session(), write_step("0-1023", "OLD"), start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=SID), gen_key(K_AES_RANGE1), end_session(), read_step("0-1023", "CHANGED", "PASS")],
        locking_admin_session() + [set_locking(RANGE1, {3: 0, 4: 4096, 5: 1, 6: 1}), end_session(), write_step("0-1023", "OLD"), start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=SID), gen_key(K_AES_RANGE1), end_session(), read_step("0-1023", "OLD", "PASS")],
    )))

    # Discovery cases are intentionally included as singletons because malformed discovery descriptors are
    # represented by the descriptor payload, not by a method status variant.
    out.append(scen(
        "opal_pass_69_discovery_inactive",
        "pass",
        [discovery_step(discovery_features(locking_enabled=0))],
        "Level 0 Discovery reports required Opal descriptors while LockingSP is inactive.",
        "opal/3.1.1", "opal/3.1.1.2", "opal/3.1.1.3", "opal/3.1.1.5",
    ))
    out.append(scen(
        "opal_fail_69_discovery_missing_v2",
        "fail",
        [discovery_step(discovery_features(locking_enabled=0)[:2])],
        "Level 0 Discovery must include the Opal SSC V2 descriptor.",
        "opal/3.1.1", "opal/3.1.1.5",
    ))
    out.append(scen(
        "opal_fail_70_discovery_enabled_inactive",
        "fail",
        [discovery_step(discovery_features(locking_enabled=1))],
        "LockingEnabled must be false before LockingSP activation.",
        "opal/3.1.1.3", "opal/3.1.1.3.1",
    ))
    out.append(scen(
        "opal_pass_70_discovery_enabled_active",
        "pass",
        active_locking_prefix() + [discovery_step(discovery_features(locking_enabled=1))],
        "LockingEnabled must be true after LockingSP activation.",
        "opal/3.1.1.3", "opal/3.1.1.3.1",
    ))
    out.append(scen(
        "opal_fail_71_discovery_too_few_admins",
        "fail",
        [discovery_step(discovery_features(admins=2))],
        "Opal SSC V2 discovery reports at least four LockingSP admin authorities.",
        "opal/3.1.1", "opal/3.1.1.5",
    ))
    out.append(scen(
        "opal_fail_72_discovery_too_few_users",
        "fail",
        [discovery_step(discovery_features(users=4))],
        "Opal SSC V2 discovery reports at least eight user authorities.",
        "opal/3.1.1", "opal/3.1.1.5",
    ))

    # ---- Round 2: deeper edge cases ----------------------------------------

    def set_trylimit(cpin_uid: str, limit: int, status: str = "SUCCESS") -> dict:
        return make_step("Set", cpin_uid, {}, {"Values": [{5: limit}]}, status, invoking_name="C_PIN")

    # 73 — WriteLocked without WriteLockEnabled: lock flag alone does not block I/O
    add(pair_scenarios(73, "write_locked_no_enable",
        "WriteLocked=1 without WriteLockEnabled=1 does not block writes (opal/4.3.5.2.1.2).",
        ("opal/4.3.5.2", "opal/4.3.5.2.1.2", "opal/4.3.7"), lambda: (
            locking_admin_session() + [set_locking(RANGE1, {3: 0, 4: 4096, 6: 0, 8: 1}), end_session(), write_step("0-1023", "DATA", "PASS")],
            locking_admin_session() + [set_locking(RANGE1, {3: 0, 4: 4096, 6: 0, 8: 1}), end_session(), write_step("0-1023", "DATA", "FAIL")],
        )))

    # 74 — ReadLocked without ReadLockEnabled: lock flag alone does not block reads
    add(pair_scenarios(74, "read_locked_no_enable",
        "ReadLocked=1 without ReadLockEnabled=1 does not block reads (opal/4.3.5.2.1.1).",
        ("opal/4.3.5.2", "opal/4.3.5.2.1.1", "opal/4.3.7"), lambda: (
            locking_admin_session() + [set_locking(RANGE1, {3: 0, 4: 4096, 5: 0, 7: 1}), end_session(), read_step("0-1023", "USER_DATA", "PASS")],
            locking_admin_session() + [set_locking(RANGE1, {3: 0, 4: 4096, 5: 0, 7: 1}), end_session(), read_step("0-1023", "DATA_PROTECTION_ERROR", "FAIL")],
        )))

    # 75 — RevertSP requires a write session (read-only session must fail)
    add(pair_scenarios(75, "revert_sp_readonly_fails",
        "RevertSP requires an authenticated write session; read-only session must be rejected.",
        ("opal/5.1.3.1", "opal/5.1.3.2", "core/5.3.3.11"), lambda: (
            active_locking_prefix() + [start_session(LOCKING_SP, write=0, authority=ADMIN1_UID, challenge=SID), revert_sp(LOCKING_SP, "NOT_AUTHORIZED")],
            active_locking_prefix() + [start_session(LOCKING_SP, write=0, authority=ADMIN1_UID, challenge=SID), revert_sp(LOCKING_SP, "SUCCESS")],
        )))

    # 76 — Revert(LockingSP) requires an AdminSP session, not a LockingSP session
    add(pair_scenarios(76, "revert_from_locking_sp_wrong_path",
        "Revert(LockingSP) must be issued from an authenticated AdminSP SID session, not from within LockingSP.",
        ("opal/5.1.2.1", "opal/5.2.2.2.2", "core/5.3.3.11"), lambda: (
            locking_admin_session() + [revert(LOCKING_SP, "NOT_AUTHORIZED")],
            locking_admin_session() + [revert(LOCKING_SP, "SUCCESS")],
        )))

    # 77 — Activate on already-active LockingSP is a no-op when SID is authenticated
    add(pair_scenarios(77, "activate_already_active_noop",
        "Activate(LockingSP) on an already-Manufactured SP is a no-op when invoked from an authenticated SID AdminSP write session.",
        ("opal/5.1.1", "opal/5.1.1.1", "opal/5.2.2.2.1"), lambda: (
            active_locking_prefix() + [start_session(ADMIN_SP, authority=SID_UID, challenge=SID), activate(LOCKING_SP, "SUCCESS")],
            active_locking_prefix() + [start_session(ADMIN_SP, write=1), activate(LOCKING_SP, "SUCCESS")],
        )))

    # 78 — User1 TryLimit=2: after two wrong PINs, the third attempt is locked out
    add(pair_scenarios(78, "user1_trylimit_lockout",
        "With TryLimit=2, two consecutive wrong PINs lock out the authority; the third attempt must fail with auth_error.",
        ("opal/4.3.1.9", "core/5.3.4.1.14", "core/5.3.4.1.14.1"), lambda: (
            active_locking_prefix() + setup_user(SID, USER_PIN) + [
                start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=SID),
                set_trylimit(C_PIN_USER1, 2),
                end_session(),
                start_session(LOCKING_SP, authority=USER1_UID, challenge="WRONG1", status="NOT_AUTHORIZED"),
                start_session(LOCKING_SP, authority=USER1_UID, challenge="WRONG2", status="NOT_AUTHORIZED"),
                start_session(LOCKING_SP, authority=USER1_UID, challenge=USER_PIN, status="AUTHORITY_LOCKED_OUT"),
            ],
            active_locking_prefix() + setup_user(SID, USER_PIN) + [
                start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=SID),
                set_trylimit(C_PIN_USER1, 2),
                end_session(),
                start_session(LOCKING_SP, authority=USER1_UID, challenge="WRONG1", status="NOT_AUTHORIZED"),
                start_session(LOCKING_SP, authority=USER1_UID, challenge="WRONG2", status="NOT_AUTHORIZED"),
                start_session(LOCKING_SP, authority=USER1_UID, challenge=USER_PIN, status="SUCCESS"),
            ],
        )))

    # 79 — After Revert(LockingSP)+re-Activate with new SID, Admin1 credential = new SID
    NEW_SID = "NEWSIDPIN"
    add(pair_scenarios(79, "reactivate_admin1_new_sid",
        "After Revert(LockingSP) and re-Activate with an updated SID PIN, Admin1 credential is the new SID value.",
        ("opal/5.1.1.2", "opal/5.1.2.1", "opal/5.2.2.3.2"), lambda: (
            # activate → revert → change SID → reactivate → Admin1 = NEW_SID
            setup_tper(MSID, SID) + activate_locking_sp(SID) + [
                start_session(ADMIN_SP, authority=SID_UID, challenge=SID),
                revert(LOCKING_SP, "SUCCESS"),
                set_cpin(C_PIN_SID, NEW_SID, "SUCCESS"),
                end_session(),
                start_session(ADMIN_SP, authority=SID_UID, challenge=NEW_SID),
                activate(LOCKING_SP, "SUCCESS"),
                end_session(),
                start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=NEW_SID, status="SUCCESS"),
            ],
            # same but use OLD SID for Admin1 after reactivation
            setup_tper(MSID, SID) + activate_locking_sp(SID) + [
                start_session(ADMIN_SP, authority=SID_UID, challenge=SID),
                revert(LOCKING_SP, "SUCCESS"),
                set_cpin(C_PIN_SID, NEW_SID, "SUCCESS"),
                end_session(),
                start_session(ADMIN_SP, authority=SID_UID, challenge=NEW_SID),
                activate(LOCKING_SP, "SUCCESS"),
                end_session(),
                start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=SID, status="SUCCESS"),
            ],
        )))

    # 80 — Admin1 can set Admin2's C_PIN and then Admin2 can authenticate
    add(pair_scenarios(80, "admin2_pin_set_by_admin1",
        "Admin1 can set Admin2 C_PIN and enable Admin2; Admin2 then authenticates with the new PIN.",
        ("opal/4.3.1.7", "opal/4.3.1.8", "opal/4.3.1.9"), lambda: (
            locking_admin_session() + [
                set_cpin(C_PIN_ADMIN2, "ADMIN2PIN", "SUCCESS"),
                set_authority(ADMIN2_UID, True, "SUCCESS"),
                end_session(),
                start_session(LOCKING_SP, authority=ADMIN2_UID, challenge="ADMIN2PIN", status="SUCCESS"),
            ],
            locking_admin_session() + [
                set_cpin(C_PIN_ADMIN2, "ADMIN2PIN", "SUCCESS"),
                set_authority(ADMIN2_UID, True, "SUCCESS"),
                end_session(),
                start_session(LOCKING_SP, authority=ADMIN2_UID, challenge="ADMIN2PIN", status="NOT_AUTHORIZED"),
            ],
        )))

    # 81 — Authority disable mid-trajectory blocks subsequent StartSession
    add(pair_scenarios(81, "authority_disable_mid_trajectory",
        "Admin1 can disable an enabled user authority; subsequent StartSession for that authority must fail.",
        ("opal/4.3.1.7", "opal/4.3.1.8", "core/5.3.4.1.5"), lambda: (
            active_locking_prefix() + setup_user(SID, USER_PIN) + [
                start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=SID),
                set_authority(USER1_UID, False, "SUCCESS"),
                end_session(),
                start_session(LOCKING_SP, authority=USER1_UID, challenge=USER_PIN, status="NOT_AUTHORIZED"),
            ],
            active_locking_prefix() + setup_user(SID, USER_PIN) + [
                start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=SID),
                set_authority(USER1_UID, False, "SUCCESS"),
                end_session(),
                start_session(LOCKING_SP, authority=USER1_UID, challenge=USER_PIN, status="SUCCESS"),
            ],
        )))

    # 82 — MBRControl.DoneOnReset causes Done to reset on power cycle, re-enabling MBR shadow writes block
    add(pair_scenarios(82, "done_on_reset_power_cycle",
        "When MBRControl.DoneOnReset includes Power Cycle, Done resets to False on power cycle; the re-enabled MBR shadow blocks writes.",
        ("opal/4.3.5.3", "opal/3.2.3", "opal/3.3.5.1", "opal/4.3.5.4"), lambda: (
            # Set Enable=1, Done=1, DoneOnReset="Power Cycle" → power cycle → Done=0 → shadow active → write blocked
            locking_admin_session() + [
                set_mbr({1: 1, 2: 1, 3: "Power Cycle"}, "SUCCESS"),
                end_session(),
                power_cycle_step(),
                write_step("0-1023", "BOOT_DATA", "FAIL"),
            ],
            locking_admin_session() + [
                set_mbr({1: 1, 2: 1, 3: "Power Cycle"}, "SUCCESS"),
                end_session(),
                power_cycle_step(),
                write_step("0-1023", "BOOT_DATA", "PASS"),
            ],
        )))

    # 83 — MBR byte-table Get succeeds in a read-only LockingSP session (ACE_Anybody)
    # MBR is a byte table; Get uses no column Cellblock — just a plain byte-range fetch.
    add(pair_scenarios(83, "mbr_byte_get_readonly",
        "MBR byte-table Get is authorized by ACE_Anybody; a read-only session is sufficient (no write session required).",
        ("opal/4.3.5.3.1", "opal/4.3.1.6", "opal/5.3.1.2"), lambda: (
            active_locking_prefix() + [start_session(LOCKING_SP, write=0), make_step("Get", MBR_TABLE_UID, {}, {}, "SUCCESS", invoking_name="MBR")],
            active_locking_prefix() + [start_session(LOCKING_SP, write=0), make_step("Get", MBR_TABLE_UID, {}, {}, "NOT_AUTHORIZED", invoking_name="MBR")],
        )))

    # 84 — Two sequential GenKey calls both invalidate the range data
    add(pair_scenarios(84, "genkey_repeated_changes_data",
        "Each GenKey on a range key independently invalidates the prior data; two sequential GenKey calls both change data.",
        ("opal/4.3.5.5", "opal/4.3.7", "core/5.3.3.16"), lambda: (
            locking_admin_session() + [
                set_locking(RANGE1, {3: 0, 4: 4096, 5: 1, 6: 1}),
                end_session(),
                write_step("0-1023", "OLD"),
                start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=SID),
                gen_key(K_AES_RANGE1),
                gen_key(K_AES_RANGE1),
                end_session(),
                read_step("0-1023", "CHANGED", "PASS"),
            ],
            locking_admin_session() + [
                set_locking(RANGE1, {3: 0, 4: 4096, 5: 1, 6: 1}),
                end_session(),
                write_step("0-1023", "OLD"),
                start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=SID),
                gen_key(K_AES_RANGE1),
                gen_key(K_AES_RANGE1),
                end_session(),
                read_step("0-1023", "OLD", "PASS"),
            ],
        )))

    # 85 — LockingSP accessible again after Revert + re-Activate with same SID
    add(pair_scenarios(85, "locking_sp_reactivate_after_revert",
        "After Revert(LockingSP) returns SP to inactive, a fresh Activate restores LockingSP and Admin1=SID auth.",
        ("opal/5.1.2.1", "opal/5.1.1.1", "opal/5.2.2.2", "opal/5.2.2.3"), lambda: (
            setup_tper(MSID, SID) + activate_locking_sp(SID) + [
                start_session(ADMIN_SP, authority=SID_UID, challenge=SID),
                revert(LOCKING_SP, "SUCCESS"),
                activate(LOCKING_SP, "SUCCESS"),
                end_session(),
                start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=SID, status="SUCCESS"),
            ],
            setup_tper(MSID, SID) + activate_locking_sp(SID) + [
                start_session(ADMIN_SP, authority=SID_UID, challenge=SID),
                revert(LOCKING_SP, "SUCCESS"),
                # LockingSP still inactive here; no re-Activate
                start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=SID, status="SUCCESS"),
            ],
        )))

    # 86 — RevertSP KeepGlobalRangeKey fails when Global Range is both ReadLocked and WriteLocked
    add(pair_scenarios(86, "revertsp_keepglobal_both_locked_fails",
        "RevertSP with KeepGlobalRangeKey=True must fail when Global Range is both ReadLocked and WriteLocked (opal/5.1.3.2).",
        ("opal/5.1.3.1", "opal/5.1.3.2", "opal/5.1.3.3"), lambda: (
            locking_admin_session() + [
                set_locking(GLOBAL_RANGE, {5: 1, 6: 1, 7: 1, 8: 1}),
                end_session(),
                start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=SID),
                revert_sp(LOCKING_SP, "FAIL", keep_global=True),
            ],
            locking_admin_session() + [
                set_locking(GLOBAL_RANGE, {5: 1, 6: 1, 7: 1, 8: 1}),
                end_session(),
                start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=SID),
                revert_sp(LOCKING_SP, "SUCCESS", keep_global=True),
            ],
        )))

    # 87 — RevertSP KeepGlobalRangeKey succeeds when Global is only WriteLocked (not both)
    add(pair_scenarios(87, "revertsp_keepglobal_only_write_locked",
        "RevertSP with KeepGlobalRangeKey=True succeeds when Global Range is WriteLocked but not ReadLocked.",
        ("opal/5.1.3.1", "opal/5.1.3.2", "opal/5.1.3.3"), lambda: (
            locking_admin_session() + [
                set_locking(GLOBAL_RANGE, {5: 1, 6: 1, 7: 0, 8: 1}),
                end_session(),
                start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=SID),
                revert_sp(LOCKING_SP, "SUCCESS", keep_global=True),
            ],
            locking_admin_session() + [
                set_locking(GLOBAL_RANGE, {5: 1, 6: 1, 7: 0, 8: 1}),
                end_session(),
                start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=SID),
                revert_sp(LOCKING_SP, "FAIL", keep_global=True),
            ],
        )))

    return out


def write_dataset() -> list[Scenario]:
    TESTCASE_DIR.mkdir(parents=True, exist_ok=True)
    for old in TESTCASE_DIR.glob("*.json"):
        old.unlink()

    rows = []
    manifest = []
    all_scenarios = scenarios()
    names = set()
    for scenario in all_scenarios:
        if scenario.name in names:
            raise ValueError(f"duplicate scenario name: {scenario.name}")
        names.add(scenario.name)
        filename = f"{scenario.name}.json"
        (TESTCASE_DIR / filename).write_text(json.dumps(scenario.steps, indent=2) + "\n")
        rows.append({"filename": filename, "label": scenario.label})
        manifest.append(
            {
                "filename": filename,
                "label": scenario.label,
                "concept": scenario.concept,
                "refs": list(scenario.refs),
            }
        )

    LABELS.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n")
    return all_scenarios


def check_with_v7() -> int:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from v7.src.solver import Solver

    solver = Solver()
    rows = [json.loads(line) for line in LABELS.read_text().splitlines() if line.strip()]
    total = len(rows)
    correct = 0
    misses = []
    for row in rows:
        steps = json.loads((TESTCASE_DIR / row["filename"]).read_text())
        pred = solver.predict_one(steps)
        if pred == row["label"]:
            correct += 1
        else:
            misses.append((row["filename"], row["label"], pred))
    print(f"v7 accuracy on opal_gap_cases: {correct}/{total} ({correct / total * 100:.1f}%)")
    if misses:
        print("misses:")
        for filename, label, pred in misses:
            print(f"  {filename}: expected={label} predicted={pred}")
    return 0 if correct == total else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="run v7 solver after generating")
    parser.add_argument("--check-only", action="store_true", help="run v7 solver without regenerating")
    args = parser.parse_args()

    if not args.check_only:
        generated = write_dataset()
        pass_count = sum(1 for s in generated if s.label == "pass")
        fail_count = len(generated) - pass_count
        print(f"Generated {len(generated)} cases ({pass_count} pass, {fail_count} fail)")
        print(f"  -> {TESTCASE_DIR}")
        print(f"  -> {LABELS}")
        print(f"  -> {MANIFEST}")

    if args.check or args.check_only:
        return check_with_v7()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

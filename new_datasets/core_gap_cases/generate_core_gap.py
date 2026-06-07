#!/usr/bin/env python3
"""Generate Core-spec gap cases in the project JSON trajectory format."""
from __future__ import annotations

import argparse
from copy import deepcopy
import json
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
V7_CUSTOM = ROOT / "new_datasets" / "customtest_84"
if str(V7_CUSTOM) not in sys.path:
    sys.path.insert(0, str(V7_CUSTOM))

from generate_synthetic import (  # noqa: E402
    ACCESS_CONTROL_TABLE_UID,
    ACE_ANYBODY_UID,
    ADMIN1_UID,
    ADMIN_SP,
    C_PIN_SID,
    C_PIN_USER1,
    GLOBAL_RANGE,
    K_AES_RANGE1,
    LOCKING_SP,
    LOG_FAKE_UID,
    LOG_TABLE_UID,
    RANGE1,
    SET_METHOD_UID,
    SID_UID,
    USER1_UID,
    activate_locking_sp,
    authenticate_step,
    end_session,
    make_step,
    set_authority,
    set_locking,
    setup_tper,
    setup_user,
    start_session,
)


OUT_DIR = Path(__file__).resolve().parent
TESTCASE_DIR = OUT_DIR / "testcases"
LABELS = OUT_DIR / "label.jsonl"
MANIFEST = OUT_DIR / "manifest.json"

TABLE_UID = "0000000100000001"
METHODID_TABLE_UID = "0000000100000006"
METHODID_GET_UID = "0000000600000016"
MBR_TABLE_UID = "0000000100000804"
LOCKING_TABLE_UID = "0000000100000802"
LOG_LIST_UID = "0000000100000A02"
CLOCKTIME_TABLE_UID = "0000000100000401"
HASH_SHA256_UID = "0000060300000001"
C_AES256_UID = "0000000C00000001"
NEW_LOG_UID = "0000000100000A09"
ADMINS_UID = "0000000900000002"
USER_PIN = "USER1PIN"


@dataclass(frozen=True)
class Scenario:
    name: str
    label: str
    steps: list[dict]
    concept: str
    refs: tuple[str, ...]


def sid_admin_session(sid: str = "SIDVAL", *, write: int = 1) -> list[dict]:
    return setup_tper("MSIDVAL", sid) + [
        start_session(ADMIN_SP, write=write, authority=SID_UID, challenge=sid),
    ]


def locking_admin_session(sid: str = "SIDVAL") -> list[dict]:
    return setup_tper("MSIDVAL", sid) + activate_locking_sp(sid) + [
        start_session(LOCKING_SP, authority="0000000900010001", challenge=sid),
    ]


def sync_session(status: str = "SUCCESS", host: int = 1, sp: int = 0x6572) -> dict:
    return make_step(
        "SyncSession",
        "0000000000000001",
        {"HostSessionID": host, "SPSessionID": sp},
        {},
        status,
        invoking_name="Session Manager UID",
    )


def trusted_session(method: str, status: str = "SUCCESS", host: int = 1, sp: int = 0x6572) -> dict:
    return make_step(
        method,
        "0000000000000001",
        {"HostSessionID": host, "SPSessionID": sp},
        {"HostResponse": "proof", "HostEncryptSessionKey": "enc", "HostIntegritySessionKey": "mac"},
        status,
        invoking_name="Session Manager UID",
    )


def sync_trusted_session(status: str = "SUCCESS", host: int = 1, sp: int = 0x6572) -> dict:
    return make_step(
        "SyncTrustedSession",
        "0000000000000001",
        {"HostSessionID": host, "SPSessionID": sp},
        {"SPResponse": "proof", "SPEncryptSessionKey": "enc", "SPIntegritySessionKey": "mac"},
        status,
        invoking_name="Session Manager UID",
    )


def start_session_raw(required: dict, optional: dict | None = None, status: str = "SUCCESS") -> dict:
    rv = {"required": {"HostSessionID": "00000001", "SPSessionID": "00006572"}, "optional": {}}
    return make_step(
        "StartSession",
        "0000000000000001",
        required,
        optional or {},
        status,
        return_values=rv,
        output_method_name="SyncSession",
        invoking_name="Session Manager UID",
    )


def start_session_without_return_ids(status: str = "SUCCESS") -> dict:
    return make_step(
        "StartSession",
        "0000000000000001",
        {"HostSessionID": 1, "SPID": ADMIN_SP, "Write": 1},
        {},
        status,
        return_values={},
        output_method_name="SyncSession",
        invoking_name="Session Manager UID",
    )


def close_session(status: str = "SUCCESS") -> dict:
    return make_step(
        "CloseSession",
        "0000000000000001",
        {"RemoteSessionNumber": 0x6572, "LocalSessionNumber": 1},
        {},
        status,
        invoking_name="Session Manager UID",
    )


def create_table(status: str = "SUCCESS", *, byte_bad: bool = False) -> dict:
    required = {
        "NewTableName": "CoreGapTable",
        "Kind": "Byte" if byte_bad else "Object",
        "GetSetACL": [ACE_ANYBODY_UID],
        "Columns": [] if byte_bad else [{"Name": "Value", "Type": "bytes"}],
        "MinSize": 1,
    }
    if byte_bad:
        required["MaxSize"] = 32
    return make_step("CreateTable", ADMIN_SP, required, {}, status, invoking_name="SP")


def create_table_missing_minsize(status: str = "SUCCESS") -> dict:
    return make_step(
        "CreateTable",
        ADMIN_SP,
        {
            "NewTableName": "CoreGapNoMinSize",
            "Kind": "Object",
            "GetSetACL": [ACE_ANYBODY_UID],
            "Columns": [{"Name": "Value", "Type": "bytes"}],
        },
        {},
        status,
        invoking_name="SP",
    )


def create_row(invoking_uid: str, status: str = "SUCCESS", invoking_name: str = "Table") -> dict:
    return make_step("CreateRow", invoking_uid, {"Row": [{"1": "row"}]}, {}, status, invoking_name=invoking_name)


def delete_row_missing(status: str = "SUCCESS") -> dict:
    return make_step("DeleteRow", TABLE_UID, {}, {}, status, invoking_name="Table")


def next_step(invoking_uid: str, status: str = "SUCCESS", *, count=1, where=None, invoking_name="Table") -> dict:
    optional = {"Count": count}
    if where is not None:
        optional["Where"] = where
    return make_step("Next", invoking_uid, {}, optional, status, invoking_name=invoking_name)


def get_acl(status: str = "SUCCESS", *, missing_method: bool = False, bad_invoking: bool = False) -> dict:
    optional = {"InvokingID": "" if bad_invoking else RANGE1}
    if not missing_method:
        optional["MethodID"] = SET_METHOD_UID
    return make_step("GetACL", ACCESS_CONTROL_TABLE_UID, {}, optional, status, invoking_name="AccessControl")


def get_free_rows(invoking_uid: str, status: str = "SUCCESS", invoking_name: str = "Table") -> dict:
    return make_step("GetFreeRows", invoking_uid, {}, {}, status, invoking_name=invoking_name)


def get_free_space(invoking_uid: str, status: str = "SUCCESS", invoking_name: str = "SP") -> dict:
    return make_step("GetFreeSpace", invoking_uid, {}, {}, status, invoking_name=invoking_name)


def package_step(method: str, invoking_uid: str, status: str, invoking_name: str = "C_PIN") -> dict:
    args = {"Purpose": "Backup"} if method == "GetPackage" else {"Value": "PACKAGE_BYTES"}
    return make_step(method, invoking_uid, args, {}, status, invoking_name=invoking_name)


def crypto_step(method: str, status: str = "SUCCESS", *, target_uid=HASH_SHA256_UID, target_name="H_SHA_256") -> dict:
    required = {}
    if method in {"Hash", "HMAC", "Encrypt", "Decrypt"}:
        required["Input"] = {"Data": "AABBCCDD"}
    return make_step(method, target_uid, required, {}, status, invoking_name=target_name)


def xor_step(status: str = "SUCCESS", pattern="not-a-uid") -> dict:
    return make_step(
        "XOR",
        ADMIN_SP,
        {"PatternInput": pattern, "DeletePattern": False, "Input": {"Data": "AA"}},
        {},
        status,
        invoking_name="SP",
    )


def random_step(status: str = "SUCCESS", count=-1) -> dict:
    return make_step("Random", ADMIN_SP, {"Count": count}, {}, status, invoking_name="SP")


def stir_step(status: str = "SUCCESS", internal="not_bool") -> dict:
    return make_step("Stir", ADMIN_SP, {"Value": {"Input": "AABB", "Internal": internal}}, {}, status, invoking_name="SP")


def clock_step(method: str, status: str = "SUCCESS") -> dict:
    required = {}
    if method in {"SetClockHigh", "SetClockLow"}:
        required["ExactTime"] = 123456
    if method in {"SetLagHigh", "SetLagLow"}:
        required["LagTime"] = 5
    return make_step(method, CLOCKTIME_TABLE_UID, required, {}, status, invoking_name="ClockTime")


def set_clocktime(status: str = "SUCCESS") -> dict:
    return make_step("Set", CLOCKTIME_TABLE_UID, {}, {"Values": [{3: 1}]}, status, invoking_name="ClockTime")


def set_cpin_columns(cpin_uid: str, columns: dict, status: str = "SUCCESS") -> dict:
    return make_step("Set", cpin_uid, {}, {"Values": [columns]}, status, invoking_name="C_PIN")


def set_authority_columns(authority_uid: str, columns: dict, status: str = "SUCCESS") -> dict:
    return make_step("Set", authority_uid, {}, {"Values": [columns]}, status, invoking_name="Authority")


def log_step(method: str, uid: str = LOG_TABLE_UID, status: str = "SUCCESS") -> dict:
    required = {}
    if method == "AddLog":
        required = {"LogEntryName": "entry", "Data": "payload"}
    return make_step(method, uid, required, {}, status, invoking_name="Log")


def create_log(status: str = "SUCCESS") -> dict:
    return make_step(
        "CreateLog",
        LOG_LIST_UID,
        {"NewLogTableName": "CoreGapLog", "HighSecurity": False, "MinSize": 1},
        {},
        status,
        return_values={"uid": NEW_LOG_UID},
        invoking_name="LogList",
    )


def meta_acl(method: str, status: str = "SUCCESS") -> dict:
    optional = {"InvokingID": RANGE1, "MethodID": SET_METHOD_UID}
    if method in {"AddACE", "RemoveACE"}:
        optional["ACE"] = ACE_ANYBODY_UID
    return make_step(method, ACCESS_CONTROL_TABLE_UID, {}, optional, status, invoking_name="AccessControl")


def issue_sp(status: str = "SUCCESS", *, missing_templates: bool = False) -> dict:
    required = {
        "SPName": "IssuedCoreSP",
        "Size": 4096,
        "Templates": ["0000000400000001"],
        "AdminExch": 0,
        "Enabled": True,
    }
    if missing_templates:
        required.pop("Templates")
    return make_step("IssueSP", ADMIN_SP, required, {}, status, invoking_name="SP")


def delete_object(invoking_uid: str, status: str = "SUCCESS", invoking_name: str = "Table") -> dict:
    return make_step("Delete", invoking_uid, {}, {}, status, invoking_name=invoking_name)


def delete_row(invoking_uid: str, rows: list, status: str = "SUCCESS", invoking_name: str = "Table") -> dict:
    return make_step("DeleteRow", invoking_uid, {"Rows": rows}, {}, status, invoking_name=invoking_name)


def gen_key_with_params(target_uid: str, optional: dict, status: str = "SUCCESS", invoking_name: str = "K_AES_256") -> dict:
    return make_step("GenKey", target_uid, {}, optional, status, invoking_name=invoking_name)


def increment_counter(status: str = "SUCCESS", monotonic: int = 1) -> dict:
    return make_step(
        "IncrementCounter",
        CLOCKTIME_TABLE_UID,
        {},
        {},
        status,
        return_values={"MonotonicTime": monotonic},
        invoking_name="ClockTime",
    )


def delete_sp(status: str = "SUCCESS") -> dict:
    return make_step("DeleteSP", LOCKING_SP, {}, {}, status, invoking_name="SP")


def properties_bad_hostprops(status: str = "SUCCESS") -> dict:
    return make_step(
        "Properties",
        "0000000000000001",
        {"HostProperties": "not-a-list-or-dict"},
        {},
        status,
        invoking_name="Session Manager UID",
    )


def get_invalid_cellblock(status: str = "SUCCESS") -> dict:
    return make_step(
        "Get",
        TABLE_UID,
        {"Cellblock": [{"startColumn": 8}, {"endColumn": 3}]},
        {},
        status,
        invoking_name="Table",
    )


def locking_set_duplicate(status: str = "SUCCESS") -> dict:
    return make_step("Set", RANGE1, {}, {"Values": [{5: 1}, {5: 0}]}, status, invoking_name="Locking")


def set_missing_where_on_object_table(status: str = "SUCCESS") -> dict:
    return make_step("Set", TABLE_UID, {}, {"Values": [{1: "CoreGap"}]}, status, invoking_name="Table")


def set_where_on_object(status: str = "SUCCESS") -> dict:
    return make_step("Set", RANGE1, {}, {"Where": {"uid": RANGE1}, "Values": [{5: 1}]}, status, invoking_name="Locking")


def set_object_with_bytes(status: str = "SUCCESS") -> dict:
    return make_step("Set", RANGE1, {}, {"Values": {"Bytes": "AABBCCDD"}}, status, invoking_name="Locking")


def set_byte_table_with_rowvalues(status: str = "SUCCESS") -> dict:
    return make_step("Set", MBR_TABLE_UID, {}, {"Values": [{1: 1}]}, status, invoking_name="MBR")


def set_byte_table_with_uid_where(status: str = "SUCCESS") -> dict:
    return make_step("Set", MBR_TABLE_UID, {}, {"Where": {"uid": MBR_TABLE_UID}, "Values": {"Bytes": "AABB"}}, status, invoking_name="MBR")


def set_byte_table_bytes(status: str = "SUCCESS") -> dict:
    return make_step("Set", MBR_TABLE_UID, {}, {"Values": {"Bytes": "AABB"}}, status, invoking_name="MBR")


def set_without_values(status: str = "SUCCESS") -> dict:
    return make_step("Set", RANGE1, {}, {}, status, invoking_name="Locking")


def verify_step(status: str = "SUCCESS", *, target_uid=HASH_SHA256_UID, target_name="H_SHA_256") -> dict:
    return make_step(
        "Verify",
        target_uid,
        {"Input": {"Data": "AABBCCDD"}, "Proof": "00112233"},
        {},
        status,
        return_values={"Result": True} if status == "SUCCESS" else {},
        invoking_name=target_name,
    )


def scen(name: str, label: str, steps: list[dict], concept: str, *refs: str) -> Scenario:
    normalized = deepcopy(steps)
    for index, step in enumerate(normalized, start=1):
        if isinstance(step, dict):
            step["index"] = index
    return Scenario(name, label, normalized, concept, tuple(refs))


def scenarios() -> list[Scenario]:
    sid = "SIDVAL"
    out: list[Scenario] = []

    out += [
        scen("core_pass_01_sync_after_start", "pass", sid_admin_session(sid) + [sync_session("SUCCESS")], "SyncSession is valid only as part of an established session-start exchange.", "core/5.2.3.2"),
        scen("core_pass_02_sync_id_mismatch_rejected", "pass", sid_admin_session(sid) + [sync_session("INVALID_PARAMETER", host=2)], "SyncSession IDs must match the established session numbers.", "core/5.2.3.2.1", "core/5.2.3.2.2"),
        scen("core_fail_02_sync_id_mismatch_success", "fail", sid_admin_session(sid) + [sync_session("SUCCESS", host=2)], "SyncSession ID mismatch cannot succeed.", "core/5.2.3.2.1", "core/5.2.3.2.2"),
        scen("core_pass_03_close_open_session", "pass", sid_admin_session(sid) + [close_session("SUCCESS")], "CloseSession is valid when a session is open.", "core/5.2.3.5"),
        scen("core_pass_04_close_without_session_rejected", "pass", [close_session("FAIL")], "CloseSession without an open session must fail.", "core/5.2.3.5"),
        scen("core_fail_04_close_without_session_success", "fail", [close_session("SUCCESS")], "CloseSession without an open session cannot succeed.", "core/5.2.3.5"),
        scen("core_pass_05_nested_start_rejected", "pass", sid_admin_session(sid) + [start_session(ADMIN_SP, status="NO_SESSIONS_AVAILABLE")], "A new StartSession while a session is already open must be rejected.", "core/3.3.7.1", "core/5.2.3.1"),
        scen("core_fail_05_nested_start_success", "fail", sid_admin_session(sid) + [start_session(ADMIN_SP, status="SUCCESS")], "A nested StartSession cannot return SUCCESS.", "core/3.3.7.1", "core/5.2.3.1"),
        scen("core_pass_06_trusted_after_sync", "pass", sid_admin_session(sid) + [trusted_session("StartTrustedSession", "SUCCESS")], "Trusted session setup follows a normal session-start exchange.", "core/5.2.3.3"),
        scen("core_pass_07_trusted_before_session_rejected", "pass", [trusted_session("StartTrustedSession", "FAIL")], "Trusted session setup requires an existing normal session.", "core/5.2.3.3"),
        scen("core_fail_07_trusted_before_session_success", "fail", [trusted_session("StartTrustedSession", "SUCCESS")], "Trusted session setup before StartSession cannot succeed.", "core/5.2.3.3"),
        scen("core_pass_08_class_authority_rejected", "pass", [start_session(ADMIN_SP, authority=ADMINS_UID, status="INVALID_PARAMETER")], "Class authorities such as Admins are not valid session authorities.", "core/5.3.4.1.2"),
        scen("core_fail_08_class_authority_success", "fail", [start_session(ADMIN_SP, authority=ADMINS_UID, status="SUCCESS")], "StartSession cannot authenticate directly as a class authority.", "core/5.3.4.1.2"),
    ]

    out += [
        scen("core_pass_09_create_table_authorized", "pass", sid_admin_session(sid) + [create_table("SUCCESS")], "CreateTable succeeds in an authorized read-write SP session.", "core/5.3.3.2"),
        scen("core_pass_10_create_table_readonly_rejected", "pass", sid_admin_session(sid, write=0) + [create_table("NOT_AUTHORIZED")], "CreateTable requires a read-write session.", "core/5.3.3.2"),
        scen("core_fail_10_create_table_readonly_success", "fail", sid_admin_session(sid, write=0) + [create_table("SUCCESS")], "CreateTable cannot succeed in a read-only session.", "core/5.3.3.2"),
        scen("core_pass_11_create_table_bad_byte_params", "pass", sid_admin_session(sid) + [create_table("INVALID_PARAMETER", byte_bad=True)], "Byte-table CreateTable must omit MaxSize and use an empty Columns list.", "core/5.3.3.2.10"),
        scen("core_fail_11_create_table_bad_byte_success", "fail", sid_admin_session(sid) + [create_table("SUCCESS", byte_bad=True)], "Malformed byte-table CreateTable parameters cannot succeed.", "core/5.3.3.2.10"),
        scen("core_pass_12_create_row_byte_table_rejected", "pass", locking_admin_session(sid) + [create_row(MBR_TABLE_UID, "INVALID_PARAMETER", "MBR")], "CreateRow is not available on byte tables.", "core/5.3.3.4"),
        scen("core_fail_12_create_row_byte_table_success", "fail", locking_admin_session(sid) + [create_row(MBR_TABLE_UID, "SUCCESS", "MBR")], "CreateRow on a byte table cannot succeed.", "core/5.3.3.4"),
        scen("core_pass_13_delete_row_missing_rows", "pass", sid_admin_session(sid) + [delete_row_missing("INVALID_PARAMETER")], "DeleteRow requires a non-empty Rows list.", "core/5.3.3.5.1"),
        scen("core_fail_13_delete_row_missing_rows_success", "fail", sid_admin_session(sid) + [delete_row_missing("SUCCESS")], "DeleteRow without Rows cannot succeed.", "core/5.3.3.5.1"),
        scen("core_pass_14_next_negative_count", "pass", sid_admin_session(sid) + [next_step(TABLE_UID, "INVALID_PARAMETER", count=-1)], "Next Count is an unsigned integer.", "core/5.3.3.8.2"),
        scen("core_fail_14_next_negative_count_success", "fail", sid_admin_session(sid) + [next_step(TABLE_UID, "SUCCESS", count=-1)], "Next with negative Count cannot succeed.", "core/5.3.3.8.2"),
        scen("core_pass_15_next_byte_table_rejected", "pass", locking_admin_session(sid) + [next_step(MBR_TABLE_UID, "INVALID_PARAMETER", invoking_name="MBR")], "Next iterates object tables, not byte tables.", "core/5.3.3.8"),
        scen("core_fail_15_next_byte_table_success", "fail", locking_admin_session(sid) + [next_step(MBR_TABLE_UID, "SUCCESS", invoking_name="MBR")], "Next on a byte table cannot succeed.", "core/5.3.3.8"),
        scen("core_pass_16_get_free_rows_object_rejected", "pass", sid_admin_session(sid) + [get_free_rows(C_PIN_SID, "INVALID_PARAMETER", "C_PIN")], "GetFreeRows is a table-level method.", "core/5.3.3.10"),
        scen("core_fail_16_get_free_rows_object_success", "fail", sid_admin_session(sid) + [get_free_rows(C_PIN_SID, "SUCCESS", "C_PIN")], "GetFreeRows on an object row cannot succeed.", "core/5.3.3.10"),
    ]

    out += [
        scen("core_pass_17_get_package_credential", "pass", sid_admin_session(sid) + [package_step("GetPackage", C_PIN_SID, "SUCCESS")], "GetPackage targets credential objects.", "core/5.3.3.17"),
        scen("core_pass_18_get_package_noncredential_rejected", "pass", locking_admin_session(sid) + [package_step("GetPackage", RANGE1, "INVALID_PARAMETER", "Locking")], "GetPackage cannot target non-credential objects.", "core/5.3.3.17"),
        scen("core_fail_18_get_package_noncredential_success", "fail", locking_admin_session(sid) + [package_step("GetPackage", RANGE1, "SUCCESS", "Locking")], "GetPackage on a non-credential object cannot succeed.", "core/5.3.3.17"),
        scen("core_pass_19_set_package_readonly_rejected", "pass", sid_admin_session(sid, write=0) + [package_step("SetPackage", C_PIN_SID, "NOT_AUTHORIZED")], "SetPackage requires write-session access.", "core/5.3.3.18"),
        scen("core_fail_19_set_package_readonly_success", "fail", sid_admin_session(sid, write=0) + [package_step("SetPackage", C_PIN_SID, "SUCCESS")], "SetPackage cannot succeed in a read-only session.", "core/5.3.3.18"),
        scen("core_pass_20_hash_without_init_rejected", "pass", sid_admin_session(sid) + [crypto_step("Hash", "FAIL")], "Hash requires a prior HashInit stream.", "core/5.6.4.12"),
        scen("core_fail_20_hash_without_init_success", "fail", sid_admin_session(sid) + [crypto_step("Hash", "SUCCESS")], "Hash before HashInit cannot succeed.", "core/5.6.4.12"),
        scen("core_pass_21_duplicate_hashinit_rejected", "pass", sid_admin_session(sid) + [crypto_step("HashInit"), crypto_step("HashInit", "FAIL")], "Only one hash stream may be open per hash object.", "core/5.6.4.11"),
        scen("core_fail_21_duplicate_hashinit_success", "fail", sid_admin_session(sid) + [crypto_step("HashInit"), crypto_step("HashInit", "SUCCESS")], "Duplicate HashInit on the same hash object cannot succeed.", "core/5.6.4.11"),
        scen("core_pass_22_hash_after_finalize_rejected", "pass", sid_admin_session(sid) + [crypto_step("HashInit"), crypto_step("HashFinalize"), crypto_step("Hash", "FAIL")], "HashFinalize closes the stream.", "core/5.6.4.13"),
        scen("core_fail_22_hash_after_finalize_success", "fail", sid_admin_session(sid) + [crypto_step("HashInit"), crypto_step("HashFinalize"), crypto_step("Hash", "SUCCESS")], "Hash after HashFinalize cannot succeed.", "core/5.6.4.13"),
        scen("core_pass_23_duplicate_encryptinit_rejected", "pass", sid_admin_session(sid) + [crypto_step("EncryptInit", target_uid=C_AES256_UID, target_name="C_AES_256"), crypto_step("EncryptInit", "FAIL", target_uid=C_AES256_UID, target_name="C_AES_256")], "Only one encryption stream may be open per credential.", "core/5.6.4.6"),
        scen("core_fail_23_duplicate_encryptinit_success", "fail", sid_admin_session(sid) + [crypto_step("EncryptInit", target_uid=C_AES256_UID, target_name="C_AES_256"), crypto_step("EncryptInit", "SUCCESS", target_uid=C_AES256_UID, target_name="C_AES_256")], "Duplicate EncryptInit cannot succeed.", "core/5.6.4.6"),
        scen("core_pass_24_xor_bad_pattern_rejected", "pass", sid_admin_session(sid) + [xor_step("INVALID_PARAMETER")], "XOR PatternInput must be a byte-table UID reference.", "core/5.6.4.17.1"),
        scen("core_fail_24_xor_bad_pattern_success", "fail", sid_admin_session(sid) + [xor_step("SUCCESS")], "XOR with malformed PatternInput cannot succeed.", "core/5.6.4.17.1"),
        scen("core_pass_25_random_negative_count", "pass", sid_admin_session(sid) + [random_step("INVALID_PARAMETER", -1)], "Random Count is an unsigned integer.", "core/5.6.4.1.1"),
        scen("core_fail_25_random_negative_success", "fail", sid_admin_session(sid) + [random_step("SUCCESS", -1)], "Random with negative Count cannot succeed.", "core/5.6.4.1.1"),
        scen("core_pass_26_stir_bad_internal", "pass", sid_admin_session(sid) + [stir_step("INVALID_PARAMETER")], "Stir Internal is a boolean field.", "core/5.6.4.2.1.2"),
        scen("core_fail_26_stir_bad_internal_success", "fail", sid_admin_session(sid) + [stir_step("SUCCESS")], "Stir with malformed Internal cannot succeed.", "core/5.6.4.2.1.2"),
    ]

    out += [
        scen("core_pass_27_clocktime_set_readonly_rejected", "pass", sid_admin_session(sid) + [set_clocktime("INVALID_PARAMETER")], "ClockTime columns are method-maintained, not directly Set by host.", "core/5.5.3.1", "core/5.5.4"),
        scen("core_fail_27_clocktime_set_readonly_success", "fail", sid_admin_session(sid) + [set_clocktime("SUCCESS")], "Direct Set of ClockTime method-maintained columns cannot succeed.", "core/5.5.3.1"),
        scen("core_pass_28_setlag_without_setclock", "pass", sid_admin_session(sid) + [clock_step("SetLagHigh", "FAIL")], "SetLagHigh must immediately follow SetClockHigh.", "core/5.5.4.3", "core/5.5.4.4"),
        scen("core_fail_28_setlag_without_setclock_success", "fail", sid_admin_session(sid) + [clock_step("SetLagHigh", "SUCCESS")], "SetLagHigh without pending SetClockHigh cannot succeed.", "core/5.5.4.4"),
        scen("core_pass_29_setlag_after_intervening_method", "pass", sid_admin_session(sid) + [clock_step("SetClockHigh"), clock_step("GetClock"), clock_step("SetLagHigh", "FAIL")], "SetClock/SetLag are an immediate method pair.", "core/5.5.5.1"),
        scen("core_fail_29_setlag_after_intervening_success", "fail", sid_admin_session(sid) + [clock_step("SetClockHigh"), clock_step("GetClock"), clock_step("SetLagHigh", "SUCCESS")], "An intervening method breaks the SetClock/SetLag pair.", "core/5.5.5.1"),
        scen("core_pass_30_clearlog_readonly_rejected", "pass", sid_admin_session(sid, write=0) + [log_step("ClearLog", LOG_TABLE_UID, "NOT_AUTHORIZED")], "ClearLog requires write access to an existing Log table.", "core/5.8.3.3"),
        scen("core_fail_30_clearlog_readonly_success", "fail", sid_admin_session(sid, write=0) + [log_step("ClearLog", LOG_TABLE_UID, "SUCCESS")], "ClearLog cannot succeed in a read-only session.", "core/5.8.3.3"),
        scen("core_pass_31_flushlog_readonly_ok", "pass", sid_admin_session(sid, write=0) + [log_step("FlushLog", LOG_TABLE_UID, "SUCCESS")], "FlushLog may be invoked without write-session mutation.", "core/5.8.3.4"),
        scen("core_pass_32_flushlog_unknown_rejected", "pass", sid_admin_session(sid) + [log_step("FlushLog", LOG_FAKE_UID, "FAIL")], "FlushLog requires an existing Log table.", "core/5.8.3.4"),
        scen("core_fail_32_flushlog_unknown_success", "fail", sid_admin_session(sid) + [log_step("FlushLog", LOG_FAKE_UID, "SUCCESS")], "FlushLog on an unknown Log table cannot succeed.", "core/5.8.3.4"),
        scen("core_pass_33_createlog_then_flush_new_log", "pass", sid_admin_session(sid) + [create_log("SUCCESS"), log_step("FlushLog", NEW_LOG_UID, "SUCCESS")], "Successful CreateLog creates a new Log table usable by log methods.", "core/5.8.3.2", "core/5.8.3.4"),
    ]

    out += [
        scen("core_pass_34a_addace_grants_set", "pass", locking_admin_session(sid) + [meta_acl("AddACE"), end_session(), start_session(LOCKING_SP), set_locking(RANGE1, {5: 1}, "SUCCESS")], "AddACE adds an ACE to the target ACL, granting unauthenticated Set via ACE_Anybody.", "core/5.3.3.14", "core/5.3.4.3.1"),
        scen("core_fail_34a_addace_grants_set_rejected", "fail", locking_admin_session(sid) + [meta_acl("AddACE"), end_session(), start_session(LOCKING_SP), set_locking(RANGE1, {5: 1}, "NOT_AUTHORIZED")], "After AddACE grants ACE_Anybody, unauthenticated Set should not be rejected.", "core/5.3.3.14", "core/5.3.4.3.1"),
        scen("core_pass_34_removeace_revokes_set", "pass", locking_admin_session(sid) + [meta_acl("AddACE"), meta_acl("RemoveACE"), end_session(), start_session(LOCKING_SP), set_locking(RANGE1, {5: 1}, "NOT_AUTHORIZED")], "RemoveACE removes a previously granted ACE from an ACL.", "core/5.3.3.15", "core/5.3.4.3.1"),
        scen("core_fail_34_removeace_still_allows_set", "fail", locking_admin_session(sid) + [meta_acl("AddACE"), meta_acl("RemoveACE"), end_session(), start_session(LOCKING_SP), set_locking(RANGE1, {5: 1}, "SUCCESS")], "After RemoveACE, unauthenticated Set should no longer be allowed.", "core/5.3.3.15"),
        scen("core_pass_35_deletemethod_revokes_set", "pass", locking_admin_session(sid) + [meta_acl("AddACE"), meta_acl("DeleteMethod"), end_session(), start_session(LOCKING_SP), set_locking(RANGE1, {5: 1}, "NOT_AUTHORIZED")], "DeleteMethod removes the AccessControl association.", "core/5.3.3.11"),
        scen("core_fail_35_deletemethod_still_allows_set", "fail", locking_admin_session(sid) + [meta_acl("AddACE"), meta_acl("DeleteMethod"), end_session(), start_session(LOCKING_SP), set_locking(RANGE1, {5: 1}, "SUCCESS")], "After DeleteMethod, unauthenticated Set should no longer be allowed.", "core/5.3.3.11"),
        scen("core_pass_36_frozen_sp_start_rejected", "pass", setup_tper("MSIDVAL", sid) + activate_locking_sp(sid) + [start_session(ADMIN_SP, authority=SID_UID, challenge=sid), make_step("Set", LOCKING_SP, {}, {"Values": [{7: 1}]}, "SUCCESS", invoking_name="SP"), end_session(), start_session(LOCKING_SP, status="SP_FROZEN")], "SPs in a frozen lifecycle state reject session startup.", "core/4.5.3"),
        scen("core_fail_36_frozen_sp_start_success", "fail", setup_tper("MSIDVAL", sid) + activate_locking_sp(sid) + [start_session(ADMIN_SP, authority=SID_UID, challenge=sid), make_step("Set", LOCKING_SP, {}, {"Values": [{7: 1}]}, "SUCCESS", invoking_name="SP"), end_session(), start_session(LOCKING_SP, status="SUCCESS")], "StartSession to a frozen SP cannot succeed.", "core/4.5.3"),
        scen("core_pass_37_reencrypt_advkey_from_idle", "pass", locking_admin_session(sid) + [set_locking(RANGE1, {13: 2}, "FAIL")], "ADVKEY_req is invalid while ReEncryptState is IDLE.", "core/5.7.3.7.4"),
        scen("core_fail_37_reencrypt_advkey_from_idle_success", "fail", locking_admin_session(sid) + [set_locking(RANGE1, {13: 2}, "SUCCESS")], "Invalid ReEncryptRequest cannot succeed.", "core/5.7.3.7.4"),
        scen("core_pass_38_global_reencrypt_create_row_rejected", "pass", locking_admin_session(sid) + [set_locking(GLOBAL_RANGE, {13: 1}, "SUCCESS"), create_row(LOCKING_TABLE_UID, "INVALID_PARAMETER", "Locking")], "Creating Locking rows fails while Global Range re-encryption is non-IDLE.", "core/5.7.3.7"),
        scen("core_fail_38_global_reencrypt_create_row_success", "fail", locking_admin_session(sid) + [set_locking(GLOBAL_RANGE, {13: 1}, "SUCCESS"), create_row(LOCKING_TABLE_UID, "SUCCESS", "Locking")], "CreateRow on Locking table cannot succeed during Global Range re-encryption.", "core/5.7.3.7"),
        scen("core_pass_39_activekey_direct_set_allowed", "pass", locking_admin_session(sid) + [set_locking(RANGE1, {10: K_AES_RANGE1}, "SUCCESS")], "Core Locking allows host direct writes to ActiveKey.", "core/5.7.3.7.2"),
        scen("core_fail_39_activekey_direct_set_rejected", "fail", locking_admin_session(sid) + [set_locking(RANGE1, {10: K_AES_RANGE1}, "NOT_AUTHORIZED")], "Authorized ActiveKey direct write should not be rejected under Core.", "core/5.7.3.7.2"),
        scen("core_pass_40_issuesp_authorized", "pass", sid_admin_session(sid) + [issue_sp("SUCCESS")], "IssueSP is a Core Admin Template method for issuing SPs.", "core/5.4.3.1"),
        scen("core_pass_41_issuesp_missing_templates", "pass", sid_admin_session(sid) + [issue_sp("INVALID_PARAMETER", missing_templates=True)], "IssueSP requires Templates and other mandatory parameters.", "core/5.4.3.1"),
        scen("core_fail_41_issuesp_missing_templates_success", "fail", sid_admin_session(sid) + [issue_sp("SUCCESS", missing_templates=True)], "IssueSP missing mandatory parameters cannot succeed.", "core/5.4.3.1"),
        scen("core_pass_42_revert_unknown_sp_rejected", "pass", sid_admin_session(sid) + [make_step("Revert", "00000205000000AA", {}, {}, "FAIL", invoking_name="SP")], "Revert is not permitted on unknown or issued SP objects in this model.", "core/4.3", "opal/5.1.2"),
        scen("core_fail_42_revert_unknown_sp_success", "fail", sid_admin_session(sid) + [make_step("Revert", "00000205000000AA", {}, {}, "SUCCESS", invoking_name="SP")], "Revert on an unknown/issued SP cannot succeed.", "core/4.3", "opal/5.1.2"),
    ]

    out += [
        scen("core_pass_43_trylimit_locks_user", "pass", setup_tper("MSIDVAL", sid) + activate_locking_sp(sid) + setup_user(sid, USER_PIN) + [start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid), set_cpin_columns(C_PIN_USER1, {5: 2}), end_session(), start_session(LOCKING_SP, authority=USER1_UID, challenge="BAD1", status="NOT_AUTHORIZED"), start_session(LOCKING_SP, authority=USER1_UID, challenge="BAD2", status="NOT_AUTHORIZED"), start_session(LOCKING_SP, authority=USER1_UID, challenge=USER_PIN, status="AUTHORITY_LOCKED_OUT")], "C_PIN TryLimit locks an authority after failed implicit authentication attempts.", "core/5.3.4.1.1.2", "core/5.1.5.15"),
        scen("core_fail_43_trylimit_allows_success", "fail", setup_tper("MSIDVAL", sid) + activate_locking_sp(sid) + setup_user(sid, USER_PIN) + [start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid), set_cpin_columns(C_PIN_USER1, {5: 2}), end_session(), start_session(LOCKING_SP, authority=USER1_UID, challenge="BAD1", status="NOT_AUTHORIZED"), start_session(LOCKING_SP, authority=USER1_UID, challenge="BAD2", status="NOT_AUTHORIZED"), start_session(LOCKING_SP, authority=USER1_UID, challenge=USER_PIN, status="SUCCESS")], "Authentication cannot succeed once Tries reaches TryLimit.", "core/5.3.4.1.1.2", "core/5.1.5.15"),
        scen("core_pass_44_pin_set_resets_tries", "pass", setup_tper("MSIDVAL", sid) + activate_locking_sp(sid) + setup_user(sid, USER_PIN) + [start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid), set_cpin_columns(C_PIN_USER1, {5: 2}), end_session(), start_session(LOCKING_SP, authority=USER1_UID, challenge="BAD1", status="NOT_AUTHORIZED"), start_session(LOCKING_SP, authority=USER1_UID, challenge="BAD2", status="NOT_AUTHORIZED"), start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid), set_cpin_columns(C_PIN_USER1, {3: "NEWUSERPIN"}), end_session(), start_session(LOCKING_SP, authority=USER1_UID, challenge="NEWUSERPIN", status="SUCCESS")], "Successful Set of a C_PIN PIN resets Tries to 0.", "core/5.3.4.1.1.2"),
        scen("core_fail_44_pin_set_does_not_reset_tries", "fail", setup_tper("MSIDVAL", sid) + activate_locking_sp(sid) + setup_user(sid, USER_PIN) + [start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid), set_cpin_columns(C_PIN_USER1, {5: 2}), end_session(), start_session(LOCKING_SP, authority=USER1_UID, challenge="BAD1", status="NOT_AUTHORIZED"), start_session(LOCKING_SP, authority=USER1_UID, challenge="BAD2", status="NOT_AUTHORIZED"), start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid), set_cpin_columns(C_PIN_USER1, {3: "NEWUSERPIN"}), end_session(), start_session(LOCKING_SP, authority=USER1_UID, challenge="NEWUSERPIN", status="AUTHORITY_LOCKED_OUT")], "A PIN update should clear the lockout counter for that C_PIN.", "core/5.3.4.1.1.2"),
        scen("core_pass_45_authenticate_disabled_success_false", "pass", setup_tper("MSIDVAL", sid) + activate_locking_sp(sid) + setup_user(sid, USER_PIN) + [start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid), set_authority(USER1_UID, enabled=False), end_session(), start_session(LOCKING_SP), authenticate_step(USER1_UID, proof=USER_PIN, auth_result=False, status="SUCCESS")], "Authenticate on a disabled authority returns SUCCESS with result False.", "core/5.3.4.1.4", "core/5.3.4.1.14.1"),
        scen("core_fail_45_authenticate_disabled_not_authorized", "fail", setup_tper("MSIDVAL", sid) + activate_locking_sp(sid) + setup_user(sid, USER_PIN) + [start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid), set_authority(USER1_UID, enabled=False), end_session(), start_session(LOCKING_SP), authenticate_step(USER1_UID, proof=USER_PIN, auth_result=None, status="NOT_AUTHORIZED")], "Disabled-authority Authenticate should not use method status NOT_AUTHORIZED.", "core/5.3.4.1.4", "core/5.3.4.1.14.1"),
        scen("core_pass_46_authenticate_exchange_success_false", "pass", setup_tper("MSIDVAL", sid) + activate_locking_sp(sid) + [start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid), set_authority_columns(USER1_UID, {5: 1, 9: "Exchange"}), end_session(), start_session(LOCKING_SP), authenticate_step(USER1_UID, auth_result=False, status="SUCCESS")], "Authorities with Operation=Exchange cannot be explicitly authenticated and return SUCCESS False.", "core/5.3.4.1.3", "core/5.3.4.1.14.1"),
        scen("core_fail_46_authenticate_exchange_invalid_parameter", "fail", setup_tper("MSIDVAL", sid) + activate_locking_sp(sid) + [start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid), set_authority_columns(USER1_UID, {5: 1, 9: "Exchange"}), end_session(), start_session(LOCKING_SP), authenticate_step(USER1_UID, auth_result=None, status="INVALID_PARAMETER")], "Exchange-authority Authenticate should return SUCCESS False rather than INVALID_PARAMETER.", "core/5.3.4.1.3", "core/5.3.4.1.14.1"),
        scen("core_pass_47_secure_required_auth_success_false", "pass", setup_tper("MSIDVAL", sid) + activate_locking_sp(sid) + setup_user(sid, USER_PIN) + [start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid), set_authority_columns(USER1_UID, {6: 1}), end_session(), start_session(LOCKING_SP), authenticate_step(USER1_UID, proof=USER_PIN, auth_result=False, status="SUCCESS")], "Authenticate without required secure messaging should fail as SUCCESS with result False.", "core/5.3.4.1.6", "core/5.3.4.1.14.1"),
        scen("core_fail_47_secure_required_auth_not_authorized", "fail", setup_tper("MSIDVAL", sid) + activate_locking_sp(sid) + setup_user(sid, USER_PIN) + [start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid), set_authority_columns(USER1_UID, {6: 1}), end_session(), start_session(LOCKING_SP), authenticate_step(USER1_UID, proof=USER_PIN, auth_result=None, status="NOT_AUTHORIZED")], "Secure-messaging Authenticate failure should not be represented as method status NOT_AUTHORIZED.", "core/5.3.4.1.6", "core/5.3.4.1.14.1"),
    ]

    out += [
        scen("core_pass_48_get_free_space_readonly", "pass", sid_admin_session(sid, write=0) + [get_free_space(ADMIN_SP, "SUCCESS")], "GetFreeSpace is an SP method that can run in an open read-only session.", "core/5.3.3.9"),
        scen("core_fail_48_get_free_space_readonly_rejected", "fail", sid_admin_session(sid, write=0) + [get_free_space(ADMIN_SP, "NOT_AUTHORIZED")], "GetFreeSpace should not require a read-write session.", "core/5.3.3.9"),
        scen("core_pass_49_get_free_rows_table", "pass", sid_admin_session(sid, write=0) + [get_free_rows(TABLE_UID, "SUCCESS")], "GetFreeRows is valid when invoked on an object table.", "core/5.3.3.10"),
        scen("core_fail_49_get_free_rows_table_rejected", "fail", sid_admin_session(sid, write=0) + [get_free_rows(TABLE_UID, "NOT_AUTHORIZED")], "GetFreeRows should succeed on an existing table in an open session.", "core/5.3.3.10"),
        scen("core_pass_50_delete_methodid_rejected", "pass", sid_admin_session(sid) + [delete_object(METHODID_GET_UID, "INVALID_PARAMETER", "MethodID")], "Delete is not permitted for MethodID rows.", "core/5.3.4.2.4"),
        scen("core_fail_50_delete_methodid_success", "fail", sid_admin_session(sid) + [delete_object(METHODID_GET_UID, "SUCCESS", "MethodID")], "MethodID rows cannot be deleted by Delete.", "core/5.3.4.2.4"),
        scen("core_pass_51_create_row_methodid_rejected", "pass", sid_admin_session(sid) + [create_row(METHODID_TABLE_UID, "INVALID_PARAMETER", "MethodID")], "CreateRow is not permitted on the MethodID table.", "core/5.3.4.2.3"),
        scen("core_fail_51_create_row_methodid_success", "fail", sid_admin_session(sid) + [create_row(METHODID_TABLE_UID, "SUCCESS", "MethodID")], "MethodID rows cannot be created through CreateRow.", "core/5.3.4.2.3"),
        scen("core_pass_52_delete_row_methodid_rejected", "pass", sid_admin_session(sid) + [delete_row(METHODID_TABLE_UID, [{"uid": METHODID_GET_UID}], "INVALID_PARAMETER", "MethodID")], "DeleteRow is not permitted on the MethodID table.", "core/5.3.4.2.4"),
        scen("core_fail_52_delete_row_methodid_success", "fail", sid_admin_session(sid) + [delete_row(METHODID_TABLE_UID, [{"uid": METHODID_GET_UID}], "SUCCESS", "MethodID")], "MethodID rows cannot be deleted through DeleteRow.", "core/5.3.4.2.4"),
        scen("core_pass_53_create_row_log_rejected", "pass", sid_admin_session(sid) + [create_row(LOG_TABLE_UID, "INVALID_PARAMETER", "Log")], "CreateRow is not permitted on Log tables.", "core/5.3.4.2.3"),
        scen("core_fail_53_create_row_log_success", "fail", sid_admin_session(sid) + [create_row(LOG_TABLE_UID, "SUCCESS", "Log")], "Log rows are created by AddLog/CreateLog, not CreateRow.", "core/5.3.4.2.3", "core/5.8.3.1"),
        scen("core_pass_54_set_duplicate_columns_rejected", "pass", locking_admin_session(sid) + [locking_set_duplicate("INVALID_PARAMETER")], "Set with the same column multiple times must return INVALID_PARAMETER.", "core/5.3.4.2.6"),
        scen("core_fail_54_set_duplicate_columns_success", "fail", locking_admin_session(sid) + [locking_set_duplicate("SUCCESS")], "Set with duplicate column identifiers cannot succeed.", "core/5.3.4.2.6"),
        scen("core_pass_55_get_invalid_cellblock_rejected", "pass", sid_admin_session(sid) + [get_invalid_cellblock("INVALID_PARAMETER")], "Get with an invalid Cellblock range must return INVALID_PARAMETER.", "core/5.3.3.6.1"),
        scen("core_fail_55_get_invalid_cellblock_success", "fail", sid_admin_session(sid) + [get_invalid_cellblock("SUCCESS")], "Get with startColumn greater than endColumn cannot succeed.", "core/5.3.3.6.1"),
    ]

    out += [
        scen("core_pass_56_genkey_public_exponent_on_media_key_rejected", "pass", locking_admin_session(sid) + [gen_key_with_params(K_AES_RANGE1, {"PublicExponent": 65537}, "INVALID_PARAMETER")], "GenKey PublicExponent is valid only for C_RSA credentials.", "core/5.3.3.16.4"),
        scen("core_fail_56_genkey_public_exponent_on_media_key_success", "fail", locking_admin_session(sid) + [gen_key_with_params(K_AES_RANGE1, {"PublicExponent": 65537}, "SUCCESS")], "GenKey with PublicExponent on a non-RSA media key cannot succeed.", "core/5.3.3.16.4"),
        scen("core_pass_57_genkey_pinlength_on_media_key_rejected", "pass", locking_admin_session(sid) + [gen_key_with_params(K_AES_RANGE1, {"PinLength": 8}, "INVALID_PARAMETER")], "GenKey PinLength is valid only for C_PIN credentials.", "core/5.3.3.16.4"),
        scen("core_fail_57_genkey_pinlength_on_media_key_success", "fail", locking_admin_session(sid) + [gen_key_with_params(K_AES_RANGE1, {"PinLength": 8}, "SUCCESS")], "GenKey with PinLength on a non-C_PIN media key cannot succeed.", "core/5.3.3.16.4"),
        scen("core_pass_58_hmac_without_init_rejected", "pass", sid_admin_session(sid) + [crypto_step("HMAC", "FAIL")], "HMAC requires a prior HMACInit stream.", "core/5.6.4.15"),
        scen("core_fail_58_hmac_without_init_success", "fail", sid_admin_session(sid) + [crypto_step("HMAC", "SUCCESS")], "HMAC before HMACInit cannot succeed.", "core/5.6.4.15"),
        scen("core_pass_59_duplicate_hmacinit_rejected", "pass", sid_admin_session(sid) + [crypto_step("HMACInit"), crypto_step("HMACInit", "FAIL")], "Only one HMAC stream may be open per hash object.", "core/5.6.4.14", "core/5.6.5.3"),
        scen("core_fail_59_duplicate_hmacinit_success", "fail", sid_admin_session(sid) + [crypto_step("HMACInit"), crypto_step("HMACInit", "SUCCESS")], "Duplicate HMACInit cannot succeed.", "core/5.6.4.14", "core/5.6.5.3"),
        scen("core_pass_60_hmac_after_finalize_rejected", "pass", sid_admin_session(sid) + [crypto_step("HMACInit"), crypto_step("HMACFinalize"), crypto_step("HMAC", "FAIL")], "HMACFinalize closes the HMAC stream.", "core/5.6.4.16"),
        scen("core_fail_60_hmac_after_finalize_success", "fail", sid_admin_session(sid) + [crypto_step("HMACInit"), crypto_step("HMACFinalize"), crypto_step("HMAC", "SUCCESS")], "HMAC after HMACFinalize cannot succeed.", "core/5.6.4.16"),
        scen("core_pass_61_decrypt_without_init_rejected", "pass", sid_admin_session(sid) + [crypto_step("Decrypt", "FAIL", target_uid=C_AES256_UID, target_name="C_AES_256")], "Decrypt requires a prior DecryptInit stream.", "core/5.6.4.4"),
        scen("core_fail_61_decrypt_without_init_success", "fail", sid_admin_session(sid) + [crypto_step("Decrypt", "SUCCESS", target_uid=C_AES256_UID, target_name="C_AES_256")], "Decrypt before DecryptInit cannot succeed.", "core/5.6.4.4"),
        scen("core_pass_62_decrypt_after_finalize_rejected", "pass", sid_admin_session(sid) + [crypto_step("DecryptInit", target_uid=C_AES256_UID, target_name="C_AES_256"), crypto_step("DecryptFinalize", target_uid=C_AES256_UID, target_name="C_AES_256"), crypto_step("Decrypt", "FAIL", target_uid=C_AES256_UID, target_name="C_AES_256")], "DecryptFinalize closes the decrypt stream.", "core/5.6.4.5"),
        scen("core_fail_62_decrypt_after_finalize_success", "fail", sid_admin_session(sid) + [crypto_step("DecryptInit", target_uid=C_AES256_UID, target_name="C_AES_256"), crypto_step("DecryptFinalize", target_uid=C_AES256_UID, target_name="C_AES_256"), crypto_step("Decrypt", "SUCCESS", target_uid=C_AES256_UID, target_name="C_AES_256")], "Decrypt after DecryptFinalize cannot succeed.", "core/5.6.4.5"),
        scen("core_pass_63_sign_invalid_target_rejected", "pass", locking_admin_session(sid) + [make_step("Sign", RANGE1, {"Input": {"Data": "AA"}}, {}, "INVALID_PARAMETER", invoking_name="Locking")], "Sign must target a public-key credential or hash object.", "core/5.6.4.9", "core/5.6.5.5"),
        scen("core_fail_63_sign_invalid_target_success", "fail", locking_admin_session(sid) + [make_step("Sign", RANGE1, {"Input": {"Data": "AA"}}, {}, "SUCCESS", invoking_name="Locking")], "Sign on a Locking row cannot succeed.", "core/5.6.4.9", "core/5.6.5.5"),
    ]

    out += [
        scen("core_pass_64_setclockhigh_then_setlaghigh", "pass", sid_admin_session(sid) + [clock_step("SetClockHigh"), clock_step("SetLagHigh", "SUCCESS")], "SetLagHigh succeeds when it immediately follows SetClockHigh.", "core/5.5.4.3", "core/5.5.4.4", "core/5.5.5.1"),
        scen("core_fail_64_setclockhigh_then_setlaghigh_rejected", "fail", sid_admin_session(sid) + [clock_step("SetClockHigh"), clock_step("SetLagHigh", "FAIL")], "The matching SetClockHigh/SetLagHigh pair should not be rejected.", "core/5.5.4.3", "core/5.5.4.4"),
        scen("core_pass_65_setclocklow_while_high_pending_rejected", "pass", sid_admin_session(sid) + [clock_step("SetClockHigh"), clock_step("SetClockLow", "FAIL")], "A new SetClock method cannot start while a SetLag method is pending.", "core/5.5.5.1"),
        scen("core_fail_65_setclocklow_while_high_pending_success", "fail", sid_admin_session(sid) + [clock_step("SetClockHigh"), clock_step("SetClockLow", "SUCCESS")], "SetClockLow cannot interrupt a pending SetClockHigh/SetLagHigh pair.", "core/5.5.5.1"),
        scen("core_pass_66_increment_counter_increases", "pass", sid_admin_session(sid, write=0) + [increment_counter("SUCCESS", 10), increment_counter("SUCCESS", 11)], "IncrementCounter returns a value greater than the previous call.", "core/5.5.4.7", "core/5.5.5.2"),
        scen("core_fail_66_increment_counter_same_value", "fail", sid_admin_session(sid, write=0) + [increment_counter("SUCCESS", 10), increment_counter("SUCCESS", 10)], "IncrementCounter must return a strictly greater value on later calls.", "core/5.5.4.7", "core/5.5.5.2"),
        scen("core_pass_67_properties_bad_hostprops_rejected", "pass", [properties_bad_hostprops("INVALID_PARAMETER")], "Properties HostProperties must be structured name/value data.", "core/5.2.2.1.1"),
        scen("core_fail_67_properties_bad_hostprops_success", "fail", [properties_bad_hostprops("SUCCESS")], "Malformed HostProperties cannot be accepted.", "core/5.2.2.1.1"),
    ]

    out += [
        scen("core_pass_68_deletesp_authorized", "pass", setup_tper("MSIDVAL", sid) + activate_locking_sp(sid) + [start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid), delete_sp("SUCCESS")], "DeleteSP is valid in an authorized read-write session to the SP being deleted.", "core/5.3.3.1", "core/5.3.4.4"),
        scen("core_pass_69_deletesp_readonly_rejected", "pass", setup_tper("MSIDVAL", sid) + activate_locking_sp(sid) + [start_session(LOCKING_SP, write=0, authority=ADMIN1_UID, challenge=sid), delete_sp("NOT_AUTHORIZED")], "DeleteSP requires a read-write session.", "core/5.3.3.1", "core/5.3.4.4"),
        scen("core_fail_69_deletesp_readonly_success", "fail", setup_tper("MSIDVAL", sid) + activate_locking_sp(sid) + [start_session(LOCKING_SP, write=0, authority=ADMIN1_UID, challenge=sid), delete_sp("SUCCESS")], "DeleteSP cannot succeed in a read-only session.", "core/5.3.3.1", "core/5.3.4.4"),
        scen("core_pass_70_delete_sp_deferred_then_session_rejected", "pass", setup_tper("MSIDVAL", sid) + activate_locking_sp(sid) + [start_session(ADMIN_SP, authority=SID_UID, challenge=sid), delete_object(LOCKING_SP, "SUCCESS", "SP"), end_session(), start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid, status="FAIL")], "Deleting an SP via AdminSP Delete takes effect after successful session close; future sessions to it fail.", "core/5.4.4.2", "core/5.3.4.4"),
        scen("core_fail_70_delete_sp_deferred_then_session_success", "fail", setup_tper("MSIDVAL", sid) + activate_locking_sp(sid) + [start_session(ADMIN_SP, authority=SID_UID, challenge=sid), delete_object(LOCKING_SP, "SUCCESS", "SP"), end_session(), start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid, status="SUCCESS")], "After successful SP deletion and close, the deleted SP cannot be opened.", "core/5.4.4.2", "core/5.3.4.4"),
    ]

    out += [
        scen("core_pass_71_startsession_negative_host_id_rejected", "pass", [start_session_raw({"HostSessionID": -1, "SPID": ADMIN_SP, "Write": 1}, status="INVALID_PARAMETER")], "StartSession HostSessionID is an unsigned integer.", "core/5.2.3.1", "core/5.2.3.1.1", "core/5.1.3.82"),
        scen("core_fail_71_startsession_negative_host_id_success", "fail", [start_session_raw({"HostSessionID": -1, "SPID": ADMIN_SP, "Write": 1}, status="SUCCESS")], "StartSession cannot accept a negative HostSessionID.", "core/5.2.3.1.1", "core/5.1.3.82"),
        scen("core_pass_72_startsession_bad_write_boolean_rejected", "pass", [start_session_raw({"HostSessionID": 1, "SPID": ADMIN_SP, "Write": "maybe"}, status="INVALID_PARAMETER")], "StartSession Write is a boolean field.", "core/5.2.3.1.3", "core/5.1.3.10"),
        scen("core_fail_72_startsession_bad_write_boolean_success", "fail", [start_session_raw({"HostSessionID": 1, "SPID": ADMIN_SP, "Write": "maybe"}, status="SUCCESS")], "StartSession cannot accept a non-boolean Write value.", "core/5.2.3.1.3"),
        scen("core_pass_73_startsession_missing_spid_rejected", "pass", [start_session_raw({"HostSessionID": 1, "Write": 1}, status="INVALID_PARAMETER")], "StartSession requires SPID.", "core/5.2.3.1", "core/5.2.3.1.2"),
        scen("core_fail_73_startsession_missing_spid_success", "fail", [start_session_raw({"HostSessionID": 1, "Write": 1}, status="SUCCESS")], "StartSession without SPID cannot succeed.", "core/5.2.3.1.2"),
        scen("core_pass_74_synctrusted_after_starttrusted", "pass", sid_admin_session(sid) + [trusted_session("StartTrustedSession"), sync_trusted_session("SUCCESS")], "SyncTrustedSession is the second half of trusted-session startup after StartTrustedSession.", "core/5.2.3.3", "core/5.2.3.4", "core/3.3.7.1.4"),
        scen("core_pass_75_synctrusted_without_trusted_rejected", "pass", sid_admin_session(sid) + [sync_trusted_session("FAIL")], "SyncTrustedSession requires a preceding StartTrustedSession exchange.", "core/5.2.3.4", "core/3.3.7.1.4"),
        scen("core_fail_75_synctrusted_without_trusted_success", "fail", sid_admin_session(sid) + [sync_trusted_session("SUCCESS")], "SyncTrustedSession cannot succeed without StartTrustedSession.", "core/5.2.3.4"),
        scen("core_pass_76_end_session_open", "pass", sid_admin_session(sid) + [end_session("SUCCESS")], "EndSession closes an open session.", "core/3.3.7.1.5"),
        scen("core_pass_77_end_session_without_session_rejected", "pass", [end_session("FAIL")], "EndSession without an open session must fail.", "core/3.3.7.1.5"),
        scen("core_fail_77_end_session_without_session_success", "fail", [end_session("SUCCESS")], "EndSession cannot close a session that does not exist.", "core/3.3.7.1.5"),
        scen("core_pass_78_authenticate_missing_authority_rejected", "pass", sid_admin_session(sid) + [make_step("Authenticate", "0000000000000001", {}, {}, "INVALID_PARAMETER", invoking_name="Session Manager UID")], "Authenticate requires an Authority parameter.", "core/5.3.4.1.14", "core/5.3.4.1.14.1"),
        scen("core_fail_78_authenticate_missing_authority_success", "fail", sid_admin_session(sid) + [make_step("Authenticate", "0000000000000001", {}, {}, "SUCCESS", invoking_name="Session Manager UID")], "Authenticate without Authority cannot succeed.", "core/5.3.4.1.14"),
        scen("core_pass_79_authenticate_class_authority_rejected", "pass", sid_admin_session(sid) + [authenticate_step(ADMINS_UID, auth_result=None, status="INVALID_PARAMETER")], "Authenticate targets Authority objects, not authority class rows such as Admins.", "core/5.3.4.1.2", "core/5.3.4.1.14"),
        scen("core_fail_79_authenticate_class_authority_success", "fail", sid_admin_session(sid) + [authenticate_step(ADMINS_UID, auth_result=None, status="SUCCESS")], "Class authority Authenticate cannot succeed.", "core/5.3.4.1.2"),
    ]

    out += [
        scen("core_pass_80_object_table_set_missing_where_rejected", "pass", sid_admin_session(sid) + [set_missing_where_on_object_table("INVALID_PARAMETER")], "Table.Set on an object table requires Where={UID}.", "core/5.3.3.7.1", "core/5.3.3.7.1.1"),
        scen("core_fail_80_object_table_set_missing_where_success", "fail", sid_admin_session(sid) + [set_missing_where_on_object_table("SUCCESS")], "Object table Set without Where cannot succeed.", "core/5.3.3.7.1.1"),
        scen("core_pass_81_object_set_with_where_rejected", "pass", locking_admin_session(sid) + [set_where_on_object("INVALID_PARAMETER")], "Object.Set must omit Where.", "core/5.3.3.7.1", "core/5.3.3.7.1.1"),
        scen("core_fail_81_object_set_with_where_success", "fail", locking_admin_session(sid) + [set_where_on_object("SUCCESS")], "Object.Set with Where cannot succeed.", "core/5.3.3.7.1.1"),
        scen("core_pass_82_object_set_with_bytes_rejected", "pass", locking_admin_session(sid) + [set_object_with_bytes("FAIL")], "Object.Set Values must use RowValues, not Bytes.", "core/5.3.3.7.2", "core/5.3.3.7.2.2"),
        scen("core_fail_82_object_set_with_bytes_success", "fail", locking_admin_session(sid) + [set_object_with_bytes("SUCCESS")], "Object.Set with byte Values cannot succeed.", "core/5.3.3.7.2"),
        scen("core_pass_83_byte_table_set_rowvalues_rejected", "pass", locking_admin_session(sid) + [set_byte_table_with_rowvalues("FAIL")], "Byte-table Set Values must use Bytes, not RowValues.", "core/5.3.3.7.2", "core/5.3.3.7.2.1"),
        scen("core_fail_83_byte_table_set_rowvalues_success", "fail", locking_admin_session(sid) + [set_byte_table_with_rowvalues("SUCCESS")], "Byte-table Set with column values cannot succeed.", "core/5.3.3.7.2.1", "core/5.3.3.7.4"),
        scen("core_pass_84_byte_table_set_uid_where_rejected", "pass", locking_admin_session(sid) + [set_byte_table_with_uid_where("INVALID_PARAMETER")], "Byte-table Set may include Where only as Row, not UID.", "core/5.3.3.7.1", "core/5.3.3.7.1.2"),
        scen("core_fail_84_byte_table_set_uid_where_success", "fail", locking_admin_session(sid) + [set_byte_table_with_uid_where("SUCCESS")], "Byte-table Set with UID Where cannot succeed.", "core/5.3.3.7.1.2"),
        scen("core_pass_85_byte_table_set_bytes_success", "pass", locking_admin_session(sid) + [set_byte_table_bytes("SUCCESS")], "Byte-table Set accepts Bytes and may omit Where to start at the first row.", "core/5.3.3.7.1.2", "core/5.3.3.7.2.1"),
        scen("core_fail_85_byte_table_set_bytes_rejected", "fail", locking_admin_session(sid) + [set_byte_table_bytes("INVALID_PARAMETER")], "Well-formed byte-table Set should not be rejected for shape reasons.", "core/5.3.3.7.2.1"),
        scen("core_pass_86_set_without_values_noop_success", "pass", locking_admin_session(sid) + [set_without_values("SUCCESS")], "Set without Values succeeds and has no effect if the invocation is otherwise valid.", "core/5.3.3.7.2"),
        scen("core_fail_86_set_without_values_rejected", "fail", locking_admin_session(sid) + [set_without_values("INVALID_PARAMETER")], "A valid Set invocation is not malformed merely because Values is omitted.", "core/5.3.3.7.2"),
    ]

    out += [
        scen("core_pass_87_setclocklow_then_setlaglow", "pass", sid_admin_session(sid) + [clock_step("SetClockLow"), clock_step("SetLagLow", "SUCCESS")], "SetLagLow succeeds when it immediately follows SetClockLow.", "core/5.5.4.5", "core/5.5.4.6", "core/5.5.5.1.3"),
        scen("core_fail_87_setclocklow_then_setlaglow_rejected", "fail", sid_admin_session(sid) + [clock_step("SetClockLow"), clock_step("SetLagLow", "FAIL")], "The matching SetClockLow/SetLagLow pair should not be rejected.", "core/5.5.4.5", "core/5.5.4.6"),
        scen("core_pass_88_setlaglow_without_setclocklow_rejected", "pass", sid_admin_session(sid) + [clock_step("SetLagLow", "FAIL")], "SetLagLow must immediately follow SetClockLow.", "core/5.5.4.5.3", "core/5.5.5.1.3"),
        scen("core_fail_88_setlaglow_without_setclocklow_success", "fail", sid_admin_session(sid) + [clock_step("SetLagLow", "SUCCESS")], "SetLagLow without pending SetClockLow cannot succeed.", "core/5.5.4.5.3"),
        scen("core_pass_89_resetclock_readonly_rejected", "pass", sid_admin_session(sid, write=0) + [clock_step("ResetClock", "NOT_AUTHORIZED")], "ResetClock mutates ClockTime state and requires write authorization.", "core/5.5.4.2", "core/5.5.5.8"),
        scen("core_fail_89_resetclock_readonly_success", "fail", sid_admin_session(sid, write=0) + [clock_step("ResetClock", "SUCCESS")], "ResetClock cannot succeed in a read-only session.", "core/5.5.4.2"),
        scen("core_pass_90_resetclock_wrong_target_rejected", "pass", sid_admin_session(sid) + [make_step("ResetClock", ADMIN_SP, {}, {}, "INVALID_PARAMETER", invoking_name="SP")], "ResetClock is a ClockTime table method.", "core/5.5.4.2"),
        scen("core_fail_90_resetclock_wrong_target_success", "fail", sid_admin_session(sid) + [make_step("ResetClock", ADMIN_SP, {}, {}, "SUCCESS", invoking_name="SP")], "ResetClock cannot target a non-ClockTime object.", "core/5.5.4.2"),
    ]

    out += [
        scen("core_pass_91_encrypt_without_init_rejected", "pass", sid_admin_session(sid) + [crypto_step("Encrypt", "FAIL", target_uid=C_AES256_UID, target_name="C_AES_256")], "Encrypt requires a prior EncryptInit stream.", "core/5.6.4.7"),
        scen("core_fail_91_encrypt_without_init_success", "fail", sid_admin_session(sid) + [crypto_step("Encrypt", "SUCCESS", target_uid=C_AES256_UID, target_name="C_AES_256")], "Encrypt before EncryptInit cannot succeed.", "core/5.6.4.7"),
        scen("core_pass_92_encrypt_after_finalize_rejected", "pass", sid_admin_session(sid) + [crypto_step("EncryptInit", target_uid=C_AES256_UID, target_name="C_AES_256"), crypto_step("EncryptFinalize", target_uid=C_AES256_UID, target_name="C_AES_256"), crypto_step("Encrypt", "FAIL", target_uid=C_AES256_UID, target_name="C_AES_256")], "EncryptFinalize closes the encryption stream.", "core/5.6.4.8", "core/5.6.5.7"),
        scen("core_fail_92_encrypt_after_finalize_success", "fail", sid_admin_session(sid) + [crypto_step("EncryptInit", target_uid=C_AES256_UID, target_name="C_AES_256"), crypto_step("EncryptFinalize", target_uid=C_AES256_UID, target_name="C_AES_256"), crypto_step("Encrypt", "SUCCESS", target_uid=C_AES256_UID, target_name="C_AES_256")], "Encrypt after EncryptFinalize cannot succeed.", "core/5.6.4.8"),
        scen("core_pass_93_encrypt_after_init_success", "pass", sid_admin_session(sid) + [crypto_step("EncryptInit", target_uid=C_AES256_UID, target_name="C_AES_256"), crypto_step("Encrypt", "SUCCESS", target_uid=C_AES256_UID, target_name="C_AES_256")], "Encrypt succeeds when an encryption stream is open.", "core/5.6.4.6", "core/5.6.4.7"),
        scen("core_fail_93_encrypt_after_init_rejected", "fail", sid_admin_session(sid) + [crypto_step("EncryptInit", target_uid=C_AES256_UID, target_name="C_AES_256"), crypto_step("Encrypt", "FAIL", target_uid=C_AES256_UID, target_name="C_AES_256")], "Encrypt should not be rejected after successful EncryptInit.", "core/5.6.4.7"),
        scen("core_pass_94_verify_hash_success", "pass", sid_admin_session(sid) + [verify_step("SUCCESS")], "Verify may target a hash object and returns a boolean result.", "core/5.6.4.10", "core/5.6.5.6.2"),
        scen("core_fail_94_verify_hash_rejected", "fail", sid_admin_session(sid) + [verify_step("NOT_AUTHORIZED")], "Authorized Verify on a hash object should not be rejected.", "core/5.6.4.10"),
        scen("core_pass_95_verify_invalid_target_rejected", "pass", locking_admin_session(sid) + [verify_step("INVALID_PARAMETER", target_uid=RANGE1, target_name="Locking")], "Verify must target a public-key credential or hash object.", "core/5.6.4.10", "core/5.6.5.6"),
        scen("core_fail_95_verify_invalid_target_success", "fail", locking_admin_session(sid) + [verify_step("SUCCESS", target_uid=RANGE1, target_name="Locking")], "Verify on a Locking row cannot succeed.", "core/5.6.4.10"),
    ]

    out += [
        scen("core_pass_96_startsession_sync_ids_present", "pass", [start_session_raw({"HostSessionID": 1, "SPID": ADMIN_SP, "Write": 1}, status="SUCCESS")], "Successful StartSession returns SyncSession values with HostSessionID and SPSessionID.", "core/5.2.3.1", "core/5.2.3.2", "core/5.2.3.2.1", "core/5.2.3.2.2"),
        scen("core_fail_96_startsession_success_missing_sync_ids", "fail", [start_session_without_return_ids("SUCCESS")], "StartSession cannot report SUCCESS without SyncSession HostSessionID and SPSessionID return values.", "core/5.2.3.2", "core/5.2.3.2.1", "core/5.2.3.2.2"),
        scen("core_pass_97_getacl_missing_methodid_rejected", "pass", sid_admin_session(sid, write=0) + [get_acl("INVALID_PARAMETER", missing_method=True)], "GetACL requires both InvokingID and MethodID UID parameters.", "core/5.3.3.13", "core/5.3.3.13.1", "core/5.3.3.13.2"),
        scen("core_fail_97_getacl_missing_methodid_success", "fail", sid_admin_session(sid, write=0) + [get_acl("SUCCESS", missing_method=True)], "GetACL without MethodID cannot succeed.", "core/5.3.3.13.2"),
        scen("core_pass_98_next_bad_where_rejected", "pass", sid_admin_session(sid, write=0) + [next_step(TABLE_UID, "INVALID_PARAMETER", where={"bad": "not-a-uid"})], "Next Where must identify a row by UID.", "core/5.3.3.8", "core/5.3.3.8.1"),
        scen("core_fail_98_next_bad_where_success", "fail", sid_admin_session(sid, write=0) + [next_step(TABLE_UID, "SUCCESS", where={"bad": "not-a-uid"})], "Next with a malformed Where row reference cannot succeed.", "core/5.3.3.8.1"),
        scen("core_pass_99_create_table_missing_minsize_rejected", "pass", sid_admin_session(sid) + [create_table_missing_minsize("INVALID_PARAMETER")], "CreateTable requires MinSize along with the table definition parameters.", "core/5.3.3.2", "core/5.3.3.2.5"),
        scen("core_fail_99_create_table_missing_minsize_success", "fail", sid_admin_session(sid) + [create_table_missing_minsize("SUCCESS")], "CreateTable without MinSize cannot succeed.", "core/5.3.3.2.5"),
    ]
    return out


def write_dataset() -> list[Scenario]:
    TESTCASE_DIR.mkdir(parents=True, exist_ok=True)
    for old in TESTCASE_DIR.glob("*.json"):
        old.unlink()

    rows = []
    manifest = []
    all_scenarios = scenarios()
    for scenario in all_scenarios:
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
    print(f"v7 accuracy on core_gap_cases: {correct}/{total} ({correct / total * 100:.1f}%)")
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

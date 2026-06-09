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
    C_PIN_MSID,
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
MBRCONTROL_UID = "0000080300000001"
BAD_MBRCONTROL_UID = "0000080300000002"
LOCKING_TABLE_UID = "0000000100000802"
TPERINFO_UID = "0000020100030001"
TEMPLATE_TABLE_UID = "0000000100000204"
TEMPLATE_BASE_UID = "0000020400000001"
TEMPLATE_LOCKING_UID = "0000020400000006"
TEMPLATE_VENDOR_UID = "00000204000000FE"
ISSUED_SP1_UID = "0000020500000003"
ISSUED_SP2_UID = "0000020500000004"
LOG_LIST_UID = "0000000100000A02"
CLOCKTIME_TABLE_UID = "0000000100000401"
HASH_SHA256_UID = "0000060300000001"
C_AES256_UID = "0000000C00000001"
NEW_LOG_UID = "0000000100000A09"
ADMINS_UID = "0000000900000002"
ACE_ADMIN_UID = "0000000800000002"
USER_PIN = "USER1PIN"
DYN_OBJECT_TABLE_UID = "0102030405060708"
DYN_BYTE_TABLE_UID = "0102030405060709"
DYN_COLUMN1_UID = "010203040506070801"
DYN_COLUMN2_UID = "010203040506070802"
DYN_ROW1_UID = "1111222233334444"
DYN_ROW2_UID = "5555666677778888"
DYN_UNKNOWN_ROW_UID = "9999AAAABBBBCCCC"
DYN_COLUMN_LABEL_UID = "2222000000000002"


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


def with_unexpected_return(step: dict) -> dict:
    cloned = deepcopy(step)
    cloned["output"]["return_values"] = [[{"Result": "unexpected"}]]
    return cloned


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


def create_dynamic_object_table(status: str = "SUCCESS", getset_acl: list[str] | None = None) -> dict:
    if getset_acl is None:
        getset_acl = [ACE_ANYBODY_UID]
    return make_step(
        "CreateTable",
        ADMIN_SP,
        {
            "NewTableName": "DynCoreTable",
            "Kind": "Object",
            "GetSetACL": getset_acl,
            "Columns": [{"Name": "Value", "ColumnNumber": 1, "Type": "bytes", "IsUnique": True}],
            "MinSize": 2,
            "MaxSize": 3,
        },
        {},
        status,
        return_values={"NewTableUID": DYN_OBJECT_TABLE_UID},
        invoking_name="SP",
    )


def create_dynamic_byte_table(status: str = "SUCCESS") -> dict:
    return make_step(
        "CreateTable",
        ADMIN_SP,
        {
            "NewTableName": "DynCoreBytes",
            "Kind": "Byte",
            "GetSetACL": [ACE_ANYBODY_UID],
            "Columns": [],
            "MinSize": 1,
        },
        {},
        status,
        return_values={"NewTableUID": DYN_BYTE_TABLE_UID},
        invoking_name="SP",
    )


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


def create_dynamic_row(value: str, row_uid: str, status: str = "SUCCESS") -> dict:
    return create_dynamic_row_values({"Value": value}, row_uid, status)


def create_dynamic_row_values(values: dict, row_uid: str, status: str = "SUCCESS") -> dict:
    return make_step(
        "CreateRow",
        DYN_OBJECT_TABLE_UID,
        {"Row": values},
        {},
        status,
        return_values={"RowUID": row_uid} if status == "SUCCESS" else {},
        invoking_name="DynCoreTable",
    )


def create_dynamic_row_value_label(value: str, label: str, row_uid: str, status: str = "SUCCESS") -> dict:
    return create_dynamic_row_values({"Value": value, "Label": label}, row_uid, status)


def get_dynamic_column_metadata(
    column_uid: str = DYN_COLUMN_LABEL_UID,
    column_number: int = 2,
    *,
    name: str = "Label",
    common_name: str | None = None,
    is_unique: bool = False,
    unique: bool | None = None,
    column_type: str = "bytes",
    table_uid: str = DYN_OBJECT_TABLE_UID,
    status: str = "SUCCESS",
) -> dict:
    if unique is not None:
        is_unique = unique
    return make_step(
        "Get",
        column_uid,
        {},
        {},
        status,
        return_values={
            "TableUID": table_uid,
            "Name": name,
            "CommonName": common_name if common_name is not None else name,
            "Type": column_type,
            "IsUnique": is_unique,
            "ColumnNumber": column_number,
        } if status == "SUCCESS" else {},
        invoking_name="Column",
    )


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


def get_free_rows(invoking_uid: str, status: str = "SUCCESS", invoking_name: str = "Table", free_rows: int | None = None) -> dict:
    return_values = {"FreeRows": free_rows} if free_rows is not None else None
    return make_step("GetFreeRows", invoking_uid, {}, {}, status, return_values=return_values, invoking_name=invoking_name)


def get_dynamic_free_rows(rows: int, status: str = "SUCCESS") -> dict:
    return make_step(
        "GetFreeRows",
        DYN_OBJECT_TABLE_UID,
        {},
        {},
        status,
        return_values={"FreeRows": rows},
        invoking_name="DynCoreTable",
    )


def get_free_space(invoking_uid: str, status: str = "SUCCESS", invoking_name: str = "SP", free_space: int | None = None) -> dict:
    return_values = {"FreeSpace": free_space} if free_space is not None and status == "SUCCESS" else None
    return make_step("GetFreeSpace", invoking_uid, {}, {}, status, return_values=return_values, invoking_name=invoking_name)


def get_free_space_with_table_rows(rows: int, status: str = "SUCCESS") -> dict:
    return make_step(
        "GetFreeSpace",
        ADMIN_SP,
        {},
        {},
        status,
        return_values={"FreeSpace": 1024, "TableRows": [{"TableUID": DYN_OBJECT_TABLE_UID, "Rows": rows}]},
        invoking_name="SP",
    )


def get_free_space_with_rows_for_table(table_uid: str, rows: int, status: str = "SUCCESS") -> dict:
    return make_step(
        "GetFreeSpace",
        ADMIN_SP,
        {},
        {},
        status,
        return_values={"FreeSpace": 1024, "TableRows": [{"TableUID": table_uid, "Rows": rows}]},
        invoking_name="SP",
    )


def get_table_rows_free(table_uid: str = TABLE_UID, rows_free: int = 0, status: str = "SUCCESS") -> dict:
    return make_step(
        "Get",
        table_uid,
        {"Cellblock": [{"startColumn": 8}, {"endColumn": 8}]},
        {},
        status,
        return_values=[[{"8": rows_free}]],
        invoking_name="Table",
    )


def get_table_rows(table_uid: str, rows: int, status: str = "SUCCESS") -> dict:
    return make_step(
        "Get",
        table_uid,
        {"Cellblock": [{"startColumn": 7}, {"endColumn": 7}]},
        {},
        status,
        return_values=[[{"7": rows}]],
        invoking_name="Table",
    )


def get_table_capacity(table_uid: str = TABLE_UID, rows: int = 0, rows_free: int = 1, max_size: int = 1, status: str = "SUCCESS") -> dict:
    return make_step(
        "Get",
        table_uid,
        {"Cellblock": [{"startColumn": 7}, {"endColumn": 12}]},
        {},
        status,
        return_values=[[{"7": rows}, {"8": rows_free}, {"12": max_size}]],
        invoking_name="Table",
    )


def get_template_instances(template_uid: str = TEMPLATE_BASE_UID, instances: int = 0, max_instances: int = 1, status: str = "SUCCESS") -> dict:
    return make_step(
        "Get",
        template_uid,
        {"Cellblock": [{"startColumn": 3}, {"endColumn": 4}]},
        {},
        status,
        return_values=[[{"3": instances}, {"4": max_instances}]],
        invoking_name="Template",
    )


def next_template_inventory(template_uids: list[str], count: int | None = None, status: str = "SUCCESS") -> dict:
    if count is None:
        count = len(template_uids)
    return make_step(
        "Next",
        TEMPLATE_TABLE_UID,
        {},
        {"Count": count},
        status,
        return_values={"Rows": [{"uid": uid} for uid in template_uids]} if status == "SUCCESS" else {},
        invoking_name="Template",
    )


def get_tperinfo_space_for_issuance(space: int, status: str = "SUCCESS") -> dict:
    return make_step(
        "Get",
        TPERINFO_UID,
        {"Cellblock": [{"startColumn": 7}, {"endColumn": 7}]},
        {},
        status,
        return_values=[[{"7": space}]],
        invoking_name="TPerInfo",
    )


def package_step(method: str, invoking_uid: str, status: str, invoking_name: str = "C_PIN") -> dict:
    args = {"Purpose": "Backup"} if method == "GetPackage" else {"Value": "PACKAGE_BYTES"}
    return make_step(method, invoking_uid, args, {}, status, invoking_name=invoking_name)


def crypto_step(
    method: str,
    status: str = "SUCCESS",
    *,
    target_uid=HASH_SHA256_UID,
    target_name="H_SHA_256",
    buffer_out: int | None = None,
    output_bytes: str | None = None,
) -> dict:
    required = {}
    if method in {"Hash", "HMAC", "Encrypt", "Decrypt"}:
        required["Input"] = {"Data": "AABBCCDD"}
    if buffer_out is not None:
        required["BufferOut"] = buffer_out
    return_values = {"Bytes": output_bytes} if output_bytes is not None and status == "SUCCESS" else None
    return make_step(method, target_uid, required, {}, status, return_values=return_values, invoking_name=target_name)


def xor_step(
    status: str = "SUCCESS",
    pattern="not-a-uid",
    *,
    buffer_out: int | None = None,
    output_bytes: str | None = None,
) -> dict:
    required = {"PatternInput": pattern, "DeletePattern": False, "Input": {"Data": "AA"}}
    if buffer_out is not None:
        required["BufferOut"] = buffer_out
    return make_step(
        "XOR",
        ADMIN_SP,
        required,
        {},
        status,
        return_values={"Bytes": output_bytes} if output_bytes is not None and status == "SUCCESS" else None,
        invoking_name="SP",
    )


def random_step(status: str = "SUCCESS", count=-1, output_bytes: str | None = None) -> dict:
    return_values = {"Random": output_bytes} if output_bytes is not None and status == "SUCCESS" else None
    return make_step("Random", ADMIN_SP, {"Count": count}, {}, status, return_values=return_values, invoking_name="SP")


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


def meta_acl_dynamic(method: str, target_method_uid: str = METHODID_GET_UID, status: str = "SUCCESS") -> dict:
    optional = {"InvokingID": DYN_OBJECT_TABLE_UID, "MethodID": target_method_uid}
    if method in {"AddACE", "RemoveACE"}:
        optional["ACE"] = ACE_ANYBODY_UID
    return make_step(method, ACCESS_CONTROL_TABLE_UID, {}, optional, status, invoking_name="AccessControl")


def get_acl_dynamic(refs: list[str], target_method_uid: str = METHODID_GET_UID, status: str = "SUCCESS") -> dict:
    return make_step(
        "GetACL",
        ACCESS_CONTROL_TABLE_UID,
        {},
        {"InvokingID": DYN_OBJECT_TABLE_UID, "MethodID": target_method_uid},
        status,
        return_values={"ACL": refs} if status == "SUCCESS" else {},
        invoking_name="AccessControl",
    )


def issue_sp(
    status: str = "SUCCESS",
    *,
    missing_templates: bool = False,
    sp_name: str = "IssuedCoreSP",
    size: int = 4096,
    return_size: int | None = None,
    return_uid: str | None = None,
    enabled: bool = True,
    templates: list[str] | None = None,
) -> dict:
    required = {
        "SPName": sp_name,
        "Size": size,
        "Templates": templates if templates is not None else ["0000000400000001"],
        "AdminExch": 0,
        "Enabled": enabled,
    }
    if missing_templates:
        required.pop("Templates")
    return_values = {}
    if return_size is not None:
        return_values["Size"] = return_size
    if return_uid is not None:
        return_values["SPID"] = return_uid
    if not return_values:
        return_values = None
    return make_step("IssueSP", ADMIN_SP, required, {}, status, return_values=return_values, invoking_name="SP")


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


def properties_tper(max_authentications: int = 2, status: str = "SUCCESS") -> dict:
    return make_step(
        "Properties",
        "0000000000000001",
        {},
        {},
        status,
        return_values=[
            {
                "Properties": {
                    "MaxComPacketSize": 2048,
                    "MaxResponseComPacketSize": 2048,
                    "MaxPacketSize": 2028,
                    "MaxIndTokenSize": 1992,
                    "MaxPackets": 1,
                    "MaxSubpackets": 1,
                    "MaxMethods": 1,
                    "MaxSessions": 1,
                    "MaxAuthentications": max_authentications,
                    "MaxTransactionLimit": 1,
                    "DefSessionTimeout": 0,
                }
            }
        ],
        invoking_name="Session Manager UID",
    )


def properties_tper_low_max_packet(status: str = "SUCCESS") -> dict:
    step = properties_tper(status=status)
    step["output"]["return_values"][0]["Properties"]["MaxPacketSize"] = 2027
    return step


def discovery_features(
    *,
    duplicate_locking: bool = False,
    out_of_order: bool = False,
    geometry_length: int = 0x1C,
    data_removal_length: int = 0x20,
    initial_sid_indicator: int | None = None,
    revert_sid_indicator: int | None = None,
    tper_reserved: int | None = None,
    locking_reserved: int | None = None,
    opal_reserved: int | None = None,
) -> list[dict]:
    opal_v2 = {"feature_code": 0x0203, "length": 0x10, "num_comids": 1, "num_admins": 4, "num_users": 8}
    if initial_sid_indicator is not None:
        opal_v2["initial_sid_indicator"] = initial_sid_indicator
    if revert_sid_indicator is not None:
        opal_v2["revert_sid_indicator"] = revert_sid_indicator
    if opal_reserved is not None:
        opal_v2["reserved_future_common"] = opal_reserved
    tper = {"feature_code": 0x0001, "length": 0x0C, "sync_supported": 1, "streaming_supported": 1}
    if tper_reserved is not None:
        tper["reserved"] = tper_reserved
    locking = {"feature_code": 0x0002, "length": 0x0C, "locking_supported": 1, "locking_enabled": 0, "media_encryption": 1, "mbr_shadowing_not_supported": 0}
    if locking_reserved is not None:
        locking["reserved"] = locking_reserved
    features = [
        tper,
        locking,
        {"feature_code": 0x0003, "length": geometry_length},
        opal_v2,
        {"feature_code": 0x0404, "length": data_removal_length},
    ]
    if duplicate_locking:
        features.insert(2, {"feature_code": 0x0002, "length": 0x0C, "locking_supported": 1, "locking_enabled": 0, "media_encryption": 1, "mbr_shadowing_not_supported": 0})
    if out_of_order:
        features[2], features[3] = features[3], features[2]
    return features


def discovery_step(features: list[dict], result: str = "pass", header: dict | None = None) -> dict:
    discovery = {"features": features}
    if header:
        discovery.update(header)
    return {
        "index": 1,
        "input": {
            "command": "IF_RECV",
            "args": {"SecurityProtocol": "01", "SecurityProtocolSpecific": "0001"},
        },
        "output": {
            "command": "IF_RECV",
            "result": result,
            "discovery": discovery,
        },
    }


def discovery_parameter_length(features: list[dict]) -> int:
    return 44 + sum(4 + int(feature["length"]) for feature in features if "length" in feature)


def get_invalid_cellblock(status: str = "SUCCESS") -> dict:
    return make_step(
        "Get",
        TABLE_UID,
        {"Cellblock": [{"startColumn": 8}, {"endColumn": 3}]},
        {},
        status,
        invoking_name="Table",
    )


def get_cpin_msid_column(value: str | None, *, status: str = "SUCCESS") -> dict:
    return_values = [[{"3": value}]] if value is not None else [[{"2": "CommonName"}]]
    return make_step(
        "Get",
        C_PIN_MSID,
        {"Cellblock": [{"startColumn": 3}, {"endColumn": 3}]},
        {},
        status,
        return_values=return_values,
        invoking_name="C_PIN",
    )


def get_cpin_trylimit(value: int | None, *, status: str = "SUCCESS") -> dict:
    return_values = [[{"5": value}]] if value is not None else [[{"2": "CommonName"}]]
    return make_step(
        "Get",
        C_PIN_SID,
        {"Cellblock": [{"startColumn": 5}, {"endColumn": 5}]},
        {},
        status,
        return_values=return_values,
        invoking_name="C_PIN",
    )


def get_locking_global_columns(range_length, *, status: str = "SUCCESS") -> dict:
    return make_step(
        "Get",
        GLOBAL_RANGE,
        {"Cellblock": [{"startColumn": 3}, {"endColumn": 8}]},
        {},
        status,
        return_values=[[{"3": 0}, {"4": range_length}, {"5": 0}, {"6": 0}, {"7": 0}, {"8": 0}]],
        invoking_name="Locking",
    )


def get_mbrcontrol_columns(enable: int, done: int, *, status: str = "SUCCESS") -> dict:
    return make_step(
        "Get",
        MBRCONTROL_UID,
        {"Cellblock": [{"startColumn": 1}, {"endColumn": 2}]},
        {},
        status,
        return_values=[[{"1": enable}, {"2": done}]],
        invoking_name="MBRControl",
    )


def get_bad_mbrcontrol_singleton(enable: int, done: int, *, status: str = "SUCCESS") -> dict:
    return make_step(
        "Get",
        BAD_MBRCONTROL_UID,
        {"Cellblock": [{"startColumn": 1}, {"endColumn": 2}]},
        {},
        status,
        return_values=[[{"1": enable}, {"2": done}]],
        invoking_name="MBRControl",
    )


def get_mbrcontrol_name_locking_uid(enable: int, done: int, *, status: str = "SUCCESS") -> dict:
    return make_step(
        "Get",
        GLOBAL_RANGE,
        {"Cellblock": [{"startColumn": 1}, {"endColumn": 2}]},
        {},
        status,
        return_values=[[{"1": enable}, {"2": done}]],
        invoking_name="MBRControl",
    )


def get_authority_enabled(authority_uid: str, enabled: int, *, status: str = "SUCCESS") -> dict:
    return make_step(
        "Get",
        authority_uid,
        {"Cellblock": [{"startColumn": 5}, {"endColumn": 5}]},
        {},
        status,
        return_values=[[{"5": enabled}]],
        invoking_name="Authority",
    )


def get_sp_lifecycle(value: int | None, *, status: str = "SUCCESS") -> dict:
    return_values = [[{"6": value}]] if value is not None else [[{"5": 0}]]
    return make_step(
        "Get",
        ADMIN_SP,
        {"Cellblock": [{"startColumn": 6}, {"endColumn": 6}]},
        {},
        status,
        return_values=return_values,
        invoking_name="SP",
    )


def get_lockinginfo_maxranges(value: int | None, *, status: str = "SUCCESS") -> dict:
    return_values = [[{"4": value}]] if value is not None else [[{"3": 1}]]
    return make_step(
        "Get",
        "0000080100000001",
        {"Cellblock": [{"startColumn": 4}, {"endColumn": 4}]},
        {},
        status,
        return_values=return_values,
        invoking_name="LockingInfo",
    )


def get_accesscontrol_common_name(value: str | None, *, status: str = "SUCCESS") -> dict:
    return_values = [[{"3": value}]] if value is not None else [[{"5": 0}]]
    return make_step(
        "Get",
        ACCESS_CONTROL_TABLE_UID,
        {"Cellblock": [{"startColumn": 3}, {"endColumn": 3}]},
        {},
        status,
        return_values=return_values,
        invoking_name="AccessControl",
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


def set_dynamic_byte_rowvalues(status: str = "SUCCESS") -> dict:
    return make_step("Set", DYN_BYTE_TABLE_UID, {}, {"Values": {"RowValues": {"Value": "AA"}}}, status, invoking_name="DynCoreBytes")


def set_dynamic_table_row(value: str, status: str = "SUCCESS", row_uid: str = DYN_ROW1_UID) -> dict:
    return make_step(
        "Set",
        DYN_OBJECT_TABLE_UID,
        {},
        {"Where": {"uid": row_uid}, "Values": {"RowValues": {"Value": value}}},
        status,
        invoking_name="DynCoreTable",
    )


def get_dynamic_table(rows: int, rows_free: int, status: str = "SUCCESS") -> dict:
    return make_step(
        "Get",
        DYN_OBJECT_TABLE_UID,
        {},
        {},
        status,
        return_values={"Rows": rows, "RowsFree": rows_free, "MinSize": 2, "MaxSize": 3},
        invoking_name="DynCoreTable",
    )


def get_dynamic_row(value: str, status: str = "SUCCESS", row_uid: str = DYN_ROW1_UID) -> dict:
    return make_step(
        "Get",
        row_uid,
        {},
        {},
        status,
        return_values={"Value": value},
        invoking_name="DynCoreRow",
    )


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
        scen("core_pass_02b_sync_sp_id_mismatch_rejected", "pass", sid_admin_session(sid) + [sync_session("INVALID_PARAMETER", sp=0x9999)], "SyncSession SPSessionID must match the established TPer session number.", "core/5.2.3.2.2"),
        scen("core_fail_02b_sync_sp_id_mismatch_success", "fail", sid_admin_session(sid) + [sync_session("SUCCESS", sp=0x9999)], "SyncSession with the wrong SPSessionID cannot succeed.", "core/5.2.3.2.2"),
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
        scen("core_pass_24b_xor_bufferout_bound", "pass",
             sid_admin_session(sid) + [xor_step("SUCCESS", pattern=DYN_BYTE_TABLE_UID, buffer_out=2, output_bytes="AABB")],
             "XOR output bytes may be equal to the explicit BufferOut limit.",
             "core/5.6.4.17.1"),
        scen("core_fail_24b_xor_bufferout_overflow", "fail",
             sid_admin_session(sid) + [xor_step("SUCCESS", pattern=DYN_BYTE_TABLE_UID, buffer_out=1, output_bytes="AABB")],
             "XOR output bytes cannot exceed explicit BufferOut.",
             "core/5.6.4.17.1"),
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
        scen("core_fail_57b_genkey_success_unexpected_return", "fail", locking_admin_session(sid) + [with_unexpected_return(gen_key_with_params(K_AES_RANGE1, {}, "SUCCESS"))], "GenKey returns an empty result list on success; non-empty return values are not compliant.", "core/5.3.3.16.3.1"),
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
        scen("core_pass_67b_properties_opal_tper_minima", "pass", [properties_tper(2)], "Explicit Opal TPerProperties include mandatory fields at or above Table 17 minima.", "opal/4.1.1.1"),
        scen("core_fail_67b_properties_low_max_packet", "fail", [properties_tper_low_max_packet()], "Explicit Opal TPerProperties cannot report MaxPacketSize below the Table 17 minimum.", "opal/4.1.1.1"),
    ]

    out += [
        scen("core_pass_68_deletesp_authorized", "pass", setup_tper("MSIDVAL", sid) + activate_locking_sp(sid) + [start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid), delete_sp("SUCCESS")], "DeleteSP is valid in an authorized read-write session to the SP being deleted.", "core/5.3.3.1", "core/5.3.4.4"),
        scen("core_fail_68b_activate_success_unexpected_return", "fail", setup_tper("MSIDVAL", sid) + [start_session(ADMIN_SP, authority=SID_UID, challenge=sid), with_unexpected_return(make_step("Activate", LOCKING_SP, {}, {}, "SUCCESS", invoking_name="SP"))], "Activate returns an empty result list on success; non-empty return values are not compliant.", "opal/5.1.1.1"),
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
        scen("core_fail_76b_end_session_success_unexpected_return", "fail", sid_admin_session(sid) + [with_unexpected_return(end_session("SUCCESS"))], "EndSession returns an empty result list on success; non-empty return values are not compliant.", "core/3.3.7.1.5"),
        scen("core_pass_77_end_session_without_session_rejected", "pass", [end_session("FAIL")], "EndSession without an open session must fail.", "core/3.3.7.1.5"),
        scen("core_fail_77_end_session_without_session_success", "fail", [end_session("SUCCESS")], "EndSession cannot close a session that does not exist.", "core/3.3.7.1.5"),
        scen("core_pass_78_authenticate_missing_authority_rejected", "pass", sid_admin_session(sid) + [make_step("Authenticate", "0000000000000001", {}, {}, "INVALID_PARAMETER", invoking_name="Session Manager UID")], "Authenticate requires an Authority parameter.", "core/5.3.4.1.14", "core/5.3.4.1.14.1"),
        scen("core_fail_78_authenticate_missing_authority_success", "fail", sid_admin_session(sid) + [make_step("Authenticate", "0000000000000001", {}, {}, "SUCCESS", invoking_name="Session Manager UID")], "Authenticate without Authority cannot succeed.", "core/5.3.4.1.14"),
        scen("core_pass_79_authenticate_class_authority_rejected", "pass", sid_admin_session(sid) + [authenticate_step(ADMINS_UID, auth_result=None, status="INVALID_PARAMETER")], "Authenticate targets Authority objects, not authority class rows such as Admins.", "core/5.3.4.1.2", "core/5.3.4.1.14"),
        scen("core_fail_79_authenticate_class_authority_success", "fail", sid_admin_session(sid) + [authenticate_step(ADMINS_UID, auth_result=None, status="SUCCESS")], "Class authority Authenticate cannot succeed.", "core/5.3.4.1.2"),
        scen("core_pass_79b_max_authentications_cap_false", "pass", [properties_tper(2)] + setup_tper("MSIDVAL", sid) + activate_locking_sp(sid) + setup_user(sid, USER_PIN) + [start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid), authenticate_step(USER1_UID, proof=USER_PIN, auth_result=False)], "MaxAuthentications counts Anybody and the startup authority, so another distinct Authenticate must return result False when the learned cap is already reached.", "core/5.3.4.1.2.1", "core/5.3.4.1.14"),
        scen("core_fail_79b_max_authentications_cap_true", "fail", [properties_tper(2)] + setup_tper("MSIDVAL", sid) + activate_locking_sp(sid) + setup_user(sid, USER_PIN) + [start_session(LOCKING_SP, authority=ADMIN1_UID, challenge=sid), authenticate_step(USER1_UID, proof=USER_PIN, auth_result=True)], "Authenticate cannot add another distinct authority beyond learned MaxAuthentications.", "core/5.3.4.1.2.1", "core/5.3.4.1.14"),
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

    out += [
        scen("core_pass_100_getclock_readonly", "pass",
             sid_admin_session(sid, write=0) + [clock_step("GetClock", "SUCCESS")],
             "GetClock is a read-only ClockTime method valid in a read-only session.",
             "core/5.5.4.1"),
        scen("core_fail_100_getclock_readonly_rejected", "fail",
             sid_admin_session(sid, write=0) + [clock_step("GetClock", "NOT_AUTHORIZED")],
             "GetClock should not require write authorization.",
             "core/5.5.4.1"),
        scen("core_pass_101_incrementcounter_wrong_target_rejected", "pass",
             sid_admin_session(sid) + [make_step("IncrementCounter", ADMIN_SP, {}, {}, "INVALID_PARAMETER", invoking_name="SP")],
             "IncrementCounter is a ClockTime method; invoking it on a non-ClockTime object is rejected.",
             "core/5.5.4.7", "core/5.5.5.2"),
        scen("core_fail_101_incrementcounter_wrong_target_success", "fail",
             sid_admin_session(sid) + [make_step("IncrementCounter", ADMIN_SP, {}, {}, "SUCCESS", invoking_name="SP")],
             "IncrementCounter on a non-ClockTime object cannot succeed.",
             "core/5.5.4.7"),
        scen("core_pass_102_addlog_to_new_log", "pass",
             sid_admin_session(sid) + [create_log("SUCCESS"), log_step("AddLog", NEW_LOG_UID, "SUCCESS")],
             "AddLog succeeds on a log table created successfully earlier in the same session.",
             "core/5.8.3.1", "core/5.8.3.2"),
        scen("core_fail_102_addlog_to_new_log_rejected", "fail",
             sid_admin_session(sid) + [create_log("SUCCESS"), log_step("AddLog", NEW_LOG_UID, "FAIL")],
             "AddLog to a valid newly created log table should not be rejected.",
             "core/5.8.3.1"),
        scen("core_pass_103_addlog_nonlog_target_rejected", "pass",
             locking_admin_session(sid) + [make_step("AddLog", LOCKING_TABLE_UID, {"LogEntryName": "entry", "Data": "payload"}, {}, "INVALID_PARAMETER", invoking_name="Locking")],
             "AddLog must target a Log table; invoking on a non-Log table returns INVALID_PARAMETER.",
             "core/5.8.3.1"),
        scen("core_fail_103_addlog_nonlog_target_success", "fail",
             locking_admin_session(sid) + [make_step("AddLog", LOCKING_TABLE_UID, {"LogEntryName": "entry", "Data": "payload"}, {}, "SUCCESS", invoking_name="Locking")],
             "AddLog cannot succeed when targeting a non-Log table.",
             "core/5.8.3.1"),
        scen("core_pass_104_getacl_bad_invoking_rejected", "pass",
             sid_admin_session(sid, write=0) + [get_acl("INVALID_PARAMETER", bad_invoking=True)],
             "GetACL InvokingID must reference a valid existing object; an empty UID is rejected.",
             "core/5.3.3.13", "core/5.3.3.13.1"),
        scen("core_fail_104_getacl_bad_invoking_success", "fail",
             sid_admin_session(sid, write=0) + [get_acl("SUCCESS", bad_invoking=True)],
             "GetACL with an invalid InvokingID cannot succeed.",
             "core/5.3.3.13.1"),
        scen("core_pass_105_hmac_after_init_succeeds", "pass",
             sid_admin_session(sid) + [crypto_step("HMACInit"), crypto_step("HMAC", "SUCCESS")],
             "HMAC with data succeeds when an HMAC stream is open via prior HMACInit.",
             "core/5.6.4.14", "core/5.6.4.15"),
        scen("core_fail_105_hmac_after_init_rejected", "fail",
             sid_admin_session(sid) + [crypto_step("HMACInit"), crypto_step("HMAC", "FAIL")],
             "HMAC should not be rejected when an HMAC stream is open.",
             "core/5.6.4.15"),
        scen("core_pass_106_next_count_zero_valid", "pass",
             sid_admin_session(sid) + [next_step(TABLE_UID, "SUCCESS", count=0)],
             "Next with Count=0 is a valid unsigned-integer request returning an empty result set.",
             "core/5.3.3.8", "core/5.3.3.8.2"),
        scen("core_fail_106_next_count_zero_rejected", "fail",
             sid_admin_session(sid) + [next_step(TABLE_UID, "INVALID_PARAMETER", count=0)],
             "Next with Count=0 must not be treated as an invalid parameter.",
             "core/5.3.3.8.2"),
        scen("core_pass_107_setpackage_authorized_succeeds", "pass",
             sid_admin_session(sid) + [package_step("SetPackage", C_PIN_SID, "SUCCESS")],
             "SetPackage succeeds on a credential object in an authorized write session.",
             "core/5.3.3.18"),
        scen("core_fail_107_setpackage_authorized_rejected", "fail",
             sid_admin_session(sid) + [package_step("SetPackage", C_PIN_SID, "NOT_AUTHORIZED")],
             "SetPackage in an authorized write session targeting a credential should not be rejected.",
             "core/5.3.3.18"),
    ]

    out += [
        scen("core_pass_108_issuesp_missing_size_rejected", "pass",
             sid_admin_session(sid) + [make_step("IssueSP", ADMIN_SP, {"SPName": "IssuedCoreSP", "Templates": ["0000000400000001"], "AdminExch": 0, "Enabled": True}, {}, "INVALID_PARAMETER", invoking_name="SP")],
             "IssueSP requires Size; omitting it is rejected with INVALID_PARAMETER.",
             "core/5.4.3.1"),
        scen("core_fail_108_issuesp_missing_size_success", "fail",
             sid_admin_session(sid) + [make_step("IssueSP", ADMIN_SP, {"SPName": "IssuedCoreSP", "Templates": ["0000000400000001"], "AdminExch": 0, "Enabled": True}, {}, "SUCCESS", invoking_name="SP")],
             "IssueSP missing required Size cannot succeed.",
             "core/5.4.3.1"),
        scen("core_pass_109_genkey_cpin_not_authorized", "pass",
             sid_admin_session(sid) + [gen_key_with_params(C_PIN_SID, {}, "NOT_AUTHORIZED", invoking_name="C_PIN")],
             "GenKey on a C_PIN credential in Opal SSC has no AccessControl ACE and returns NOT_AUTHORIZED.",
             "core/5.3.3.16", "core/5.3.3.16.4"),
        scen("core_fail_109_genkey_cpin_success", "fail",
             sid_admin_session(sid) + [gen_key_with_params(C_PIN_SID, {}, "SUCCESS", invoking_name="C_PIN")],
             "GenKey on a C_PIN credential cannot succeed without an authorized ACE in Opal SSC.",
             "core/5.3.3.16"),
        scen("core_pass_110_addlog_missing_logentryname_rejected", "pass",
             sid_admin_session(sid) + [make_step("AddLog", LOG_TABLE_UID, {"Data": "payload"}, {}, "INVALID_PARAMETER", invoking_name="Log")],
             "AddLog requires LogEntryName; omitting it returns INVALID_PARAMETER.",
             "core/5.8.3.1", "core/5.8.3.1.1"),
        scen("core_fail_110_addlog_missing_logentryname_success", "fail",
             sid_admin_session(sid) + [make_step("AddLog", LOG_TABLE_UID, {"Data": "payload"}, {}, "SUCCESS", invoking_name="Log")],
             "AddLog without required LogEntryName cannot succeed.",
             "core/5.8.3.1.1"),
        scen("core_pass_111_hash_after_init_succeeds", "pass",
             sid_admin_session(sid) + [crypto_step("HashInit"), crypto_step("Hash", "SUCCESS")],
             "Hash with data succeeds when a hash stream is open via prior HashInit.",
             "core/5.6.4.11", "core/5.6.4.12"),
        scen("core_fail_111_hash_after_init_rejected", "fail",
             sid_admin_session(sid) + [crypto_step("HashInit"), crypto_step("Hash", "FAIL")],
             "Hash should not be rejected when a hash stream is open.",
             "core/5.6.4.12"),
        scen("core_pass_112_clearlog_new_log_succeeds", "pass",
             sid_admin_session(sid) + [create_log("SUCCESS"), log_step("ClearLog", NEW_LOG_UID, "SUCCESS")],
             "ClearLog succeeds on a log table created within the current write session.",
             "core/5.8.3.2", "core/5.8.3.3"),
        scen("core_fail_112_clearlog_new_log_rejected", "fail",
             sid_admin_session(sid) + [create_log("SUCCESS"), log_step("ClearLog", NEW_LOG_UID, "FAIL")],
             "ClearLog on a valid newly created log table should not fail.",
             "core/5.8.3.3"),
        scen("core_pass_113_decrypt_after_init_succeeds", "pass",
             sid_admin_session(sid) + [crypto_step("DecryptInit", target_uid=C_AES256_UID, target_name="C_AES_256"), crypto_step("Decrypt", "SUCCESS", target_uid=C_AES256_UID, target_name="C_AES_256")],
             "Decrypt succeeds when a decrypt stream is open via prior DecryptInit.",
             "core/5.6.4.3", "core/5.6.4.4"),
        scen("core_fail_113_decrypt_after_init_rejected", "fail",
             sid_admin_session(sid) + [crypto_step("DecryptInit", target_uid=C_AES256_UID, target_name="C_AES_256"), crypto_step("Decrypt", "FAIL", target_uid=C_AES256_UID, target_name="C_AES_256")],
             "Decrypt should not be rejected when a decrypt stream is open.",
             "core/5.6.4.4"),
        scen("core_pass_114_verify_wrong_proof_success_false", "pass",
             sid_admin_session(sid) + [make_step("Verify", HASH_SHA256_UID, {"Input": {"Data": "AABBCCDD"}, "Proof": "BADPROOF"}, {}, "SUCCESS", return_values={"Result": False}, invoking_name="H_SHA_256")],
             "Verify with a non-matching proof returns SUCCESS with Result=False rather than a failure method status.",
             "core/5.6.4.10", "core/5.6.5.6.2"),
        scen("core_fail_114_verify_wrong_proof_as_fail", "fail",
             sid_admin_session(sid) + [make_step("Verify", HASH_SHA256_UID, {"Input": {"Data": "AABBCCDD"}, "Proof": "BADPROOF"}, {}, "FAIL", invoking_name="H_SHA_256")],
             "Verify with a non-matching proof must not return a FAIL method status.",
             "core/5.6.4.10"),
    ]

    out += [
        scen("core_pass_115_dynamic_unique_conflict_rejected", "pass",
             sid_admin_session(sid) + [create_dynamic_object_table(), create_dynamic_row("A", DYN_ROW1_UID), create_dynamic_row("A", DYN_ROW2_UID, "UNIQUENESS_CONFLICT")],
             "CreateRow on a learned dynamic table rejects duplicate values in columns marked IsUnique.",
             "core/3.2.5.4", "core/5.3.3.4", "core/5.1.5.8"),
        scen("core_fail_115_dynamic_unique_conflict_success", "fail",
             sid_admin_session(sid) + [create_dynamic_object_table(), create_dynamic_row("A", DYN_ROW1_UID), create_dynamic_row("A", DYN_ROW2_UID, "SUCCESS")],
             "CreateRow cannot succeed when a learned unique-column value duplicates an existing dynamic row.",
             "core/3.2.5.4", "core/5.3.3.4"),
        scen("core_pass_116_dynamic_byte_next_rejected", "pass",
             sid_admin_session(sid) + [create_dynamic_byte_table(), next_step(DYN_BYTE_TABLE_UID, "INVALID_PARAMETER", invoking_name="DynCoreBytes")],
             "Next is not valid on learned dynamic byte tables.",
             "core/5.3.3.8"),
        scen("core_fail_116_dynamic_byte_next_success", "fail",
             sid_admin_session(sid) + [create_dynamic_byte_table(), next_step(DYN_BYTE_TABLE_UID, "SUCCESS", invoking_name="DynCoreBytes")],
             "Next cannot succeed on a learned dynamic byte table.",
             "core/5.3.3.8"),
        scen("core_pass_117_dynamic_byte_set_rowvalues_rejected", "pass",
             sid_admin_session(sid) + [create_dynamic_byte_table(), set_dynamic_byte_rowvalues("INVALID_PARAMETER")],
             "Set on a learned dynamic byte table must use Bytes, not RowValues.",
             "core/5.3.3.7.2", "core/5.3.3.7.2.1"),
        scen("core_fail_117_dynamic_byte_set_rowvalues_success", "fail",
             sid_admin_session(sid) + [create_dynamic_byte_table(), set_dynamic_byte_rowvalues("SUCCESS")],
             "Set with RowValues cannot succeed on a learned dynamic byte table.",
             "core/5.3.3.7.2.1"),
        scen("core_pass_118_dynamic_getfreespace_tablerows", "pass",
             sid_admin_session(sid) + [create_dynamic_object_table(), create_dynamic_row("A", DYN_ROW1_UID), get_free_space_with_table_rows(1)],
             "GetFreeSpace TableRows for a learned dynamic table reflects tracked rows remaining.",
             "core/5.3.3.9", "core/5.3.3.9.1.2"),
        scen("core_fail_118_dynamic_getfreespace_tablerows_wrong", "fail",
             sid_admin_session(sid) + [create_dynamic_object_table(), create_dynamic_row("A", DYN_ROW1_UID), get_free_space_with_table_rows(0)],
             "GetFreeSpace cannot report a wrong TableRows value for a learned dynamic table with complete inventory.",
             "core/5.3.3.9.1.2"),
        scen("core_pass_119_dynamic_delete_row_mixed_unknown_rejected", "pass",
             sid_admin_session(sid) + [create_dynamic_object_table(), create_dynamic_row("A", DYN_ROW1_UID), delete_row(DYN_OBJECT_TABLE_UID, [{"uid": DYN_ROW1_UID}, {"uid": DYN_UNKNOWN_ROW_UID}], "FAIL", "DynCoreTable"), get_dynamic_free_rows(1)],
             "DeleteRow is all-or-fail when any requested dynamic row is unknown.",
             "core/5.3.3.5", "core/5.3.3.5.2.1"),
        scen("core_fail_119_dynamic_delete_row_mixed_unknown_success", "fail",
             sid_admin_session(sid) + [create_dynamic_object_table(), create_dynamic_row("A", DYN_ROW1_UID), delete_row(DYN_OBJECT_TABLE_UID, [{"uid": DYN_ROW1_UID}, {"uid": DYN_UNKNOWN_ROW_UID}], "SUCCESS", "DynCoreTable")],
             "DeleteRow cannot succeed when a request mixes known and unknown dynamic rows.",
             "core/5.3.3.5.2.1"),
        scen("core_pass_120_dynamic_table_get_metadata", "pass",
             sid_admin_session(sid) + [create_dynamic_object_table(), create_dynamic_row("A", DYN_ROW1_UID), get_dynamic_table(rows=1, rows_free=1)],
             "Get on a learned dynamic table reports tracked Rows and RowsFree metadata.",
             "core/5.3.3.6", "core/5.3.2.3.8", "core/5.3.2.3.9"),
        scen("core_fail_120_dynamic_table_get_metadata_wrong", "fail",
             sid_admin_session(sid) + [create_dynamic_object_table(), create_dynamic_row("A", DYN_ROW1_UID), get_dynamic_table(rows=1, rows_free=2)],
             "Get on a learned dynamic table cannot report stale RowsFree metadata.",
             "core/5.3.2.3.9"),
        scen("core_pass_121_dynamic_row_set_then_get", "pass",
             sid_admin_session(sid) + [create_dynamic_object_table(), create_dynamic_row("A", DYN_ROW1_UID), set_dynamic_table_row("B"), get_dynamic_row("B")],
             "Set on a learned dynamic object table updates the tracked dynamic row value used by later Get.",
             "core/5.3.3.7", "core/5.3.3.6"),
        scen("core_fail_121_dynamic_row_set_then_get_stale", "fail",
             sid_admin_session(sid) + [create_dynamic_object_table(), create_dynamic_row("A", DYN_ROW1_UID), set_dynamic_table_row("B"), get_dynamic_row("A")],
             "After dynamic row Set, a later Get cannot return the stale pre-update value.",
             "core/5.3.3.7", "core/5.3.3.6"),
        scen("core_pass_121b_dynamic_column_metadata_create_row", "pass",
             sid_admin_session(sid) + [create_dynamic_object_table(), get_dynamic_column_metadata(unique=False), create_dynamic_row_value_label("A", "One", DYN_ROW1_UID)],
             "Concrete Column-row metadata extends a learned dynamic table schema used by CreateRow.",
             "core/5.3.2.4", "core/5.3.3.4"),
        scen("core_pass_121c_dynamic_column_metadata_missing_rejected", "pass",
             sid_admin_session(sid) + [create_dynamic_object_table(), get_dynamic_column_metadata(unique=False), create_dynamic_row("A", DYN_ROW1_UID, "INVALID_PARAMETER")],
             "CreateRow must include concrete columns learned from Column-row metadata.",
             "core/5.3.2.4", "core/5.3.3.4"),
        scen("core_fail_121c_dynamic_column_metadata_missing_success", "fail",
             sid_admin_session(sid) + [create_dynamic_object_table(), get_dynamic_column_metadata(unique=False), create_dynamic_row("A", DYN_ROW1_UID, "SUCCESS")],
             "CreateRow success with a missing concrete Column-row-defined column is non-compliant.",
             "core/5.3.2.4", "core/5.3.3.4"),
        scen("core_pass_121d_dynamic_column_metadata_unique_rejected", "pass",
             sid_admin_session(sid) + [create_dynamic_object_table(), get_dynamic_column_metadata(unique=True), create_dynamic_row_value_label("A", "Dup", DYN_ROW1_UID), create_dynamic_row_value_label("B", "Dup", DYN_ROW2_UID, "UNIQUENESS_CONFLICT")],
             "Concrete Column-row IsUnique metadata participates in dynamic CreateRow duplicate checks.",
             "core/3.2.5.4", "core/5.3.2.4", "core/5.3.3.4", "core/5.1.5.8"),
        scen("core_fail_121d_dynamic_column_metadata_unique_success", "fail",
             sid_admin_session(sid) + [create_dynamic_object_table(), get_dynamic_column_metadata(unique=True), create_dynamic_row_value_label("A", "Dup", DYN_ROW1_UID), create_dynamic_row_value_label("B", "Dup", DYN_ROW2_UID, "SUCCESS")],
             "CreateRow cannot succeed when it duplicates a value in a unique column learned from Column-row metadata.",
             "core/3.2.5.4", "core/5.3.2.4", "core/5.3.3.4"),
        scen("core_pass_122_cpin_msid_get_requested_pin", "pass",
             [start_session(ADMIN_SP), get_cpin_msid_column("MSIDVAL")],
             "Successful C_PIN_MSID Get of requested PIN column returns that requested column.",
             "opal/4.2.1.8", "core/5.3.3.6.2"),
        scen("core_fail_122_cpin_msid_get_missing_requested_pin", "fail",
             [start_session(ADMIN_SP), get_cpin_msid_column(None)],
             "Successful C_PIN_MSID Get cannot omit a requested authorized PIN column.",
             "opal/4.2.1.8", "core/5.3.3.6.2"),
        scen("core_pass_123_locking_global_get_range_length", "pass",
             locking_admin_session(sid) + [get_locking_global_columns(0)],
             "Locking Global Get reports tracked RangeLength for the requested column.",
             "opal/4.3.5.2", "core/5.3.3.6.2"),
        scen("core_fail_123_locking_global_get_wrong_range_length", "fail",
             locking_admin_session(sid) + [get_locking_global_columns(1)],
             "Locking Global Get cannot return a RangeLength different from tracked state.",
             "opal/4.3.5.2", "core/5.3.3.6.2"),
        scen("core_pass_124_mbrcontrol_get_defaults", "pass",
             locking_admin_session(sid) + [get_mbrcontrol_columns(0, 0)],
             "MBRControl Get reports tracked default Enable and Done values.",
             "opal/4.3.5.3", "core/5.3.3.6.2"),
        scen("core_fail_124_mbrcontrol_get_wrong_enable", "fail",
             locking_admin_session(sid) + [get_mbrcontrol_columns(1, 0)],
             "MBRControl Get cannot report Enable different from tracked state.",
             "opal/4.3.5.3", "core/5.3.3.6.2"),
        scen("core_pass_125_authority_enabled_after_set", "pass",
             locking_admin_session(sid) + [set_authority(USER1_UID, enabled=True), get_authority_enabled(USER1_UID, 1)],
             "Authority Get reports the tracked Enabled value after a successful Set.",
             "core/5.3.2.10.6", "core/5.3.3.6.2"),
        scen("core_fail_125_authority_enabled_stale_after_set", "fail",
             locking_admin_session(sid) + [set_authority(USER1_UID, enabled=True), get_authority_enabled(USER1_UID, 0)],
             "Authority Get cannot return a stale Enabled value after a successful Set.",
             "core/5.3.2.10.6", "core/5.3.3.6.2"),
        scen("core_pass_126_sp_get_lifecycle", "pass",
             sid_admin_session(sid) + [get_sp_lifecycle(9)],
             "SP Get reports the requested tracked LifeCycleState column.",
             "core/5.4.2.4.7", "core/5.3.3.6.2"),
        scen("core_fail_126_sp_get_missing_lifecycle", "fail",
             sid_admin_session(sid) + [get_sp_lifecycle(None)],
             "SP Get cannot omit the requested tracked LifeCycleState column.",
             "core/5.4.2.4.7", "core/5.3.3.6.2"),
        scen("core_pass_127_lockinginfo_get_maxranges", "pass",
             locking_admin_session(sid) + [get_lockinginfo_maxranges(8)],
             "LockingInfo Get returns requested MaxRanges at the Opal minimum.",
             "opal/4.3.5.1", "core/5.3.3.6.2"),
        scen("core_fail_127_lockinginfo_get_missing_maxranges", "fail",
             locking_admin_session(sid) + [get_lockinginfo_maxranges(None)],
             "LockingInfo Get cannot omit requested MaxRanges.",
             "opal/4.3.5.1", "core/5.3.3.6.2"),
        scen("core_pass_128_accesscontrol_get_commonname", "pass",
             locking_admin_session(sid) + [get_accesscontrol_common_name("ACL_Common")],
             "AccessControl Get returns the requested readable CommonName column.",
             "core/5.3.2.7", "core/5.3.3.6.2"),
        scen("core_fail_128_accesscontrol_get_missing_commonname", "fail",
             locking_admin_session(sid) + [get_accesscontrol_common_name(None)],
             "AccessControl Get cannot omit a requested readable CommonName column in an authorized successful response.",
             "core/5.3.2.7", "core/5.3.3.6.2"),
        scen("core_pass_129_cpin_get_trylimit", "pass",
             sid_admin_session(sid) + [get_cpin_trylimit(0)],
             "C_PIN Get returns the requested readable TryLimit metadata column.",
             "core/5.3.2.12", "core/5.3.3.6.2"),
        scen("core_fail_129_cpin_get_missing_trylimit", "fail",
             sid_admin_session(sid) + [get_cpin_trylimit(None)],
             "C_PIN Get cannot omit a requested readable TryLimit metadata column in an authorized successful response.",
             "core/5.3.2.12", "core/5.3.3.6.2"),
        scen("core_pass_130_mbrcontrol_singleton_uid", "pass",
             locking_admin_session(sid) + [get_mbrcontrol_columns(0, 0)],
             "MBRControl Get succeeds on the exact Opal singleton row UID.",
             "opal/4.3.5.3"),
        scen("core_fail_130_mbrcontrol_non_singleton_uid_success", "fail",
             locking_admin_session(sid) + [get_bad_mbrcontrol_singleton(0, 0)],
             "MBRControl is a singleton Opal object; a different MBRControl-family row UID cannot succeed.",
             "opal/4.3.5.3"),
        scen("core_pass_131_invoking_name_uid_family_match", "pass",
             locking_admin_session(sid) + [get_mbrcontrol_columns(0, 0)],
             "A concrete invoking object name and UID from the same family can be accepted.",
             "core/5.3.3.6", "opal/4.3.5.3"),
        scen("core_fail_131_invoking_name_uid_family_mismatch_success", "fail",
             locking_admin_session(sid) + [get_mbrcontrol_name_locking_uid(0, 0)],
             "A method invocation with incompatible concrete object name and UID families cannot succeed.",
             "core/5.3.3.6"),
        scen("core_pass_132_dynamic_getsetacl_anybody_set", "pass",
             sid_admin_session(sid) + [create_dynamic_object_table(), create_dynamic_row("A", DYN_ROW1_UID), end_session(), start_session(ADMIN_SP), set_dynamic_table_row("B", "SUCCESS")],
             "A dynamic table created with GetSetACL=ACE_Anybody permits Set in an unauthenticated write session.",
             "core/5.3.3.1", "core/5.3.3.7", "core/5.3.4.2"),
        scen("core_fail_132_dynamic_getsetacl_anybody_set_rejected", "fail",
             sid_admin_session(sid) + [create_dynamic_object_table(), create_dynamic_row("A", DYN_ROW1_UID), end_session(), start_session(ADMIN_SP), set_dynamic_table_row("B", "NOT_AUTHORIZED")],
             "A dynamic table GetSetACL=ACE_Anybody grant cannot be rejected when the session is otherwise valid.",
             "core/5.3.3.1", "core/5.3.3.7", "core/5.3.4.2"),
        scen("core_pass_133_dynamic_getsetacl_admin_get_rejected", "pass",
             sid_admin_session(sid) + [create_dynamic_object_table(getset_acl=[ACE_ADMIN_UID]), create_dynamic_row("A", DYN_ROW1_UID), end_session(), start_session(ADMIN_SP, write=0), get_dynamic_row("A", "NOT_AUTHORIZED")],
             "A dynamic table created with an Admins-only GetSetACL rejects unauthenticated Get.",
             "core/5.3.3.1", "core/5.3.3.6", "core/5.3.4.2"),
        scen("core_fail_133_dynamic_getsetacl_admin_get_success", "fail",
             sid_admin_session(sid) + [create_dynamic_object_table(getset_acl=[ACE_ADMIN_UID]), create_dynamic_row("A", DYN_ROW1_UID), end_session(), start_session(ADMIN_SP, write=0), get_dynamic_row("A", "SUCCESS")],
             "A dynamic table Admins-only GetSetACL cannot return row data to an unauthenticated session.",
             "core/5.3.3.1", "core/5.3.3.6", "core/5.3.4.2"),
        scen("core_pass_134_issuesp_space_exhausted_rejected", "pass",
             sid_admin_session(sid) + [get_tperinfo_space_for_issuance(4096), issue_sp("SUCCESS", sp_name="IssuedCoreSP_A", size=4096), issue_sp("INSUFFICIENT_SPACE", sp_name="IssuedCoreSP_B", size=1)],
             "IssueSP cannot succeed after learned TPerInfo.SpaceForIssuance has been exhausted.",
             "core/5.4.2.1.7", "core/5.4.3.1"),
        scen("core_fail_134_issuesp_space_exhausted_success", "fail",
             sid_admin_session(sid) + [get_tperinfo_space_for_issuance(4096), issue_sp("SUCCESS", sp_name="IssuedCoreSP_A", size=4096), issue_sp("SUCCESS", sp_name="IssuedCoreSP_B", size=1)],
             "IssueSP success after learned issuance space is exhausted is non-compliant.",
             "core/5.4.2.1.7", "core/5.4.3.1"),
        scen("core_fail_165_issuesp_space_exhausted_wrong_status", "fail",
             sid_admin_session(sid) + [get_tperinfo_space_for_issuance(4096), issue_sp("SUCCESS", sp_name="IssuedCoreSP_A", size=4096), issue_sp("FAIL", sp_name="IssuedCoreSP_B", size=1)],
             "IssueSP resource exhaustion must use the specific insufficient-space status when learned issuance space is concrete.",
             "core/5.4.2.1.7", "core/5.4.3.1"),
        scen("core_fail_135_issuesp_returned_size_exceeds_space", "fail",
             sid_admin_session(sid) + [get_tperinfo_space_for_issuance(1024), issue_sp("SUCCESS", sp_name="IssuedCoreSP_Big", size=512, return_size=2048)],
             "IssueSP cannot report an allocated Size larger than learned TPerInfo.SpaceForIssuance.",
             "core/5.4.2.1.7", "core/5.4.3.1"),
        scen("core_pass_136_discovery_optional_descriptor_lengths", "pass",
             [discovery_step(discovery_features())],
             "Level 0 Discovery accepts ordered descriptors with exact optional Geometry and Data Removal lengths.",
             "opal/3.1.1.4", "opal/3.1.1.5"),
        scen("core_pass_136b_discovery_header_version", "pass",
             [discovery_step(discovery_features(), header={"major_version": 0, "minor_version": 1})],
             "Level 0 Discovery accepts the standard header version 0.1 when explicitly reported.",
             "core/3.3.6.3.1"),
        scen("core_fail_136b_discovery_bad_header_major", "fail",
             [discovery_step(discovery_features(), header={"major_version": 1, "minor_version": 1})],
             "Level 0 Discovery header MajorVersion must be 0x0000 when explicitly reported.",
             "core/3.3.6.3.1"),
        scen("core_fail_136c_discovery_bad_header_minor", "fail",
             [discovery_step(discovery_features(), header={"major_version": 0, "minor_version": 2})],
             "Level 0 Discovery header MinorVersion must be 0x0001 when explicitly reported.",
             "core/3.3.6.3.1"),
        scen("core_fail_136_discovery_duplicate_feature_code", "fail",
             [discovery_step(discovery_features(duplicate_locking=True))],
             "Level 0 Discovery cannot contain duplicate concrete feature descriptor codes.",
             "core/3.3.6.3.1"),
        scen("core_fail_137_discovery_out_of_order_feature_code", "fail",
             [discovery_step(discovery_features(out_of_order=True))],
             "Level 0 Discovery descriptors must be reported in increasing feature-code order.",
             "core/3.3.6.3.1"),
        scen("core_fail_138_discovery_bad_geometry_length", "fail",
             [discovery_step(discovery_features(geometry_length=0x18))],
             "Geometry descriptor length must be 0x1C when the optional descriptor is present.",
             "opal/3.1.1.4"),
        scen("core_fail_139_discovery_bad_data_removal_length", "fail",
             [discovery_step(discovery_features(data_removal_length=0x1C))],
             "Data Removal descriptor length must be 0x20 when the optional descriptor is present.",
             "opal/3.1.1.5"),
        scen("core_pass_139b_discovery_opal_v2_sid_indicators", "pass",
             [discovery_step(discovery_features(initial_sid_indicator=0x00, revert_sid_indicator=0xFF))],
             "Opal V2 C_PIN_SID indicator values 0x00 and 0xFF are defined.",
             "opal/3.1.1.5"),
        scen("core_fail_139b_discovery_reserved_initial_sid_indicator", "fail",
             [discovery_step(discovery_features(initial_sid_indicator=0x01))],
             "Opal V2 Initial C_PIN_SID PIN Indicator values 0x01..0xFE are reserved.",
             "opal/3.1.1.5"),
        scen("core_fail_139c_discovery_reserved_revert_sid_indicator", "fail",
             [discovery_step(discovery_features(revert_sid_indicator=0xFE))],
             "Opal V2 C_PIN_SID PIN revert behavior values 0x01..0xFE are reserved.",
             "opal/3.1.1.5"),
        scen("core_pass_139d_discovery_reserved_fields_zero", "pass",
             [discovery_step(discovery_features(tper_reserved=0, locking_reserved=0, opal_reserved=0), header={"major_version": 0, "minor_version": 1, "reserved": 0})],
             "Explicit Level 0 Discovery reserved fields are compliant when they are zero.",
             "opal/3.1.1.1", "opal/3.1.1.2", "opal/3.1.1.3", "opal/3.1.1.5"),
        scen("core_fail_139d_discovery_header_reserved_nonzero", "fail",
             [discovery_step(discovery_features(), header={"major_version": 0, "minor_version": 1, "reserved": 1})],
             "Level 0 Discovery header reserved bytes 8-15 must be zero when exposed.",
             "opal/3.1.1.1"),
        scen("core_fail_139e_discovery_tper_reserved_nonzero", "fail",
             [discovery_step(discovery_features(tper_reserved=0x20))],
             "TPer Discovery descriptor reserved bits/bytes must be zero when exposed.",
             "opal/3.1.1.2"),
        scen("core_fail_139f_discovery_locking_reserved_nonzero", "fail",
             [discovery_step(discovery_features(locking_reserved=1))],
             "Locking Discovery descriptor reserved bytes must be zero when exposed.",
             "opal/3.1.1.3"),
        scen("core_fail_139g_discovery_opal_reserved_nonzero", "fail",
             [discovery_step(discovery_features(opal_reserved=0x80))],
             "Opal V2 Discovery descriptor reserved future-common fields must be zero when exposed.",
             "opal/3.1.1.5"),
        scen("core_pass_139h_discovery_total_length_exact", "pass",
             [discovery_step(discovery_features(), header={"length_of_parameter_data": discovery_parameter_length(discovery_features()), "complete": True})],
             "Complete Level 0 Discovery LengthOfParameterData matches the returned descriptor byte count.",
             "opal/3.1.1.1"),
        scen("core_fail_139h_discovery_total_length_short", "fail",
             [discovery_step(discovery_features(), header={"length_of_parameter_data": discovery_parameter_length(discovery_features()) - 1})],
             "Level 0 Discovery LengthOfParameterData cannot be shorter than the concrete returned descriptors.",
             "opal/3.1.1.1"),
        scen("core_fail_139i_discovery_total_length_complete_long", "fail",
             [discovery_step(discovery_features(), header={"length_of_parameter_data": discovery_parameter_length(discovery_features()) + 4, "complete": True})],
             "Complete Level 0 Discovery LengthOfParameterData cannot exceed the concrete descriptor byte count without explicit tail evidence.",
             "opal/3.1.1.1"),
        scen("core_pass_139i_discovery_total_length_truncated_long", "pass",
             [discovery_step(discovery_features(), header={"length_of_parameter_data": discovery_parameter_length(discovery_features()) + 4, "truncated": True})],
             "A truncated Level 0 Discovery response may report a larger total length than the returned descriptors.",
             "opal/3.1.1.1"),
        scen("core_pass_140_getfreerows_learned_table_rowsfree", "pass",
             sid_admin_session(sid, write=0) + [get_table_rows_free(TABLE_UID, 0), get_free_rows(TABLE_UID, "SUCCESS", free_rows=0)],
             "GetFreeRows reflects a concrete RowsFree value learned from the target Table row.",
             "core/5.3.3.10"),
        scen("core_fail_140_getfreerows_wrong_learned_table_rowsfree", "fail",
             sid_admin_session(sid, write=0) + [get_table_rows_free(TABLE_UID, 0), get_free_rows(TABLE_UID, "SUCCESS", free_rows=1)],
             "GetFreeRows cannot contradict a concrete RowsFree value learned from the target Table row.",
             "core/5.3.3.10"),
        scen("core_pass_141_getfreespace_tablerows_learned_table", "pass",
             sid_admin_session(sid, write=0) + [get_table_rows_free(TABLE_UID, 0), get_free_space_with_rows_for_table(TABLE_UID, 0)],
             "GetFreeSpace.TableRows reflects concrete RowsFree values learned from preconfigured Table rows.",
             "core/5.3.3.9"),
        scen("core_fail_141_getfreespace_tablerows_wrong_learned_table", "fail",
             sid_admin_session(sid, write=0) + [get_table_rows_free(TABLE_UID, 0), get_free_space_with_rows_for_table(TABLE_UID, 1)],
             "GetFreeSpace.TableRows cannot contradict concrete RowsFree values learned from preconfigured Table rows.",
             "core/5.3.3.9"),
        scen("core_pass_142_dynamic_addace_grants_get", "pass",
             sid_admin_session(sid) + [create_dynamic_object_table(getset_acl=[ACE_ADMIN_UID]), create_dynamic_row("A", DYN_ROW1_UID), meta_acl_dynamic("AddACE", METHODID_GET_UID), end_session(), start_session(ADMIN_SP, write=0), get_dynamic_row("A", "SUCCESS")],
             "AddACE on a dynamic table Get ACL can add ACE_Anybody and permit a later unauthenticated Get.",
             "core/5.3.3.14", "core/5.3.4.3.1"),
        scen("core_fail_142_dynamic_addace_get_still_rejected", "fail",
             sid_admin_session(sid) + [create_dynamic_object_table(getset_acl=[ACE_ADMIN_UID]), create_dynamic_row("A", DYN_ROW1_UID), meta_acl_dynamic("AddACE", METHODID_GET_UID), end_session(), start_session(ADMIN_SP, write=0), get_dynamic_row("A", "NOT_AUTHORIZED")],
             "A dynamic table Get ACL modified by AddACE(ACE_Anybody) cannot still reject the authorized Get.",
             "core/5.3.3.14", "core/5.3.4.3.1"),
        scen("core_pass_142b_dynamic_addace_requires_admin_acl", "pass",
             sid_admin_session(sid) + [create_dynamic_object_table(getset_acl=[ACE_ADMIN_UID]), end_session(), start_session(ADMIN_SP), meta_acl_dynamic("AddACE", METHODID_GET_UID, "NOT_AUTHORIZED")],
             "AddACE on a concrete dynamic AccessControl row requires its AddACEACL authorization.",
             "core/5.3.3.14", "core/5.3.4.3.1"),
        scen("core_fail_142b_dynamic_addace_unauth_success", "fail",
             sid_admin_session(sid) + [create_dynamic_object_table(getset_acl=[ACE_ADMIN_UID]), end_session(), start_session(ADMIN_SP), meta_acl_dynamic("AddACE", METHODID_GET_UID, "SUCCESS")],
             "AddACE cannot bypass the concrete dynamic AccessControl row's AddACEACL.",
             "core/5.3.3.14", "core/5.3.4.3.1"),
        scen("core_pass_143_dynamic_removeace_revokes_get", "pass",
             sid_admin_session(sid) + [create_dynamic_object_table(getset_acl=[ACE_ANYBODY_UID]), create_dynamic_row("A", DYN_ROW1_UID), meta_acl_dynamic("RemoveACE", METHODID_GET_UID), end_session(), start_session(ADMIN_SP, write=0), get_dynamic_row("A", "NOT_AUTHORIZED")],
             "RemoveACE on a concrete dynamic Get ACL revokes the ACE and later unauthenticated Get is rejected.",
             "core/5.3.3.15", "core/5.3.4.3.1"),
        scen("core_fail_143_dynamic_removeace_get_still_success", "fail",
             sid_admin_session(sid) + [create_dynamic_object_table(getset_acl=[ACE_ANYBODY_UID]), create_dynamic_row("A", DYN_ROW1_UID), meta_acl_dynamic("RemoveACE", METHODID_GET_UID), end_session(), start_session(ADMIN_SP, write=0), get_dynamic_row("A", "SUCCESS")],
             "A dynamic Get ACL emptied by RemoveACE cannot fall back to the CreateTable GetSetACL.",
             "core/5.3.3.15", "core/5.3.4.3.1"),
        scen("core_pass_143b_dynamic_removeace_requires_admin_acl", "pass",
             sid_admin_session(sid) + [create_dynamic_object_table(getset_acl=[ACE_ANYBODY_UID]), end_session(), start_session(ADMIN_SP), meta_acl_dynamic("RemoveACE", METHODID_GET_UID, "NOT_AUTHORIZED")],
             "RemoveACE on a concrete dynamic AccessControl row requires its RemoveACEACL authorization.",
             "core/5.3.3.15", "core/5.3.4.3.1"),
        scen("core_fail_143b_dynamic_removeace_unauth_success", "fail",
             sid_admin_session(sid) + [create_dynamic_object_table(getset_acl=[ACE_ANYBODY_UID]), end_session(), start_session(ADMIN_SP), meta_acl_dynamic("RemoveACE", METHODID_GET_UID, "SUCCESS")],
             "RemoveACE cannot bypass the concrete dynamic AccessControl row's RemoveACEACL.",
             "core/5.3.3.15", "core/5.3.4.3.1"),
        scen("core_pass_144_dynamic_deletemethod_revokes_get", "pass",
             sid_admin_session(sid) + [create_dynamic_object_table(getset_acl=[ACE_ANYBODY_UID]), create_dynamic_row("A", DYN_ROW1_UID), meta_acl_dynamic("DeleteMethod", METHODID_GET_UID), end_session(), start_session(ADMIN_SP, write=0), get_dynamic_row("A", "NOT_AUTHORIZED")],
             "DeleteMethod on a concrete dynamic Get ACL removes that method authorization for later Get.",
             "core/5.3.3.16", "core/5.3.4.3.1"),
        scen("core_fail_144_dynamic_deletemethod_get_still_success", "fail",
             sid_admin_session(sid) + [create_dynamic_object_table(getset_acl=[ACE_ANYBODY_UID]), create_dynamic_row("A", DYN_ROW1_UID), meta_acl_dynamic("DeleteMethod", METHODID_GET_UID), end_session(), start_session(ADMIN_SP, write=0), get_dynamic_row("A", "SUCCESS")],
             "A dynamic Get ACL removed by DeleteMethod cannot fall back to the CreateTable GetSetACL.",
             "core/5.3.3.16", "core/5.3.4.3.1"),
        scen("core_pass_144b_dynamic_deletemethod_requires_admin_acl", "pass",
             sid_admin_session(sid) + [create_dynamic_object_table(getset_acl=[ACE_ANYBODY_UID]), end_session(), start_session(ADMIN_SP), meta_acl_dynamic("DeleteMethod", METHODID_GET_UID, "NOT_AUTHORIZED")],
             "DeleteMethod on a concrete dynamic AccessControl row requires its DeleteMethodACL authorization.",
             "core/5.3.3.16", "core/5.3.4.3.1"),
        scen("core_fail_144b_dynamic_deletemethod_unauth_success", "fail",
             sid_admin_session(sid) + [create_dynamic_object_table(getset_acl=[ACE_ANYBODY_UID]), end_session(), start_session(ADMIN_SP), meta_acl_dynamic("DeleteMethod", METHODID_GET_UID, "SUCCESS")],
             "DeleteMethod cannot bypass the concrete dynamic AccessControl row's DeleteMethodACL.",
             "core/5.3.3.16", "core/5.3.4.3.1"),
        scen("core_pass_145_dynamic_getacl_returns_acl", "pass",
             sid_admin_session(sid) + [create_dynamic_object_table(getset_acl=[ACE_ANYBODY_UID]), get_acl_dynamic([ACE_ANYBODY_UID])],
             "GetACL on a concrete dynamic AccessControl row returns the tracked ACE list.",
             "core/5.3.3.13", "core/5.3.4.3.1"),
        scen("core_fail_145_dynamic_getacl_wrong_acl", "fail",
             sid_admin_session(sid) + [create_dynamic_object_table(getset_acl=[ACE_ANYBODY_UID]), get_acl_dynamic([ACE_ADMIN_UID])],
             "GetACL on a concrete dynamic AccessControl row cannot return an ACL list that contradicts tracked state.",
             "core/5.3.3.13", "core/5.3.4.3.1"),
        scen("core_pass_146_dynamic_create_row_rowsfree_zero_rejected", "pass",
             sid_admin_session(sid) + [create_dynamic_object_table(), create_dynamic_row("A", DYN_ROW1_UID), create_dynamic_row("B", DYN_ROW2_UID), create_dynamic_row("C", DYN_UNKNOWN_ROW_UID, "INSUFFICIENT_ROWS")],
             "CreateRow cannot succeed when tracked dynamic RowsFree is already zero, even before MaxSize is reached.",
             "core/5.3.3.4.2.1"),
        scen("core_fail_146_dynamic_create_row_rowsfree_zero_success", "fail",
             sid_admin_session(sid) + [create_dynamic_object_table(), create_dynamic_row("A", DYN_ROW1_UID), create_dynamic_row("B", DYN_ROW2_UID), create_dynamic_row("C", DYN_UNKNOWN_ROW_UID, "SUCCESS")],
             "CreateRow success contradicts concrete dynamic RowsFree=0 state.",
             "core/5.3.3.4.2.1"),
        scen("core_fail_166_dynamic_create_row_rowsfree_zero_wrong_status", "fail",
             sid_admin_session(sid) + [create_dynamic_object_table(), create_dynamic_row("A", DYN_ROW1_UID), create_dynamic_row("B", DYN_ROW2_UID), create_dynamic_row("C", DYN_UNKNOWN_ROW_UID, "FAIL")],
             "Dynamic CreateRow exhaustion must use the specific insufficient-rows status when RowsFree=0 is concrete.",
             "core/5.3.3.4.2.1"),
        scen("core_pass_147_learned_table_create_row_rowsfree_zero_rejected", "pass",
             sid_admin_session(sid) + [get_table_rows_free(TABLE_UID, 0), create_row(TABLE_UID, "INSUFFICIENT_ROWS", "Table")],
             "CreateRow cannot succeed when concrete Table.RowsFree for the target table is zero.",
             "core/5.3.3.4.2.1"),
        scen("core_fail_147_learned_table_create_row_rowsfree_zero_success", "fail",
             sid_admin_session(sid) + [get_table_rows_free(TABLE_UID, 0), create_row(TABLE_UID, "SUCCESS", "Table")],
             "CreateRow success contradicts concrete learned Table.RowsFree=0 state.",
             "core/5.3.3.4.2.1"),
        scen("core_fail_167_learned_table_create_row_rowsfree_zero_wrong_status", "fail",
             sid_admin_session(sid) + [get_table_rows_free(TABLE_UID, 0), create_row(TABLE_UID, "FAIL", "Table")],
             "Preconfigured-table CreateRow exhaustion must use the specific insufficient-rows status when Table.RowsFree=0 is concrete.",
             "core/5.3.3.4.2.1"),
        scen("core_pass_148_issuesp_known_template_available", "pass",
             sid_admin_session(sid) + [get_table_rows(TEMPLATE_TABLE_UID, 2), next_template_inventory([TEMPLATE_BASE_UID, TEMPLATE_LOCKING_UID], count=2), issue_sp("SUCCESS", sp_name="IssuedCoreSP_TemplateOK", templates=[TEMPLATE_BASE_UID])],
             "IssueSP may use a template UID that is present in a complete learned Template table inventory.",
             "core/5.4.3.1", "core/5.4.2.1"),
        scen("core_pass_149_issuesp_unknown_template_rejected", "pass",
             sid_admin_session(sid) + [get_table_rows(TEMPLATE_TABLE_UID, 2), next_template_inventory([TEMPLATE_BASE_UID, TEMPLATE_LOCKING_UID], count=2), issue_sp("INVALID_PARAMETER", sp_name="IssuedCoreSP_TemplateMissing", templates=[TEMPLATE_VENDOR_UID])],
             "IssueSP cannot use a template UID absent from a complete learned Template table inventory.",
             "core/5.4.3.1", "core/5.4.2.1"),
        scen("core_fail_149_issuesp_unknown_template_success", "fail",
             sid_admin_session(sid) + [get_table_rows(TEMPLATE_TABLE_UID, 2), next_template_inventory([TEMPLATE_BASE_UID, TEMPLATE_LOCKING_UID], count=2), issue_sp("SUCCESS", sp_name="IssuedCoreSP_TemplateMissing", templates=[TEMPLATE_VENDOR_UID])],
             "IssueSP success with a template absent from complete learned inventory is non-compliant.",
             "core/5.4.3.1", "core/5.4.2.1"),
        scen("core_pass_150_createtable_table_rowsfree_zero_rejected", "pass",
             sid_admin_session(sid) + [get_table_rows_free(TABLE_UID, 0), create_table("INSUFFICIENT_ROWS")],
             "CreateTable cannot succeed when the concrete Table table RowsFree value is zero.",
             "core/5.3.3.2"),
        scen("core_fail_150_createtable_table_rowsfree_zero_success", "fail",
             sid_admin_session(sid) + [get_table_rows_free(TABLE_UID, 0), create_table("SUCCESS")],
             "CreateTable success contradicts concrete Table table RowsFree=0 state.",
             "core/5.3.3.2"),
        scen("core_fail_168_createtable_table_rowsfree_zero_wrong_status", "fail",
             sid_admin_session(sid) + [get_table_rows_free(TABLE_UID, 0), create_table("FAIL")],
             "CreateTable exhaustion must use the specific insufficient-rows status when the Table table RowsFree=0 is concrete.",
             "core/5.3.3.2"),
        scen("core_pass_151_table_capacity_consistent", "pass",
             sid_admin_session(sid, write=0) + [get_table_capacity(TABLE_UID, rows=2, rows_free=1, max_size=3)],
             "Table Get capacity metadata is internally consistent when Rows + RowsFree is within MaxSize.",
             "core/5.3.2.2", "core/5.3.3.6.2"),
        scen("core_fail_151_table_capacity_rowsfree_exceeds_max", "fail",
             sid_admin_session(sid, write=0) + [get_table_capacity(TABLE_UID, rows=2, rows_free=2, max_size=3)],
             "Table Get capacity metadata cannot report Rows + RowsFree greater than MaxSize.",
             "core/5.3.2.2", "core/5.3.3.6.2"),
        scen("core_fail_152_table_capacity_rows_exceeds_max", "fail",
             sid_admin_session(sid, write=0) + [get_table_capacity(TABLE_UID, rows=4, rows_free=0, max_size=3)],
             "Table Get capacity metadata cannot report Rows greater than MaxSize.",
             "core/5.3.2.2", "core/5.3.3.6.2"),
        scen("core_pass_153_issuesp_distinct_returned_uids", "pass",
             sid_admin_session(sid) + [issue_sp("SUCCESS", sp_name="IssuedCoreSP_UID1", return_uid=ISSUED_SP1_UID), issue_sp("SUCCESS", sp_name="IssuedCoreSP_UID2", return_uid=ISSUED_SP2_UID)],
             "IssueSP may return distinct concrete SP UIDs for distinct issued SPs.",
             "core/5.4.3.1"),
        scen("core_fail_153_issuesp_duplicate_returned_uid_success", "fail",
             sid_admin_session(sid) + [issue_sp("SUCCESS", sp_name="IssuedCoreSP_UID1", return_uid=ISSUED_SP1_UID), issue_sp("SUCCESS", sp_name="IssuedCoreSP_UID2", return_uid=ISSUED_SP1_UID)],
             "IssueSP cannot successfully return a concrete SP UID that was already issued.",
             "core/5.4.3.1"),
        scen("core_pass_154_issued_disabled_sp_start_rejected", "pass",
             sid_admin_session(sid) + [issue_sp("SUCCESS", sp_name="IssuedCoreSP_Disabled", return_uid=ISSUED_SP1_UID, enabled=False), end_session(), start_session(ISSUED_SP1_UID, status="SP_DISABLED")],
             "A concrete issued SP created with Enabled=False rejects later StartSession with SP_DISABLED.",
             "core/4.3.6", "core/5.4.3.1"),
        scen("core_fail_154_issued_disabled_sp_start_success", "fail",
             sid_admin_session(sid) + [issue_sp("SUCCESS", sp_name="IssuedCoreSP_Disabled", return_uid=ISSUED_SP1_UID, enabled=False), end_session(), start_session(ISSUED_SP1_UID, status="SUCCESS")],
             "StartSession cannot succeed for a concrete issued SP whose IssueSP Enabled parameter was false.",
             "core/4.3.6", "core/5.4.3.1"),
        scen("core_pass_154b_issued_sp_delete_releases_template_instance", "pass",
             sid_admin_session(sid) + [
                 get_template_instances(TEMPLATE_BASE_UID, instances=0, max_instances=1),
                 issue_sp("SUCCESS", sp_name="IssuedCoreSP_TemplateOne", return_uid=ISSUED_SP1_UID, templates=[TEMPLATE_BASE_UID]),
                 issue_sp("FAIL", sp_name="IssuedCoreSP_TemplateTwo", return_uid=ISSUED_SP2_UID, templates=[TEMPLATE_BASE_UID]),
                 delete_object(ISSUED_SP1_UID, "SUCCESS", "SP"),
                 end_session(),
                 start_session(ADMIN_SP, authority=SID_UID, challenge=sid),
                 issue_sp("SUCCESS", sp_name="IssuedCoreSP_TemplateThree", return_uid=ISSUED_SP2_UID, templates=[TEMPLATE_BASE_UID]),
             ],
             "Deleting a concrete issued SP releases its concrete Template Instances count for later IssueSP.",
             "core/5.4.2.1", "core/5.4.3.1", "core/5.4.4.2"),
        scen("core_fail_154b_issued_sp_delete_template_instance_stale", "fail",
             sid_admin_session(sid) + [
                 get_template_instances(TEMPLATE_BASE_UID, instances=0, max_instances=1),
                 issue_sp("SUCCESS", sp_name="IssuedCoreSP_TemplateOne", return_uid=ISSUED_SP1_UID, templates=[TEMPLATE_BASE_UID]),
                 issue_sp("FAIL", sp_name="IssuedCoreSP_TemplateTwo", return_uid=ISSUED_SP2_UID, templates=[TEMPLATE_BASE_UID]),
                 delete_object(ISSUED_SP1_UID, "SUCCESS", "SP"),
                 end_session(),
                 start_session(ADMIN_SP, authority=SID_UID, challenge=sid),
                 issue_sp("FAIL", sp_name="IssuedCoreSP_TemplateThree", return_uid=ISSUED_SP2_UID, templates=[TEMPLATE_BASE_UID]),
             ],
             "Template Instances cannot remain consumed after the concrete issued SP using that template has been deleted.",
             "core/5.4.2.1", "core/5.4.3.1", "core/5.4.4.2"),
        scen("core_pass_155_random_count_length", "pass",
             sid_admin_session(sid) + [random_step("SUCCESS", 4, output_bytes="AABBCCDD")],
             "Random Count=4 returns exactly four random bytes when output bytes are present.",
             "core/5.6.4.1"),
        scen("core_fail_155_random_count_wrong_length", "fail",
             sid_admin_session(sid) + [random_step("SUCCESS", 4, output_bytes="AABB")],
             "Random cannot return fewer or more bytes than the requested Count when output bytes are present.",
             "core/5.6.4.1"),
        scen("core_pass_155b_random_count_zero_empty", "pass",
             sid_admin_session(sid) + [random_step("SUCCESS", 0, output_bytes="")],
             "Random Count=0 returns an empty byte result when output bytes are present.",
             "core/5.6.4.1"),
        scen("core_pass_156_hash_bufferout_bound", "pass",
             sid_admin_session(sid) + [crypto_step("HashInit"), crypto_step("Hash", "SUCCESS", buffer_out=4, output_bytes="AABBCCDD")],
             "Hash output bytes may be equal to the explicit BufferOut limit.",
             "core/5.6.4.12"),
        scen("core_fail_156_hash_bufferout_overflow", "fail",
             sid_admin_session(sid) + [crypto_step("HashInit"), crypto_step("Hash", "SUCCESS", buffer_out=2, output_bytes="AABBCCDD")],
             "Hash output bytes cannot exceed explicit BufferOut.",
             "core/5.6.4.12"),
        scen("core_pass_157_hashfinalize_bufferout_bound", "pass",
             sid_admin_session(sid) + [crypto_step("HashInit"), crypto_step("HashFinalize", "SUCCESS", buffer_out=2, output_bytes="AABB")],
             "HashFinalize output bytes may be equal to the explicit BufferOut limit.",
             "core/5.6.4.13"),
        scen("core_fail_157_hashfinalize_bufferout_overflow", "fail",
             sid_admin_session(sid) + [crypto_step("HashInit"), crypto_step("HashFinalize", "SUCCESS", buffer_out=1, output_bytes="AABB")],
             "HashFinalize output bytes cannot exceed explicit BufferOut.",
             "core/5.6.4.13"),
        scen("core_pass_160_deleted_dynamic_table_get_rejected", "pass",
             sid_admin_session(sid) + [create_dynamic_object_table(), delete_object(DYN_OBJECT_TABLE_UID, "SUCCESS", "DynCoreTable"), get_dynamic_table(rows=0, rows_free=2, status="FAIL")],
             "A deleted dynamic table UID cannot later be used for Get.",
             "core/5.3.3.1", "core/5.3.3.6"),
        scen("core_fail_160_deleted_dynamic_table_get_success", "fail",
             sid_admin_session(sid) + [create_dynamic_object_table(), delete_object(DYN_OBJECT_TABLE_UID, "SUCCESS", "DynCoreTable"), get_dynamic_table(rows=0, rows_free=2, status="SUCCESS")],
             "Get cannot succeed on a dynamic table after that concrete table UID was deleted.",
             "core/5.3.3.1", "core/5.3.3.6"),
        scen("core_pass_160b_dynamic_table_delete_restores_table_rowsfree", "pass",
             sid_admin_session(sid) + [get_table_rows_free(TABLE_UID, 1), create_dynamic_object_table(), delete_object(DYN_OBJECT_TABLE_UID, "SUCCESS", "DynCoreTable"), get_free_rows(TABLE_UID, "SUCCESS", free_rows=1)],
             "Deleting a known dynamic table restores the learned Table table RowsFree counter.",
             "core/5.3.3.3", "core/5.3.3.10"),
        scen("core_fail_160b_dynamic_table_delete_rowsfree_stale", "fail",
             sid_admin_session(sid) + [get_table_rows_free(TABLE_UID, 1), create_dynamic_object_table(), delete_object(DYN_OBJECT_TABLE_UID, "SUCCESS", "DynCoreTable"), get_free_rows(TABLE_UID, "SUCCESS", free_rows=0)],
             "Table table RowsFree cannot remain consumed after the concrete dynamic table has been deleted.",
             "core/5.3.3.3", "core/5.3.3.10"),
        scen("core_pass_161_deleted_dynamic_row_get_rejected", "pass",
             sid_admin_session(sid) + [create_dynamic_object_table(), create_dynamic_row("A", DYN_ROW1_UID), delete_object(DYN_ROW1_UID, "SUCCESS", "DynCoreRow"), get_dynamic_row("A", "FAIL")],
             "A deleted dynamic row UID cannot later be used for Get.",
             "core/5.3.3.1", "core/5.3.3.6"),
        scen("core_fail_161_deleted_dynamic_row_get_success", "fail",
             sid_admin_session(sid) + [create_dynamic_object_table(), create_dynamic_row("A", DYN_ROW1_UID), delete_object(DYN_ROW1_UID, "SUCCESS", "DynCoreRow"), get_dynamic_row("A", "SUCCESS")],
             "Get cannot succeed on a dynamic row after that concrete row UID was deleted.",
             "core/5.3.3.1", "core/5.3.3.6"),
        scen("core_pass_162_deleted_dynamic_table_getacl_rejected", "pass",
             sid_admin_session(sid) + [create_dynamic_object_table(getset_acl=[ACE_ANYBODY_UID]), delete_object(DYN_OBJECT_TABLE_UID, "SUCCESS", "DynCoreTable"), get_acl_dynamic([ACE_ANYBODY_UID], status="FAIL")],
             "Deleting a dynamic table removes its concrete dynamic AccessControl association.",
             "core/5.3.3.1", "core/5.3.3.13"),
        scen("core_fail_162_deleted_dynamic_table_getacl_success", "fail",
             sid_admin_session(sid) + [create_dynamic_object_table(getset_acl=[ACE_ANYBODY_UID]), delete_object(DYN_OBJECT_TABLE_UID, "SUCCESS", "DynCoreTable"), get_acl_dynamic([ACE_ANYBODY_UID], status="SUCCESS")],
             "GetACL cannot succeed for a deleted dynamic table AccessControl association.",
             "core/5.3.3.1", "core/5.3.3.13"),
        scen("core_pass_163_issued_sp_getfreespace_within_size", "pass",
             sid_admin_session(sid) + [issue_sp("SUCCESS", sp_name="IssuedCoreSP_Free", size=4096, return_uid=ISSUED_SP1_UID), end_session(), start_session(ISSUED_SP1_UID, write=0), get_free_space(ISSUED_SP1_UID, "SUCCESS", free_space=4096)],
             "GetFreeSpace on a concrete issued SP may report free space up to the issued Size.",
             "core/5.3.3.9", "core/5.4.3.1"),
        scen("core_fail_163_issued_sp_getfreespace_exceeds_size", "fail",
             sid_admin_session(sid) + [issue_sp("SUCCESS", sp_name="IssuedCoreSP_Free", size=4096, return_uid=ISSUED_SP1_UID), end_session(), start_session(ISSUED_SP1_UID, write=0), get_free_space(ISSUED_SP1_UID, "SUCCESS", free_space=4097)],
             "GetFreeSpace on a concrete issued SP cannot report FreeSpace greater than the issued Size.",
             "core/5.3.3.9", "core/5.4.3.1"),
        scen("core_pass_164_admin_delete_issued_sp_deferred", "pass",
             sid_admin_session(sid) + [issue_sp("SUCCESS", sp_name="IssuedCoreSP_Delete", return_uid=ISSUED_SP1_UID), delete_object(ISSUED_SP1_UID, "SUCCESS", "SP"), end_session(), start_session(ISSUED_SP1_UID, status="FAIL")],
             "AdminSP Delete on an issued SP takes effect at session close and prevents later StartSession.",
             "core/5.3.3.1.1", "core/5.4.4.2"),
        scen("core_fail_164_admin_delete_issued_sp_deferred_start_success", "fail",
             sid_admin_session(sid) + [issue_sp("SUCCESS", sp_name="IssuedCoreSP_Delete", return_uid=ISSUED_SP1_UID), delete_object(ISSUED_SP1_UID, "SUCCESS", "SP"), end_session(), start_session(ISSUED_SP1_UID, status="SUCCESS")],
             "StartSession cannot succeed after deferred AdminSP Delete of a concrete issued SP.",
             "core/5.3.3.1.1", "core/5.4.4.2"),
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

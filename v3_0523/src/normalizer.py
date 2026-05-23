import re

from .spec_docs import column_number_for_name


ADMIN_SP = "0000020500000001"
LOCKING_SP = "0000020500000002"

SESSION_MANAGER_UID = "00000000000000FF"
LOCKING_SP_UID = "0000020500000002"
BAD_LOCKING_SP_UID = "0000010500000004"

C_PIN_MSID_UID = "0000000B00008402"
C_PIN_SID_UID = "0000000B00000001"
LOCKING_GLOBAL_UID = "0000080200000001"
MBR_CONTROL_UID = "0000080300000001"
LOCKING_INFO_UID = "0000080100000001"

SID_AUTHORITY_UID = "0000000900000006"
ADMIN1_AUTHORITY_UID = "0000000900010001"


STATUS_ALIASES = {
    "success": "success",
    "pass": "success",
    "passed": "success",
    "not_authorized": "not_authorized",
    "notauthorized": "not_authorized",
    "invalid_parameter": "invalid_parameter",
    "invalidparameter": "invalid_parameter",
    "sp_busy": "sp_busy",
    "sp_failed": "sp_failed",
    "sp_disabled": "sp_disabled",
    "sp_frozen": "sp_frozen",
    "no_sessions_available": "no_sessions_available",
    "nosessionsavailable": "no_sessions_available",
    "uniqueness_conflict": "uniqueness_conflict",
    "insufficient_space": "insufficient_space",
    "insufficient_rows": "insufficient_rows",
    "insufficient_columns": "insufficient_columns",
    "invalid_command": "invalid_command",
    "unsupported": "unsupported",
    "tper_malfunction": "tper_malfunction",
    "transaction_failure": "transaction_failure",
    "response_overflow": "response_overflow",
    "authority_locked_out": "authority_locked_out",
    "fail": "fail",
    "failed": "fail",
    "failure": "fail",
}


def compact_uid(value):
    if value is None:
        return None
    compacted = re.sub(r"[^0-9A-Fa-f]", "", str(value)).upper()
    return compacted or None


def normalize_status(value):
    if value is None:
        return None
    text = str(value).strip().lower().replace("-", "_").replace(" ", "_")
    text = re.sub(r"_+", "_", text)
    return STATUS_ALIASES.get(text, text)


def is_success_status(status):
    return normalize_status(status) == "success"


def status_from(inp, out):
    output_status = normalize_status(out.get("status_codes") if isinstance(out, dict) else None)
    input_status = normalize_status(inp.get("status_codes") if isinstance(inp, dict) else None)
    return output_status if output_status is not None else input_status


def to_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in {"true", "t", "yes", "y", "1"}:
        return True
    if text in {"false", "f", "no", "n", "0", ""}:
        return False
    return None


def to_int(value):
    if isinstance(value, bool):
        return int(value)
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
        if re.fullmatch(r"[0-9A-Fa-f]+", text):
            if re.search(r"[A-Fa-f]", text) or (len(text) > 2 and text.startswith("0")):
                return int(text, 16)
            return int(text, 10)
    except ValueError:
        return None
    return None


def column_number(column, family=None):
    if isinstance(column, int):
        return column
    if column is None:
        return None
    text = str(column).strip().lower()
    if not text:
        return None
    if family and not text.startswith("0x") and not text.isdigit():
        named = column_number_for_name(family, column)
        if named is not None:
            return named
    try:
        if text.startswith("0x"):
            return int(text, 16)
        if text.isdigit():
            return int(text, 10)
        if re.fullmatch(r"[0-9a-f]+", text):
            return int(text, 16)
    except ValueError:
        return None
    if family:
        return column_number_for_name(family, column)
    return None


def canonical_sp(spid):
    spid = compact_uid(spid)
    if spid == ADMIN_SP:
        return "AdminSP"
    if spid == LOCKING_SP:
        return "LockingSP"
    if spid and spid.startswith("00000205"):
        return f"SP_{spid[-4:]}"
    return spid


def canonical_authority(uid):
    uid = compact_uid(uid)
    if uid == "0000000900000001":
        return "Anybody"
    if uid == "0000000900000002":
        return "Admins"
    if uid == "0000000900030000":
        return "Users"
    if uid == SID_AUTHORITY_UID:
        return "SID"
    if uid == ADMIN1_AUTHORITY_UID:
        return "Admin1"
    if uid and uid.startswith("000000090001"):
        return f"Admin{int(uid[-4:], 16)}"
    if uid and uid.startswith("000000090003"):
        return f"User{int(uid[-4:], 16)}"
    if uid and uid.startswith("00000009"):
        return f"Authority_{uid[-6:]}"
    return uid


def authority_uid_for_cpin(uid):
    uid = compact_uid(uid)
    if not uid or not uid.startswith("0000000B"):
        return None
    if uid == C_PIN_MSID_UID:
        return "MSID"
    if uid == C_PIN_SID_UID:
        return "SID"
    return canonical_authority("00000009" + uid[8:])


def locking_range_from_uid(uid):
    uid = compact_uid(uid)
    if not uid or not uid.startswith("00000802"):
        return None
    if uid == LOCKING_GLOBAL_UID or uid[8:12] == "0000":
        return "Global"
    if uid[8:12] == "0003":
        index = int(uid[-4:], 16)
        return f"Range{index}"
    return f"Range_{uid[-6:]}"


def media_key_range_from_uid(uid):
    uid = compact_uid(uid)
    if not uid or not (uid.startswith("00000805") or uid.startswith("00000806")):
        return None
    if uid[8:12] == "0000":
        return "Global"
    if uid[8:12] == "0003":
        index = int(uid[-4:], 16)
        return f"Range{index}"
    return f"Range_{uid[-6:]}"


def canonical_object(name, uid):
    uid = compact_uid(uid)
    if uid == SESSION_MANAGER_UID:
        return "SessionManager"
    if uid == LOCKING_SP_UID:
        return "LockingSP"
    if uid == BAD_LOCKING_SP_UID:
        return "NonLockingSP"
    if uid and uid.startswith("00000205"):
        return canonical_sp(uid)
    if uid == C_PIN_MSID_UID:
        return "C_PIN_MSID"
    if uid == C_PIN_SID_UID:
        return "C_PIN_SID"
    if uid and uid.startswith("0000000B"):
        authority = authority_uid_for_cpin(uid)
        if authority and not authority.startswith("Authority_"):
            return f"C_PIN_{authority}"
        return f"C_PIN_{uid[-6:]}"
    if uid and uid.startswith("00000009"):
        return canonical_authority(uid)
    if uid and uid.startswith("00000801"):
        return "LockingInfo"
    if uid and uid.startswith("00000802"):
        locking_range = locking_range_from_uid(uid)
        if locking_range == "Global":
            return "Locking_Global"
        return f"Locking_{locking_range}"
    if uid and uid.startswith("00000803"):
        return "MBRControl"
    if uid and uid.startswith("00000805"):
        key_range = media_key_range_from_uid(uid)
        return f"{key_range}_Key" if key_range else "K_AES_128_Key"
    if uid and uid.startswith("00000806"):
        key_range = media_key_range_from_uid(uid)
        return f"{key_range}_Key" if key_range else "K_AES_256_Key"

    if name:
        normalized_name = str(name).strip().replace(" ", "_")
        lower_name = normalized_name.lower()
        if lower_name == "lockinginfo":
            return "LockingInfo"
        if lower_name == "mbrcontrol":
            return "MBRControl"
        if lower_name in {"accesscontrol", "access_control"}:
            return "AccessControl"
        if lower_name == "ace":
            return "ACE"
        if lower_name == "column":
            return "Column"
        if lower_name in {"methodid", "method_id"}:
            return "MethodID"
        if lower_name == "table":
            return "Table"
        if lower_name == "spinfo":
            return "SPInfo"
        if lower_name == "sptemplates":
            return "SPTemplates"
        if lower_name == "secretprotect":
            return "SecretProtect"
        if lower_name == "datastore":
            return "DataStore"
        if lower_name == "mbr":
            return "MBR"
        if lower_name.startswith("k_aes"):
            return f"{normalized_name}_Key"
        return normalized_name
    return uid


def object_family(uid, obj):
    uid = compact_uid(uid)
    if obj == "SessionManager":
        return "SessionManager"
    if obj in {"AdminSP", "LockingSP"} or (uid and uid.startswith("00000205")):
        return "SP"
    if obj and obj.startswith("C_PIN_"):
        return "C_PIN"
    if obj and (obj == "SID" or obj.startswith("Admin") or obj.startswith("User") or obj.startswith("Authority_")):
        return "Authority"
    if obj == "LockingInfo":
        return "LockingInfo"
    if obj and obj.startswith("Locking_"):
        return "Locking"
    if obj == "MBRControl":
        return "MBRControl"
    if uid and (uid.startswith("00000805") or uid.startswith("00000806")):
        return "MediaKey"
    if obj in {"ACE", "AccessControl", "Column", "MethodID", "Table", "SPInfo", "SPTemplates", "SecretProtect", "DataStore", "MBR"}:
        return obj
    if obj and obj.endswith("_Key"):
        return "MediaKey"
    return None


def normalize_lba(value):
    if value is None:
        return None
    numbers = [int(part) for part in re.findall(r"\d+", str(value))]
    if not numbers:
        return None
    if len(numbers) == 1:
        return (numbers[0], numbers[0])
    return (numbers[0], numbers[1])


def normalize_args(args):
    if isinstance(args, dict):
        required = args.get("required") if isinstance(args.get("required"), dict) else {}
        optional = args.get("optional") if isinstance(args.get("optional"), dict) else {}
        return required, optional
    return {}, {}


def arg_value(required, optional, *names):
    for name in names:
        if isinstance(required, dict) and name in required:
            return required[name]
        if isinstance(optional, dict) and name in optional:
            return optional[name]
    wanted = {name.lower() for name in names}
    for source in (required, optional):
        if not isinstance(source, dict):
            continue
        for key, value in source.items():
            if str(key).lower() in wanted:
                return value
    return None


def iter_value_dicts(value):
    if isinstance(value, dict):
        yield value
        for nested in value.values():
            yield from iter_value_dicts(nested)
    elif isinstance(value, list):
        for item in value:
            yield from iter_value_dicts(item)


def extract_columns(value, family=None):
    columns = {}
    for item in iter_value_dicts(value):
        for key, item_value in item.items():
            column = column_number(key, family)
            if column is not None:
                columns[column] = item_value
    return columns


def first_value(values, column=None, family=None):
    if column is not None:
        return extract_columns(values, family).get(column)
    if not isinstance(values, list):
        return None
    for item in values:
        if isinstance(item, dict) and item:
            return next(iter(item.values()))
    return None


def extract_return_column(return_values, column):
    return extract_columns(return_values).get(column)


def normalize_cellblock(cellblock, family=None):
    start = None
    end = None
    invalid = False
    saw_start = False
    saw_end = False
    if isinstance(cellblock, list):
        for item in cellblock:
            if not isinstance(item, dict):
                invalid = True
                continue
            for key in ("startColumn", "StartColumn", "start_column"):
                if key in item:
                    saw_start = True
                    start = column_number(item.get(key), family)
                    invalid = invalid or start is None
            for key in ("endColumn", "EndColumn", "end_column"):
                if key in item:
                    saw_end = True
                    end = column_number(item.get(key), family)
                    invalid = invalid or end is None
    elif isinstance(cellblock, dict):
        if any(key in cellblock for key in ("startColumn", "StartColumn", "start_column")):
            saw_start = True
            start = column_number(cellblock.get("startColumn") or cellblock.get("StartColumn") or cellblock.get("start_column"), family)
            invalid = invalid or start is None
        if any(key in cellblock for key in ("endColumn", "EndColumn", "end_column")):
            saw_end = True
            end = column_number(cellblock.get("endColumn") or cellblock.get("EndColumn") or cellblock.get("end_column"), family)
            invalid = invalid or end is None

    if start is None and end is not None:
        start = end
    if end is None and start is not None:
        end = start
    columns = list(range(start, end + 1)) if start is not None and end is not None and start <= end else []
    if cellblock is not None and not (saw_start or saw_end):
        invalid = True
    return {"raw": cellblock, "start": start, "end": end, "columns": columns, "invalid": invalid}


def unrecognized_column_keys(value, family=None):
    if value is None:
        return False
    wrappers = {"rowvalues", "bytes", "values", "where"}
    if isinstance(value, dict):
        for key, item_value in value.items():
            normalized_key = str(key).strip().lower()
            if normalized_key in wrappers:
                if unrecognized_column_keys(item_value, family):
                    return True
                continue
            if column_number(key, family) is None:
                return True
        return False
    if isinstance(value, list):
        return any(unrecognized_column_keys(item, family) for item in value)
    return False


def find_named_value(value, names):
    wanted = {name.lower() for name in names}
    if isinstance(value, dict):
        for key, item_value in value.items():
            if str(key).lower() in wanted:
                return item_value
            nested = find_named_value(item_value, names)
            if nested is not None:
                return nested
    elif isinstance(value, list):
        for item in value:
            nested = find_named_value(item, names)
            if nested is not None:
                return nested
    return None


def normalize_record(record):
    inp = record.get("input", {}) if isinstance(record, dict) else {}
    out = record.get("output", {}) if isinstance(record, dict) else {}
    method = inp.get("method")
    index = record.get("index") if isinstance(record, dict) else None

    if isinstance(method, dict):
        required, optional = normalize_args(method.get("args"))
        invoking = inp.get("invoking_id") if isinstance(inp.get("invoking_id"), dict) else {}
        uid = compact_uid(invoking.get("uid"))
        obj = canonical_object(invoking.get("name"), uid)
        family = object_family(uid, obj)
        values = optional.get("Values")
        value_columns = extract_columns(values, family)
        return_columns = extract_columns(out.get("return_values"), family)
        cellblock = normalize_cellblock(required.get("Cellblock"), family)
        authority_uid = compact_uid(
            arg_value(required, optional, "HostSigningAuthority", "Authority", "SigningAuthority")
        )
        host_exchange_uid = compact_uid(arg_value(required, optional, "HostExchangeAuthority"))
        sp_exchange_uid = compact_uid(arg_value(required, optional, "SPExchangeAuthority"))
        sp_signing_uid = compact_uid(arg_value(required, optional, "SPSigningAuthority"))
        host_challenge = arg_value(required, optional, "HostChallenge", "Challenge")
        proof = arg_value(required, optional, "Proof", "HostChallenge", "Challenge")
        auth_result = find_named_value(out.get("return_values"), {"Success", "Result"})
        parameters = {}
        parameters.update(required)
        parameters.update(optional)

        event = {
            "index": index,
            "kind": "method",
            "method": method.get("name"),
            "method_uid": compact_uid(method.get("uid")),
            "object": obj,
            "object_family": family,
            "object_name": invoking.get("name"),
            "object_uid": uid,
            "spid": compact_uid(required.get("SPID")),
            "sp": canonical_sp(required.get("SPID")),
            "write": to_bool(required.get("Write")) if "Write" in required else None,
            "authority": canonical_authority(authority_uid),
            "authority_uid": authority_uid,
            "host_exchange_authority_uid": host_exchange_uid,
            "host_exchange_authority": canonical_authority(host_exchange_uid),
            "sp_exchange_authority_uid": sp_exchange_uid,
            "sp_exchange_authority": canonical_authority(sp_exchange_uid),
            "sp_signing_authority_uid": sp_signing_uid,
            "sp_signing_authority": canonical_authority(sp_signing_uid),
            "challenge": host_challenge,
            "proof": proof,
            "auth_result": to_bool(auth_result),
            "parameters": parameters,
            "required_parameters": required,
            "optional_parameters": optional,
            "where": arg_value(required, optional, "Where"),
            "count": to_int(arg_value(required, optional, "Count")),
            "keep_global_range_key": to_bool(arg_value(required, optional, "KeepGlobalRangeKey")),
            "values": values if isinstance(values, list) else [],
            "value_columns": value_columns,
            "set_column_3": value_columns.get(3),
            "cellblock": cellblock["raw"],
            "cellblock_start": cellblock["start"],
            "cellblock_end": cellblock["end"],
            "cellblock_columns": cellblock["columns"],
            "cellblock_invalid": cellblock["invalid"],
            "value_columns_invalid": unrecognized_column_keys(values, family),
            "return_columns": return_columns,
            "return_column_3": return_columns.get(3),
            "input_status": normalize_status(inp.get("status_codes")),
            "output_status": normalize_status(out.get("status_codes")),
            "status": status_from(inp, out),
            "locking_range": locking_range_from_uid(uid),
            "key_range": media_key_range_from_uid(uid),
            "raw": record,
        }
        event["credential_authority"] = authority_uid_for_cpin(uid)
        return event

    command = inp.get("command")
    in_args = inp.get("args") if isinstance(inp.get("args"), dict) else {}
    out_args = out.get("args") if isinstance(out.get("args"), dict) else {}
    kind = str(command).strip().lower() if command else "unknown"
    if kind not in {"read", "write"}:
        kind = "command"
    result = out_args.get("result")
    if result is None and isinstance(out, dict):
        result = out.get("result")
    return {
        "index": index,
        "kind": kind,
        "command": command,
        "lba": normalize_lba(in_args.get("LBA")),
        "pattern": in_args.get("pattern"),
        "result": result,
        "input_status": normalize_status(inp.get("status_codes")),
        "output_status": normalize_status(out.get("status_codes")),
        "status": status_from(inp, out),
        "raw": record,
    }


def normalize_trajectory(steps):
    return [normalize_record(step) for step in steps]

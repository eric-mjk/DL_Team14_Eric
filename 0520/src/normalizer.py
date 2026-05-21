import re


ADMIN_SP = "0000020500000001"
LOCKING_SP = "0000020500000002"

SESSION_MANAGER_UID = "00000000000000FF"
LOCKING_SP_UID = "0000020500000002"
BAD_LOCKING_SP_UID = "0000010500000004"

C_PIN_MSID_UID = "0000000B00008402"
C_PIN_SID_UID = "0000000B00000001"
LOCKING_GLOBAL_UID = "0000080200000001"
LOCKING_RANGE1_UID = "0000080200030001"
MBR_CONTROL_UID = "0000080300000001"
LOCKING_INFO_UID = "0000080100000001"
RANGE1_KEY_UID = "0000080600030001"

SID_AUTHORITY_UID = "0000000900000006"
ADMIN1_AUTHORITY_UID = "0000000900010001"


def compact_uid(value):
    if value is None:
        return None
    return re.sub(r"[^0-9A-Fa-f]", "", str(value)).upper()


def normalize_status(value):
    if value is None:
        return None
    text = str(value).strip().lower().replace("-", "_").replace(" ", "_")
    if text in {"success", "pass", "passed"}:
        return "success"
    if text in {"not_authorized", "notauthorized"}:
        return "not_authorized"
    if text in {"invalid_parameter", "invalidparameter"}:
        return "invalid_parameter"
    if text in {"fail", "failed", "failure"}:
        return "fail"
    return text


def is_success_status(status):
    return normalize_status(status) == "success"


def canonical_sp(spid):
    spid = compact_uid(spid)
    if spid == ADMIN_SP:
        return "AdminSP"
    if spid == LOCKING_SP:
        return "LockingSP"
    return spid


def canonical_authority(uid):
    uid = compact_uid(uid)
    if uid == SID_AUTHORITY_UID:
        return "SID"
    if uid == ADMIN1_AUTHORITY_UID:
        return "Admin1"
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


def canonical_object(name, uid):
    uid = compact_uid(uid)
    if uid == SESSION_MANAGER_UID:
        return "SessionManager"
    if uid == LOCKING_SP_UID:
        return "LockingSP"
    if uid == BAD_LOCKING_SP_UID:
        return "NonLockingSP"
    if uid == C_PIN_MSID_UID:
        return "C_PIN_MSID"
    if uid == C_PIN_SID_UID:
        return "C_PIN_SID"
    if uid and uid.startswith("0000000B"):
        return f"C_PIN_{uid[-6:]}"
    if uid and uid.startswith("00000009"):
        return canonical_authority(uid)
    if uid == LOCKING_GLOBAL_UID:
        return "Locking_Global"
    if uid == LOCKING_RANGE1_UID:
        return "Locking_Range1"
    if uid == MBR_CONTROL_UID:
        return "MBRControl"
    if uid == LOCKING_INFO_UID:
        return "LockingInfo"
    if uid == RANGE1_KEY_UID:
        return "Range1_Key"
    if name:
        return str(name).replace(" ", "_")
    return uid


def normalize_lba(value):
    if value is None:
        return None
    numbers = [int(part) for part in re.findall(r"\d+", str(value))]
    if not numbers:
        return None
    if len(numbers) == 1:
        return (numbers[0], numbers[0])
    return (numbers[0], numbers[1])


def first_value(values, column=None):
    if not isinstance(values, list):
        return None
    for item in values:
        if not isinstance(item, dict):
            continue
        if column is None and item:
            return next(iter(item.values()))
        if str(column) in item:
            return item[str(column)]
        hex_column = f"0x{int(column):02X}" if isinstance(column, int) else None
        if hex_column and hex_column in item:
            return item[hex_column]
    return None


def extract_return_column(return_values, column):
    if isinstance(return_values, dict):
        return None
    if not isinstance(return_values, list):
        return None
    wanted = str(column)
    for outer in return_values:
        items = outer if isinstance(outer, list) else [outer]
        for item in items:
            if isinstance(item, dict) and wanted in item:
                return item[wanted]
    return None


def normalize_record(record):
    inp = record.get("input", {}) if isinstance(record, dict) else {}
    out = record.get("output", {}) if isinstance(record, dict) else {}
    method = inp.get("method")
    index = record.get("index") if isinstance(record, dict) else None

    if isinstance(method, dict):
        args = method.get("args") if isinstance(method.get("args"), dict) else {}
        required = args.get("required") if isinstance(args.get("required"), dict) else {}
        optional = args.get("optional") if isinstance(args.get("optional"), dict) else {}
        invoking = inp.get("invoking_id") if isinstance(inp.get("invoking_id"), dict) else {}
        uid = compact_uid(invoking.get("uid"))
        method_name = method.get("name")
        values = optional.get("Values")

        event = {
            "index": index,
            "kind": "method",
            "method": method_name,
            "object": canonical_object(invoking.get("name"), uid),
            "object_name": invoking.get("name"),
            "object_uid": uid,
            "sp": canonical_sp(required.get("SPID")),
            "write": bool(required.get("Write")) if "Write" in required else None,
            "authority": canonical_authority(optional.get("HostSigningAuthority")),
            "authority_uid": compact_uid(optional.get("HostSigningAuthority")),
            "challenge": optional.get("HostChallenge"),
            "values": values if isinstance(values, list) else [],
            "set_column_3": first_value(values, 3),
            "cellblock": required.get("Cellblock"),
            "return_column_3": extract_return_column(out.get("return_values"), 3),
            "status": normalize_status(out.get("status_codes")),
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
    return {
        "index": index,
        "kind": kind,
        "command": command,
        "lba": normalize_lba(in_args.get("LBA")),
        "pattern": in_args.get("pattern"),
        "result": out_args.get("result"),
        "status": normalize_status(out.get("status_codes")),
        "raw": record,
    }


def normalize_trajectory(steps):
    return [normalize_record(step) for step in steps]

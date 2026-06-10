import re

from .spec_docs import METHOD_NAMES, column_number_for_name, method_name_from_value


ADMIN_SP = "0000020500000001"
LOCKING_SP = "0000020500000002"

SESSION_MANAGER_UID = "00000000000000FF"
SESSION_MANAGER_ALIASES = {SESSION_MANAGER_UID, "0000000000000001"}
LOCKING_SP_UID = "0000020500000002"
BAD_LOCKING_SP_UID = "0000010500000004"

C_PIN_MSID_UID = "0000000B00008402"
C_PIN_SID_UID = "0000000B00000001"
LOCKING_GLOBAL_UID = "0000080200000001"
MBR_CONTROL_UID = "0000080300000001"
LOCKING_INFO_UID = "0000080100000001"

LOCKING_TABLE_UIDS = {
    "0000000100000001": "Table",
    "0000000100000002": "SPInfo",
    "0000000100000003": "SPTemplates",
    "0000000100000006": "MethodID",
    "0000000100000007": "AccessControl",
    "0000000100000008": "ACE",
    "0000000100000009": "Authority",
    "000000010000000B": "C_PIN",
    "000000010000001D": "SecretProtect",
    "0000000100000204": "Template",
    "0000000100000205": "SP",
    "0000000100000401": "ClockTime",
    "0000000100000801": "LockingInfo",
    "0000000100000802": "Locking",
    "0000000100000803": "MBRControl",
    "0000000100000804": "MBR",
    "0000000100000805": "K_AES_128_Key",
    "0000000100000806": "K_AES_256_Key",
    "0000000100000A01": "Log",
    "0000000100000A02": "LogList",
    "0000000100001001": "DataStore",
    "0000000100000201": "TPerInfo",
    "0000000100001101": "DataRemovalMechanism",
}

SID_AUTHORITY_UID = "0000000900000006"
ADMIN1_AUTHORITY_UID = "0000000900010001"
PSID_AUTHORITY_UID = "000000090001FF01"  # Physical Secure ID — Opal PSID Feature Set spec


STATUS_ALIASES = {
    "success": "success",
    "successful": "success",
    "ok": "success",
    "pass": "success",
    "passed": "success",
    "not_authorized": "not_authorized",
    "notauthorized": "not_authorized",
    "access_denied": "not_authorized",
    "invalid_parameter": "invalid_parameter",
    "invalidparameter": "invalid_parameter",
    "sp_busy": "sp_busy",
    "spbusy": "sp_busy",
    "sp_failed": "sp_failed",
    "sp_fail": "sp_failed",
    "spfailed": "sp_failed",
    "sp_disabled": "sp_disabled",
    "spdisabled": "sp_disabled",
    "sp_frozen": "sp_frozen",
    "spfrozen": "sp_frozen",
    "no_sessions_available": "no_sessions_available",
    "nosessionsavailable": "no_sessions_available",
    "uniqueness_conflict": "uniqueness_conflict",
    "uniquenessconflict": "uniqueness_conflict",
    "insufficient_space": "insufficient_space",
    "insufficientspace": "insufficient_space",
    "insufficient_rows": "insufficient_rows",
    "insufficientrows": "insufficient_rows",
    "insufficient_columns": "insufficient_columns",
    "insufficientcolumns": "insufficient_columns",
    "invalid_command": "invalid_command",
    "invalidcommand": "invalid_command",
    "unsupported": "unsupported",
    "tper_malfunction": "tper_malfunction",
    "tpermalfunction": "tper_malfunction",
    "transaction_failure": "transaction_failure",
    "transactionfailure": "transaction_failure",
    "response_overflow": "response_overflow",
    "responseoverflow": "response_overflow",
    "authority_locked_out": "authority_locked_out",
    "authoritylockedout": "authority_locked_out",
    "obsolete": "obsolete",
    "fail": "fail",
    "failed": "fail",
    "failure": "fail",
    "error": "fail",
}

# spec core/5.1.5 Table 166: numeric/hex status code to canonical name (additive support).
_STATUS_NUMERIC = {
    0: "success", 1: "not_authorized", 2: "obsolete", 3: "sp_busy", 4: "sp_failed",
    5: "sp_disabled", 6: "sp_frozen", 7: "no_sessions_available",
    8: "uniqueness_conflict", 9: "insufficient_space", 10: "insufficient_rows",
    12: "invalid_parameter", 13: "obsolete", 14: "obsolete",
    15: "tper_malfunction", 16: "transaction_failure",
    17: "response_overflow", 18: "authority_locked_out", 63: "fail",
}


def compact_uid(value):
    if value is None:
        return None
    text = str(value).strip()
    if re.match(r"^0[Xx]", text):
        text = text[2:]
    compacted = re.sub(r"[^0-9A-Fa-f]", "", text).upper()
    return compacted or None


def normalize_status(value):
    if value is None:
        return None
    # Integer status codes: spec core/5.1.5 Table 166.
    if isinstance(value, int):
        return _STATUS_NUMERIC.get(value, f"status_{value}")
    text = str(value).strip()
    # Hex string: "0x00", "0x0C", "0x3F", etc.
    if re.match(r"^0[Xx][0-9A-Fa-f]+$", text):
        try:
            return _STATUS_NUMERIC.get(int(text, 16), f"status_{text.lower()}")
        except ValueError:
            pass
    text = text.lower().replace("-", "_").replace(" ", "_")
    text = re.sub(r"_+", "_", text)
    return STATUS_ALIASES.get(text, text)


def is_success_status(status):
    return normalize_status(status) == "success"


def status_from(inp, out):
    output_status = normalize_status(dict_value(out, "status_codes") if isinstance(out, dict) else None)
    input_status = normalize_status(dict_value(inp, "status_codes") if isinstance(inp, dict) else None)
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


def sp_identity(value):
    """Resolve an SPID that may be an 8-byte UID in any hex formatting or a
    symbolic name ("AdminSP", "LockingSP"). Returns (canonical_sp, uid)."""
    if value is None:
        return None, None
    text = str(value).strip()
    if not text:
        return None, None
    hex_body = re.sub(r"^0[xX]", "", text)
    compact = re.sub(r"[^0-9A-Fa-f]", "", hex_body)
    if len(compact) == 16 and re.fullmatch(r"[0-9A-Fa-f\s:_\-]+", hex_body):
        compact = compact.upper()
        return canonical_sp(compact), compact
    token = re.sub(r"[^0-9a-z]", "", text.lower())
    if token in {"adminsp", "adminspuid"}:
        return "AdminSP", ADMIN_SP
    if token in {"lockingsp", "lockingspuid"}:
        return "LockingSP", LOCKING_SP
    return canonical_sp(value), compact_uid(value)


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
    if uid == PSID_AUTHORITY_UID:
        return "PSID"
    if uid == ADMIN1_AUTHORITY_UID:
        return "Admin1"
    if uid and uid.startswith("000000090001"):
        return f"Admin{int(uid[-4:], 16)}"
    if uid and uid.startswith("000000090003"):
        return f"User{int(uid[-4:], 16)}"
    # AdminSP admin authorities use a different UID range: 0000000900000201 (Admin1),
    # 0000000900000202 (Admin2), etc.  Map these before the generic fallback so that
    # session_has_admin_authority correctly recognises them as "Admin*" names.
    if uid and uid.startswith("00000009000002"):
        return f"Admin{int(uid[14:], 16)}"
    if uid and uid.startswith("00000009"):
        return f"Authority_{uid[-6:]}"
    return uid


_AUTHORITY_NAME_TOKENS = {
    "anybody": "Anybody",
    "admins": "Admins",
    "users": "Users",
    "makers": "Makers",
    "sid": "SID",
    "msid": "MSID",
    "psid": "PSID",
}


def _authority_name_from_token(token):
    """Canonical authority name for a compact lowercase token, else None."""
    if token in _AUTHORITY_NAME_TOKENS:
        return _AUTHORITY_NAME_TOKENS[token]
    match = re.fullmatch(r"(admin|user)(\d+)", token)
    if match:
        return f"{match.group(1).title()}{int(match.group(2))}"
    return None


def authority_identity(value):
    """Resolve an authority parameter that may be an 8-byte UID in any hex
    formatting or a symbolic name ("Admin1", "SID"). Returns (name, uid)."""
    if value is None:
        return None, None
    if isinstance(value, (bytes, bytearray)):
        uid = value.hex().upper()
        return canonical_authority(uid), uid
    text = str(value).strip()
    if not text:
        return None, None
    hex_body = re.sub(r"^0[xX]", "", text)
    compact = re.sub(r"[^0-9A-Fa-f]", "", hex_body)
    if len(compact) == 16 and re.fullmatch(r"[0-9A-Fa-f\s:_\-]+", hex_body):
        compact = compact.upper()
        return canonical_authority(compact), compact
    token = re.sub(r"[^0-9a-z]", "", text.lower())
    name = _authority_name_from_token(token)
    if name:
        return name, None
    uid = compact_uid(value)
    return canonical_authority(uid), uid


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


def locking_range_from_name(name):
    """Resolve a Locking-range identity from an object *name* when the trace
    omits the UID: "Locking_GlobalRange" -> "Global", "Locking Range1" -> "Range1"."""
    if not name:
        return None
    token = re.sub(r"[^0-9a-z]", "", str(name).lower())
    if token.startswith("lockinginfo"):
        return None
    if not (token.startswith("locking") or token.endswith("range") or "range" in token):
        return None
    if "global" in token:
        return "Global"
    match = re.search(r"range(\d+)", token)
    if match and (token.startswith("locking") or token.startswith("range")):
        return f"Range{int(match.group(1))}"
    return None


def credential_authority_from_object(obj):
    """C_PIN_<Authority> object names map to the credential they store."""
    if not isinstance(obj, str) or not obj.startswith("C_PIN_"):
        return None
    suffix = obj[len("C_PIN_"):]
    return _authority_name_from_token(re.sub(r"[^0-9a-z]", "", suffix.lower()))


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
    if uid in SESSION_MANAGER_ALIASES:
        return "SessionManager"
    if name and "session" in name.lower() and "manager" in name.lower():
        return "SessionManager"
    if uid == LOCKING_SP_UID:
        return "LockingSP"
    if uid == BAD_LOCKING_SP_UID:
        return "NonLockingSP"
    if uid and uid.startswith("00000205"):
        return canonical_sp(uid)
    if uid in LOCKING_TABLE_UIDS:
        return LOCKING_TABLE_UIDS[uid]
    if uid == C_PIN_MSID_UID:
        return "C_PIN_MSID"
    if uid == C_PIN_SID_UID:
        return "C_PIN_SID"
    if uid and uid.startswith("0000000B"):
        authority = authority_uid_for_cpin(uid)
        if authority and not authority.startswith("Authority_"):
            return f"C_PIN_{authority}"
        return f"C_PIN_{uid[-6:]}"
    if uid and uid.startswith("00000006"):
        return "MethodID"
    if uid and uid.startswith("00000007"):
        return "AccessControl"
    if uid and uid.startswith("00000008"):
        return "ACE"
    if uid and uid.startswith("00000009"):
        return canonical_authority(uid)
    if uid and uid.startswith("00000401"):
        return "ClockTime"
    if uid and uid.startswith("00000801"):
        return "LockingInfo"
    if uid and uid.startswith("00000802"):
        locking_range = locking_range_from_uid(uid)
        if locking_range == "Global":
            return "Locking_Global"
        return f"Locking_{locking_range}"
    if uid and uid.startswith("00000803"):
        return "MBRControl"
    if uid and uid.startswith("00000804"):
        return "MBR"
    if uid and uid.startswith("00000805"):
        key_range = media_key_range_from_uid(uid)
        return f"{key_range}_Key" if key_range else "K_AES_128_Key"
    if uid and uid.startswith("00000806"):
        key_range = media_key_range_from_uid(uid)
        return f"{key_range}_Key" if key_range else "K_AES_256_Key"
    if uid and uid.startswith("00000A01"):
        return "Log"
    if uid and uid.startswith("00000A02"):
        return "LogList"
    if uid and uid.startswith("00001001"):
        return "DataStore"
    if uid and uid.startswith("0000001D"):
        return "SecretProtect"
    if uid and uid.startswith("00000201"):
        return "TPerInfo"
    if uid and uid.startswith("00001101"):
        return "DataRemovalMechanism"

    if name:
        normalized_name = str(name).strip().replace(" ", "_")
        lower_name = normalized_name.lower()
        token = re.sub(r"[^0-9a-z]", "", lower_name)
        if token == "adminsp":
            return "AdminSP"
        if token == "lockingsp":
            return "LockingSP"
        if token.startswith("cpin"):
            # canonicalize C_PIN object names: "c_pin_sid" -> "C_PIN_SID",
            # "C PIN Admin1" -> "C_PIN_Admin1"
            authority = _authority_name_from_token(token[4:]) if token[4:] else None
            if authority:
                return f"C_PIN_{authority}"
            if not token[4:]:
                return "C_PIN"
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
        if lower_name == "clocktime":
            return "ClockTime"
        if lower_name == "log":
            return "Log"
        if lower_name in {"loglist", "log_list"}:
            return "LogList"
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
    if obj and (obj in {"SID", "Anybody", "Admins", "Users"} or obj.startswith("Admin") or obj.startswith("User") or obj.startswith("Authority_")):
        return "Authority"
    if uid and uid.startswith("00000006"):
        return "MethodID"
    if uid and uid.startswith("00000007"):
        return "AccessControl"
    if uid and uid.startswith("00000008"):
        return "ACE"
    if uid and uid.startswith("00000401"):
        return "ClockTime"
    if obj == "LockingInfo":
        return "LockingInfo"
    if obj and obj.startswith("Locking_"):
        return "Locking"
    if obj == "MBRControl":
        return "MBRControl"
    if uid and uid in LOCKING_TABLE_UIDS:
        mapped = LOCKING_TABLE_UIDS[uid]
        if mapped in {"K_AES_128_Key", "K_AES_256_Key"}:
            return "MediaKey"
        return mapped
    if uid and (uid.startswith("00000805") or uid.startswith("00000806")):
        return "MediaKey"
    if uid and uid.startswith("00000804"):
        return "MBR"
    if uid and uid.startswith("00000A01"):
        return "Log"
    if uid and uid.startswith("00000A02"):
        return "LogList"
    if uid and uid.startswith("00001001"):
        return "DataStore"
    if uid and uid.startswith("0000001D"):
        return "SecretProtect"
    if uid and uid.startswith("00000201"):
        return "TPerInfo"
    if uid and uid.startswith("00000204"):
        return "Template"
    if uid and uid.startswith("00001101"):
        return "DataRemovalMechanism"
    if obj in {"ACE", "AccessControl", "Column", "MethodID", "Table", "SPInfo", "SPTemplates", "Template", "SecretProtect", "DataStore", "MBR", "ClockTime", "Log", "LogList", "TPerInfo", "DataRemovalMechanism"}:
        return obj
    if obj and obj.endswith("_Key"):
        return "MediaKey"
    return None


def object_family_from_uid(uid):
    uid = compact_uid(uid)
    if not uid:
        return None
    return object_family(uid, canonical_object(None, uid))


def object_family_from_name(name):
    if name is None:
        return None
    token = normalized_key_token(name)
    if "sessionmanager" in token:
        return "SessionManager"
    if token in {"adminsp", "lockingsp"} or token.endswith("sp"):
        return "SP"
    if token.startswith("cpin") or token == "cpin":
        return "C_PIN"
    if token.startswith("mbrcontrol"):
        return "MBRControl"
    if token == "mbr" or token.startswith("mbrtable"):
        return "MBR"
    if token.startswith("lockinginfo"):
        return "LockingInfo"
    if token.startswith("locking"):
        return "Locking"
    if token in {"sid", "anybody", "admins", "users", "authority"} or token.startswith("admin") or token.startswith("user"):
        return "Authority"
    if token.startswith("mediakey") or token.startswith("kaes") or token.endswith("key"):
        return "MediaKey"
    return None


def object_families_compatible(left, right):
    if left == right:
        return True
    media_key_aliases = {"K_AES_128_Key", "K_AES_256_Key", "MediaKey"}
    if left in media_key_aliases and right in media_key_aliases:
        return True
    return False


def _has_any_parameter(required, optional, *names):
    return arg_value(required, optional, *names) is not None


def _return_values_nonempty(out):
    if not isinstance(out, dict):
        return False
    values = out.get("return_values")
    return values not in (None, {}, [])


# Case/spacing-insensitive lookup of spec method names: "STARTSESSION",
# "start_session", and "Start Session" must all dispatch to judge_start_session
# instead of silently falling through to the heuristic fallback.
_METHOD_NAME_CANONICAL = {
    re.sub(r"[^0-9a-z]", "", name.lower()): name for name in METHOD_NAMES
}


def canonical_method_name(name):
    if name is None:
        return None
    text = str(name).strip()
    if not text:
        return None
    token = re.sub(r"[^0-9a-z]", "", text.lower())
    return _METHOD_NAME_CANONICAL.get(token, text)


def infer_method_name(method_uid, obj, family, required, optional, out):
    """Infer stripped method names only when the UID is missing or ambiguous."""
    compact = compact_uid(method_uid)
    if compact and compact not in {"0000000600000016"}:
        return method_name_from_value(method_uid)

    if _has_any_parameter(required, optional, "SPID", "HostSessionID", "Write"):
        return "StartSession"
    if _has_any_parameter(required, optional, "Proof", "Authority", "HostSigningAuthority", "HostChallenge"):
        if obj == "SessionManager":
            return "Authenticate"
    if _has_any_parameter(required, optional, "Values"):
        return "Set"
    if _has_any_parameter(required, optional, "Cellblock", "Count", "Where"):
        return "Get"

    if family == "AccessControl":
        if _has_any_parameter(required, optional, "ACE"):
            return "AddACE"
        if _has_any_parameter(required, optional, "InvokingID", "MethodID"):
            return "GetACL"
    if family == "LogList" or _has_any_parameter(required, optional, "NewLogTableName"):
        return "CreateLog"
    if family == "Log" or _has_any_parameter(required, optional, "LogEntryName", "Data"):
        return "AddLog"
    if family == "SP" or obj == "NonLockingSP":
        if _has_any_parameter(required, optional, "KeepGlobalRangeKey"):
            return "RevertSP"
        return "Activate"
    if family in {"MediaKey", "C_PIN"}:
        return "GenKey"
    if obj == "SessionManager":
        if _return_values_nonempty(out):
            return "Properties"
        return "EndSession"
    if not compact and obj is None and not required and not optional:
        return "EndSession"

    return method_name_from_value(method_uid)


def normalize_lba(value):
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return (value, value)
    if isinstance(value, (list, tuple)):
        numbers = [to_int(item) for item in value]
        numbers = [n for n in numbers if n is not None]
        if not numbers:
            return None
        if len(numbers) == 1:
            return (numbers[0], numbers[0])
        return (numbers[0], numbers[1])
    # Hex-aware tokenization: "0x50 ~ 0x57" must parse as (80, 87), not (0, 50).
    tokens = re.findall(r"0[xX][0-9A-Fa-f]+|\d+", str(value))
    numbers = [
        int(token, 16) if token.lower().startswith("0x") else int(token)
        for token in tokens
    ]
    if not numbers:
        return None
    if len(numbers) == 1:
        return (numbers[0], numbers[0])
    return (numbers[0], numbers[1])


ARG_KEY_ALIASES = {
    "hostsessionid": "HostSessionID",
    "spsessionid": "SPSessionID",
    "spid": "SPID",
    "write": "Write",
    "hostsigningauthority": "HostSigningAuthority",
    "authority": "Authority",
    "signingauthority": "SigningAuthority",
    "hostexchangeauthority": "HostExchangeAuthority",
    "spexchangeauthority": "SPExchangeAuthority",
    "spsigningauthority": "SPSigningAuthority",
    "hostchallenge": "HostChallenge",
    "challenge": "Challenge",
    "proof": "Proof",
    "cellblock": "Cellblock",
    "where": "Where",
    "count": "Count",
    "keepglobalrangekey": "KeepGlobalRangeKey",
    "values": "Values",
    "hostproperties": "HostProperties",
    "remotesessionnumber": "RemoteSessionNumber",
    "localsessionnumber": "LocalSessionNumber",
    "sessiontimeout": "SessionTimeout",
    "transtimeout": "TransTimeout",
    "initialcredit": "InitialCredit",
    "minsize": "MinSize",
    "maxsize": "MaxSize",
    "hintsize": "HintSize",
    "invokingid": "InvokingID",
    "methodid": "MethodID",
    "ace": "ACE",
    "newtablename": "NewTableName",
    "kind": "Kind",
    "getsetacl": "GetSetACL",
    "columns": "Columns",
    "row": "Row",
    "rows": "Rows",
    "purpose": "Purpose",
    "value": "Value",
    "input": "Input",
    "patterninput": "PatternInput",
    "deletepattern": "DeletePattern",
    "internal": "Internal",
    "exacttime": "ExactTime",
    "lagtime": "LagTime",
    "logentryname": "LogEntryName",
    "data": "Data",
    "newlogtablename": "NewLogTableName",
    "highsecurity": "HighSecurity",
    "spname": "SPName",
    "templates": "Templates",
}


def normalized_key_token(key):
    return re.sub(r"[^0-9a-z]", "", str(key or "").lower())


def canonical_arg_key(key):
    return ARG_KEY_ALIASES.get(normalized_key_token(key), key)


def canonicalize_arg_dict(args):
    if not isinstance(args, dict):
        return {}
    normalized = {}
    for key, value in args.items():
        canonical = canonical_arg_key(key)
        normalized[canonical] = value
    return normalized


def dict_value(source, *names):
    if not isinstance(source, dict):
        return None
    for name in names:
        if name in source:
            return source[name]
    wanted = {normalized_key_token(name) for name in names}
    for key, value in source.items():
        if normalized_key_token(key) in wanted:
            return value
    return None


# spec core/5.2.3.1, 5.3.4.1: required method parameters are positional in the
# method-call encoding; named keys in traces are a generator convenience. When a
# trace encodes "required" as a plain list, recover the names from the method's
# spec signature instead of dropping the parameters.
_POSITIONAL_REQUIRED_SIGNATURES = {
    "StartSession": ("HostSessionID", "SPID", "Write"),
    "SyncSession": ("HostSessionID", "SPSessionID"),
    "StartTrustedSession": ("HostSessionID", "SPSessionID"),
    "SyncTrustedSession": ("HostSessionID", "SPSessionID"),
    "CloseSession": ("RemoteSessionNumber", "LocalSessionNumber"),
    "Authenticate": ("Authority", "Proof"),
    "Random": ("Count",),
}


def _args_from_list(items, method_name=None):
    """Merge a list-form parameter encoding: dict items carry named values,
    scalar items are positional and mapped via the method signature."""
    named = {}
    signature = _POSITIONAL_REQUIRED_SIGNATURES.get(method_name or "", ())
    position = 0
    for item in items:
        if isinstance(item, dict):
            named.update(canonicalize_arg_dict(item))
            continue
        if position < len(signature):
            named.setdefault(signature[position], item)
        position += 1
    return named


def normalize_args(args, method_name=None):
    if isinstance(args, dict):
        required_raw = dict_value(args, "required")
        optional_raw = dict_value(args, "optional")
        if isinstance(required_raw, list):
            required = _args_from_list(required_raw, method_name)
        else:
            required = canonicalize_arg_dict(required_raw)
        if isinstance(optional_raw, list):
            optional = _args_from_list(optional_raw, method_name)
        else:
            optional = canonicalize_arg_dict(optional_raw)
        for key, value in args.items():
            if normalized_key_token(key) in {"required", "optional"}:
                continue
            optional.setdefault(canonical_arg_key(key), value)
        return required, optional
    if isinstance(args, list):
        optional = {}
        for item in args:
            if isinstance(item, dict):
                optional.update(canonicalize_arg_dict(item))
        if method_name and not optional:
            positional = _args_from_list(args, method_name)
            if positional:
                return positional, {}
        return {}, optional
    return {}, {}


def arg_value(required, optional, *names):
    for name in names:
        if isinstance(required, dict) and name in required:
            return required[name]
        if isinstance(optional, dict) and name in optional:
            return optional[name]
    wanted = {normalized_key_token(name) for name in names}
    for source in (required, optional):
        if not isinstance(source, dict):
            continue
        for key, value in source.items():
            if normalized_key_token(key) in wanted:
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


def duplicate_column_keys(value, family=None):
    columns = []
    for item in iter_value_dicts(value):
        for key in item:
            column = column_number(key, family)
            if column is not None:
                columns.append(column)
    return len(columns) != len(set(columns))


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


# spec core/5.3.2.3 Table 168: Cellblock fields are Table(0), startRow(1),
# endRow(2), startColumn(3), endColumn(4). A cellblock that addresses rows only
# (byte-table reads) is valid even though it names no columns.
_CELLBLOCK_FIELDS = {
    "table": "table",
    "0": "table",
    "0x00": "table",
    "startrow": "start_row",
    "1": "start_row",
    "0x01": "start_row",
    "endrow": "end_row",
    "2": "end_row",
    "0x02": "end_row",
    "startcolumn": "start_column",
    "3": "start_column",
    "0x03": "start_column",
    "0x3": "start_column",
    "endcolumn": "end_column",
    "4": "end_column",
    "0x04": "end_column",
    "0x4": "end_column",
}


def _cellblock_field(key):
    token = re.sub(r"[^0-9a-z]", "", str(key).lower())
    # restore the 0x prefix lost by token stripping for hex-style keys
    if token not in _CELLBLOCK_FIELDS and str(key).strip().lower().startswith("0x"):
        token = str(key).strip().lower()
    return _CELLBLOCK_FIELDS.get(token)


def normalize_cellblock(cellblock, family=None):
    start = None
    end = None
    start_row = None
    end_row = None
    invalid = False
    saw_field = False
    items = []
    if isinstance(cellblock, dict):
        items = [cellblock]
    elif isinstance(cellblock, list):
        for item in cellblock:
            if isinstance(item, dict):
                items.append(item)
            else:
                invalid = True
    for item in items:
        for key, value in item.items():
            field = _cellblock_field(key)
            if field is None:
                continue
            saw_field = True
            if field == "start_column":
                start = column_number(value, family)
                invalid = invalid or start is None
            elif field == "end_column":
                end = column_number(value, family)
                invalid = invalid or end is None
            elif field == "start_row":
                start_row = to_int(value)
            elif field == "end_row":
                end_row = to_int(value)

    if start is None and end is not None:
        start = end
    if end is None and start is not None:
        end = start
    columns = list(range(start, end + 1)) if start is not None and end is not None and start <= end else []
    if cellblock is not None and not saw_field:
        invalid = True
    return {
        "raw": cellblock,
        "start": start,
        "end": end,
        "start_row": start_row,
        "end_row": end_row,
        "columns": columns,
        "invalid": invalid,
    }


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


def _strip_tcg_atom_header(hex_text):
    """Strip a single leading TCG bytes-atom header (core/3.2.2.3) from compact
    upper-hex text, only when the encoded length exactly matches the payload.

    Short atom:  1-byte header 0b10_B_S_LLLL (bytes atoms 0xA0-0xBF).
    Medium atom: 2-byte header 0b110_B_S_LLL + 1 length byte (bytes atoms 0xD0-0xD7).
    Long atom:   4-byte header 0b111000_B_S + 3 length bytes (bytes atoms 0xE2-0xE3).
    """
    if not hex_text or len(hex_text) % 2 != 0 or len(hex_text) < 4:
        return None
    try:
        first = int(hex_text[0:2], 16)
    except ValueError:
        return None
    body_len = len(hex_text) // 2
    if 0xA0 <= first <= 0xBF:  # short bytes atom
        if (first & 0x0F) == body_len - 1:
            return hex_text[2:]
        return None
    if 0xD0 <= first <= 0xD7 and len(hex_text) >= 6:  # medium bytes atom
        try:
            length = ((first & 0x07) << 8) | int(hex_text[2:4], 16)
        except ValueError:
            return None
        if length == body_len - 2:
            return hex_text[4:]
        return None
    if first in {0xE2, 0xE3} and len(hex_text) >= 10:  # long bytes atom
        try:
            length = int(hex_text[2:8], 16)
        except ValueError:
            return None
        if length == body_len - 4:
            return hex_text[8:]
    return None


def canonical_credential(value):
    """Canonicalize a credential/challenge value for comparison.

    Returns compact upper-hex for byte-like encodings (bytes, int lists,
    hex strings with any 0x/case/spacing) and the stripped text itself for
    plain-text PINs. Comparison must use credentials_equal(), which also
    bridges text-vs-hex-of-text and atom-header-wrapped encodings.
    """
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        return value.hex().upper()
    if isinstance(value, list) and value and all(
        isinstance(item, int) and 0 <= item <= 255 for item in value
    ):
        return "".join(f"{item:02X}" for item in value)
    if isinstance(value, str):
        text = value.strip()
        if re.match(r"^0[Xx]", text):
            text = text[2:]
        compact = re.sub(r"[\s:,-]+", "", text)
        if compact and len(compact) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", compact):
            return compact.upper()
        return text
    return value


def _credential_forms(value):
    canon = canonical_credential(value)
    forms = {canon}
    if isinstance(canon, str) and canon:
        if re.fullmatch(r"[0-9A-F]+", canon) and len(canon) % 2 == 0:
            stripped = _strip_tcg_atom_header(canon)
            if stripped:
                forms.add(stripped)
        else:
            # plain-text PIN: also match its byte-hex spelling
            forms.add(canon.encode("utf-8", errors="ignore").hex().upper())
    forms.discard(None)
    return forms


def credentials_equal(left, right):
    """Tolerant credential equality across encodings of the same byte value."""
    if left == right:
        return True
    if left is None or right is None:
        return False
    return bool(_credential_forms(left) & _credential_forms(right))


def credential_is_empty(value):
    return value is None or value == "" or value == b"" or value == []


def byte_length(value):
    raw = find_named_value(value, {"Bytes"})
    if raw is None:
        raw = value
    if isinstance(raw, (bytes, bytearray)):
        return len(raw)
    if isinstance(raw, list):
        return len(raw)
    if isinstance(raw, str):
        text = raw.strip()
        if text.lower().startswith("0x"):
            text = text[2:]
        compact = re.sub(r"\s+", "", text)
        if compact and len(compact) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", compact):
            return len(compact) // 2
        return len(text)
    return None


def _parse_feature_code(val):
    """Return feature code as int, accepting int or hex/decimal string."""
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        s = val.strip()
        try:
            return int(s, 16) if s.startswith("0x") or s.startswith("0X") else int(s)
        except ValueError:
            pass
    return None


def _normalize_discovery(record, index, inp, out, in_args, disc_raw):
    """Normalize an IF_RECV Level 0 Discovery record into a 'discovery' kind event."""
    # disc_raw may be a dict with a 'features' list, or directly a list of feature dicts.
    def _first_present(source, *keys):
        for key in keys:
            if key in source:
                return source.get(key)
        return None

    if isinstance(disc_raw, dict):
        features_raw = disc_raw.get("features") or []
        discovery_header = {
            "length_of_parameter_data": _first_present(disc_raw, "length_of_parameter_data", "LengthOfParameterData", "length"),
            "major_version": _first_present(disc_raw, "major_version", "MajorVersion", "major"),
            "minor_version": _first_present(disc_raw, "minor_version", "MinorVersion", "minor"),
            "reserved": _first_present(disc_raw, "reserved", "Reserved", "reserved_8_15", "Reserved8_15"),
            "truncated": _first_present(disc_raw, "truncated", "Truncated", "partial", "Partial", "is_truncated"),
            "complete": _first_present(disc_raw, "complete", "Complete", "non_truncated", "NonTruncated", "exact_length", "ExactLength"),
        }
    elif isinstance(disc_raw, list):
        features_raw = disc_raw
        discovery_header = {}
    else:
        features_raw = []
        discovery_header = {}

    features = {}
    feature_codes = []
    duplicate_feature_codes = []
    for feat in features_raw:
        if not isinstance(feat, dict):
            continue
        code = _parse_feature_code(
            feat.get("feature_code") or feat.get("feature") or feat.get("code")
        )
        if code is not None:
            if code in features and code not in duplicate_feature_codes:
                duplicate_feature_codes.append(code)
            feature_codes.append(code)
            features[code] = feat

    result = dict_value(out, "result") if isinstance(out, dict) else None
    result_ok = str(result or "").strip().lower() in {"pass", "success", "ok", ""}
    return {
        "index": index,
        "kind": "discovery",
        "command": dict_value(inp, "command"),
        "result": result,
        "result_ok": result_ok,
        "features": features,
        "feature_codes": feature_codes,
        "duplicate_feature_codes": duplicate_feature_codes,
        "discovery_header": {k: v for k, v in discovery_header.items() if v is not None},
        "input_status": normalize_status(dict_value(inp, "status_codes")),
        "output_status": normalize_status(dict_value(out, "status_codes")),
        "status": status_from(inp, out),
        "raw": record,
    }


def normalize_record(record):
    inp = dict_value(record, "input") if isinstance(record, dict) else {}
    out = dict_value(record, "output") if isinstance(record, dict) else {}
    inp = inp if isinstance(inp, dict) else {}
    out = out if isinstance(out, dict) else {}
    method = dict_value(inp, "method")
    index = dict_value(record, "index") if isinstance(record, dict) else None

    if isinstance(method, dict):
        method_name_hint = canonical_method_name(
            dict_value(method, "name")
        ) or method_name_from_value(dict_value(method, "uid"))
        required, optional = normalize_args(dict_value(method, "args"), method_name_hint)
        invoking_raw = dict_value(inp, "invoking_id")
        invoking = invoking_raw if isinstance(invoking_raw, dict) else {}
        uid = compact_uid(dict_value(invoking, "uid"))
        obj = canonical_object(dict_value(invoking, "name"), uid)
        family = object_family(uid, obj)
        values = arg_value(required, optional, "Values")
        value_columns = extract_columns(values, family)
        return_values = dict_value(out, "return_values")
        return_columns = extract_columns(return_values, family)
        cellblock = normalize_cellblock(arg_value(required, optional, "Cellblock"), family)
        authority_name, authority_uid = authority_identity(
            arg_value(required, optional, "HostSigningAuthority", "Authority", "SigningAuthority")
        )
        host_exchange_name, host_exchange_uid = authority_identity(
            arg_value(required, optional, "HostExchangeAuthority")
        )
        sp_exchange_name, sp_exchange_uid = authority_identity(
            arg_value(required, optional, "SPExchangeAuthority")
        )
        sp_signing_name, sp_signing_uid = authority_identity(
            arg_value(required, optional, "SPSigningAuthority")
        )
        host_challenge = arg_value(required, optional, "HostChallenge", "Challenge")
        proof = arg_value(required, optional, "Proof", "HostChallenge", "Challenge")
        auth_result = find_named_value(return_values, {"Success", "Result"})
        parameters = {}
        parameters.update(required)
        parameters.update(optional)

        method_uid_raw = dict_value(method, "uid")
        explicit_method_name = canonical_method_name(dict_value(method, "name"))
        method_name = explicit_method_name or infer_method_name(method_uid_raw, obj, family, required, optional, out)
        # TCG EndSession: host-side session close has no formal MethodID UID and may
        # appear as null name + null UID when the name field is omitted by the generator.
        # Detect by: both method UID and invoking_id UID are absent (null).
        if not method_name and method_uid_raw is None and not uid:
            method_name = "EndSession"
        object_name_family = object_family_from_name(dict_value(invoking, "name"))
        object_uid_family = object_family_from_uid(uid)
        name_uid_conflict = bool(
            object_name_family
            and object_uid_family
            and not object_families_compatible(object_name_family, object_uid_family)
        )

        event = {
            "index": index,
            "kind": "method",
            "method": method_name,
            "method_inferred": not bool(explicit_method_name),
            "method_uid": compact_uid(method_uid_raw),
            "object": obj,
            "object_family": family,
            "object_name": dict_value(invoking, "name"),
            "object_name_family": object_name_family,
            "object_uid": uid,
            "object_uid_family": object_uid_family,
            "name_uid_conflict": name_uid_conflict,
            "spid": sp_identity(arg_value(required, optional, "SPID"))[1],
            "sp": sp_identity(arg_value(required, optional, "SPID"))[0],
            "write": to_bool(arg_value(required, optional, "Write")) if arg_value(required, optional, "Write") is not None else None,
            "authority": authority_name,
            "authority_uid": authority_uid,
            "host_exchange_authority_uid": host_exchange_uid,
            "host_exchange_authority": host_exchange_name,
            "sp_exchange_authority_uid": sp_exchange_uid,
            "sp_exchange_authority": sp_exchange_name,
            "sp_signing_authority_uid": sp_signing_uid,
            "sp_signing_authority": sp_signing_name,
            "challenge": host_challenge,
            "proof": proof,
            "auth_result": to_bool(auth_result),
            "parameters": parameters,
            "required_parameters": required,
            "optional_parameters": optional,
            "where": arg_value(required, optional, "Where"),
            "count": to_int(arg_value(required, optional, "Count")),
            "keep_global_range_key": to_bool(arg_value(required, optional, "KeepGlobalRangeKey")),
            "values": values if isinstance(values, (list, dict)) else [],
            "value_columns": value_columns,
            "value_columns_duplicate": duplicate_column_keys(values, family),
            "value_byte_length": byte_length(values),
            "set_column_3": value_columns.get(3),
            "cellblock": cellblock["raw"],
            "cellblock_start": cellblock["start"],
            "cellblock_end": cellblock["end"],
            "cellblock_start_row": cellblock["start_row"],
            "cellblock_end_row": cellblock["end_row"],
            "cellblock_columns": cellblock["columns"],
            "cellblock_invalid": cellblock["invalid"],
            "value_columns_invalid": unrecognized_column_keys(values, family),
            "return_columns": return_columns,
            "return_column_3": return_columns.get(3),
            "input_status": normalize_status(dict_value(inp, "status_codes")),
            "output_status": normalize_status(dict_value(out, "status_codes")),
            "status": status_from(inp, out),
            "locking_range": locking_range_from_uid(uid)
            or (
                locking_range_from_name(dict_value(invoking, "name"))
                if family == "Locking"
                else None
            ),
            "key_range": media_key_range_from_uid(uid),
            "raw": record,
        }
        event["credential_authority"] = authority_uid_for_cpin(uid) or credential_authority_from_object(obj)
        return event

    command = dict_value(inp, "command")
    in_args_raw = dict_value(inp, "args")
    out_args_raw = dict_value(out, "args")
    in_args = in_args_raw if isinstance(in_args_raw, dict) else {}
    out_args = out_args_raw if isinstance(out_args_raw, dict) else {}

    # Level 0 Discovery: IF_RECV with a "discovery" payload in the output.
    if str(command or "").strip().upper() in {"IF_RECV", "IFRECEIVE", "IF-RECV"}:
        disc = dict_value(out, "discovery") if isinstance(out, dict) else None
        if disc is None:
            disc = dict_value(out, "descriptors") if isinstance(out, dict) else None
        if disc is not None:
            return _normalize_discovery(record, index, inp, out, in_args, disc)

    kind = str(command).strip().lower() if command else "unknown"
    if kind not in {"read", "write"}:
        kind = "command"
    result = dict_value(out_args, "result")
    if result is None and isinstance(out, dict):
        result = dict_value(out, "result")
    return {
        "index": index,
        "kind": kind,
        "command": command,
        "lba": normalize_lba(dict_value(in_args, "LBA")),
        "pattern": dict_value(in_args, "pattern", "Pattern"),
        "result": result,
        "input_status": normalize_status(dict_value(inp, "status_codes")),
        "output_status": normalize_status(dict_value(out, "status_codes")),
        "status": status_from(inp, out),
        "raw": record,
    }


def normalize_trajectory(steps):
    return [normalize_record(step) for step in steps]

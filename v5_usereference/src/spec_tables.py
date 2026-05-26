"""
spec_tables.py — TCG Storage / Opal SSC table definitions for v5 solver.

Defines UIDs, authority names, object semantics, and access-control policies
used by the rule-based component of solver.py.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# ─────────────────────────────────────────────────────────────
# SP UIDs (Opal SSC spec, Table 15 — SP Preconfiguration)
# ─────────────────────────────────────────────────────────────
ADMIN_SP = "0000020500000001"
LOCKING_SP = "0000020500000002"

# ─────────────────────────────────────────────────────────────
# Authority UIDs
# ─────────────────────────────────────────────────────────────
# Common / class authorities (both SPs)
ANYBODY_AUTHORITY = "0000000900000001"   # Opal UID for Anybody — no authentication required
SID_AUTHORITY = "0000000900000006"       # Storage Identification — owner authority

# Admin SP authorities
MAKERS_AUTHORITY       = "0000000900000004"  # Opal Makers authority
ADMINS_AUTHORITY_ADSP  = "0000000900000002"  # Admins class in AdminSP
PSID_AUTHORITY         = "000000090001FF01"  # Physical-layer revert authority (not TCG method)
ADMIN_SP_ADMIN1        = "0000000900000201"  # Admin1 within AdminSP (if present)

# Locking SP class authorities
ADMINS_AUTHORITY   = "0000000900000002"  # Admins class (shared across SPs)
USERS_AUTHORITY    = "0000000900030000"  # Users class
LOCKING_USER0      = "0000000900030000"  # == Users class UID in Opal

# Locking SP Admin1–Admin4
LOCKING_ADMIN1_AUTHORITY = "0000000900010001"
LOCKING_ADMIN2_AUTHORITY = "0000000900010002"
LOCKING_ADMIN3_AUTHORITY = "0000000900010003"
LOCKING_ADMIN4_AUTHORITY = "0000000900010004"

# Locking SP User1–User8 (common range)
LOCKING_USER1_AUTHORITY = "0000000900030001"
LOCKING_USER2_AUTHORITY = "0000000900030002"
LOCKING_USER3_AUTHORITY = "0000000900030003"
LOCKING_USER4_AUTHORITY = "0000000900030004"
LOCKING_USER5_AUTHORITY = "0000000900030005"
LOCKING_USER6_AUTHORITY = "0000000900030006"
LOCKING_USER7_AUTHORITY = "0000000900030007"
LOCKING_USER8_AUTHORITY = "0000000900030008"

# ─────────────────────────────────────────────────────────────
# C_PIN UIDs (credential objects)
# ─────────────────────────────────────────────────────────────
C_PIN_MSID          = "0000000B00008402"  # MSID (factory default, read-only by design)
C_PIN_SID           = "0000000B00000001"  # SID credential (AdminSP)
C_PIN_ADMIN_SP_ADM1 = "0000000B00000201"  # Admin1 credential in AdminSP
C_PIN_LOCKING_ADM1  = "0000000B00010001"  # Admin1 credential in LockingSP
C_PIN_LOCKING_ADM2  = "0000000B00010002"
C_PIN_LOCKING_ADM3  = "0000000B00010003"
C_PIN_LOCKING_ADM4  = "0000000B00010004"
C_PIN_LOCKING_USR1  = "0000000B00030001"  # User1 credential in LockingSP
C_PIN_LOCKING_USR2  = "0000000B00030002"
C_PIN_LOCKING_USR3  = "0000000B00030003"
C_PIN_LOCKING_USR4  = "0000000B00030004"

# ─────────────────────────────────────────────────────────────
# Locking / MBR UIDs
# ─────────────────────────────────────────────────────────────
LOCKING_GLOBAL_RANGE = "0000080200000001"
LOCKING_RANGE1       = "0000080200030001"
LOCKING_RANGE2       = "0000080200030002"
LOCKING_RANGE3       = "0000080200030003"
LOCKING_RANGE4       = "0000080200030004"
MBRCONTROL_UID       = "0000080300000001"

# ─────────────────────────────────────────────────────────────
# Human-readable name maps (debug only)
# ─────────────────────────────────────────────────────────────
AUTHORITY_NAMES: dict[str, str] = {
    ANYBODY_AUTHORITY:        "Anybody",
    SID_AUTHORITY:            "SID",
    PSID_AUTHORITY:           "PSID",
    MAKERS_AUTHORITY:         "Makers",
    ADMINS_AUTHORITY:         "Admins",
    USERS_AUTHORITY:          "Users",
    ADMIN_SP_ADMIN1:          "Admin1(AdminSP)",
    LOCKING_ADMIN1_AUTHORITY: "Admin1",
    LOCKING_ADMIN2_AUTHORITY: "Admin2",
    LOCKING_ADMIN3_AUTHORITY: "Admin3",
    LOCKING_ADMIN4_AUTHORITY: "Admin4",
    LOCKING_USER1_AUTHORITY:  "User1",
    LOCKING_USER2_AUTHORITY:  "User2",
    LOCKING_USER3_AUTHORITY:  "User3",
    LOCKING_USER4_AUTHORITY:  "User4",
    LOCKING_USER5_AUTHORITY:  "User5",
    LOCKING_USER6_AUTHORITY:  "User6",
    LOCKING_USER7_AUTHORITY:  "User7",
    LOCKING_USER8_AUTHORITY:  "User8",
}

SP_NAMES: dict[str, str] = {
    ADMIN_SP:   "AdminSP",
    LOCKING_SP: "LockingSP",
}

# Populated dynamically by the solver as it learns credential values
CREDENTIAL_NAMES: dict[str, str] = {}


# ─────────────────────────────────────────────────────────────
# Object semantics — column structure for each table type
# ─────────────────────────────────────────────────────────────
# Column keys throughout this module use the normalized hex string form
# produced by normalizer.normalize_column_key():
#   decimal  hex str   field
#     3       "3"      RangeStart / PIN
#     5       "5"      ReadLockEnabled / TryLimit
#     7       "7"      ReadLocked
#    10       "a"      ActiveKey
#    16       "10"     ContOnReset   (NB: "10" is the 2-digit hex literal)
# The solver uses int tuples for Cellblock ranges and hex strings for
# Values column keys — make sure the sets match what normalize_column_key()
# would produce for the actual JSON column identifiers in the test cases.

@dataclass
class ObjectSemantic:
    """Captures readable/writable column metadata for a TCG table object type."""
    # Keys are (startColumn_int, endColumn_int) or the string "all".
    # Values are tuples of normalized hex column key strings.
    readable_column_sets: dict

    # Set of normalized hex column key strings that are host-writable.
    # Empty frozenset → skip column-level Set validation (fall through to policy).
    writable_columns: frozenset

    # For Authority objects: columns whose Set is allowed without elevated authority
    # (i.e., the Enabled flag column, col 5 → "5").
    authority_update_columns: tuple = field(default_factory=tuple)


# Locking object (table 0x00000802):
# col 3=RangeStart, 4=RangeLength, 5=RdLockEn, 6=WrLockEn,
# col 7=RdLocked, 8=WrLocked, 9=LockOnReset,
# col 10(a)=ActiveKey, 11(b)=NextKey, 12(c)=ReEncryptState, 13(d)=ReEncryptRequest
# col 14(e)=AdvKeyMode, 15(f)=VerifyMode, 16(10)=ContOnReset
# Cols 17-19 (11-13 hex) are read-only progress/status columns.
_LOCKING_READABLE_COLS = frozenset([
    "3", "4", "5", "6", "7", "8", "9",
    "a", "b", "c", "d", "e", "f",
    "10", "11", "12", "13",
])
_LOCKING_WRITABLE_COLS = frozenset([
    "3", "4",              # RangeStart, RangeLength
    "5", "6",              # ReadLockEnabled, WriteLockEnabled
    "7", "8",              # ReadLocked, WriteLocked
    "9",                   # LockOnReset
    "a", "b",              # ActiveKey, NextKey
    "d",                   # ReEncryptRequest (c is read-only from host)
    "e", "f",              # AdvKeyMode, VerifyMode
    "10",                  # ContOnReset
])

# MBRControl: col 1=Enable, 2=Done, 3=DoneOnReset
_MBRCONTROL_COLS = frozenset(["1", "2", "3"])

# Authority: col 4=Class, 5=Enabled, 6=Secure, 9=Operation, 10(a)=Credential
_AUTHORITY_WRITABLE = frozenset(["4", "5", "6", "9", "a"])

OBJECT_SEMANTICS: dict[str, ObjectSemantic] = {
    # ── Locking range ──────────────────────────────────────────
    "LOCKING": ObjectSemantic(
        readable_column_sets={
            # Exact Cellblock ranges seen in test cases
            (3, 3):  ("3",),
            (4, 4):  ("4",),
            (5, 5):  ("5",),
            (6, 6):  ("6",),
            (7, 7):  ("7",),
            (8, 8):  ("8",),
            (9, 9):  ("9",),
            (3, 4):  ("3", "4"),
            (5, 6):  ("5", "6"),
            (7, 8):  ("7", "8"),
            (3, 8):  ("3", "4", "5", "6", "7", "8"),
            (3, 9):  ("3", "4", "5", "6", "7", "8", "9"),
            (5, 8):  ("5", "6", "7", "8"),
            (3, 19): tuple(str(c) if c < 10 else format(c, "x") for c in range(3, 20)),
        },
        writable_columns=_LOCKING_WRITABLE_COLS,
    ),

    # ── MBRControl ────────────────────────────────────────────
    "MBRCONTROL": ObjectSemantic(
        readable_column_sets={
            (1, 1): ("1",),
            (2, 2): ("2",),
            (3, 3): ("3",),
            (1, 2): ("1", "2"),
            (1, 3): ("1", "2", "3"),
        },
        writable_columns=_MBRCONTROL_COLS,
    ),

    # ── Authority ─────────────────────────────────────────────
    "AUTHORITY": ObjectSemantic(
        readable_column_sets={
            (4, 4): ("4",),
            (5, 5): ("5",),
            (4, 5): ("4", "5"),
            (4, 6): ("4", "5", "6"),
            (1, 10): tuple(str(c) if c < 10 else format(c, "x") for c in range(1, 11)),
        },
        writable_columns=_AUTHORITY_WRITABLE,
        authority_update_columns=("5",),  # Enabled flag
    ),

    # ── LockingInfo (read-only by host) ───────────────────────
    "LOCKINGINFO": ObjectSemantic(
        readable_column_sets={
            (1, 1): ("1",),
            (2, 2): ("2",),
            (3, 3): ("3",),
            (4, 4): ("4",),
            (5, 5): ("5",),
            (1, 5): ("1", "2", "3", "4", "5"),
            (1, 8): ("1", "2", "3", "4", "5", "6", "7", "8"),
        },
        writable_columns=frozenset(),  # No host-writable columns
    ),
}


# ─────────────────────────────────────────────────────────────
# Access-control policies
# ─────────────────────────────────────────────────────────────

@dataclass
class Policy:
    """Minimal access-control policy for a (method, object_name) pair.

    solver.py checks these in _policy_failure().  All fields are optional;
    None / False / empty mean "no restriction on that dimension".
    """
    # If set, the current session's SPID must equal this value.
    session_spid: str | None = None

    # If True, the session must have at least one authenticated authority
    # (i.e. session.authenticated is True).
    require_authenticated: bool = False

    # If non-empty, at least one of these authority UIDs must be present
    # in session.authenticated_authorities.
    allowed_authorities: set | None = None

    # If set, this SP UID must be in state.activated_sps.
    require_activated_sp: str | None = None

    # Status code to return when the policy check fails.
    failure_status: str = "NOT_AUTHORIZED"


# Convenience sets
_LOCKING_ADMINS: set[str] = {
    LOCKING_ADMIN1_AUTHORITY, LOCKING_ADMIN2_AUTHORITY,
    LOCKING_ADMIN3_AUTHORITY, LOCKING_ADMIN4_AUTHORITY,
    ADMINS_AUTHORITY,  # class authority
}
_LOCKING_ALL_AUTH: set[str] = _LOCKING_ADMINS | {
    LOCKING_USER1_AUTHORITY, LOCKING_USER2_AUTHORITY,
    LOCKING_USER3_AUTHORITY, LOCKING_USER4_AUTHORITY,
    USERS_AUTHORITY,  # class authority
}

# POLICIES maps (METHOD_UPPER, OBJECT_NAME_UPPER) → Policy.
# Object names are produced by normalize_status(invoking_id["name"]) in solver.py,
# which uppercases and underscore-joins.  E.g. "LockingSP" → "LOCKINGSP".
POLICIES: dict[tuple[str, str], Policy] = {
    # ── LockingSP GET ────────────────────────────────────────
    # Locking table GET: spec ACE_Locking_RangeN_Get_RangeStartToActiveKey = Admins only
    # (UID/CommonName readable by Anybody, but property columns require Admins)
    ("GET", "LOCKING"): Policy(
        session_spid=LOCKING_SP,
        require_authenticated=True,
        allowed_authorities=_LOCKING_ADMINS,
        require_activated_sp=LOCKING_SP,
    ),
    ("GET", "LOCKINGINFO"): Policy(
        session_spid=LOCKING_SP,
        require_authenticated=True,
        allowed_authorities=_LOCKING_ADMINS,
        require_activated_sp=LOCKING_SP,
    ),
    # MBRControl: ACE_Anybody — open LockingSP session is sufficient
    ("GET", "MBRCONTROL"): Policy(
        session_spid=LOCKING_SP,
        require_activated_sp=LOCKING_SP,
    ),
    # MBR byte-table: open LockingSP session (Anybody)
    ("GET", "MBR"): Policy(
        session_spid=LOCKING_SP,
        require_activated_sp=LOCKING_SP,
    ),
    # DataStore byte-table: admin required (spec opal/4.3.8.1)
    ("GET", "DATASTORE"): Policy(
        session_spid=LOCKING_SP,
        require_authenticated=True,
        allowed_authorities=_LOCKING_ADMINS,
        require_activated_sp=LOCKING_SP,
    ),

    # ── LockingSP SET ────────────────────────────────────────
    # Authority Set (Enable/Disable): Admin authority in LockingSP required
    # (This covers the typical Opal use-case: Admin1 enabling User1-8, Admin2-4)
    ("SET", "AUTHORITY"): Policy(
        session_spid=LOCKING_SP,
        require_authenticated=True,
        allowed_authorities=_LOCKING_ADMINS,
        require_activated_sp=LOCKING_SP,
    ),
    # Locking range Set: authenticated (Admin or User with ACE)
    # Locking table SET: all column ACEs require Admins (ACE_Locking_*_Set_*)
    ("SET", "LOCKING"): Policy(
        session_spid=LOCKING_SP,
        require_authenticated=True,
        allowed_authorities=_LOCKING_ADMINS,
        require_activated_sp=LOCKING_SP,
    ),
    # MBRControl Set: Admin authority required
    ("SET", "MBRCONTROL"): Policy(
        session_spid=LOCKING_SP,
        require_authenticated=True,
        allowed_authorities=_LOCKING_ADMINS,
        require_activated_sp=LOCKING_SP,
    ),
    # MBR Set: Admin authority required
    ("SET", "MBR"): Policy(
        session_spid=LOCKING_SP,
        require_authenticated=True,
        allowed_authorities=_LOCKING_ADMINS,
        require_activated_sp=LOCKING_SP,
    ),
    # DataStore Set: Admin authority required
    ("SET", "DATASTORE"): Policy(
        session_spid=LOCKING_SP,
        require_authenticated=True,
        allowed_authorities=_LOCKING_ADMINS,
        require_activated_sp=LOCKING_SP,
    ),

    # ── AdminSP operations ───────────────────────────────────
    # Activate LockingSP: SID authenticated in AdminSP write session
    ("ACTIVATE", "LOCKINGSP"): Policy(
        session_spid=ADMIN_SP,
        require_authenticated=True,
        allowed_authorities={SID_AUTHORITY},
    ),

    # ── Revert (full drive reset via AdminSP) ────────────────
    # Revert AdminSP or LockingSP: SID authenticated in AdminSP write session
    ("REVERT", "ADMINSP"): Policy(
        session_spid=ADMIN_SP,
        require_authenticated=True,
        allowed_authorities={SID_AUTHORITY},
    ),
    ("REVERT", "LOCKINGSP"): Policy(
        session_spid=ADMIN_SP,
        require_authenticated=True,
        allowed_authorities={SID_AUTHORITY},
    ),

    # ── GenKey (media encryption key regeneration) ───────────
    # Generates new AES key for a locking range:
    # Authenticated Admin write session in LockingSP required.
    ("GENKEY", "K_AES_256"): Policy(
        session_spid=LOCKING_SP,
        require_authenticated=True,
        allowed_authorities=_LOCKING_ADMINS,
        require_activated_sp=LOCKING_SP,
    ),
    ("GENKEY", "K_AES_128"): Policy(
        session_spid=LOCKING_SP,
        require_authenticated=True,
        allowed_authorities=_LOCKING_ADMINS,
        require_activated_sp=LOCKING_SP,
    ),
    # Some implementations use the short name K_AES
    ("GENKEY", "K_AES"): Policy(
        session_spid=LOCKING_SP,
        require_authenticated=True,
        allowed_authorities=_LOCKING_ADMINS,
        require_activated_sp=LOCKING_SP,
    ),
}

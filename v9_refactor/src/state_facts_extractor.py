from __future__ import annotations

from copy import deepcopy
from typing import Any


STATE_FACTS_WHITELIST_VERSION = "state_facts_v1"

SESSION_FIELDS = (
    "open",
    "sp",
    "authority",
    "authorities",
    "write",
    "had_failure",
    "trusted",
    "host_session_id",
    "sp_session_id",
)

CREDENTIAL_FIELDS = (
    "SID",
    "MSID",
    "Admin1",
    "Admin2",
    "Admin3",
    "Admin4",
    "User1",
    "User2",
    "User3",
    "User4",
    "User5",
    "User6",
    "User7",
    "User8",
)

SP_LIFECYCLE_FIELDS = ("AdminSP", "LockingSP")

LOCKING_RANGE_FIELDS = (
    "range_start",
    "range_length",
    "read_lock_enabled",
    "read_locked",
    "write_lock_enabled",
    "write_locked",
    "lock_on_reset",
    "active_key",
    "next_key",
    "reencrypt_state",
    "reencrypt_request",
)

STATE_FACT_TOP_LEVEL_FIELDS = (
    "session",
    "credentials",
    "sp_lifecycle",
    "locking_sp_active",
    "locking_ranges",
    "key_generations_by_range",
    "capacity",
    "issued_sps",
)

SP_BYTE_SPACE_FIELDS = ("sp", "size", "size_in_use", "free", "source")
TABLE_CAPACITY_FIELDS = ("uid", "rows", "rows_free", "max_size", "source")
ISSUED_SP_FIELDS = (
    "uid",
    "sp",
    "name",
    "size",
    "size_blocks",
    "requested_size_blocks",
    "size_evidence",
    "size_is_exact",
    "templates",
    "enabled",
    "source",
    "lifecycle",
    "deleted",
    "deleted_by",
)


def extract_state_facts(
    state: dict[str, Any] | None,
    *,
    max_locking_ranges: int = 32,
    max_sp_byte_space_entries: int = 16,
    max_table_capacity_entries: int = 32,
    max_issued_sps: int = 32,
) -> dict[str, Any]:
    """Return the narrow audit-safe state fact bundle for evidence packets.

    This extractor is deliberately a whitelist over the live state shape.  It
    never reuses ``llm_parse_fallback._state_snapshot`` wholesale and never
    includes broad history/tables/raw-payload fields.
    """

    state = state if isinstance(state, dict) else {}
    missing_fields: list[str] = []

    session = _mapping(state.get("session"))
    session_facts = _extract_fields(session, SESSION_FIELDS, "session", missing_fields)
    session_facts.setdefault("authorities", [])
    if isinstance(session_facts.get("authorities"), set):
        session_facts["authorities"] = sorted(session_facts["authorities"])
    elif session_facts.get("authorities") is None:
        session_facts["authorities"] = []

    credentials = _mapping(state.get("credentials"))
    credential_facts = _extract_fields(
        credentials,
        CREDENTIAL_FIELDS,
        "credentials",
        missing_fields,
        transform=_redact_credential_value,
    )

    sp_lifecycle = _mapping(state.get("sp_lifecycle"))
    lifecycle_facts = _extract_fields(sp_lifecycle, SP_LIFECYCLE_FIELDS, "sp_lifecycle", missing_fields)

    ranges = _mapping(state.get("locking_ranges"))
    range_items = sorted(ranges.items(), key=lambda item: str(item[0]))
    locking_ranges_truncated = len(range_items) > max_locking_ranges
    selected_ranges = range_items[:max_locking_ranges]
    locking_range_facts: dict[str, dict[str, Any]] = {}
    for name, entry in selected_ranges:
        entry = _mapping(entry)
        locking_range_facts[str(name)] = _extract_fields(
            entry,
            LOCKING_RANGE_FIELDS,
            f"locking_ranges.{name}",
            missing_fields,
        )

    sp_byte_space_items = sorted(_mapping(state.get("sp_byte_space")).items(), key=lambda item: str(item[0]))
    sp_byte_space_truncated = len(sp_byte_space_items) > max_sp_byte_space_entries
    sp_byte_space_facts = {
        str(sp): _extract_optional_fields(_mapping(entry), SP_BYTE_SPACE_FIELDS)
        for sp, entry in sp_byte_space_items[:max_sp_byte_space_entries]
    }

    table_capacity_items = sorted(_mapping(state.get("table_capacity")).items(), key=lambda item: str(item[0]))
    table_capacity_truncated = len(table_capacity_items) > max_table_capacity_entries
    table_capacity_facts: dict[str, dict[str, Any]] = {}
    for uid, entry in table_capacity_items[:max_table_capacity_entries]:
        fact = _extract_optional_fields(_mapping(entry), TABLE_CAPACITY_FIELDS)
        fact.setdefault("uid", str(uid))
        table_capacity_facts[str(uid)] = fact

    issued_sp_items = sorted(_mapping(state.get("issued_sps")).items(), key=lambda item: str(item[0]))
    issued_sps_truncated = len(issued_sp_items) > max_issued_sps
    issued_sp_facts: dict[str, dict[str, Any]] = {}
    lifecycle = _mapping(state.get("sp_lifecycle"))
    for uid, entry in issued_sp_items[:max_issued_sps]:
        fact = _extract_optional_fields(_mapping(entry), ISSUED_SP_FIELDS)
        fact.setdefault("uid", str(uid))
        sp = fact.get("sp")
        if fact.get("lifecycle") is None and sp in lifecycle:
            fact["lifecycle"] = _json_ready(lifecycle.get(sp))
        issued_sp_facts[str(uid)] = fact

    facts_truncated = any((locking_ranges_truncated, sp_byte_space_truncated, table_capacity_truncated, issued_sps_truncated))

    return {
        "meta": {
            "source_whitelist_version": STATE_FACTS_WHITELIST_VERSION,
            "facts_truncated": facts_truncated,
            "truncation": {
                "locking_ranges": locking_ranges_truncated,
                "sp_byte_space": sp_byte_space_truncated,
                "table_capacity": table_capacity_truncated,
                "issued_sps": issued_sps_truncated,
            },
            "missing_fields": missing_fields,
            "ignored_fields": [],
        },
        "session": session_facts,
        "credentials": credential_facts,
        "sp_lifecycle": lifecycle_facts,
        "locking_sp_active": _json_ready(state.get("locking_sp_active")),
        "locking_ranges": locking_range_facts,
        "key_generations_by_range": _json_ready(state.get("key_generations_by_range") or {}),
        "capacity": {
            "sp_issuance_space": _extract_optional_fields(_mapping(state.get("sp_issuance_space")), ("free", "source")),
            "sp_byte_space": sp_byte_space_facts,
            "table_capacity": table_capacity_facts,
        },
        "issued_sps": issued_sp_facts,
    }


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _extract_fields(
    mapping: dict[str, Any],
    fields: tuple[str, ...],
    prefix: str,
    missing_fields: list[str],
    *,
    transform=None,
) -> dict[str, Any]:
    extracted: dict[str, Any] = {}
    for field in fields:
        if field not in mapping:
            missing_fields.append(f"{prefix}.{field}")
        value = mapping.get(field)
        if transform is not None:
            value = transform(value)
        extracted[field] = _json_ready(value)
    return extracted


def _extract_optional_fields(mapping: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    return {field: _json_ready(mapping.get(field)) for field in fields}


def _redact_credential_value(value: Any) -> Any:
    if value is None or value == "":
        return value
    return "<redacted>"


def _json_ready(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, set):
        return sorted(_json_ready(item) for item in value)
    if isinstance(value, tuple):
        return [_json_ready(item) for item in value]
    if isinstance(value, list):
        return [_json_ready(item) for item in value]
    return deepcopy(value)

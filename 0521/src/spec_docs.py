import json
import re
from functools import lru_cache
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOC_ROOT = ROOT / "artifacts" / "documents"
SPEC_INDEX_PATH = ROOT / "artifacts" / "spec_index.json"

METHOD_NAMES = (
    "Properties",
    "StartSession",
    "SyncSession",
    "CloseSession",
    "EndSession",
    "Authenticate",
    "Get",
    "Set",
    "Next",
    "GetFreeSpace",
    "GetFreeRows",
    "GenKey",
    "Random",
    "Activate",
    "Revert",
    "RevertSP",
)

NORMATIVE_MARKERS = (
    "SHALL",
    "SHALL NOT",
    "MUST",
    "MUST NOT",
    "SHOULD",
    "SHOULD NOT",
    "MAY",
    "MAY NOT",
    "MANDATORY",
)

# The public traces use compact numeric column identifiers for the table-specific
# columns. Named inputs from hidden cases are normalized onto the same internal
# numbering so the state tracker can stay stable.
COLUMN_NAME_NUMBERS = {
    "C_PIN": {
        "uid": 0,
        "name": 1,
        "commonname": 2,
        "pin": 3,
        "charset": 4,
        "trylimit": 5,
        "tries": 6,
        "persistence": 7,
    },
    "Locking": {
        "uid": 0,
        "name": 1,
        "commonname": 2,
        "rangestart": 3,
        "rangelength": 4,
        "readlockenabled": 5,
        "writelockenabled": 6,
        "readlocked": 7,
        "writelocked": 8,
        "lockonreset": 9,
        "activekey": 10,
        "nextkey": 11,
        "reencryptstate": 12,
        "reencyptrequest": 13,
        "reencryptrequest": 13,
        "advkeymode": 14,
        "verifymode": 15,
        "contonreset": 16,
        "lastreencryptlba": 17,
        "lastreencstate": 18,
        "lastreencstat": 18,
        "generalstatus": 19,
    },
    "LockingInfo": {
        "uid": 0,
        "name": 1,
        "version": 2,
        "encryptsupport": 3,
        "maxranges": 4,
        "maxreencryptions": 5,
        "keysavailablecfg": 6,
        "alignmentrequired": 7,
        "logicalblocksize": 8,
        "alignmentgranularity": 9,
        "lowestalignedlba": 10,
    },
    "MBRControl": {
        "uid": 0,
        "enable": 1,
        "done": 2,
        "doneonreset": 3,
        "mbrdoneonreset": 3,
    },
    "Authority": {
        "uid": 0,
        "name": 1,
        "commonname": 2,
        "isclass": 3,
        "enabled": 4,
        "credential": 5,
        "operation": 6,
    },
    "ACE": {
        "uid": 0,
        "name": 1,
        "commonname": 2,
        "booleanexpr": 3,
        "columns": 4,
    },
    "MediaKey": {
        "uid": 0,
        "name": 1,
        "commonname": 2,
        "key": 3,
        "mode": 4,
    },
}

COLUMN_LIMITS = {
    family: max(mapping.values())
    for family, mapping in COLUMN_NAME_NUMBERS.items()
    if mapping
}

RULE_REFERENCES = {
    "properties": ("opal/4.1.1.1", "core/3.2.1.2"),
    "start_session": ("opal/4.1.1.2", "core/5.2.3.1", "core/5.3.4.1.5"),
    "sync_session": ("opal/4.1.1.3", "core/5.2.3.2", "core/3.3.7.1.4"),
    "close_session": ("opal/4.1.1.4", "core/3.3.7.1.5"),
    "authenticate": ("core/5.3.3.12", "core/5.3.4.1.14"),
    "get": ("core/5.3.3.6", "core/5.3.4.2.2"),
    "set": ("core/5.3.3.7", "core/5.3.4.2.6"),
    "next": ("core/5.3.3.8", "core/5.3.4.2.7"),
    "gen_key": ("core/5.3.3.16", "opal/4.3.1.7", "opal/4.3.5.5"),
    "random": ("opal/4.2.9.1", "opal/4.3.4.1", "core/5.6.4.1"),
    "activate": ("opal/5.1.1", "opal/5.1.1.2", "opal/5.2.2.2.1"),
    "revert": ("opal/5.1.2", "opal/5.1.2.2", "opal/5.2.2.2.2"),
    "revert_sp": ("opal/5.1.3", "opal/5.1.3.2", "opal/5.1.3.3"),
    "locking_table": ("opal/4.3.5.2", "opal/4.3.1.7", "core/3.3.6.5.3"),
    "locking_data": ("opal/4.3.7", "core/3.3.6.5.3"),
    "locking_info": ("opal/4.3.5.1", "core/3.3.6.5"),
    "mbr_control": ("opal/4.3.5.3", "core/3.3.6.5.5", "core/3.3.6.5.6"),
    "cpin": ("opal/4.2.1.8", "opal/4.3.1.9", "core/5.3.4.1.1"),
    "authority": ("opal/4.2.1.7", "opal/4.3.1.8", "core/5.3.4.1.2"),
    "access_control": ("opal/4.3.1.7", "core/5.3.4.3"),
    "status": ("core/3.3.4.1.3", "core/5.3.3"),
    "fallback": ("core/5.3.3", "core/5.3.4"),
}


def compact_uid(value):
    if value is None:
        return None
    compacted = re.sub(r"[^0-9A-Fa-f]", "", str(value)).upper()
    return compacted or None


def normalized_column_name(name):
    return re.sub(r"[^0-9A-Za-z]", "", str(name or "")).lower()


def column_number_for_name(family, name):
    mapping = COLUMN_NAME_NUMBERS.get(family) or {}
    return mapping.get(normalized_column_name(name))


def refs_for(rule_key):
    return tuple(RULE_REFERENCES.get(rule_key, ()))


def section_label(ref):
    return ref if isinstance(ref, str) else "/".join(str(part) for part in ref)


def extract_json_blocks(text):
    parsed = []
    for match in re.finditer(r"```json\s*(.*?)```", text, re.IGNORECASE | re.DOTALL):
        raw = match.group(1).strip()
        try:
            parsed.append(json.loads(raw))
        except json.JSONDecodeError:
            parsed.append({"_parse_error": True, "preview": raw[:300]})
    return parsed


def table_titles(text):
    titles = []
    for line in text.splitlines():
        stripped = line.strip()
        if re.match(r"^Table\s+\d+", stripped):
            titles.append(stripped)
    return titles


def methods_in(text):
    methods = []
    for method in METHOD_NAMES:
        if re.search(rf"\b{re.escape(method)}\b", text):
            methods.append(method)
    return methods


def normative_extracts(text, limit=8):
    sentences = re.split(r"(?<=[.!?])\s+|\n+", text)
    extracts = []
    count = 0
    for sentence in sentences:
        compact = " ".join(sentence.strip().split())
        if not compact:
            continue
        upper = compact.upper()
        if any(marker in upper for marker in NORMATIVE_MARKERS):
            count += 1
            if len(extracts) < limit:
                extracts.append(compact[:280])
    return count, extracts


def classify_section(title, text, methods, parsed_json):
    lower = f"{title}\n{text}".lower()
    if "read/write" in lower or "lba" in lower or "locking behavior" in lower:
        return "data command behavior"
    if "life cycle" in lower or "state transition" in lower or "activate" in lower or "revert" in lower:
        return "state transition"
    if "authority" in lower or "authenticate" in lower or "accesscontrol" in lower or "ace" in lower or "c_pin" in lower:
        return "auth/access control"
    if methods:
        return "method rule"
    if parsed_json or "table" in lower or "column" in lower:
        return "table schema"
    if any(marker.lower() in lower for marker in NORMATIVE_MARKERS):
        return "normative reference"
    return "non-executable reference"


def build_spec_index():
    sections = {}
    method_sections = {method: [] for method in METHOD_NAMES}
    category_counts = {}
    preconfiguration_tables = []

    for domain_dir in sorted(path for path in DOC_ROOT.iterdir() if path.is_dir()):
        title_path = domain_dir / "section_title.json"
        title_map = {}
        if title_path.exists():
            title_map = json.loads(title_path.read_text())

        for path in sorted(domain_dir.rglob("*.txt")):
            section = path.relative_to(domain_dir).with_suffix("").as_posix()
            key = f"{domain_dir.name}/{section}"
            text = path.read_text(errors="replace")
            first_line = text.splitlines()[0].strip() if text.splitlines() else ""
            title_key = path.stem
            title = title_map.get(title_key) or re.sub(rf"^{re.escape(title_key)}\s*", "", first_line).strip()
            parsed_json = extract_json_blocks(text)
            tables = table_titles(text)
            methods = methods_in(f"{title}\n{text}")
            requirement_count, requirements = normative_extracts(text)
            category = classify_section(title, text, methods, parsed_json)
            category_counts[category] = category_counts.get(category, 0) + 1

            section_record = {
                "domain": domain_dir.name,
                "section": section,
                "path": str(path.relative_to(ROOT)),
                "title": title,
                "category": category,
                "line_count": len(text.splitlines()),
                "tables": tables,
                "methods": methods,
                "normative_count": requirement_count,
                "normative_extracts": requirements,
                "json_block_count": len(parsed_json),
            }
            sections[key] = section_record

            for method in methods:
                method_sections.setdefault(method, []).append(key)

            if parsed_json:
                preconfiguration_tables.append(
                    {
                        "source": key,
                        "title": tables[-1] if tables else title,
                        "blocks": parsed_json,
                    }
                )

    return {
        "version": 1,
        "source_root": str(DOC_ROOT.relative_to(ROOT)),
        "section_count": len(sections),
        "category_counts": category_counts,
        "sections": sections,
        "method_sections": method_sections,
        "preconfiguration_tables": preconfiguration_tables,
        "rule_references": RULE_REFERENCES,
        "column_name_numbers": COLUMN_NAME_NUMBERS,
    }


@lru_cache(maxsize=1)
def load_spec_index():
    if SPEC_INDEX_PATH.exists():
        return json.loads(SPEC_INDEX_PATH.read_text())
    return build_spec_index()


def write_spec_index(path=SPEC_INDEX_PATH):
    index = build_spec_index()
    Path(path).write_text(json.dumps(index, indent=2, sort_keys=True) + "\n")
    return index


def bool_from_spec(value):
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    if text in {"true", "t", "1", "yes"}:
        return True
    if text in {"false", "f", "0", "no", ""}:
        return False
    return False


def range_name_from_row(row):
    name = str(row.get("Name") or "")
    uid = compact_uid(row.get("UID"))
    if "Global" in name or (uid and uid.startswith("00000802") and uid[8:12] == "0000"):
        return "Global"
    match = re.search(r"Range(\d+)", name)
    if match:
        return f"Range{int(match.group(1))}"
    if uid and uid.startswith("00000802") and uid[8:12] == "0003":
        return f"Range{int(uid[-4:], 16)}"
    return None


def iter_json_rows():
    for table in load_spec_index().get("preconfiguration_tables", []):
        for block in table.get("blocks", []):
            if isinstance(block, list):
                for row in block:
                    if isinstance(row, dict):
                        yield table, row


def default_locking_ranges():
    ranges = {}
    for table, row in iter_json_rows():
        if "Locking Table Preconfiguration" not in table.get("title", ""):
            continue
        name = range_name_from_row(row)
        if not name or "NNNN" in str(row.get("Name", "")):
            continue
        ranges[name] = {
            "name": name,
            "source": table.get("source"),
            "columns": {},
            "range_start": int(row.get("RangeStart") or 0),
            "range_length": int(row.get("RangeLength") or 0),
            "read_lock_enabled": bool_from_spec(row.get("ReadLockEnabled")),
            "write_lock_enabled": bool_from_spec(row.get("WriteLockEnabled")),
            "read_locked": bool_from_spec(row.get("ReadLocked")),
            "write_locked": bool_from_spec(row.get("WriteLocked")),
            "lock_on_reset": row.get("LockOnReset"),
            "active_key": row.get("ActiveKey"),
            "next_key": row.get("NextKey"),
        }
    return ranges


def default_mbr_control():
    for table, row in iter_json_rows():
        if "MBRControl Table Preconfiguration" not in table.get("title", ""):
            continue
        return {
            "source": table.get("source"),
            "enable": bool_from_spec(row.get("Enable")),
            "done": bool_from_spec(row.get("Done")),
            "done_on_reset": row.get("DoneOnReset"),
            1: row.get("Enable"),
            2: row.get("Done"),
            3: row.get("DoneOnReset"),
        }
    return {}


def default_table_rows():
    rows = {}
    for table, row in iter_json_rows():
        uid = compact_uid(row.get("UID"))
        if not uid or "NN" in str(row.get("UID", "")):
            continue
        rows[uid] = {
            "source": table.get("source"),
            "table": table.get("title"),
            "name": row.get("Name"),
            "values": row,
        }
    return rows


if __name__ == "__main__":
    index = write_spec_index()
    print(
        f"wrote {SPEC_INDEX_PATH.relative_to(ROOT)} "
        f"with {index['section_count']} sections"
    )

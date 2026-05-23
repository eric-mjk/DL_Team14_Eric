import json
import re
from functools import lru_cache
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOC_ROOT = ROOT / "artifacts" / "documents"
SPEC_INDEX_PATH = ROOT / "artifacts" / "spec_index.json"
SPEC_COVERAGE_REPORT_PATH = ROOT / "artifacts" / "spec_coverage_report.json"
SPEC_COVERAGE_MD_PATH = ROOT / "spec_coverage.md"

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
        "class": 4,
        "authorityclass": 4,
        "enabled": 5,
        "secure": 6,
        "hashandsign": 7,
        "presentcertificate": 8,
        "operation": 9,
        "credential": 10,
        "responsesign": 11,
        "responseexch": 12,
        "clockstart": 13,
        "clockend": 14,
        "limit": 15,
        "uses": 16,
        "log": 17,
        "logto": 18,
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

COLUMN_NAME_NUMBERS.update({
    "AccessControl": {
        "uid": 0,
        "invokingid": 1,
        "invokingobject": 1,
        "object": 1,
        "table": 1,
        "methodid": 2,
        "method": 2,
        "methodname": 2,
        "commonname": 3,
        "name": 3,
        "acl": 4,
        "ace": 4,
        "acelist": 4,
        "aces": 4,
        "log": 5,
        "addaceacl": 6,
        "removeaceacl": 7,
        "getaclacl": 8,
        "deletemethodacl": 9,
        "addacelog": 10,
        "acladdacelog": 10,
        "removeacelog": 11,
        "getacllog": 12,
        "deletemethodlog": 13,
        "logto": 14,
    },
    "DataStore": {"uid": 0, "name": 1, "commonname": 2, "startrow": 3, "endrow": 4, "value": 5},
    "SP": {"uid": 0, "name": 1, "org": 2, "owningauthority": 2, "effectiveauth": 3, "dateofissue": 4, "bytes": 5, "lifecycle": 6, "lifecyclestate": 6, "enabled": 6, "frozen": 7},
    "MethodID": {"uid": 0, "name": 1, "commonname": 2, "templateid": 3},
    "Table": {"uid": 0, "name": 1, "commonname": 2, "templateid": 3, "kind": 4, "column": 5, "numcolumns": 6, "rows": 7, "rowsfree": 8, "rowbytes": 9, "lastid": 10, "minsize": 11, "maxsize": 12, "mandatorywritegranularity": 13, "recommendedaccessgranularity": 14},
    "Column": {"uid": 0, "name": 1, "commonname": 2, "type": 3, "isunique": 4, "columnnumber": 5, "transactional": 6, "next": 7, "attributeflags": 8},
    "SecretProtect": {"uid": 0, "name": 1, "commonname": 2, "protect": 3, "columnnumber": 3},
})

COLUMN_LIMITS = {
    family: max(mapping.values())
    for family, mapping in COLUMN_NAME_NUMBERS.items()
    if mapping
}

READ_ONLY_COLUMNS = {
    "C_PIN": {0, 1, 2, 6},
    "Authority": {0, 1, 2, 3},
    "ACE": {0, 1, 2},
    "AccessControl": set(COLUMN_NAME_NUMBERS["AccessControl"].values()),
    "Locking": {0, 1, 2, 10},
    "LockingInfo": set(COLUMN_NAME_NUMBERS["LockingInfo"].values()),
    "MBRControl": {0},
    "MediaKey": {0, 1, 2},
    "SP": set(COLUMN_NAME_NUMBERS["SP"].values()),
    "MethodID": set(COLUMN_NAME_NUMBERS["MethodID"].values()),
    "Table": {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
    "Column": set(COLUMN_NAME_NUMBERS["Column"].values()),
    "SecretProtect": {0, 1, 2},
}

WRITE_ONLY_COLUMNS = {
    "C_PIN": {3},
    "MediaKey": {3},
}

RULE_REFERENCES = {
    "properties": ("opal/4.1.1.1", "core/3.2.1.2"),
    "start_session": ("opal/4.1.1.2", "core/5.2.3.1", "core/5.3.4.1.5"),
    "sync_session": ("opal/4.1.1.3", "core/5.2.3.2", "core/3.3.7.1.4"),
    "close_session": ("opal/4.1.1.4", "core/3.3.7.1.5"),
    "authenticate": ("core/5.3.3.12", "core/5.3.4.1.14", "core/5.3.4.1.14.1"),
    "get": ("core/5.3.3.6", "core/5.3.3.6.1", "core/5.3.4.2.2", "core/5.6.5.1"),
    "set": ("core/5.3.3.7", "core/5.3.4.2.6"),
    "next": ("core/5.3.3.8", "core/5.3.4.2.7"),
    "gen_key": ("core/5.3.3.16", "opal/4.3.1.7", "opal/4.3.5.5"),
    "random": ("opal/4.2.9.1", "opal/4.3.4.1", "core/5.6.4.1"),
    "activate": ("opal/5.1.1", "opal/5.1.1.2", "opal/5.2.2.2.1"),
    "revert": ("opal/5.1.2", "opal/5.1.2.2", "opal/5.2.2.2.2"),
    "revert_sp": ("opal/5.1.3", "opal/5.1.3.2", "opal/5.1.3.3"),
    "locking_table": ("opal/4.3.5.2", "opal/4.3.5.2.1.1", "opal/4.3.5.2.1.2", "opal/4.3.5.2.2", "opal/4.3.1.7", "core/5.7.2.2", "core/5.7.3.3", "core/5.7.3.4", "core/5.7.3.5", "core/3.3.6.5.3"),
    "locking_data": ("opal/4.3.7", "core/5.7.3.2", "core/3.3.6.5.3"),
    "locking_info": ("opal/4.3.5.1", "core/5.7.2.1", "core/3.3.6.5"),
    "mbr_control": ("opal/4.3.5.3", "opal/4.3.5.3.1", "core/5.7.2.5", "core/5.7.3.6", "core/3.3.6.5.5", "core/3.3.6.5.6"),
    "cpin": ("opal/4.2.1.8", "opal/4.3.1.9", "core/5.3.2.12", "core/5.3.4.1.1", "core/5.3.4.1.1.2"),
    "authority": ("opal/4.2.1.7", "opal/4.3.1.8", "core/5.3.2.10", "core/5.3.4.1.2", "core/5.3.4.1.3", "core/5.3.4.1.4"),
    "access_control": ("opal/4.2.1.5", "opal/4.2.1.6", "opal/4.3.1.6", "opal/4.3.1.7", "core/3.4.2", "core/3.4.2.1", "core/3.4.2.2", "core/3.4.2.3", "core/5.3.2.7", "core/5.3.2.9", "core/5.3.4.3"),
    "status": ("core/3.3.4.1", "core/5.1.5", "core/5.1.5.1", "core/5.1.5.2", "core/5.1.5.3", "core/5.1.5.4", "core/5.1.5.5", "core/5.1.5.6", "core/5.1.5.7", "core/5.1.5.8", "core/5.1.5.9", "core/5.1.5.10", "core/5.1.5.11", "core/5.1.5.12", "core/5.1.5.13", "core/5.1.5.14", "core/5.1.5.15", "core/5.1.5.16", "core/5.3.3"),
    "fallback": ("core/5.3.3", "core/5.3.4"),
}


def compact_uid(value):
    if value is None:
        return None
    compacted = re.sub(r"[^0-9A-Fa-f]", "", str(value)).upper()
    return compacted or None


def normalized_column_name(name):
    return re.sub(r"[^0-9A-Za-z]", "", str(name or "")).lower()


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


def parse_column_number(value):
    text = str(value or "").strip()
    if not text:
        return None
    match = re.search(r"0x([0-9A-Fa-f]+)|\b(\d+)\b", text)
    if not match:
        return None
    if match.group(1):
        return int(match.group(1), 16)
    return int(match.group(2), 10)


def markdown_rows(text):
    rows = []
    for line in text.splitlines():
        stripped = line.strip()
        if not (stripped.startswith("|") and stripped.endswith("|")):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if cells and all(re.fullmatch(r":?-{2,}:?", cell.replace(" ", "")) for cell in cells):
            continue
        rows.append(cells)
    return rows


def extract_column_definitions(title, text, tables):
    family = family_from_title(title) or family_from_title(" ".join(tables))
    if not family:
        return []
    rows = markdown_rows(text)
    definitions = []
    header = None
    for cells in rows:
        normalized_cells = [normalized_column_name(cell) for cell in cells]
        if "columnnumber" in normalized_cells and "columnname" in normalized_cells:
            header = normalized_cells
            continue
        if not header:
            continue
        if len(cells) < len(header):
            cells = cells + [""] * (len(header) - len(cells))
        data = dict(zip(header, cells))
        raw_number = data.get("columnnumber")
        if not re.search(r"0x[0-9A-Fa-f]+", str(raw_number or "")):
            continue
        number = parse_column_number(raw_number)
        name = data.get("columnname")
        if number is None or not name:
            continue
        definitions.append(
            {
                "family": family,
                "number": number,
                "name": name,
                "is_unique": data.get("isunique") or "",
                "type": data.get("columntype") or "",
            }
        )
    return definitions


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
    auth_terms = re.search(r"\b(authority|authenticate|authentication|accesscontrol|access control|c_pin|credential)\b", lower)
    ace_terms = re.search(r"\bace\b|\bacl\b|aces and acls", lower)
    if "read/write" in lower or "lba" in lower or "locking behavior" in lower:
        return "data command behavior"
    if "life cycle" in lower or "state transition" in lower or "activate" in lower or "revert" in lower:
        return "state transition"
    if auth_terms or ace_terms:
        return "auth/access control"
    if methods:
        return "method rule"
    if parsed_json or "table" in lower or "column" in lower:
        return "table schema"
    if any(marker.lower() in lower for marker in NORMATIVE_MARKERS):
        return "normative reference"
    return "non-executable reference"


def build_base_spec_index():
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
            relative_path = path.relative_to(domain_dir)
            if any(part.startswith(".") for part in relative_path.parts):
                continue
            section = relative_path.with_suffix("").as_posix()
            key = f"{domain_dir.name}/{section}"
            text = path.read_text(errors="replace")
            first_line = text.splitlines()[0].strip() if text.splitlines() else ""
            title_key = path.stem
            title = title_map.get(title_key) or re.sub(rf"^{re.escape(title_key)}\s*", "", first_line).strip()
            parsed_json = extract_json_blocks(text)
            tables = table_titles(text)
            column_definitions = extract_column_definitions(title, text, tables)
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
                "column_definitions": column_definitions,
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



ACCESS_POLICY_FAMILIES = {"ACE", "AccessControl", "Authority", "C_PIN"}


def row_lookup(row, *names):
    normalized = {normalized_column_name(key): value for key, value in row.items()}
    for name in names:
        value = normalized.get(normalized_column_name(name))
        if value is not None:
            return value
    return None


def family_from_title(title):
    compact = normalized_column_name(title)
    if compact == "ace" or "acetable" in compact or "acelist" in compact:
        return "ACE"
    if "cpin" in compact:
        return "C_PIN"
    if "authority" in compact:
        return "Authority"
    if "accesscontrol" in compact:
        return "AccessControl"
    if "lockinginfo" in compact:
        return "LockingInfo"
    if "locking" in compact:
        return "Locking"
    if "mbrcontrol" in compact:
        return "MBRControl"
    if "mediakey" in compact or "kaes" in compact:
        return "MediaKey"
    if "datastore" in compact:
        return "DataStore"
    if "secretprotect" in compact:
        return "SecretProtect"
    if "methodid" in compact:
        return "MethodID"
    if "columntable" in compact or "columnobjecttable" in compact:
        return "Column"
    if "tabletable" in compact or "tableobjecttable" in compact:
        return "Table"
    if compact.startswith("sp") or "sptable" in compact:
        return "SP"
    return None


def family_from_row(table, row):
    family = family_from_title(table.get("title", "")) or family_from_title(str(row.get("Table", "")))
    if family:
        return family
    uid = compact_uid(row.get("UID"))
    if uid and uid.startswith("0000000B"):
        return "C_PIN"
    if uid and uid.startswith("00000009"):
        return "Authority"
    if uid and uid.startswith("00000801"):
        return "LockingInfo"
    if uid and uid.startswith("00000802"):
        return "Locking"
    if uid and uid.startswith("00000803"):
        return "MBRControl"
    if uid and (uid.startswith("00000805") or uid.startswith("00000806")):
        return "MediaKey"
    if uid and uid.startswith("00000205"):
        return "SP"
    return None


def mutability_for_column(family, number):
    if number in WRITE_ONLY_COLUMNS.get(family, set()):
        return "write_only"
    if number in READ_ONLY_COLUMNS.get(family, set()):
        return "read_only"
    return "read_write"


def add_schema_column(schemas, family, name, number, source=None, type_hint=None):
    if family is None or number is None:
        return
    schema = schemas.setdefault(family, {"columns": {}, "name_to_number": {}, "sources": []})
    if source and source not in schema["sources"]:
        schema["sources"].append(source)
    normalized = normalized_column_name(name)
    if normalized:
        schema["name_to_number"][normalized] = number
    current = schema["columns"].setdefault(str(number), {"number": number, "names": [], "mutability": mutability_for_column(family, number)})
    if name and str(name) not in current["names"]:
        current["names"].append(str(name))
    if type_hint and "type" not in current:
        current["type"] = type_hint


def build_table_schemas_from_index(index):
    schemas = {}
    for family, mapping in COLUMN_NAME_NUMBERS.items():
        for name, number in mapping.items():
            add_schema_column(schemas, family, name, number, source="built-in")
    for key, record in (index.get("sections") or {}).items():
        for column in record.get("column_definitions") or []:
            add_schema_column(
                schemas,
                column.get("family"),
                column.get("name"),
                column.get("number"),
                source=key,
                type_hint=column.get("type"),
            )
    for table in index.get("preconfiguration_tables", []):
        for block in table.get("blocks", []):
            if not isinstance(block, list):
                continue
            for row in block:
                if not isinstance(row, dict):
                    continue
                family = family_from_row(table, row)
                for name, value in row.items():
                    number = column_number_for_name_no_schema(family, name)
                    if number is not None:
                        add_schema_column(schemas, family, name, number, source=table.get("source"), type_hint=type(value).__name__)
    for schema in schemas.values():
        numbers = [int(number) for number in schema.get("columns", {})]
        schema["max_column"] = max(numbers) if numbers else None
    return schemas


def column_number_for_name_no_schema(family, name):
    mapping = COLUMN_NAME_NUMBERS.get(family) or {}
    return mapping.get(normalized_column_name(name))


def table_schema_for_family(family):
    if not family:
        return {}
    try:
        index = load_spec_index()
    except Exception:
        index = {}
    schemas = index.get("table_schemas") if isinstance(index, dict) else None
    if not schemas:
        schemas = build_table_schemas_from_index(index if isinstance(index, dict) else {})
    return schemas.get(family, {})


def max_column_for_family(family):
    schema = table_schema_for_family(family)
    if schema.get("max_column") is not None:
        return schema.get("max_column")
    return COLUMN_LIMITS.get(family)


def read_only_columns_for_family(family):
    schema = table_schema_for_family(family)
    columns = set(READ_ONLY_COLUMNS.get(family, set()))
    for number, meta in schema.get("columns", {}).items():
        if meta.get("mutability") == "read_only":
            columns.add(int(number))
    return columns


def write_only_columns_for_family(family):
    schema = table_schema_for_family(family)
    columns = set(WRITE_ONLY_COLUMNS.get(family, set()))
    for number, meta in schema.get("columns", {}).items():
        if meta.get("mutability") == "write_only":
            columns.add(int(number))
    return columns


def column_number_for_name(family, name):
    normalized = normalized_column_name(name)
    schema = table_schema_for_family(family)
    number = schema.get("name_to_number", {}).get(normalized)
    if number is not None:
        return number
    return column_number_for_name_no_schema(family, name)


def authority_name_from_uid(uid):
    uid = compact_uid(uid)
    if uid == "0000000900000001":
        return "Anybody"
    if uid == "0000000900000002":
        return "Admins"
    if uid == "0000000900030000":
        return "Users"
    if uid == "0000000900000006":
        return "SID"
    if uid and uid.startswith("000000090001"):
        return f"Admin{int(uid[-4:], 16)}"
    if uid and uid.startswith("000000090003"):
        return f"User{int(uid[-4:], 16)}"
    if uid and uid.startswith("00000009"):
        return f"Authority_{uid[-6:]}"
    return None


def authority_name_from_cpin_uid(uid):
    uid = compact_uid(uid)
    if uid == "0000000B00008402":
        return "MSID"
    if uid == "0000000B00000001":
        return "SID"
    if uid and uid.startswith("0000000B"):
        return authority_name_from_uid("00000009" + uid[8:])
    return None


def normalize_authority_name(value):
    uid_name = authority_name_from_uid(value)
    if uid_name:
        return uid_name
    text = str(value or "").strip().replace(" ", "")
    if not text:
        return None
    lowered = text.lower()
    if lowered in {"sid", "admins", "users", "anybody"}:
        return text[0].upper() + text[1:]
    match = re.search(r"(Admin|User)(\d+)", text, re.IGNORECASE)
    if match:
        return f"{match.group(1).title()}{int(match.group(2))}"
    return text


def method_name_from_value(value):
    text = str(value or "").strip()
    for method in sorted(METHOD_NAMES, key=len, reverse=True):
        if method.lower() in text.lower():
            return method
    return text or None


def is_template_uid_text(value):
    text = str(value or "")
    return bool(re.search(r"\b[TXMN]{2,}\b|[+*()]", text, re.IGNORECASE))


def exact_uid_or_none(value):
    if is_template_uid_text(value):
        return None
    compact = compact_uid(value)
    return compact if compact and len(compact) >= 16 else None


def column_list_from_value(value, family=None):
    if value is None:
        return None
    if isinstance(value, int):
        return [value]
    if isinstance(value, str):
        if value.strip().lower() in {"all", "*", "any"}:
            return "all"
        numbers = []
        for part in re.split(r"[,;\s]+", value.strip()):
            if not part:
                continue
            if re.fullmatch(r"0x[0-9a-fA-F]+", part):
                numbers.append(int(part, 16))
            elif part.isdigit():
                numbers.append(int(part, 10))
            else:
                number = column_number_for_name(family, part)
                if number is None and family is None:
                    hits = {mapping[normalized_column_name(part)] for mapping in COLUMN_NAME_NUMBERS.values() if normalized_column_name(part) in mapping}
                    if hits:
                        number = sorted(hits)[0]
                if number is not None:
                    numbers.append(number)
        return numbers or None
    if isinstance(value, dict):
        start = row_lookup(value, "StartColumn", "startColumn", "Start")
        end = row_lookup(value, "EndColumn", "endColumn", "End")
        start_number = column_list_from_value(start, family)
        end_number = column_list_from_value(end, family)
        if start_number and end_number and isinstance(start_number, list) and isinstance(end_number, list):
            return list(range(start_number[0], end_number[0] + 1))
        columns = []
        for item in value.values():
            nested = column_list_from_value(item, family)
            if nested == "all":
                return "all"
            if nested:
                columns.extend(nested)
        return sorted(set(columns)) if columns else None
    if isinstance(value, list):
        columns = []
        for item in value:
            nested = column_list_from_value(item, family)
            if nested == "all":
                return "all"
            if nested:
                columns.extend(nested)
        return sorted(set(columns)) if columns else None
    return None


def build_access_policy_from_index(index):
    policy = {"ace_rows": {}, "access_control_rows": [], "authority_rows": {}, "credential_to_authority": {}}
    for table in index.get("preconfiguration_tables", []):
        for block in table.get("blocks", []):
            if not isinstance(block, list):
                continue
            for row in block:
                if not isinstance(row, dict):
                    continue
                family = family_from_row(table, row)
                source = table.get("source")
                uid = exact_uid_or_none(row.get("UID")) or exact_uid_or_none(row_lookup(row, "UID"))
                name = row_lookup(row, "Name", "CommonName") or uid
                if family == "ACE":
                    ace_id = uid or normalized_column_name(name)
                    policy["ace_rows"][ace_id] = {
                        "uid": uid,
                        "name": name,
                        "boolean_expr": row_lookup(row, "BooleanExpr", "BooleanExpression", "BoolExpr"),
                        "columns": column_list_from_value(row_lookup(row, "Columns", "Column", "ColumnList")),
                        "source": source,
                    }
                elif family == "AccessControl":
                    ace_value = row_lookup(row, "ACL", "CommonName", "ACE", "ACEs", "ACEList", "AllowedACE", "AllowedACEs")
                    refs = []
                    raw_refs = ace_value if isinstance(ace_value, list) else [ace_value]
                    for item in raw_refs:
                        item_text = str(item or "").strip()
                        compact = compact_uid(item_text)
                        ref = compact if compact and len(compact) >= 16 else normalized_column_name(item_text)
                        if ref:
                            refs.append(ref)
                    invoking_value = row_lookup(row, "InvokingID", "InvokingObject", "Object", "Table")
                    policy["access_control_rows"].append({
                        "uid": uid,
                        "name": name,
                        "invoking_uid": exact_uid_or_none(invoking_value),
                        "invoking_pattern": str(invoking_value or ""),
                        "invoking_name": invoking_value,
                        "method": method_name_from_value(row_lookup(row, "MethodID", "Method", "MethodName")),
                        "ace_refs": refs,
                        "source": source,
                    })
                elif family == "Authority":
                    authority = normalize_authority_name(uid or name)
                    if authority:
                        policy["authority_rows"][authority] = {
                            "uid": uid,
                            "name": name,
                            "is_class": bool_from_spec(row_lookup(row, "IsClass")),
                            "class": normalize_authority_name(row_lookup(row, "Class", "AuthorityClass")),
                            "enabled": bool_from_spec(row_lookup(row, "Enabled")),
                            "operation": row_lookup(row, "Operation"),
                            "credential": compact_uid(row_lookup(row, "Credential", "CredentialID")),
                            "credential_name": row_lookup(row, "Credential", "CredentialID"),
                            "source": source,
                        }
                elif family == "C_PIN":
                    authority = authority_name_from_cpin_uid(uid) or normalize_authority_name(name)
                    if uid and authority:
                        policy["credential_to_authority"][uid] = authority
    return policy


def default_access_policy():
    index = load_spec_index()
    policy = index.get("access_policy") if isinstance(index, dict) else None
    if policy:
        return policy
    return build_access_policy_from_index(index if isinstance(index, dict) else {})


def is_transport_layer_only(key, record):
    title = "{} {}".format(record.get("title", ""), key).lower()
    transport_prefixes = (
        "core/3.2.2",
        "core/3.2.3",
        "core/3.3.1",
        "core/3.3.2",
        "core/3.3.3",
        "core/3.3.4",
        "core/3.3.6",
        "core/3.3.8",
        "core/3.3.9",
        "core/3.3.10",
        "opal/3.1.1",
        "opal/3.2",
        "opal/3.3",
    )
    if key.startswith(transport_prefixes):
        return True
    transport_terms = (
        "packet",
        "compacket",
        "subpacket",
        "transport layer",
        "interface layer",
        "communication layer",
        "comid",
        "if-send",
        "if-recv",
        "acknowledgement",
        "acknak",
        "sequencenumbers",
        "seqnumber",
        "mintransfer",
        "outstandingdata",
        "security protocol",
        "protocol stack reset",
        "tcg reset",
        "tcg power cycle",
        "tcg hardware reset",
        "level 0 discovery",
    )
    return any(term in title for term in transport_terms)


def is_type_definition_only(key, record):
    title = "{} {}".format(record.get("title", ""), key).lower()
    if key.startswith("core/5.1.3") or key.startswith("core/5.1.4"):
        executable_type_sections = {
            "core/5.1.4.2.3",
            "core/5.1.4.2.6",
        }
        return key not in executable_type_sections
    type_terms = (
        "data types",
        "tokens",
        "atoms",
        "reserved",
        "padding",
        "pad",
        "uid assignments",
        "approved references",
        "document references",
    )
    return any(term in title for term in type_terms)


def is_metadata_schema_only(key, record):
    category = record.get("category")
    title = "{} {}".format(record.get("title", ""), key).lower()
    schema_prefixes = (
        "core/5.3.2.",
        "core/5.4.2.",
        "core/5.6.3.",
        "core/5.7.2.",
        "core/5.8.2.",
    )
    if key.startswith(schema_prefixes) and category in {"table schema", "auth/access control", "data command behavior", "method rule"}:
        return True
    if category != "table schema":
        return False
    metadata_terms = (
        "metadata group",
        "table description",
        "column table",
        "type table",
        "spinfo",
        "sptemplates",
        "cryptosuite",
        "loglist",
        "certificates",
    )
    return any(term in title for term in metadata_terms)


def classify_coverage(key, record, implemented_refs):
    category = record.get("category")
    title = "{} {}".format(record.get("title", ""), key).lower()
    if key in implemented_refs:
        return "implemented"
    if is_transport_layer_only(key, record):
        return "transport_layer_only"
    if is_type_definition_only(key, record):
        return "type_definition_only"
    if is_metadata_schema_only(key, record):
        return "schema_metadata_only"
    if category in {"non-executable reference"}:
        return "non_executable"
    if "optional" in title or "vendor" in title or "may" in " ".join(record.get("normative_extracts", [])).lower():
        return "vendor_optional"
    if category in {"method rule", "auth/access control", "table schema", "state transition", "data command behavior"}:
        return "partial" if record.get("normative_count", 0) else "indexed_only"
    return "indexed_only"


def rule_keys_by_ref(refs_by_rule):
    result = {}
    for rule_key, refs in refs_by_rule.items():
        for ref in refs:
            result.setdefault(ref, []).append(rule_key)
    return result


def gap_reason_for(record, status):
    category = record.get("category")
    if status == "partial":
        return "Normative section is in an executable category, but no direct RuleResult spec_ref maps to this section."
    if status == "indexed_only":
        return "Normative section is indexed but currently has no executable oracle/state rule reference."
    if status == "vendor_optional":
        return "Section appears optional or vendor-specific; it is tracked but not turned into a deterministic rule."
    if status == "non_executable":
        return "Section is classified as explanatory/non-executable."
    if status == "transport_layer_only":
        return "Section constrains packets, tokens, ComIDs, discovery, or transport behavior that normalized traces do not expose."
    if status == "type_definition_only":
        return "Section defines data encodings or reusable types rather than an executable oracle decision."
    if status == "schema_metadata_only":
        return "Section contributes schema metadata but does not require a separate runtime oracle rule."
    return None


def recommended_action_for(record, status):
    category = record.get("category")
    if status == "implemented":
        return "Keep rule reference current when the implementation changes."
    if status == "partial":
        if category == "auth/access control":
            return "Attach the section to a concrete ACE/AccessControl, Authority, or credential rule when modeled."
        if category == "table schema":
            return "Map documented columns and mutability into table_schemas or mark the section non-executable."
        if category == "state transition":
            return "Add or link a lifecycle/reset side-effect rule, or classify the text as explanatory."
        if category == "data command behavior":
            return "Add or link a Read/Write data-behavior rule for the affected range/key state."
        if category == "method rule":
            return "Add or link a method-specific judge path or documented fallback status class."
        return "Add a direct RuleResult spec_ref or classify the section explicitly."
    if status == "indexed_only":
        return "Classify as non_executable/vendor_optional or add a direct rule reference if it is normative."
    if status == "transport_layer_only":
        return "Keep indexed for traceability; implement only if future traces expose raw packet/transport fields."
    if status == "type_definition_only":
        return "Keep indexed as parser/schema context; implement only if normalized traces expose the type-specific value."
    if status == "schema_metadata_only":
        return "Use extracted columns through table_schemas; add oracle checks only for executable access/state effects."
    return "No executable action planned unless hidden traces expose this behavior."


def build_coverage_report(index):
    refs_by_rule = index.get("rule_references", RULE_REFERENCES)
    refs_to_rules = rule_keys_by_ref(refs_by_rule)
    implemented_refs = set(refs_to_rules)
    sections = index.get("sections", {})
    coverage = {}
    counts = {}
    normative_gaps = []
    normative_gap_details = []
    for key, record in sorted(sections.items()):
        status = classify_coverage(key, record, implemented_refs)
        counts[status] = counts.get(status, 0) + 1
        implemented_by = sorted(refs_to_rules.get(key, []))
        entry = {
            "status": status,
            "category": record.get("category"),
            "title": record.get("title"),
            "normative_count": record.get("normative_count", 0),
            "normative_extracts": record.get("normative_extracts", []),
            "methods": record.get("methods", []),
            "path": record.get("path"),
            "implemented_by": implemented_by,
            "gap_reason": None,
            "recommended_action": recommended_action_for(record, status),
        }
        if record.get("normative_count", 0) and status in {"indexed_only", "partial"} and key not in implemented_refs:
            entry["gap_reason"] = gap_reason_for(record, status)
            normative_gaps.append(key)
            normative_gap_details.append({
                "section": key,
                "status": status,
                "category": record.get("category"),
                "title": record.get("title"),
                "reason": entry["gap_reason"],
                "recommended_action": entry["recommended_action"],
            })
        coverage[key] = entry
    unresolved_refs = sorted(ref for ref in implemented_refs if ref not in sections)
    rules_without_refs = sorted(rule_key for rule_key, refs in refs_by_rule.items() if not refs)
    return {
        "version": 2,
        "section_count": len(sections),
        "all_sections_classified": len(coverage) == len(sections) and all(item.get("status") for item in coverage.values()),
        "coverage_counts": counts,
        "sections": coverage,
        "normative_gaps": normative_gaps,
        "normative_gap_details": normative_gap_details,
        "unresolved_rule_refs": unresolved_refs,
        "rules_without_refs": rules_without_refs,
        "implemented_refs": sorted(implemented_refs),
        "rule_keys_by_ref": {key: sorted(value) for key, value in sorted(refs_to_rules.items())},
    }


def coverage_markdown(report, index):
    counts = report.get("coverage_counts", {})
    category_counts = index.get("category_counts", {})
    lines = [
        "# 0523 Spec Coverage",
        "",
        "Generated from `artifacts/spec_index.json` and the rule references used by the deterministic oracle.",
        "",
        "## Indexed Corpus",
        "",
        "- Total indexed sections: {}".format(report.get("section_count", 0)),
        "- Categories: " + ", ".join(f"{name} {count}" for name, count in sorted(category_counts.items())),
        "- Coverage states: " + ", ".join(f"{name} {count}" for name, count in sorted(counts.items())),
        "- Unresolved rule refs: {}".format(len(report.get("unresolved_rule_refs", []))),
        "- Rules without refs: {}".format(len(report.get("rules_without_refs", []))),
        "- Normative gaps: {}".format(len(report.get("normative_gaps", []))),
        "- All sections classified: {}".format(str(report.get("all_sections_classified", False)).lower()),
        "",
        "## Implemented / Partial Rule Groups",
        "",
        "- Session and method dispatch rules are implemented for every method in `METHOD_NAMES`, with explicit fallback coverage for protected methods.",
        "- ACE, AccessControl, Authority, and C_PIN preconfiguration rows are extracted into structured policy metadata when present.",
        "- Table schemas combine documented column names, preconfiguration rows, and conservative mutability hints.",
        "- LockingSP lifecycle, Revert/RevertSP reset scope, locking range flags, and data key generation are executable oracle rules.",
        "",
        "## Gap Policy",
        "",
        "- Normative sections without an executable rule are listed in `artifacts/spec_coverage_report.json` as gaps with reason and recommended action.",
        "- Explanatory, transport-layer, type-definition, schema-metadata, and optional/vendor-specific sections stay indexed and are classified rather than converted into speculative rules.",
    ]
    return "\n".join(lines) + "\n"


def enrich_spec_index(index):
    index = dict(index)
    index["table_schemas"] = build_table_schemas_from_index(index)
    index["access_policy"] = build_access_policy_from_index(index)
    return index


_BASE_BUILD_SPEC_INDEX = build_base_spec_index


def build_spec_index():
    return enrich_spec_index(_BASE_BUILD_SPEC_INDEX())


@lru_cache(maxsize=1)
def load_spec_index():
    if SPEC_INDEX_PATH.exists():
        return enrich_spec_index(json.loads(SPEC_INDEX_PATH.read_text()))
    return build_spec_index()


def write_spec_coverage(index):
    report = build_coverage_report(index)
    SPEC_COVERAGE_REPORT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    SPEC_COVERAGE_MD_PATH.write_text(coverage_markdown(report, index))
    return report


def write_spec_index(path=SPEC_INDEX_PATH):
    index = build_spec_index()
    Path(path).write_text(json.dumps(index, indent=2, sort_keys=True) + "\n")
    write_spec_coverage(index)
    return index
if __name__ == "__main__":
    index = write_spec_index()
    print(
        f"wrote {SPEC_INDEX_PATH.relative_to(ROOT)} "
        f"with {index['section_count']} sections"
    )

# Spec Coverage Explanation

This document explains the two files that track how much of the TCG Core and
Opal documentation is represented in the current deterministic oracle:

- `spec_coverage.md`: this human-readable explanation and summary.
- `artifacts/spec_index.json`: the machine-readable index built from the parsed
  specification text under `artifacts/documents`.

There is also a third generated artifact:

- `artifacts/spec_coverage_report.json`: the detailed per-section coverage
  report derived from `spec_index.json` and the rule references used by the
  oracle.

## Why This Exists

The solver is not just matching public test cases. It tries to judge whether the
final SSD command response is compliant with the TCG Storage Core and Opal SSC
specifications. To make that maintainable, the project tracks:

1. Which spec sections exist in the parsed documents.
2. Which sections are executable rules for this task.
3. Which executable sections are implemented in code.
4. Which sections are intentionally classified as non-executable, metadata,
   transport-only, type definitions, or optional/vendor-specific behavior.
5. Which normative sections still have no direct rule implementation.

## What `artifacts/spec_index.json` Is

`spec_index.json` is a structured index of the parsed spec text. It is produced
by `src/spec_docs.py` from:

```text
artifacts/documents/core/
artifacts/documents/opal/
```

In this repository those paths are symlinks to the shared root `documents/`
directory, so every version folder can use the same extracted spec text.

The index contains:

- `sections`: every parsed Core/Opal section, keyed like `core/3.3.7.1.4` or
  `opal/5.1.2`.
- `method_sections`: sections that mention known TCG methods such as `Get`,
  `Set`, `StartSession`, `Authenticate`, `GenKey`, `Activate`, `Revert`, and
  `RevertSP`.
- `table_schemas`: extracted table/column knowledge for objects such as
  `Authority`, `C_PIN`, `Locking`, `MBRControl`, `MediaKey`, `SP`, and
  `AccessControl`.
- `access_policy`: extracted AccessControl rows and ACE references.
- `preconfiguration_tables`: documented preconfigured rows from the Opal spec.
- `column_name_numbers`: normalization hints that map named columns onto the
  numeric column identifiers seen in JSON traces.
- `rule_references`: mapping from rule names used in code to spec sections.

Current indexed corpus:

| Item | Count |
|---|---:|
| Indexed spec sections | 1376 |
| Method groups | 56 |
| Table schemas | 19 |
| AccessControl rows | 114 |
| Preconfiguration tables | 50 |
| Rule reference keys | 36 |
| Column name schemas | 19 |

## What `spec_coverage.md` Is

This file is the human explanation of that tracking system. It is not the
source of truth for every section; the source of truth is the JSON artifacts.
Use this file to understand the process, then inspect
`artifacts/spec_coverage_report.json` when you need exact section-level detail.

## What `artifacts/spec_coverage_report.json` Is

The coverage report compares the indexed sections against the spec references
emitted by the deterministic oracle and related rule tables. It answers:

- Is this section implemented by an executable rule?
- Is it partially represented?
- Is it only indexed for future work?
- Is it non-executable for this project?
- Is it a normative gap that should eventually receive a rule or a documented
  exclusion?

Current coverage status:

| Coverage status | Count | Meaning |
|---|---:|---|
| `implemented` | 240 | A code rule or rule group directly references this section. |
| `partial` | 103 | Some behavior is represented, but the full section is broader than current rules. |
| `indexed_only` | 212 | Parsed and classified, but no executable rule currently points to it. |
| `schema_metadata_only` | 343 | Table/column/schema metadata, useful for normalization and validation. |
| `transport_layer_only` | 174 | Transport/packet details mostly outside final-response judging. |
| `type_definition_only` | 129 | Data type/encoding definitions rather than direct behavior rules. |
| `non_executable` | 94 | Background, explanatory, or reference text not implemented as a rule. |
| `vendor_optional` | 81 | Optional/vendor-specific behavior not generalized into the oracle. |

Additional checks:

| Check | Current value |
|---|---:|
| Normative gaps | ~120 |
| Implemented refs | 240 |
| Rules without refs | 0 |
| Unresolved rule refs | 0 |
| All sections classified | true |

## How Implementation Tracking Works

The tracking path is:

1. `src/spec_docs.py` reads the parsed documents and builds/enriches
   `spec_index.json`.
2. `src/spec_docs.py` extracts method mentions, table schemas, access-control
   rows, column names, and normative markers.
3. The oracle and state logic emit rule references through helpers such as
   `spec_refs_for(...)` in `src/oracle.py`.
4. `src/spec_tables.py` contains explicit policy tables for implemented object
   and method access rules.
5. `build_coverage_report(...)` in `src/spec_docs.py` compares implemented rule
   refs with indexed document sections.
6. `artifacts/spec_coverage_report.json` records status, reason, and recommended
   action for each indexed section.

The key design choice is that every section is classified. A section does not
need to become executable code if it is only transport detail, type definition,
schema metadata, or optional/vendor-specific behavior. But it should still be
visible in the report so we know it was considered.

## What Is Implemented

The implemented rule groups include:

- Properties response requirements.
- StartSession and Authenticate credential checks.
- session open/close lifecycle.
- Authority `Enabled`, `Secure`, and lockout-related behavior.
- C_PIN credential updates and restricted PIN-column reads.
- MSID/SID/Admin/User authority behavior.
- AdminSP and LockingSP activation and revert behavior.
- Locking range reads/sets and writable column validation.
- MBRControl reads/sets.
- GenKey effects on credentials and data readability.
- Data-plane Read/Write consistency and read-locked range behavior.
- Table schema validation for known objects and columns.

The synthetic dataset in `customtest_57/` contains PASS/FAIL examples for many
of these rule groups, so changes can be regression-tested without regenerating
the dataset:

```bash
cd v6/customtest_57
python generate_synthetic.py --check-only
```

## What Is Not Fully Implemented

Not every indexed section is implemented. That is expected. The remaining gaps
fall into three broad categories:

- Real future work: normative behavior that could affect command-response
  judging and should receive a direct rule or test.
- Partial coverage: broad sections where the project implements the subset
  needed for known traces and likely hidden cases.
- Deliberately non-executable material: type definitions, packet/transport
  details, explanatory sections, and optional/vendor-specific features.

For exact unresolved items, inspect:

```text
artifacts/spec_coverage_report.json
```

Look for sections with `status` values such as `indexed_only` or `partial`, and
check their `reason` and `recommended_action` fields.

## How To Use This When Adding Rules

When implementing a new spec rule:

1. Find the relevant section in `artifacts/spec_index.json` or
   `artifacts/spec_coverage_report.json`.
2. Add or update the deterministic rule in `src/oracle.py`, `src/solver.py`,
   `src/state.py`, or `src/spec_tables.py`.
3. Attach the correct spec reference through the existing rule-ref mechanism.
4. Add PASS and FAIL synthetic cases under `customtest_57/`.
5. Regenerate coverage artifacts if the section references changed.
6. Run public and synthetic checks.

The goal is not to claim 100% executable implementation of the whole TCG spec.
The goal is traceability: implemented rules should point to documentation, and
unimplemented documentation should be visible rather than forgotten.

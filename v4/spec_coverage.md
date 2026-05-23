# v3 Spec Coverage

Generated from `artifacts/spec_index.json` and the rule references used by the deterministic oracle.

## Indexed Corpus

- Total indexed sections: 1376
- Categories: auth/access control 301, data command behavior 54, method rule 94, non-executable reference 235, normative reference 109, state transition 59, table schema 524
- Coverage states: implemented 97, indexed_only 222, non_executable 166, partial 142, schema_metadata_only 346, transport_layer_only 174, type_definition_only 129, vendor_optional 100
- Unresolved rule refs: 0
- Rules without refs: 0
- Normative gaps: 171
- All sections classified: true

## Implemented / Partial Rule Groups

- Session and method dispatch rules are implemented for every method in `METHOD_NAMES`, with explicit fallback coverage for protected methods.
- ACE, AccessControl, Authority, and C_PIN preconfiguration rows are extracted into structured policy metadata when present.
- Table schemas combine documented column names, preconfiguration rows, and conservative mutability hints.
- LockingSP lifecycle, Revert/RevertSP reset scope, locking range flags, and data key generation are executable oracle rules.

## Gap Policy

- Normative sections without an executable rule are listed in `artifacts/spec_coverage_report.json` as gaps with reason and recommended action.
- Explanatory, transport-layer, type-definition, schema-metadata, and optional/vendor-specific sections stay indexed and are classified rather than converted into speculative rules.

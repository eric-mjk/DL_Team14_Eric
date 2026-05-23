# 0521 Spec Coverage

Generated from `artifacts/spec_index.json` and the rule references used by the deterministic oracle.

## Indexed Corpus

- Total indexed sections: 1376
- Categories: auth/access control 245, data command behavior 54, method rule 113, non-executable reference 245, normative reference 110, state transition 59, table schema 550
- Coverage states: implemented 51, indexed_only 506, non_executable 243, partial 360, vendor_optional 216
- Unresolved rule refs: 0
- Rules without refs: 0
- Normative gaps: 446
- All sections classified: true

## Implemented / Partial Rule Groups

- Session and method dispatch rules are implemented for every method in `METHOD_NAMES`, with explicit fallback coverage for protected methods.
- ACE, AccessControl, Authority, and C_PIN preconfiguration rows are extracted into structured policy metadata when present.
- Table schemas combine documented column names, preconfiguration rows, and conservative mutability hints.
- LockingSP lifecycle, Revert/RevertSP reset scope, locking range flags, and data key generation are executable oracle rules.

## Gap Policy

- Normative sections without an executable rule are listed in `artifacts/spec_coverage_report.json` as gaps with reason and recommended action.
- Explanatory and optional/vendor-specific sections stay indexed and are classified rather than converted into speculative rules.

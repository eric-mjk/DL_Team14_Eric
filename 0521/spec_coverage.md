# 0521 Spec Coverage

`artifacts/spec_index.json` is generated from every `*.txt` document under
`artifacts/documents`, including checkpoint copies present in the tree.

## Indexed Corpus

- Total indexed sections: 1383
- Categories: auth/access control 247, data command behavior 54, method rule 114, table schema 553, state transition 60, normative reference 110, non-executable reference 245
- Parsed preconfiguration/table JSON groups: 50
- Method mappings include: Properties, StartSession, SyncSession, CloseSession, Authenticate, Get, Set, Next, GetFreeSpace, GetFreeRows, GenKey, Random, Activate, Revert, RevertSP

## Implemented Rule Groups

- Session Manager: Properties, StartSession, SyncSession, CloseSession/EndSession.
- Authentication: StartSession credential matching, explicit Authenticate, per-session authorities, auth failure status classes.
- Table operations: Get, Set, Next with cellblock/value validation and method-aware protected fallback.
- Opal lifecycle: Activate, Revert, RevertSP, LockingSP active/inactive state, SID-to-Admin credential copy, failed mutation non-effects.
- Locking/data behavior: preconfigured Locking/MBR defaults, generic range columns, Read/Write lock checks, GenKey/Revert/RevertSP data invalidation.
- Traceability: `SOLVER_DEBUG=1` prints rule verdicts with spec section refs.

## Deliberate Runtime Boundaries

- Explanatory sections are indexed as non-executable references rather than turned into code.
- Optional/vendor-specific behavior is represented as conservative status classes unless the trace provides concrete evidence.
- Full ACE BooleanExpr evaluation is approximated by Admin/User authority classes because the traces expose normalized command outcomes, not complete ACL graph mutation histories.

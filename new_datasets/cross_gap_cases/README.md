# cross_gap_cases

Synthetic test cases targeting **Core-Opal crossover behaviors** — rules that require knowledge of both the TCG Core spec and the Opal SSC spec simultaneously.

## Focus Areas

Unlike `opal_gap_cases` (Opal-only rules) and `core_gap_cases` (Core-only rules), these cases test:

1. **SP-scoped authority lookup** — Core mandates authority lookup within the SP hosting the session; Opal defines which authorities exist in AdminSP vs. LockingSP.
2. **Write-session gating for lifecycle mutations** — Core's write-session requirement applies to Opal's Activate and Revert operations.
3. **SID credential scope** — SID is defined in AdminSP (Opal) but the Core authentication model determines whether SID can be used outside AdminSP.
4. **TryLimit + Revert interaction** — Core's TryLimit model interacts with Opal's C_PIN credential reset on Revert/RevertSP.
5. **GenKey invalidates locking** — Core's GenKey semantics interact with Opal's per-range key and lock state.
6. **PIN change → re-auth required** — Core's credential update rules apply to Opal's C_PIN hierarchy.
7. **LockingRange ACE policy** — Core's ACE/AccessControl evaluation applies to Opal's locking range Set columns.
8. **MBRControl + session type** — Opal's MBRControl write requires Core's write-session; read-only session rejects it.
9. **DataRemoval parameter validation** — Core's Set column validation applies to Opal's DataRemovalMechanism table.
10. **AdminSP → LockingSP authority isolation** — Core mandates per-SP authority lookup; Admin1 in LockingSP is distinct from Admin1 in AdminSP.
11. **Revert vs RevertSP scope** — Core's session closure on Revert interacts with Opal's state reset semantics.
12. **Discovery + Activate state** — Opal's Level 0 Discovery locking_enabled field reflects Opal's Activate lifecycle transition.
13. **C_PIN NOPIN encoding** — Core's Get return-value semantics apply to Opal's C_PIN PIN column.
14. **Next on Opal tables** — Core's Next method semantics apply to Opal-defined tables.
15. **AccessControl row mutation** — Core's ACE evaluation gates Opal's AccessControl table Set operations.

## Layout

```
cross_gap_cases/
  testcases/          # one JSON trajectory per case
  label.jsonl         # {"filename": ..., "label": "pass"|"fail"}
  manifest.json       # [{filename, concept, refs, ...}]
  generate_cross_gap.py
  validate_debug.py
  debug_audit.json    # written by validate_debug.py
  debug_audit.md      # human-readable audit report
  AGENT_START.md      # current status and next steps
  FIX_RECCOMENDATIONS.md
  README.md
```

## Commands

```bash
# Regenerate testcases
python3 new_datasets/cross_gap_cases/generate_cross_gap.py

# Check v7 label accuracy
python3 new_datasets/cross_gap_cases/generate_cross_gap.py --check

# Full debug audit
python3 new_datasets/cross_gap_cases/validate_debug.py

# Strict mode (fails on misses or weak reasons)
python3 new_datasets/cross_gap_cases/validate_debug.py --strict
```

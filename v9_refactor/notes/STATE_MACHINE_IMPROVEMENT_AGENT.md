# Agent instructions: improving the v9 state machine

Use this file when you are ordered to improve the `v9_refactor` state machine from `TODO.md`, evidence packets, artifacts, or local documentation.

## Mission

Improve deterministic protocol validation while preserving v8/v9 baseline behavior and producing interpretable facts that can later support LLM audit/debug workflows. The LLM should not be used as a routine runtime judge, and it should not directly flip deterministic verdicts unless a future task explicitly changes that policy.

The state machine is expected to produce two useful outputs:

1. a deterministic verdict for scoring, and
2. an interpretable evidence trail for later review by a human or LLM.

Do not optimize only for the verdict. When adding a rule or facet, also think about what compact fact, rule trace, spec reference, and risk flag would let another agent understand the decision later.

## Mandatory first steps

1. Read these notes:
   - `v9_refactor/notes/notes.md`
   - `v9_refactor/notes/TODO.md`
   - `.omx/plans/v9_refactor_evidence_packet_first_rev4.md` if present
2. Inspect the relevant source before editing:
   - `v9_refactor/src/solver.py`
   - `v9_refactor/src/state.py`
   - `v9_refactor/src/oracle.py`
   - `v9_refactor/src/normalizer.py`
   - `v9_refactor/src/parse_audit.py`
   - `v9_refactor/src/state_facts_extractor.py`
   - `v9_refactor/src/packet_serializer.py`
   - `v9_refactor/src/evidence_packet_writer.py`
3. Prefer local protocol evidence:
   - `project_specification.md`
   - `v9_refactor/artifacts/spec_index.json`
   - `v9_refactor/artifacts/documents/`
4. Generate or inspect evidence packets for failing/interesting trajectories using `EVIDENCE_PACKET_AUDIT_PATH`.

## Rule triage policy

Implement deterministic state-machine/oracle rules only when all of the following are true:

- The behavior is a clear spec-backed rule gap.
- The required evidence is concrete, or can be tracked as a general fact with provenance.
- The rule applies across protocol behavior, not just a filename, synthetic generator artifact, or one adversarial case.
- The normalizer provides enough structure to avoid guessing.
- The change can be locked with regression tests.

Do not implement as deterministic state-machine truth when:

- method names or UID names are stripped and intent must be guessed,
- raw evidence is ambiguous,
- the desired behavior depends on a dataset-specific pattern,
- the correct action is parser fallback/RAG repair/LLM audit,
- the rule would weaken an existing public/core/cross/opal/custom passing case.

Classify unresolved items explicitly as:

- `deterministic_rule_gap`
- `parser_recovery`
- `ambiguous_or_dataset_specific`

## Implementation pattern

1. Reproduce the miss or gap with the smallest targeted case available.
2. Add or update a regression test before changing broad state logic when practical.
3. Add the narrowest general fact/rule needed.
4. Prefer domain helpers/facets over growing one large branch in `oracle.py` or `state.py`.
5. Preserve packet behavior:
   - no raw payload blobs,
   - no credential leakage,
   - no wholesale `_state_snapshot`,
   - no prompt payload changes,
   - no extra LLM calls,
   - packet on/off verdict parity.
6. Add or update spec references where the rule relies on a local document section/path.
7. Update `v9_refactor/notes/TODO.md` and/or `v9_refactor/notes/notes.md` with what changed and what remains.

## Evidence packet workflow

When investigating a trajectory:

1. Run with packet emission:

   ```bash
   cd v9_refactor
   EVIDENCE_PACKET_AUDIT_PATH=/tmp/v9_packets.jsonl PYTHONPATH=. python -m unittest discover -s tests
   ```

   For dataset sweeps, set the same environment variable around the dataset runner.

2. Inspect these packet sections first:
   - `normalized_events`
   - `state_facts`
   - `rule_trace`
   - `spec_references`
   - `risk_flags`
   - `provenance`
   - `subsystem_flags`
3. If a needed fact is absent, add a bounded named fact with source/provenance rather than dumping entire mutable state.
4. If facts conflict or evidence is incomplete, prefer a risk flag/abstain over a guessed verdict.

## Evidence packet responsibilities for state-machine edits

When a state-machine change introduces a new semantic domain, update the evidence packet/fact surface if the new information is useful for audit. Examples:

- Dynamic table/ACL work should expose table identity, schema completeness, row inventory completeness, ACL source, and authorization conclusion facts.
- Capacity work should expose row capacity vs byte-space capacity separately, including whether each value is concrete or unknown.
- IssueSP work should expose issued-SP UID/name/template/size/lifecycle facts only when concrete.
- Authenticate work should expose challenge/proof state without leaking credentials or proof secrets.
- Return-shape rules should expose requested columns/parameters and the response-shape reason.

Never add full raw state dumps. Add bounded, named, redacted facts with provenance.

## Verification gates

For documentation-only changes:

```bash
ls v9_refactor/notes
```

For code changes:

```bash
cd v9_refactor
PYTHONPATH=. python -m unittest discover -s tests
```

For state-machine semantic changes, also run the relevant targeted dataset suite when available. Typical command shape:

```bash
PYTHONPATH=/workspace/Eric/ws/v9_refactor \
uv run python /workspace/Eric/ws/new_datasets/run_all_tests.py /workspace/Eric/ws/new_datasets core_gap_cases cross_gap_cases opal_gap_cases
```

Use full sweeps before submission or after risky changes. Always report exact commands and results.

## Anti-patterns

Avoid these even if they improve one adversarial score:

- hardcoding filenames, case IDs, or synthetic generator patterns,
- guessing stripped method names or stripped UID names inside the deterministic oracle,
- weakening existing tests to pass new cases,
- using LLM output to directly override deterministic verdicts by default,
- adding broad catch-all status matching without concrete state preconditions,
- storing raw secrets, credentials, or full payload blobs in evidence packets,
- expanding `oracle.py`/`state.py` with large unrelated branches when a facet/helper would isolate the domain.

## Preferred future facets

When a change is larger than a small rule, consider extracting a facet/helper around one protocol domain:

- `DynamicTableFacet`
- `AccessControlFacet`
- `CapacityFacet`
- `IssueSPFacet`
- `SessionFacet`
- `CryptoAuthFacet`
- `DiscoveryFacet`
- `ReturnShapeFacet`

Each facet should own its facts, update rules, validation rules, spec references, and unknown/ambiguous behavior.

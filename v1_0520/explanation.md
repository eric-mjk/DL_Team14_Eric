# Current Approach

The `0520` solver is a deterministic, rule-first SSD protocol test oracle. It does not use the previous Qwen prompt baseline at runtime. Instead, it reads the full command-response trajectory, reconstructs the relevant protocol state from all non-final steps, and judges whether the final response is compliant with that inferred state.

The core idea is:

```text
raw JSON trajectory
  -> canonical events
  -> state tracker over events[:-1]
  -> final-response oracle
  -> "pass" or "fail"
```

This matches the project framing: `pass` does not mean the SSD returned `SUCCESS`, and `fail` does not mean the SSD returned an error. The solver asks whether the final response is the response the protocol state allows.

## Entry Point

`src/solver.py` keeps the grader-facing contract:

- `Solver.predict(dataset)` returns a dictionary from testcase id to `"pass"` or `"fail"`.
- `Solver.predict_one(steps)` handles one trajectory.
- The output labels are always lowercase.

For each trajectory, `predict_one` does:

```python
events = normalize_trajectory(steps)
state = track_state(events[:-1])
result = judge_final(state, events[-1])
return result.verdict
```

Only the final event is judged. Earlier events are used only to infer state.

## Normalization

`src/normalizer.py` converts raw testcase JSON into canonical event dictionaries. This hides noisy JSON shape differences and maps important UIDs into symbolic names.

It normalizes:

- method records such as `StartSession`, `Get`, `Set`, `Activate`, `GenKey`, `Properties`, and `EndSession`;
- non-TCG data commands such as `Read` and `Write`;
- status strings such as `SUCCESS`, `Success`, `NOT AUTHORIZED`, `INVALID_PARAMETER`, and `FAIL`;
- SPIDs such as `AdminSP` and `LockingSP`;
- authority UIDs such as `SID`, `Admin1`, and generated `Authority_xxxxxx` names;
- important objects such as `C_PIN_MSID`, `C_PIN_SID`, `Locking_Global`, `Locking_Range1`, `MBRControl`, `LockingInfo`, and `Range1_Key`;
- LBA ranges such as `"80 ~ 87"` into tuple form.

The normalized events preserve raw records too, so more rules can be added later without changing the solver interface.

## State Tracking

`src/state.py` processes all events before the final target command.

Tracked state includes:

- current session: open/closed, SP, authority, and write flag;
- credentials for `SID`, `MSID`, `Admin1`, and dynamically observed authorities;
- whether the Locking SP has been activated;
- Locking range and MBR control values seen through successful `Set` operations;
- key generation counters, especially for `Range1_Key`;
- written LBA patterns and the key generation at the time of each write;
- observed reads for debugging and future extension.

The most important invariant is that failed operations do not mutate state. For example:

- failed `StartSession` does not open a session;
- failed `Set` does not update credentials or locking config;
- failed `Activate` does not activate the Locking SP;
- failed `GenKey` does not change the key generation counter.

This is what lets the solver reason about long-range state instead of treating the final status code in isolation.

## Final Oracle

`src/oracle.py` compares the final event against the inferred state and returns:

```python
RuleResult(verdict, confidence, reason)
```

Current high-confidence rules cover the public-case taxonomy:

- `Properties` on the Session Manager should succeed.
- `Get(C_PIN_MSID)` requires an open AdminSP session.
- `StartSession` succeeds when the challenge matches the tracked credential and fails when it does not.
- LockingSP `StartSession` requires successful LockingSP activation first.
- `C_PIN Set` requires an authenticated write session.
- `Authority Set`, `Locking Set`, and `MBRControl Set` require an authenticated Admin1 LockingSP write session.
- `Activate` succeeds only when activating the actual LockingSP object from an authenticated SID AdminSP write session.
- `GenKey(Range1_Key)` requires an authenticated Admin1 LockingSP write session.
- `Get(Locking)`, `Get(MBRControl)`, and `Get(LockingInfo)` require an open LockingSP session.
- A final `Read` after a successful `GenKey` should not return the old written pattern. Returning the old pattern is judged `fail`; returning different/random data is judged `pass`.

There is also a conservative fallback: success-like final responses become `pass`, and error-like final responses become `fail`, unless a specific rule overrides that behavior.

## Debugging

Normal evaluation is quiet. To print the final event, prediction, and rule reason, run with:

```bash
SOLVER_DEBUG=1 DATASET_DIR=../dataset LABEL_PATH=../dataset/label.jsonl python evaluate.py
```

This is useful for error analysis because each prediction can be traced to a rule reason instead of a black-box model output.

## Current Status

The current implementation is deterministic and offline. It does not load a model, use network access, or depend on GPU availability during evaluation.

Verified public result:

```text
score=100.00
```

The implementation is ready as a first submission baseline. The main remaining work is private-set hardening: adding broader protocol rules for unseen object/method combinations, more complete authorization logic, and stronger fallbacks for protected operations.

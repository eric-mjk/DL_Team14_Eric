# 0521 Solver 설명

`0521` solver는 deterministic rule-based SSD/TCG protocol oracle이다. 모델이나 네트워크를 사용하지 않고, testcase의 command-response trajectory를 읽어서 마지막 response가 현재 프로토콜 상태와 일치하는지 판단한다.

핵심 흐름은 다음과 같다.

```text
raw JSON trajectory
  -> canonical events
  -> state tracker over events[:-1]
  -> final-response oracle on events[-1]
  -> "pass" or "fail"
```

여기서 `pass`는 SSD가 `SUCCESS`를 반환했다는 뜻이 아니다. `pass`는 마지막 response가 이전 step들로 복원한 상태에서 프로토콜상 자연스럽다는 뜻이다. `fail`도 단순히 SSD가 error status를 반환했다는 뜻이 아니라, 마지막 response가 현재 상태와 모순된다는 뜻이다.

## Entry Point

`src/solver.py`가 grader-facing interface를 유지한다.

- `Solver.predict(dataset)`은 testcase id에서 `"pass"`/`"fail"`로 가는 dict를 반환한다.
- `Solver.predict_one(steps)`는 하나의 trajectory를 처리한다.
- 출력 label은 항상 lowercase다.

`predict_one()`의 핵심은 다음 세 줄이다.

```python
events = normalize_trajectory(steps)
state = track_state(events[:-1])
result = judge_final(state, events[-1])
```

즉 모든 step을 normalized event로 바꾼 뒤, 마지막 step 직전까지의 event만 replay해서 state를 만들고, 마지막 event만 oracle로 판정한다.

## Normalizer

`src/normalizer.py`는 raw testcase JSON을 canonical event dict로 변환한다. JSON shape 차이를 숨기고, UID나 column name처럼 rule에 필요한 값을 안정적인 내부 표현으로 바꾼다.

정규화하는 주요 항목은 다음과 같다.

- method: `Properties`, `StartSession`, `SyncSession`, `Authenticate`, `Get`, `Set`, `Next`, `Random`, `Activate`, `GenKey`, `Revert`, `RevertSP`, `CloseSession` 등
- data command: `Read`, `Write`
- status: `SUCCESS`, `NOT_AUTHORIZED`, `INVALID_PARAMETER`, `FAIL` 등을 canonical status로 변환
- SPID: `AdminSP`, `LockingSP`, generic SP UID
- authority: `SID`, `Admin1`, `User1`, generic Authority UID
- object family: `C_PIN`, `Authority`, `Locking`, `LockingInfo`, `MBRControl`, `MediaKey`, `SP` 등
- `Values`, `Cellblock`, `HostChallenge`, `HostSigningAuthority`, `SPID`, `KeepGlobalRangeKey` 같은 method parameter
- LBA range와 Read/Write pattern/result

`artifacts/spec_index.json`에서 온 column-name mapping도 사용해서 `ReadLocked`, `WriteLocked`, `PIN` 같은 named column을 내부 numeric column으로 맞춘다.

## State Tracking

`src/state.py`는 마지막 step 전까지의 event들을 순서대로 적용한다. 현재 solver가 추적하는 상태는 다음과 같다.

- session open/closed, 현재 SP, write/read mode
- 현재 session에서 인증된 authority set
- `SID`, `MSID`, `Admin1`, `UserN` 등 credential
- LockingSP lifecycle과 active 여부
- Locking range의 `RangeStart`, `RangeLength`, `ReadLockEnabled`, `WriteLockEnabled`, `ReadLocked`, `WriteLocked`
- MBRControl 값
- media key generation count
- Write된 LBA pattern과 당시 key generation
- Read 기록과 debug용 history

가장 중요한 invariant는 실패한 state-changing operation은 상태를 바꾸지 않는다는 것이다.

예를 들어:

- 실패한 `Set(C_PIN)`은 PIN을 바꾸지 않는다.
- 실패한 `Activate(LockingSP)`는 LockingSP를 활성화하지 않는다.
- 실패한 `GenKey`는 key generation을 증가시키지 않는다.
- 실패한 `Revert/RevertSP`는 lifecycle이나 data state를 reset하지 않는다.

실패 event는 완전히 버리는 것은 아니다. history에는 남고, open session 안의 실패 method는 `session.had_failure=True`로 표시된다. 하지만 실제 credential, lifecycle, locking config, key generation 같은 상태 변경은 성공한 event만 반영한다.

## Final Oracle

`src/oracle.py`는 마지막 event를 현재 state와 비교한다. 먼저 마지막 response를 status class로 바꾼다.

대표 status class는 다음과 같다.

- `success`
- `auth_error`
- `invalid_parameter`
- `resource_error`
- `error`
- `data_success`
- `data_error`

그 다음 method나 command 종류별로 expected status class를 계산한다.

주요 rule은 다음과 같다.

- `Properties`는 Session Manager에 호출되어야 한다.
- `StartSession`은 SP availability, session open 여부, credential/challenge match를 본다.
- `Authenticate`는 open session과 proof/credential match를 본다.
- `Get`은 object family별 access-control과 Cellblock validity를 본다.
- `Set`은 write session, authenticated authority, protected column access를 본다.
- `Activate`는 AdminSP write session과 SID authority가 있어야 LockingSP activation으로 인정한다.
- `GenKey`는 active LockingSP와 authenticated LockingSP admin write session이 필요하다.
- `Revert/RevertSP`는 owner/admin write session과 target SP lifecycle을 본다.
- `Read/Write`는 Locking range lock flags, range overlap, GenKey 이후 data invalidation을 본다.

마지막으로 expected status class와 actual status class가 맞으면 `pass`, 맞지 않으면 `fail`을 반환한다.

## Spec Index와 Traceability

`src/spec_docs.py`는 `artifacts/documents` 아래의 Core/Opal 문서 txt를 스캔해서 `artifacts/spec_index.json`을 만든다. 현재 index는 문서 트리의 모든 txt section을 포함한다.

index에는 다음 정보가 들어간다.

- section id, title, path
- category: method rule, table schema, auth/access control, state transition, data command behavior 등
- method-to-section mapping
- normative extract count
- preconfiguration JSON table
- rule reference mapping
- column-name mapping

oracle의 `RuleResult`에는 적용된 spec section ref가 붙는다. `SOLVER_DEBUG=1`을 켜면 최종 event, expected/actual status, verdict, state summary, spec refs, reason을 함께 볼 수 있다.

```bash
SOLVER_DEBUG=1 DATASET_DIR=../dataset LABEL_PATH=../dataset/label.jsonl python evaluate.py
```

## Current Status

현재 구현은 deterministic/offline이다. runtime에서 LLM, network, GPU를 사용하지 않는다.

검증된 public score:

```text
score=100.00
```

현재 방향은 public testcase만 맞추는 것이 아니라, Core/Opal 문서 기반으로 state machine과 oracle rule을 확장해서 hidden testcase에서도 일반화하는 것이다.

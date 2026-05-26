# v5 Solver 설명

`v5` solver는 deterministic rule-based SSD/TCG protocol oracle이다. 모델이나 네트워크를 사용하지 않고, testcase의 command-response trajectory를 읽어서 마지막 response가 현재 프로토콜 상태와 일치하는지 판단한다.

핵심 흐름은 다음과 같다.

```text
raw JSON trajectory
  -> canonical events (normalize_trajectory)
  -> state tracker over events[:-1]  (StateMachine.apply)
  -> final-response oracle on events[-1]  (Solver._expected_*)
  -> "pass" or "fail"
```

여기서 `pass`는 SSD가 `SUCCESS`를 반환했다는 뜻이 아니다. `pass`는 마지막 response가 이전 step들로 복원한 상태에서 프로토콜상 자연스럽다는 뜻이다. `fail`도 단순히 SSD가 error status를 반환했다는 뜻이 아니라, 마지막 response가 현재 상태와 모순된다는 뜻이다.

## Entry Point

`src/solver.py`가 grader-facing interface를 유지한다.

- `Solver.predict(dataset)`: testcase id에서 `"pass"`/`"fail"`로 가는 dict 반환
- `Solver.predict_one(steps)`: 하나의 trajectory를 처리
- 출력 label은 항상 lowercase

`predict_one()`의 핵심 흐름:

```python
events = normalize_trajectory(steps)          # canonical event dicts
machine = StateMachine()
for event in events[:-1]:                     # replay prefix
    machine.apply(event)
solver = Solver(machine.state)
verdict = solver.judge(events[-1])            # oracle on final event
return verdict  # "pass" or "fail"
```

즉 모든 step을 normalized event로 바꾼 뒤, 마지막 step 직전까지만 replay해서 state를 만들고, 마지막 event만 oracle로 판정한다.

## Architecture Overview

v5는 모든 코드가 **단일 파일 `src/solver.py`** 에 있다. 이전 v3의 `normalizer.py`, `state.py`, `oracle.py` 구조에서 일원화되었다.

주요 클래스:

| 클래스 | 역할 |
|---|---|
| `ProtocolState` | dataclass — 프로토콜 상태 전체를 담는 컨테이너 |
| `StateMachine` | `ProtocolState`를 event 단위로 mutation하는 state tracker |
| `ExpectedOutcome` | oracle 결과를 담는 데이터 클래스 (`status`, `reason`) |
| `Solver` | oracle — 현재 state에서 final event가 expected인지 판정 |

`src/spec_tables.py`는 policy 상수(POLICIES dict, allowed authorities 등)를 담는 별도 모듈이다.

## Normalizer (normalize_trajectory)

`normalize_trajectory(steps)` 함수가 raw testcase JSON을 canonical event dict로 변환한다. JSON shape 차이를 숨기고, UID나 column name처럼 rule에 필요한 값을 안정적인 내부 표현으로 바꾼다.

주요 정규화 항목:

- method: `Properties`, `StartSession`, `Authenticate`, `Get`, `Set`, `Activate`, `GenKey`, `Revert`, `RevertSP`, `EndSession` 등
- data command: `Read`, `Write`
- status: `SUCCESS`, `NOT_AUTHORIZED`, `INVALID_PARAMETER`, `FAIL` 등을 canonical uppercase status로 변환
- SPID: `AdminSP`, `LockingSP`
- authority: `SID`, `Admin1`, `User1` 등
- object UID family: `C_PIN`, `Authority`, `Locking`, `LockingInfo`, `MBRControl`, `MediaKey`, `SP` 등
- method parameter: `Values`, `Cellblock`, `HostChallenge`, `HostSigningAuthority`, `SPID`, `KeepGlobalRangeKey`
- LBA range와 Read/Write pattern/result

## State Tracking (StateMachine)

`StateMachine`은 마지막 step 전까지의 event들을 순서대로 적용한다.

`ProtocolState`에 담기는 주요 필드:

- `session`: `{open, spid, authority, write}` — 현재 세션 정보
- `credentials`: `{SID, MSID, Admin1, ...}` — credential 값 (raw bytes)
- `authenticated_authorities`: 현재 세션에서 인증된 authority set
- `locking_sp_active`: LockingSP lifecycle 상태
- `enabled_authorities`: `authority → bool` dict
- `deleted_credentials`: 삭제된 credential set (Revert 등에 의해)
- `locking_ranges`: range UID → config dict (ReadLocked, WriteLocked, ...)
- `key_generations`: `{range_key_uid → count}` — GenKey 성공 시 증가
- `writes`: `{lba_tuple → {pattern, key_gen_snapshot}}` — LBA write 기록

가장 중요한 invariant: **실패한 state-changing operation은 상태를 바꾸지 않는다.**

예시:
- 실패한 `Set(C_PIN)` → PIN 유지
- 실패한 `Activate(LockingSP)` → LockingSP 미활성화
- 실패한 `GenKey` → key generation 증가 안 함
- 실패한 `Revert/RevertSP` → lifecycle/data state reset 안 함

## Final Oracle (Solver)

`Solver`는 현재 `ProtocolState`를 받아, final event가 프로토콜상 expected인지 판정한다.

판정 흐름:

1. `Read` → `_expected_read`: key generation snapshot 비교
2. `Write` → 항상 pass (write 자체는 oracle 판정 안 함)
3. method → method명으로 dispatch:
   - `_expected_properties`
   - `_expected_start_session`
   - `_expected_get`
   - `_expected_set`
   - `_expected_activate`
   - `_expected_gen_key`
   - `_expected_revert`
   - `_expected_end_session`

`ExpectedOutcome.status`와 실제 response status를 비교해서 match이면 `"pass"`, 아니면 `"fail"`.

### Policy 시스템 (spec_tables.py)

`spec_tables.py`의 `POLICIES` dict가 operation별 ACL을 정의한다. 각 `Policy`는 다음을 지정한다:

- `session_spid`: 어떤 SP에서 호출해야 하는지
- `require_authenticated`: 인증 필요 여부
- `allowed_authorities`: 허용된 authority set
- `require_activated_sp`: activated 상태여야 하는 SP

이 POLICIES는 spec의 ACE/AccessControl 테이블 규칙을 정적으로 구현한 것이다.

### 주요 spec 규칙

**C_PIN PIN 컬럼 (column 3) 읽기 규칙:**
- `ACE_C_PIN_MSID_Get_PIN`: C_PIN_MSID의 PIN은 Anybody가 읽을 수 있음 (AdminSP에서)
- `ACE_C_PIN_SID_Get_NOPIN`: 이름에 "NOPIN"이 있음 — SID 자신도 자기 PIN 못 읽음
- `ACE_C_PIN_Admins_Get_All_NOPIN`: LockingSP Admin도 자기 C_PIN PIN 못 읽음
- 결론: **C_PIN_MSID를 제외한 모든 C_PIN의 PIN 컬럼은 읽을 수 없음**

**Revert ACL:**
- spec ACE_SP_SID OR ACE_Admin: SID 또는 Admin authority 둘 중 하나면 충분
- AdminSP write session 필요

**GET/SET Locking table:**
- LockingSP Admins 인증 필요 (ACE_Locking_RangeN_Get/Set)
- activated LockingSP 필요

## 디버그 실행

```bash
# 공개 dataset 평가
cd v5_usereference
python evaluate.py

# 디버그 출력 활성화
SOLVER_DEBUG=1 python evaluate.py

# 합성 테스트 케이스 생성 및 정확도 확인
python generate_synthetic.py --check
```

## Synthetic Test Cases

→ `tests/` 디렉토리 아래의 [SYNTHETIC_TESTS.md](tests/SYNTHETIC_TESTS.md) 참조

## 현재 상태

- Public dataset: 20/20 (100%)
- Synthetic dataset: 57/57 (100%)
- Runtime: 완전히 deterministic, offline (LLM/network/GPU 없음)

### v5 주요 수정 이력 (spec 감사 기반, 2026-05-26)

| 수정 항목 | 파일 | spec 근거 |
|---|---|---|
| Revert ACL: SID OR Admin (OR로 수정) | solver.py | opal/5.1.2 |
| C_PIN PIN Get 불가: MSID만 예외 | solver.py | opal/4.2.1.5 ACE_*_NOPIN |
| GET Locking: Admins 인증 필요 | spec_tables.py | opal ACE_Locking_RangeN_Get |
| SET Locking: Admins 인증 필요 | spec_tables.py | opal ACE_Locking_RangeN_Set |

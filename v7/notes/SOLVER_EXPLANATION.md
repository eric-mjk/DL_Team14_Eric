# v6 Solver 설명

`v6` solver는 deterministic rule-based SSD/TCG protocol oracle이다. 모델이나 네트워크를 사용하지 않고, testcase의 command-response trajectory를 읽어서 마지막 response가 현재 프로토콜 상태와 일치하는지 판단한다.

핵심 흐름은 다음과 같다.

```text
raw JSON trajectory
  -> canonical events (normalize_trajectory)        # normalizer.py
  -> state tracker over events[:-1]  (track_state)  # state.py
  -> final-response oracle on events[-1]  (judge_final)  # oracle.py
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
events = normalize_trajectory(steps)   # canonical event dicts (normalizer.py)
state  = track_state(events[:-1])      # replay prefix (state.py)
result = judge_final(state, events[-1])# oracle on final event (oracle.py)
return result.verdict  # "pass" or "fail"
```

즉 모든 step을 normalized event로 바꾼 뒤, 마지막 step 직전까지만 replay해서 state를 만들고, 마지막 event만 oracle로 판정한다.

## Architecture Overview

v6는 코드를 **5개 파일로 분리**했다. v5의 단일 파일 `solver.py` 에서 역할별로 모듈을 분리해서 유지보수성을 높였다.

| 파일 | 역할 |
|---|---|
| `solver.py` | grader-facing entry point, `Solver.predict` / `predict_one`, debug summary |
| `normalizer.py` | raw JSON record → canonical event dict, UID/method/status 정규화 |
| `state.py` | prefix event replay, `ProtocolState` mutation, TryLimit/re-encrypt 추적 |
| `oracle.py` | final event judging, method별 dispatch, ACE/AccessControl policy 평가 |
| `spec_docs.py` | spec metadata, column maps, rule refs, coverage helpers, NOT_READABLE_VIA_GET |

`src/spec_tables.py`는 이전 버전의 정적 policy 상수를 담는 레거시 모듈로 유지된다.

## Normalizer (normalizer.py)

`normalize_trajectory(steps)` 함수가 raw testcase JSON을 canonical event dict로 변환한다.

주요 정규화 항목:

- method: `Properties`, `StartSession`, `Authenticate`, `Get`, `Set`, `Activate`, `GenKey`, `Revert`, `RevertSP`, `EndSession` 등
- data command: `Read`, `Write`
- IF_RECV command: `kind="discovery"` 이벤트로 정규화 (Level 0 Discovery)
- status: `SUCCESS`, `NOT_AUTHORIZED`, `INVALID_PARAMETER`, `FAIL` 등을 canonical uppercase로 변환
- SPID: `AdminSP`, `LockingSP`
- authority: `SID`, `Admin1`, `User1` 등
- object UID family: `C_PIN`, `Authority`, `Locking`, `LockingInfo`, `MBRControl`, `MediaKey`, `SP` 등
- method parameter: `Values`, `Cellblock`, `HostChallenge`, `HostSigningAuthority`, `SPID`, `KeepGlobalRangeKey`
- MethodID UID-to-name normalization (preconfiguration table 기반)
- LBA range와 Read/Write pattern/result

## State Tracking (state.py)

`track_state(events)` 함수가 prefix event들을 순서대로 적용해서 `ProtocolState` dict를 반환한다.

`ProtocolState`에 담기는 주요 필드:

- `session`: `{open, spid, authority, write, trusted}` — 현재 세션 정보
- `credentials`: `{SID, MSID, Admin1, ...}` — credential 값 (raw bytes)
- `authenticated_authorities`: 현재 세션에서 인증된 authority set
- `locking_sp_active`: LockingSP lifecycle 상태
- `enabled_authorities`: `authority → bool` dict
- `secure_authorities`: `authority → bool` dict (Authority.Secure 컬럼)
- `deleted_credentials`: 삭제된 credential set (Revert 등에 의해)
- `locking_ranges`: range UID → config dict (ReadLocked, WriteLocked, ReEncryptState 등)
- `key_generations`: `{range_key_uid → count}` — GenKey 성공 시 증가
- `writes`: `{lba_tuple → {pattern, key_gen_snapshot}}` — LBA write 기록
- `trylimit_by_authority`: authority별 TryLimit 설정
- `failed_auth_counts`: authority별 실패 인증 횟수
- `ace_rows`, `access_control_rows`: 동적으로 변경된 ACE/AccessControl 상태

가장 중요한 invariant: **실패한 state-changing operation은 상태를 바꾸지 않는다.**

예시:
- 실패한 `Set(C_PIN)` → PIN 유지
- 실패한 `Activate(LockingSP)` → LockingSP 미활성화
- 실패한 `GenKey` → key generation 증가 안 함
- 실패한 `Revert/RevertSP` → lifecycle/data state reset 안 함

## Final Oracle (oracle.py)

`judge_final(state, event)` 함수가 현재 state에서 final event가 프로토콜상 expected인지 판정한다.

판정 흐름 (method별 dispatch):

| Kind/Method | 함수 |
|---|---|
| `discovery` (IF_RECV) | `judge_discovery` |
| `Read` | `judge_read` |
| `Write` | pass-through |
| `Properties` | `judge_properties` |
| `StartSession` | `judge_start_session` |
| `Authenticate` | `judge_authenticate` |
| `Get` | `judge_get` |
| `Set` | `judge_set` |
| `Activate` | `judge_activate` |
| `GenKey` | `judge_gen_key` |
| `Revert` | `judge_revert` |
| `RevertSP` | `judge_revert_sp` |
| `GetACL`, `AddACE`, `RemoveACE`, `DeleteMethod` | `judge_meta_acl` |
| `AddLog`, `CreateLog`, `ClearLog`, `FlushLog` | `judge_log` |
| clock, crypto, hash/HMAC, sign/verify, table mgmt 등 | 개별 judge 함수 |

`RuleResult.verdict`와 실제 response status를 비교해서 match이면 `"pass"`, 아니면 `"fail"`.

### ACE/AccessControl 정책 시스템

oracle.py는 `spec_docs.py`에서 로드한 ACE/AccessControl 행을 동적으로 평가한다.

- `lookup_ace(state, sp, object_family, method)`: 해당 object/method의 ACE 행 조회
- BooleanExpr evaluator: `Admins`, `Users`, `Anybody`, `SID`, 특정 authority 토큰 처리
- 동적 상태: `state["ace_rows"]`, `state["access_control_rows"]`가 `Set/AddACE/RemoveACE`로 변경될 수 있음
- `NOT_READABLE_VIA_GET`: AccessControl table (N) 컬럼(1,2,4,8)은 Get으로 읽을 수 없음

### Level 0 Discovery

`judge_discovery(state, event)`:
- required feature descriptors: 0x0001(TPer), 0x0002(Locking), 0x0203(Opal SSC V2)
- TPer sync/streaming bit, Locking supported/media_enc/mbr_shadow 검증
- LockingEnabled vs locking_sp_active 일치 검증
- Opal V2 admin/user/comid count 검증 (None 가드 적용)

### 주요 spec 규칙

**C_PIN PIN 컬럼 (column 3) 읽기:**
- `ACE_C_PIN_MSID_Get_PIN`: C_PIN_MSID의 PIN은 Anybody가 읽을 수 있음
- `ACE_C_PIN_SID_Get_NOPIN` / `ACE_C_PIN_Admins_Get_All_NOPIN`: MSID 외 모든 C_PIN PIN 컬럼 읽기 불가

**Revert ACL:** SID 또는 Admin authority 중 하나면 충분 (opal/5.1.2)

**Locking table GET/SET:** LockingSP Admins 인증 필요

**Re-encryption:** column 12 read-only, ReEncryptState 전이 추적, NextKey Set은 IDLE 상태에서만

## 디버그 실행

```bash
# 공개 dataset 평가
cd v6
python evaluate.py

# 디버그 출력 활성화
SOLVER_DEBUG=1 python evaluate.py

# 합성 테스트 케이스 정확도 확인
cd v6/customtest_57
python generate_synthetic.py --check-only
```

## Synthetic Test Cases

→ `v6/customtest_57/` 디렉토리 참조

## 현재 상태

- Public dataset: 20/20 (100%)
- Synthetic dataset: 84/84 (100%)
- Runtime: 완전히 deterministic, offline (LLM/network/GPU 없음)

### v6 주요 수정 이력 (spec 감사 DEFER tier, 2026-05-27)

| 수정 항목 | 파일 | spec 근거 |
|---|---|---|
| 5파일 아키텍처 분리 | 전체 | — |
| Level 0 Discovery 판정 | normalizer.py, oracle.py | opal/3.1.1 |
| AccessControl (N) 컬럼 읽기 금지 | oracle.py, spec_docs.py | opal/4.2.6.1 |
| AccessControl 전체 행 Get (N) 우회 버그 수정 | oracle.py | opal/4.2.6.1 |
| GetACL: open session만 필요 (ACE_Anybody) | oracle.py | opal SSC |
| Re-encryption 컬럼 스키마 완성 | state.py, oracle.py | core/5.7.3 |
| Log 메서드 지원 | oracle.py | core log methods |
| TryLimit/Tries 추적 | state.py, oracle.py | core/3.3.7.4 |
| DoneOnReset 논리 수정 | state.py | opal/4.3.1.6 |
| AddACE/RemoveACE/DeleteMethod | oracle.py | core meta-ACL |
| 반복 Activate SID→Admin1 재복사 버그 수정 | state.py | opal/5.1.1.2 |

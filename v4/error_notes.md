# v3 Error Notes

- Broadened status normalization to compare expected status classes instead of only success vs failure.
- Treated prior failed state-changing methods as non-mutating: failed credential, activation, and key-generation attempts do not update replayed state.
- Replaced the broad success-like method fallback with method-aware authorization defaults for protected operations.
- Generalized Locking, C_PIN, Authority, SP, and media-key object handling by UID family so hidden range/key rows are not tied to public-case exact UIDs.
- Added locking-range read/write checks using ReadLockEnabled, WriteLockEnabled, ReadLocked, and WriteLocked columns before applying key-generation readback rules.
- Added a generated spec index from all document text files and attached spec section references to debug oracle decisions.
- Added lifecycle handling for Revert/RevertSP and initialized Locking/MBR defaults from Opal preconfiguration tables.
- Added generated coverage reporting (`spec_coverage.md` plus `artifacts/spec_coverage_report.json`) and fixed rule-reference validation so all emitted refs resolve into the index.
- Extracted ACE, AccessControl, Authority, and C_PIN preconfiguration rows into state policy metadata, with a conservative three-valued BooleanExpr evaluator.
- Added schema-first column validation, read-only Set handling, named Cellblock normalization, and Locking range overlap checks.
- Extended debug output with matched policy source and coverage status.
- Excluded checkpoint document copies from spec indexing, upgraded coverage gaps with reasons/actions, and made successful policy-table operations update ACE/AccessControl/Authority/C_PIN state.
- Parsed documented markdown table descriptions into `table_schemas`, including Authority column 0x05 `Enabled`, AccessControl column 0x04 `ACL`, generic Table/Column metadata, and Locking/MBR/MediaKey aliases.
- Classified transport-layer, packet/token, data-type, and schema-metadata-only sections outside the executable normative gap list; current generated gap count is 171 with no unresolved refs.
- Added a method preflight matrix for common fail conditions: missing required parameters, malformed `Cellblock`/`Values`/`Where`/`Count`, invalid targets, closed sessions, and read-only write attempts.
- Tightened `Authority.Enabled`, class authority tokens (`Admins`, `Users`, `Anybody`), dynamic ACE/AccessControl mutation, `KeepGlobalRangeKey`, and range-crossing lock behavior.
- Corrected `Set` without `Values` to be a no-op success candidate, and corrected disabled-authority `Authenticate` to expect `SUCCESS` with a false result instead of an authorization status.

## v3 Second Pass — Spec Audit 수정 사항 (2026-05-23)

이번 세션에서는 spec 문서(`artifacts/documents/opal/`, `artifacts/documents/core/`)를 전체 감사해서 oracle과 state tracker의 미구현 규칙을 찾아 수정했다.

### 배경 및 접근 방식

접근은 다음과 같다:

1. **오라클이 뭘 판정하는지 파악**: 마지막 command의 response가 이전 step들로 복원한 상태에서 프로토콜상 허용되는지 확인. status class 비교.
2. **Spec 문서 전체 감사**: `opal/4.x`, `opal/5.x`, `core/3.x` 섹션을 읽으면서 구현된 rule과 실제 spec 사이의 gap을 찾음.
3. **병목**: policy path(spec_index ACE/AccessControl)가 맞으면 fallback이 안 실행되므로, fallback logic의 버그는 spec_index에 해당 ACE가 없는 경우에만 표면에 드러남. 따라서 spec_index에 없는 ACE를 쓰는 hidden testcase가 있으면 fallback 버그가 verdict를 망침.

### First Pass 수정 (이전 세션, spec 버그 3개)

**Bug 1 — C_PIN col 3 (PIN) hidden from Get**
- `judge_get`에서 policy check 이후, write-only column (`write_only_columns_for_family`)이 요청된 경우 `auth_error` 반환
- C_PIN MSID는 예외 (`ACE_C_PIN_MSID_Get_PIN`으로 명시 허용, spec opal/4.2.1.5)

**Bug 2 — User1 Class=Null: Users 클래스에 속하지 않음**
- `authority_classes_for`의 fallback 로직이 `authority.startswith("User")`로 User1을 Users에 포함시켰음
- spec opal/4.3.1.8: User1은 Class=Null, Users 클래스 아님
- regex `re.fullmatch(r"User[2-9]\d*|User\d{2,}", authority)`로 User2 이상만 Users에 포함하도록 수정

**Bug 3 — Activate 시 Admin1 무조건 덮어쓰기**
- `apply_successful_activate`가 `Admin1 is None`일 때만 SID 값 복사했음
- spec opal/5.1.1.2: Activate 시점에 SID PIN을 Admin1에 항상 복사 (기존 값 덮어씀)
- `is None` guard 제거

**Fix 4 (Plan) — MBRControl Get fallback: admin 불필요**
- fallback이 `session_has_admin_authority` 요구했음
- spec opal/4.3.1.6: `ACE_Anybody` 적용 → open LockingSP session만 있으면 됨

**Fix 5 (Plan) — GenKey on C_PIN: 잘못된 status class**
- C_PIN에 GenKey → `invalid_parameter` 반환 (기존)
- Opal SSC AccessControl 테이블에 C_PIN GenKey ACE 없음 → SSD는 `not_authorized` 반환
- `family == "C_PIN"` 이면 `auth_error` class 반환하도록 수정

### Second Pass 수정 (이번 세션, spec 감사 후 6개 rule)

**Fix 1 — LockOnReset list type 처리 (`state.py: reset_flag_enabled`)**
- `to_bool`이 list를 처리 못 해서 잘못된 값 반환
- LockOnReset은 reset type enum의 set: 빈 list → False, non-empty → True
- `isinstance(value, (list, tuple, set))` 분기 추가

**Fix 2 — MBR DoneOnReset 논리 반전 (`state.py: apply_reset_like_event`)**
- reset 발생 시 `state["mbr"]["done"] = done_on_reset` 으로 그대로 복사 (버그)
- spec opal/4.3.1.6: DoneOnReset=True이면 reset 시 Done을 **False로** 설정 (MBR shadow 상태 초기화)
- `if parsed: state["mbr"]["done"] = False` 로 수정

**Fix 3 — TryLimit/Tries 추적 (`state.py` + `oracle.py`)**
- spec core/3.3.7.4: Authenticate 실패 시 Tries 증가, TryLimit 초과 시 AUTHORITY_LOCKED_OUT
- 추가한 state 필드: `trylimit_by_authority`, `failed_auth_counts`
- `apply_event`: 실패한 `Authenticate` event에서 `failed_auth_counts[authority]` 증가
- `remember_successful_authenticate`, `remember_successful_start_session`: 성공 시 count 초기화
- `apply_successful_get`, `apply_successful_set`: C_PIN col 5 (TryLimit) 읽으면 `trylimit_by_authority[authority]` 저장
- `oracle.py: is_authority_locked_out()`: `failed >= trylimit > 0`이면 locked out 판정
- `judge_start_session`, `judge_authenticate`: credential check 전에 lockout 여부 먼저 확인

**Fix 4 — C_PIN_SID Set: SID authority만 허용 (`oracle.py: judge_set`)**
- 기존 fallback이 Admins 전체에 C_PIN_SID Set을 허용했음
- spec opal/4.2.1.5: `ACE_C_PIN_SID_Set_PIN`은 SID 자신만 허용 (Admin1 불가)
- `obj == "C_PIN_SID" and target_sp == "AdminSP"` 케이스를 분리해서 `"SID" in authorities` 만 허용

**Fix 5 — DataStore fallback: admin 필요 (`oracle.py: judge_get`, `judge_set`)**
- DataStore가 generic "non-sensitive" fallback으로 빠져 인증 없이 허용될 수 있었음
- spec opal/4.3.8.1: `ACE_DataStore_Get_All`, `ACE_DataStore_Set_All` BooleanExpr = Admins
- `judge_get` admin-required family set에 `"DataStore"` 추가
- `judge_set` admin-required family set에 `"DataStore"` 추가

### 검증

모든 수정 후 public score 유지 확인:

```
score=100.00
```

---

## 한국어 실행 흐름 요약

`v3` solver는 testcase 전체를 바로 pass/fail로 분류하지 않는다. 먼저 마지막 step을 제외한 이전 step들을 replay해서 SSD/TCG 상태를 복원하고, 마지막 step의 output/status가 그 상태에서 프로토콜상 허용되는지 oracle로 판단한다.

실행 흐름은 다음과 같다.

```text
raw JSON trajectory
  -> normalizer가 canonical event로 변환
  -> state tracker가 events[:-1]만 replay
  -> oracle이 events[-1]을 현재 상태와 비교
  -> "pass" 또는 "fail"
```

중요한 점은 이전 step이 `FAIL`, `NOT_AUTHORIZED`, `INVALID_PARAMETER` 같은 실패 status를 갖는 경우다. 이런 step은 읽기는 하지만 상태를 바꾸지 않는다. 예를 들어 실패한 `Set(C_PIN)`은 PIN을 바꾸지 않고, 실패한 `Activate`는 LockingSP를 활성화하지 않고, 실패한 `GenKey`는 key generation을 증가시키지 않는다. 실패 기록은 history와 `session.had_failure`에는 남지만, 현재 판단의 핵심은 "성공한 이전 step들만 실제 상태 변경으로 반영한다"는 invariant다.

마지막 step은 별도로 oracle이 직접 판정한다. oracle은 마지막 event의 실제 status를 `success`, `auth_error`, `invalid_parameter`, `resource_error`, `data_success`, `data_error` 같은 status class로 바꾸고, 현재 상태에서 기대되는 status class와 비교한다. 따라서 `pass`는 "마지막 command가 SUCCESS였다"는 뜻이 아니라, "마지막 response가 현재 프로토콜 상태와 일치한다"는 뜻이다. 반대로 `fail`은 "마지막 response가 현재 상태에서 말이 안 된다"는 뜻이다.

현재 oracle이 보는 주요 상태는 session open 여부, 현재 SP, write/read mode, 인증된 authority, SID/MSID/Admin/User credential, LockingSP lifecycle, Locking range config, MBRControl, key generation, 그리고 LBA write/read 기록이다. `SOLVER_DEBUG=1`을 켜면 최종 event, 기대 status, 실제 status, verdict, state summary, 적용된 spec section ref, reason을 함께 출력한다.

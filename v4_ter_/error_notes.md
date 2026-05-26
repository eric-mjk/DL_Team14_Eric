# v4 Error Notes

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
- Added UID-only normalization for Locking SP table objects and `SecretProtect` rows so hidden traces that omit friendly object names still hit the existing `DataStore`, `MBR`, `SecretProtect`, `Locking`, `MBRControl`, and media-key oracle rules.
- Added duplicate-column detection for `Set` `RowValues`; Core 5.3.4.2.6 requires duplicate columns in one `Set` invocation to fail with `INVALID_PARAMETER`.
- Added conservative unsigned-integer preflight for session parameters (`HostSessionID`, `SessionTimeout`, `TransTimeout`, `InitialCredit`) so malformed or negative values fail without guessing device-specific timeout bounds.
- Extended UID-only normalization to core metadata and policy tables (`Table`, `SPInfo`, `SPTemplates`, `MethodID`, `AccessControl`, `ACE`, `Authority`, `SP`) and classified class authorities (`Anybody`, `Admins`, `Users`) as `Authority` objects.
- Rejected `Next` on byte tables (`MBR`, `DataStore`) as `INVALID_PARAMETER`; Core `Next` iterates object-table UID rows, while these Opal tables are byte tables.
- Added malformed-boolean preflight for `StartSession.Write` and `RevertSP.KeepGlobalRangeKey` when those parameters are present.
- Recognized Opal byte-table invoking UIDs for MBR (`00 00 08 04 ...`) and DataStore (`00 00 10 01 ...`); MBR Get now follows ACE_Anybody/open-LockingSP semantics and MBR Set requires authenticated LockingSP admin write access.
- Added modeled `StartTrustedSession`/`SyncTrustedSession` support: both are accepted only on the Session Manager after a normal session is open, and successful exchanges mark the session as trusted.
- Added `Set.Where` preflight from Core 5.3.3.7.1: object-row `Set` fails if `Where` is present, while table-level `Set` on object tables fails if `Where` is omitted; byte tables are left to byte-row rules.
- Normalized list-form method `args` into optional named parameters and added a `Properties.HostProperties` shape check for the required list of name/value pairs.
- Tightened `StartSession` required-parameter validation to require `HostSessionID`, `SPID`, and `Write` per the Core method signature.
- Added `HostSessionID` required-parameter validation for `SyncSession`, `StartTrustedSession`, and `SyncTrustedSession`.
- Added MethodID UID-to-name normalization from the Opal Admin/Locking SP MethodID preconfiguration tables so UID-only method invocations and dynamic AccessControl method references resolve to canonical method names.
- Hardened MethodID UID parsing for spec/template suffixes such as `*MT1`, avoiding accidental extra digits in compacted UIDs.
- Tracked `Authority.Secure` from spec defaults and trajectory Set/Get updates; explicit `Authenticate` now fails when a secure-messaging authority is used before the session is marked trusted.
- Fixed TryLimit replay for `Authenticate` responses encoded as `SUCCESS` with result `False`; these now increment failed authentication counts instead of being treated as successful non-mutating calls.
- Counted failed authenticated `StartSession` attempts toward TryLimit lockout, matching the spec requirement for implicit session-start authentication failures.
- Capped replayed failed-authentication counts at nonzero `TryLimit` so tracked `Tries` does not increment beyond the configured limit.
- Reset replayed failed-authentication counts after successful C_PIN PIN changes via `Set` or `GenKey`, matching the spec Tries reset side effect.
- Added guarded byte-table `MandatoryWriteGranularity` enforcement: when concrete numeric table metadata is known, byte-table `Set` now validates both `Where` offset and `Values.Bytes` length alignment.
- Added ReEncryptRequest/ReEncryptState handling for Locking rows: column 12 is host read-only, invalid request/state pairs now fail per Core 5.7.3.7.4, and successful request Sets replay the documented state/key transitions.
- Tightened `Next.Where` preflight from Core 5.3.3.8.1: when present it must normalize to a 16-hex-digit UID reference, while omitted `Where` still starts iteration from the table's first row.
- Modeled Core Crypto `Stir`: named `Stir` invocations are no longer treated as unsupported, require `Value`, reject malformed `Internal`, and enforce the required non-success status for false `Value`/`Internal` requests.
- Corrected Table metadata mutability for Opal granularity columns: `MandatoryWriteGranularity` and `RecommendedAccessGranularity` are now read-only, while Core `MaxSize` remains host-settable.
- Tightened Core `Random` preflight so the required `Count` parameter must be present and parse as a nonnegative unsigned integer before normal session authorization is considered.
- Added target-shape preflight for table-management free-space methods: `GetFreeRows` must be invoked on a table UID and `GetFreeSpace` must be invoked on an SP target, matching the Core method signatures.
- Expanded `cell_block` normalization to accept Core numeric component names `0x03`/`0x04` (and decimal aliases) for `startColumn`/`endColumn`, avoiding false malformed-Cellblock failures on spec-form inputs.
- Enforced the Core `cell_block` byte-table restriction for `Get`: byte tables (`MBR`, `DataStore`) now reject start/end column components because byte-table accesses are row/byte addressed.
- Added the Core `NextKey` write-state rule for Locking rows: Set of column 11 is accepted only while the tracked `ReEncryptState` is IDLE; non-IDLE attempts now return a non-success expectation.
- Completed basic Locking re-encryption column schema coverage for columns 14-19: `AdvKeyMode`/`VerifyMode` reject reserved enum values, and progress/status columns 17-19 are host read-only.
- Tightened Sync/Trusted session parameter validation: `SPSessionID` is now required and checked as a uinteger, and shared unsigned/boolean preflight scans every named parameter instead of stopping at the first valid one.
- Added Core `CloseSession` signature validation: `RemoteSessionNumber` and `LocalSessionNumber` are required unsigned parameters before the close-session state rule is applied.
- Added Core `Set.Values` shape validation: byte tables must use `Bytes`, while object/object-table Sets reject `Bytes` payloads and continue to use RowValues/column-value semantics.
- Added Core `Set.Where` type validation: table-level object-table Sets require a UID-shaped `Where`, while byte-table Sets require a nonnegative row/offset value.
- Tightened `Properties.HostProperties` list validation so present list entries must be non-empty property maps; omitted, empty-list, and map-form HostProperties remain accepted.
- Added conservative Core `GetPackage`/`SetPackage` support so named invocations are no longer unsupported: required signature parameters are enforced, targets must be credential objects, and normal credential access-control/write-session expectations apply.
- Tracked established `HostSessionID`/`SPSessionID` across successful Start/Sync/Trusted session exchanges and reject later Sync/Trusted calls whose session numbers do not match the active session.
- Added ClockTime UID normalization and conservative Core `IncrementCounter` support: the method is accepted in read-only sessions on the `ClockTime` table and rejected on incompatible targets.
- Added conservative Core `GetClock` support using the same ClockTime table target validation and read-only-session allowance as `IncrementCounter`.
- Added conservative Core Encrypt/Decrypt stream support: Init opens a per-credential stream, Encrypt/Decrypt and Finalize require that stream, duplicate Init fails, and named crypto methods are no longer treated as unsupported.
- Added Core Hash stream support for `H_SHA_*` objects: `HashInit` opens a per-object stream, `Hash`/`HashFinalize` require it, duplicate Init fails, and Finalize closes it.
- Added Core HMAC stream support for `H_SHA_*` objects, mirroring Hash stream handling for `HMACInit`, `HMAC`, and `HMACFinalize`.
- Added conservative Core `Sign`/`Verify` support for public-key credential and `H_SHA_*` hash objects, with incompatible targets rejected before normal access-control expectations.
- Added conservative Core `XOR` support as an SP method: required `PatternInput`/`DeletePattern`/`Input` parameters are enforced, `DeletePattern` must be boolean, and `PatternInput` must be a UID-shaped byte-table reference.
- Added conservative Core `CreateRow`/`DeleteRow` support: both are write-session table methods for object tables, byte-table/object-row targets are invalid, and `DeleteRow.Rows` must be a non-empty UID list.
- Added conservative Core `Delete`/`DeleteSP` support so named destructive methods are no longer unsupported; both require an authorized write session and `Delete` rejects non-object targets such as `SessionManager`.
- Added conservative Core `CreateTable` support: required signature parameters and unsigned size fields are validated, byte-table creation rejects `MaxSize` and non-empty `Columns`, and normal SP write authorization is enforced.
- Added Core meta-ACL method support for `GetACL`, `AddACE`, and `RemoveACE`: required UID parameters are validated, targets must be the `AccessControl` table, and write-session requirements are enforced for mutations.
- Added Core `DeleteMethod` support as the fourth meta-ACL method, sharing AccessControl-table target validation, UID parameter validation, and write-session enforcement.
- Added Clock mutation method support for `ResetClock`, `SetClockHigh`/`SetLagHigh`, and `SetClockLow`/`SetLagLow`, including ClockTime target checks, required time/lag parameters, write authorization, and immediate SetClock-to-SetLag pairing.
- Added Log template method support for `AddLog`, `CreateLog`, `ClearLog`, and `FlushLog`: Log/LogList UIDs now normalize, signatures are checked, table-level targets are enforced, and read-only `AddLog`/`FlushLog` sessions are accepted where the spec allows them.

## v4 Second Pass — Spec Audit 수정 사항 (2026-05-23)

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

`v4` solver는 testcase 전체를 바로 pass/fail로 분류하지 않는다. 먼저 마지막 step을 제외한 이전 step들을 replay해서 SSD/TCG 상태를 복원하고, 마지막 step의 output/status가 그 상태에서 프로토콜상 허용되는지 oracle로 판단한다.

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

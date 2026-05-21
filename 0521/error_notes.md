# 0521 Error Notes

- Broadened status normalization to compare expected status classes instead of only success vs failure.
- Treated prior failed state-changing methods as non-mutating: failed credential, activation, and key-generation attempts do not update replayed state.
- Replaced the broad success-like method fallback with method-aware authorization defaults for protected operations.
- Generalized Locking, C_PIN, Authority, SP, and media-key object handling by UID family so hidden range/key rows are not tied to public-case exact UIDs.
- Added locking-range read/write checks using ReadLockEnabled, WriteLockEnabled, ReadLocked, and WriteLocked columns before applying key-generation readback rules.
- Added a generated spec index from all document text files and attached spec section references to debug oracle decisions.
- Added lifecycle handling for Revert/RevertSP and initialized Locking/MBR defaults from Opal preconfiguration tables.

## 한국어 실행 흐름 요약

`0521` solver는 testcase 전체를 바로 pass/fail로 분류하지 않는다. 먼저 마지막 step을 제외한 이전 step들을 replay해서 SSD/TCG 상태를 복원하고, 마지막 step의 output/status가 그 상태에서 프로토콜상 허용되는지 oracle로 판단한다.

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

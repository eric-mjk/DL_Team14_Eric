# Spec Coverage Notes

이 파일은 v3에서 자동 생성된 `artifacts/spec_index.json` 기반 coverage 시스템을 설명했던 문서다.
v5에서는 spec_index.json 시스템이 제거되었으므로 해당 내용은 더 이상 유효하지 않다.

## v5 Coverage 방식

v5는 정적 분석 대신 다음 방식으로 spec 준수를 추적한다.

1. **`src/spec_tables.py`**: 각 operation의 ACL policy를 POLICIES dict로 명시적으로 정의.
   - spec ACE 테이블 항목을 `Policy` 객체로 직접 코드화
   - allowed_authorities, require_authenticated, session_spid 등

2. **`src/solver.py`**: 각 `_expected_*` 메서드에 spec 근거 주석 포함.
   - 예: `# Spec ACL: ACE_SP_SID OR ACE_Admin`
   - 예: `# ACE_C_PIN_MSID_Get_PIN → Anybody`

3. **Synthetic test cases (`tests/`)**: spec 규칙별로 PASS/FAIL 케이스를 수동으로 작성.
   - 새로운 spec 규칙을 구현할 때 대응하는 합성 케이스도 추가해서 회귀를 방지

## 현재 구현된 주요 Spec 규칙

| Spec 항목 | 구현 위치 | 상태 |
|---|---|---|
| Properties (opal/5.1.2) | `_expected_properties` | implemented |
| StartSession credential check | `_expected_start_session` | implemented |
| Get C_PIN_MSID PIN (ACE_C_PIN_MSID_Get_PIN) | `_can_read_cpin_col3` | implemented |
| Get C_PIN_* PIN blocked (ACE_*_NOPIN) | `_can_read_cpin_col3` | implemented |
| Set C_PIN_SID: SID only | `_expected_set` | implemented |
| Activate: SID in AdminSP write session | `_expected_activate` | implemented |
| GenKey: LockingSP Admins only | `_expected_gen_key` | implemented |
| Revert: SID OR Admin (opal/5.1.2) | `_expected_revert` | implemented |
| GET Locking: Admins only | POLICIES[("GET","LOCKING")] | implemented |
| SET Locking: Admins only | POLICIES[("SET","LOCKING")] | implemented |
| Read: key generation check | `_expected_read` | implemented |
| Authority.Enabled check | `_expected_start_session` | implemented |

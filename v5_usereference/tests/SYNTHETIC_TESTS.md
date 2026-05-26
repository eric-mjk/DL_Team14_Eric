# Synthetic Test Cases

`tests/` 디렉토리는 oracle 검증용 합성 test trajectory를 담는다.

```
tests/
├── synthetic_testcases/      # 57개 .json 파일 (tc1.json 포맷과 동일)
│   ├── syn_pass_01_*.json
│   ├── syn_fail_01_*.json
│   └── ...
└── synthetic_labels.jsonl    # 각 파일의 정답 label
```

## 목적

Public dataset은 20개(tc1–tc20)뿐이다. Synthetic test case는 이 20개 외에 oracle이 다루는 spec 규칙별로 추가적인 PASS/FAIL 케이스를 제공한다. 숨겨진 private test case에서도 oracle이 올바르게 동작하는지 사전 검증하는 용도다.

## 파일 포맷

각 `syn_*.json`은 `tc1.json`–`tc20.json`과 동일한 포맷이다.

```json
[
  {
    "input": { ... },
    "output": { "status": "SUCCESS", ... }
  },
  ...
]
```

- 마지막 step의 `output.status`가 oracle이 판정하는 response다.
- 파일명의 `pass`/`fail`은 해당 trajectory에서 기대되는 oracle verdict다.

`synthetic_labels.jsonl` 포맷:

```jsonl
{"filename": "syn_pass_01_properties.json", "label": "pass"}
{"filename": "syn_fail_01_properties.json", "label": "fail"}
...
```

## 실행 방법

```bash
# 케이스 생성 (tests/synthetic_testcases/ 에 작성)
cd v5_usereference
python generate_synthetic.py

# 생성 + 정확도 확인 (solver.predict 호출)
python generate_synthetic.py --check

# 예상 출력
# Generated 57 cases (30 pass, 27 fail)
#   → .../tests/synthetic_testcases/
#   → .../tests/synthetic_labels.jsonl
# Synthetic dataset accuracy: 57/57 (100.0%)
```

## 케이스 목록 및 테스트 대상 규칙

| 파일 | verdict | 테스트 규칙 |
|---|---|---|
| syn_pass_01 / syn_fail_01 | pass/fail | Properties response status |
| syn_pass_02 / syn_fail_02 | pass/fail | 미인증 세션 StartSession |
| syn_pass_03 / syn_fail_03 | pass/fail | SID credential 일치/불일치 |
| syn_pass_04 | pass | 잘못된 PIN → NOT_AUTHORIZED = pass |
| syn_pass_05 / syn_fail_05 | pass/fail | User1 credential 인증 |
| syn_pass_06 / syn_fail_06 | pass/fail | User1 wrong PIN |
| syn_pass_07 / syn_fail_07 | pass/fail | User1 empty PIN |
| syn_pass_08 / syn_fail_08 | pass/fail | GenKey 후 read (새 key = pass, 구 data = fail) |
| syn_pass_09 / syn_fail_10 | pass/fail | MBRControl Get (인증됨/미인증) |
| syn_pass_11 / syn_fail_11 | pass/fail | Locking range Set |
| syn_pass_12 / syn_fail_12 | pass/fail | C_PIN_MSID PIN 읽기 (읽을 수 있음/없음) |
| syn_pass_13 | pass | SID가 자기 C_PIN 못 읽음 = NOT_AUTHORIZED = pass |
| syn_pass_14 / syn_fail_14 | pass/fail | Locking GET (올바른/잘못된 response) |
| syn_pass_15 / syn_fail_15 | pass/fail | RevertSP 세션 lifecycle |
| syn_pass_16 / syn_fail_16 | pass/fail | 크리덴셜 업데이트 후 최신 PIN 사용 |
| syn_pass_17 / syn_fail_17 | pass/fail | Locking GET 미인증 (NOT_AUTHORIZED = pass, SUCCESS = fail) |
| syn_pass_18 | pass | Admin2 empty PIN |
| syn_pass_19 / syn_fail_19 | pass/fail | disabled User1 authority |
| syn_pass_20 / syn_fail_20 | pass/fail | Global range RangeStart=0 |
| syn_pass_22 / syn_fail_22 | pass/fail | GenKey C_PIN 권한 없음 |
| syn_pass_23 | pass | MBRControl Set |
| syn_pass_25 / syn_fail_25 | pass/fail | SID reads own C_PIN (NOT_AUTHORIZED = pass, SUCCESS = fail) |
| syn_pass_25b / syn_fail_25b | pass/fail | Admin1 reads SID C_PIN |
| syn_pass_26 / syn_fail_26 | pass/fail | Admin1 reads own C_PIN |
| syn_pass_27 / syn_fail_27 | pass/fail | User1 reads own C_PIN |
| syn_pass_27b / syn_fail_27b | pass/fail | Admin1 reads User1 C_PIN |
| syn_pass_28 / syn_fail_28 | pass/fail | Write then Read (same key = pass, different pattern = fail) |
| syn_pass_29 / syn_fail_29 | pass/fail | LockingSP session before Activate |
| syn_pass_30 / syn_fail_30 | pass/fail | Read on locked range |
| syn_pass_31 / syn_fail_31 | pass/fail | Activate: SID required |
| syn_fail_32 | fail | Activate: wrong target UID |

## 새 케이스 추가 방법

1. `generate_synthetic.py`에서 새로운 시나리오 함수를 작성한다.

   ```python
   def tc_my_new_rule_pass() -> Scenario:
       steps = []
       # ... build trajectory steps ...
       return Scenario(
           name="syn_pass_XX_my_rule",
           verdict="pass",
           steps=steps,
           description="SSD correctly returns NOT_AUTHORIZED for ...",
       )
   ```

2. `SCENARIOS` 리스트에 추가한다.

3. `python generate_synthetic.py --check` 로 검증한다.

**중요:** 새 spec 규칙 구현 시에는 반드시 PASS와 FAIL 케이스를 쌍으로 추가한다. PASS만 있으면 oracle이 항상 "pass"를 반환해도 통과한다.

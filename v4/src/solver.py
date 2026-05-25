from __future__ import annotations

import copy
import os
from dataclasses import dataclass, field
from typing import Any
from .spec_tables import (
    ADMIN_SP,
    LOCKING_SP,
    ANYBODY_AUTHORITY,
    SID_AUTHORITY,
    AUTHORITY_NAMES,
    CREDENTIAL_NAMES,
    OBJECT_SEMANTICS,
    POLICIES,
    SP_NAMES,
)


LOCKING_ADMIN1_AUTHORITY = "0000000900010001"
LOCKING_USER1_AUTHORITY = "0000000900030001"
ADMINS_AUTHORITY = "0000000900000002"
USERS_AUTHORITY = "0000000900030000"

C_PIN_MSID = "0000000B00008402"
C_PIN_SID = "0000000B00000001"
C_PIN_ADMIN_SP_ADMIN1 = "0000000B00000201"
C_PIN_LOCKING_ADMIN1 = "0000000B00010001"
C_PIN_LOCKING_USER1 = "0000000B00030001"
LOCKING_GLOBAL_RANGE = "0000080200000001"
LOCKING_RANGE1 = "0000080200030001"
MBRCONTROL_UID = "0000080300000001"

TRUE_VALUES = {"1", "TRUE", "T", "YES", "ON"}
FALSE_VALUES = {"0", "FALSE", "F", "NO", "OFF"}
ERROR_RESULTS = {"FAIL", "FAILED", "ERROR", "DATA_PROTECTION_ERROR", "DATA PROTECTION ERROR", "PROTECTED"}

def normalize_uid(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return text.replace(" ", "").replace("0X", "").replace("0x", "").upper()


def normalize_status(value: Any) -> str:
    if value is None:
        return ""
    return "_".join(str(value).strip().replace("-", " ").split()).upper()


def normalize_column_key(value: Any) -> str:
    text = str(value).strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    if text in {"a", "b", "c", "d", "e", "f"}:
        return text
    try:
        return format(int(text, 16), "x")
    except ValueError:
        return text.lstrip("0") or "0"


def to_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        return None
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        if any(ch in "abcdefABCDEF" for ch in text):
            return int(text, 16)
        return int(text, 10)
    except ValueError:
        return None


def to_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return bool(value)
    text = str(value).strip().upper()
    if text in TRUE_VALUES:
        return True
    if text in FALSE_VALUES:
        return False
    return None


def get_path(data: Any, *path: Any, default: Any = None) -> Any:
    cur = data
    for part in path:
        if isinstance(cur, dict):
            if part not in cur:
                return default
            cur = cur[part]
            continue
        if isinstance(cur, list) and isinstance(part, int):
            if part < 0 or part >= len(cur):
                return default
            cur = cur[part]
            continue
        return default
    return cur


def flatten_nested_dicts(values: Any) -> list[dict[str, Any]]:
    flat: list[dict[str, Any]] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            flat.append(node)
            for child in node.values():
                walk(child)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(values)
    return flat


@dataclass
class SessionState:
    spid: str | None = None
    authority: str | None = None
    authenticated: bool = False
    write: bool = False
    authenticated_authorities: set[str] = field(default_factory=lambda: {ANYBODY_AUTHORITY})


@dataclass
class ProtocolState:
    session: SessionState = field(default_factory=SessionState)
    credentials: dict[str, str] = field(default_factory=dict)
    enabled_authorities: set[str] = field(
        default_factory=lambda: {ANYBODY_AUTHORITY, SID_AUTHORITY, LOCKING_ADMIN1_AUTHORITY}
    )
    activated_sps: set[str] = field(default_factory=set)
    object_values: dict[str, dict[str, Any]] = field(default_factory=dict)
    object_reads: dict[str, dict[str, Any]] = field(default_factory=dict)
    latest_credential: str | None = None
    last_sp_uid_read: str | None = None
    pre_genkey_read_result: str | None = None
    user_data: dict[str, str] = field(default_factory=dict)
    erased_ranges: set[str] = field(default_factory=set)
    genkey_effective: bool = False
    data_removed: bool = False
    last_genkey_attempt_status: str = ""


@dataclass
class ExpectedOutcome:
    status: str | None = None
    read_result_equals_previous: bool | None = None
    read_result_differs_previous: bool | None = None
    read_result_equals_written: str | None = None
    interface_result: str | None = None
    interface_result_should_fail: bool = False
    allowed_statuses: set[str] = field(default_factory=set)
    required_values: dict[str, Any] = field(default_factory=dict)
    requires_nonempty_values: bool = False


class Solver:
    def __init__(self):
        self.debug_enabled = os.environ.get("DEBUG_SOLVER", "").strip().lower() in {"1", "true", "yes", "on"}
        self.enable_llm_judge = os.environ.get("ENABLE_LLM_JUDGE", "").strip().lower() in {"1", "true", "yes", "on"}
        self._reset_state()

        self.llm_judge = None
        if self.enable_llm_judge:
            from .llm_judge import LLMProtocolJudge

            self.llm_judge = LLMProtocolJudge()

    def _reset_state(self) -> None:
        self.state = ProtocolState()
        self.debug_events: list[str] = []

    def predict(self, dataset):
        if self.llm_judge is None or not self.llm_judge.is_enabled():
            return {item["id"]: self.predict_one(item["steps"]) for item in dataset}

        predictions: dict[str, str] = {}
        llm_requests: list[dict[str, Any]] = []
        llm_items: list[tuple[str, str]] = []

        for item in dataset:
            steps = item.get("steps", [])
            if not steps:
                predictions[item["id"]] = "fail"
                continue

            expected, verdict, state_snapshot = self._rule_assessment(steps)
            rule_prediction = "pass" if verdict else "fail"
            predictions[item["id"]] = rule_prediction
            llm_items.append((item["id"], rule_prediction))
            llm_requests.append(
                {
                    "steps": steps,
                    "state_snapshot": state_snapshot,
                    "rule_prediction": rule_prediction,
                    "rule_reason": self._format_rule_reason(expected),
                }
            )

        for (case_id, rule_prediction), decision in zip(llm_items, self.llm_judge.judge_many(llm_requests)):
            if decision.usable and (decision.confidence or 0.0) >= self.llm_judge.config.min_confidence:
                predictions[case_id] = decision.verdict or rule_prediction

        return predictions

    def predict_one(self, steps):
        if not steps:
            return "fail"

        expected, verdict, state_snapshot = self._rule_assessment(steps)
        # 1. LLM 판단 기능이 켜져 있는지 확인 (ENABLE_LLM_JUDGE)
        rule_prediction = "pass" if verdict else "fail"
        if self.llm_judge is not None and self.llm_judge.is_enabled():
            # 2. 규칙 기반 알고리즘이 예측한 근거를 문자열로 만들어 LLM에게 힌트로 제공
            rule_reason = self._format_rule_reason(expected)
            
            # 3. LLM에게 현재까지의 트래킹된 SSD 상태(self.state)와 규칙 기반 결과를 던져주고 최종 판단 위임
            llm_decision = self.llm_judge.judge(
                steps=steps,
                state_snapshot=state_snapshot,
                rule_prediction=rule_prediction,
                rule_reason=rule_reason
            )
            # 4. LLM이 올바른 응답을 생성하여 사용 가능한(usable) 상태일 경우, LLM의 결과를 반환
            if llm_decision.usable and (llm_decision.confidence or 0.0) >= self.llm_judge.config.min_confidence:
                self._debug(f"[LLM] Verdict: {llm_decision.verdict} | Conf: {llm_decision.confidence}")
                return llm_decision.verdict
        self._emit_debug_trace(steps[-1], expected, verdict)
        return "pass" if verdict else "fail"

    def _rule_assessment(self, steps: list[dict[str, Any]]) -> tuple[ExpectedOutcome, bool, ProtocolState]:
        self._reset_state()
        for step in steps[:-1]:
            self._ingest_step(step)

        expected = self._expected_outcome(steps[-1])
        verdict = self._compare_with_actual(steps[-1], expected)
        return expected, verdict, copy.deepcopy(self.state)

    def _format_rule_reason(self, expected: ExpectedOutcome) -> str:
        return (
            f"expected_status={expected.status}; allowed_statuses={sorted(expected.allowed_statuses)}; "
            f"read_differs_previous={expected.read_result_differs_previous}; "
            f"read_equals_written={expected.read_result_equals_written}; interface_result={expected.interface_result}; "
            f"interface_should_fail={expected.interface_result_should_fail}; "
            f"required_values={expected.required_values or '{}'}."
        )

    def _ingest_step(self, step: dict[str, Any]) -> None:
        method = self._method_name(step)
        failed_step_fingerprint = None
        step_status = self._output_status(step)
        if step_status and step_status != "SUCCESS":
            failed_step_fingerprint = self._state_fingerprint()
        if method == "STARTSESSION":
            self._ingest_start_session(step)
        elif method == "ENDSESSION":
            self._ingest_end_session(step)
        elif method == "GET":
            self._ingest_get(step)
        elif method == "SET":
            self._ingest_set(step)
        elif method == "ACTIVATE":
            self._ingest_activate(step)
        elif method == "AUTHENTICATE":
            self._ingest_authenticate(step)
        elif method == "GENKEY":
            self._ingest_genkey(step)
        elif method in {"REVERT", "REVERTSP"}:
            self._ingest_revert(step)
        elif method == "READ":
            self._ingest_read(step)
        elif method == "WRITE":
            self._ingest_write(step)

        if failed_step_fingerprint is not None:
            self._verify_failed_step_preserves_state(step, failed_step_fingerprint)

    def _ingest_start_session(self, step: dict[str, Any]) -> None:
        if self._output_status(step) != "SUCCESS":
            self._debug(
                f"step {step.get('index')}: StartSession failed with status={self._output_status(step)}; state unchanged"
            )
            return
        self.state.session = SessionState(
            spid=normalize_uid(get_path(step, "input", "method", "args", "required", "SPID")),
            authority=normalize_uid(get_path(step, "input", "method", "args", "optional", "HostSigningAuthority")),
            authenticated=get_path(step, "input", "method", "args", "optional", "HostSigningAuthority") is not None,
            write=bool(to_bool(get_path(step, "input", "method", "args", "required", "Write"))),
        )
        if self.state.session.authority:
            self.state.session.authenticated_authorities.add(self.state.session.authority)
        self._debug(
            f"step {step.get('index')}: session opened spid={SP_NAMES.get(self.state.session.spid, self.state.session.spid)} "
            f"authority={AUTHORITY_NAMES.get(self.state.session.authority, self.state.session.authority)} "
            f"authenticated={self.state.session.authenticated}"
        )

    def _ingest_end_session(self, step: dict[str, Any]) -> None:
        if self._output_status(step) == "SUCCESS":
            self.state.session = SessionState()
            self._debug(f"step {step.get('index')}: session closed")

    def _ingest_get(self, step: dict[str, Any]) -> None:
        if self._output_status(step) != "SUCCESS":
            self._debug(f"step {step.get('index')}: GET {self._object_name(step)} failed with status={self._output_status(step)}")
            return
        object_uid = normalize_uid(get_path(step, "input", "invoking_id", "uid"))
        object_name = self._object_name(step)
        values = self._extract_return_values(step)
        if object_uid:
            self.state.object_reads[object_uid] = values
            if values:
                self.state.object_values.setdefault(object_uid, {}).update(values)
        if object_name == "C_PIN":
            credential = values.get("3")
            if credential is not None:
                normalized = str(credential)
                self.state.credentials[self._credential_key(step)] = normalized
                self._learn_credential_aliases(object_uid, normalized)
                self.state.latest_credential = normalized
                self._debug(f"step {step.get('index')}: learned credential for {self._credential_key(step)}")
        elif object_name == "SP" and object_uid is not None:
            self.state.last_sp_uid_read = object_uid
            self._debug(f"step {step.get('index')}: read SP object uid={object_uid}")

    def _ingest_set(self, step: dict[str, Any]) -> None:
        if self._output_status(step) != "SUCCESS":
            self._debug(f"step {step.get('index')}: SET {self._object_name(step)} failed with status={self._output_status(step)}")
            return
        object_uid = normalize_uid(get_path(step, "input", "invoking_id", "uid"))
        object_name = self._object_name(step)
        values = self._extract_set_values(step)
        if object_uid and values:
            current = self.state.object_values.setdefault(object_uid, {})
            current.update(values)
            self._debug(f"step {step.get('index')}: updated object {object_uid} values={values}")
        if object_name == "C_PIN":
            credential = values.get("3")
            if credential is not None:
                normalized = str(credential)
                self.state.credentials[self._credential_key(step)] = normalized
                self._learn_credential_aliases(object_uid, normalized)
                self.state.latest_credential = normalized
                self._debug(f"step {step.get('index')}: updated credential for {self._credential_key(step)}")
        elif object_name == "AUTHORITY":
            self._update_authority_enabled(object_uid, values)

    def _ingest_activate(self, step: dict[str, Any]) -> None:
        if self._output_status(step) != "SUCCESS":
            self._debug(f"step {step.get('index')}: ACTIVATE failed with status={self._output_status(step)}")
            return
        object_uid = normalize_uid(get_path(step, "input", "invoking_id", "uid"))
        if object_uid:
            self.state.activated_sps.add(object_uid)
            if object_uid == LOCKING_SP:
                sid_pin = self.state.credentials.get(C_PIN_SID) or self.state.credentials.get(C_PIN_MSID)
                if sid_pin is not None:
                    self.state.credentials[C_PIN_LOCKING_ADMIN1] = sid_pin
                    self.state.credentials[LOCKING_ADMIN1_AUTHORITY] = sid_pin
            self._debug(f"step {step.get('index')}: activated SP uid={object_uid}")

    def _ingest_authenticate(self, step: dict[str, Any]) -> None:
        if self._output_status(step) != "SUCCESS":
            return
        result = self._auth_result(step)
        if result is not True:
            return
        authority = normalize_uid(get_path(step, "input", "method", "args", "required", "Authority"))
        if authority:
            self.state.session.authenticated = True
            self.state.session.authority = authority
            self.state.session.authenticated_authorities.add(authority)

    def _ingest_genkey(self, step: dict[str, Any]) -> None:
        status = self._output_status(step)
        self.state.last_genkey_attempt_status = status
        if status == "SUCCESS":
            self.state.genkey_effective = True
            if self._object_name(step) == "C_PIN":
                object_uid = normalize_uid(get_path(step, "input", "invoking_id", "uid"))
                if object_uid:
                    self.state.credentials.pop(object_uid, None)
            else:
                affected_range = self._range_for_key_uid(normalize_uid(get_path(step, "input", "invoking_id", "uid")))
                if affected_range:
                    self.state.erased_ranges.add(affected_range)
        self._debug(
            f"step {step.get('index')}: GenKey status={status} effective_genkey={self.state.genkey_effective}"
        )

    def _ingest_revert(self, step: dict[str, Any]) -> None:
        if self._output_status(step) != "SUCCESS":
            return
        method = self._method_name(step)
        target_uid = normalize_uid(get_path(step, "input", "invoking_id", "uid"))
        if method == "REVERTSP" or target_uid in {ADMIN_SP, LOCKING_SP}:
            keep_global = method == "REVERTSP" and self._keep_global_range_key(step)
            if target_uid in {LOCKING_SP, ADMIN_SP} or self.state.session.spid == LOCKING_SP:
                self.state.activated_sps.discard(LOCKING_SP)
            if not keep_global and (target_uid in {LOCKING_SP, ADMIN_SP} or self.state.session.spid == LOCKING_SP):
                self.state.data_removed = True
                self.state.genkey_effective = True
                self.state.erased_ranges.add(LOCKING_GLOBAL_RANGE)
            if target_uid == ADMIN_SP:
                msid = self.state.credentials.get(C_PIN_MSID)
                sid = self.state.credentials.get(C_PIN_SID)
                self.state = ProtocolState()
                if msid is not None:
                    self.state.credentials[C_PIN_MSID] = msid
                if sid is not None:
                    self.state.credentials[C_PIN_SID] = sid

    def _ingest_read(self, step: dict[str, Any]) -> None:
        result = get_path(step, "output", "args", "result")
        if result is not None:
            self.state.pre_genkey_read_result = self._normalize_read_result(result)
            self._debug(f"step {step.get('index')}: remembered read result={self.state.pre_genkey_read_result}")

    def _ingest_write(self, step: dict[str, Any]) -> None:
        result = self._interface_result(step)
        if normalize_status(result) not in {"PASS", "SUCCESS", "OK"}:
            return
        pattern = get_path(step, "input", "args", "pattern")
        if pattern is not None:
            self.state.user_data[self._lba_key(step)] = self._normalize_read_result(pattern)
            self.state.data_removed = False

    def _expected_outcome(self, step: dict[str, Any]) -> ExpectedOutcome:
        method = self._method_name(step)
        if method == "PROPERTIES":
            return ExpectedOutcome(status="SUCCESS", requires_nonempty_values=True)
        if method == "GET":
            return self._expected_get(step)
        if method == "STARTSESSION":
            return self._expected_start_session(step)
        if method == "ACTIVATE":
            return self._expected_activate(step)
        if method == "AUTHENTICATE":
            return self._expected_authenticate(step)
        if method == "SET":
            return self._expected_set(step)
        if method == "GENKEY":
            return self._expected_genkey(step)
        if method == "REVERT":
            return self._expected_revert(step)
        if method == "REVERTSP":
            return self._expected_revert_sp(step)
        if method == "READ":
            return self._expected_read(step)
        if method == "WRITE":
            return self._expected_write(step)
        return ExpectedOutcome(status="SUCCESS")

    def _expected_get(self, step: dict[str, Any]) -> ExpectedOutcome:
        object_name = self._object_name(step)
        if object_name == "C_PIN":
            return self._expected_cpin_get(step)

        if object_name == "SP":
            return ExpectedOutcome(status="SUCCESS")

        if object_name in {"MBR", "DATASTORE"}:
            policy_failure = self._admin_policy_failure()
            if policy_failure is not None:
                return ExpectedOutcome(status=policy_failure)
            return ExpectedOutcome(status="SUCCESS")

        policy_failure = self._policy_failure("GET", object_name)
        if policy_failure is not None:
            return ExpectedOutcome(status=policy_failure)

        object_uid = normalize_uid(get_path(step, "input", "invoking_id", "uid"))
        semantic = OBJECT_SEMANTICS.get(object_name)

        if object_name == "LOCKING":
            return self._expected_locking_get(step)

        if object_name == "MBRCONTROL":
            expected = ExpectedOutcome(status="SUCCESS")
            if object_uid:
                expected.required_values.update(self.state.object_values.get(object_uid, {}))
            if not expected.required_values and semantic is not None:
                start_col, end_col = self._cellblock_range(step)
                expected_columns = semantic.readable_column_sets.get((start_col, end_col), ())
                expected.required_values.update({key: None for key in expected_columns})
            if not expected.required_values:
                expected.requires_nonempty_values = True
            return expected

        if semantic is not None and semantic.readable_column_sets:
            expected = ExpectedOutcome(status="SUCCESS")
            expected_columns = self._expected_columns_for_range(step, semantic.readable_column_sets)
            if expected_columns:
                expected.required_values.update({key: None for key in expected_columns})
            else:
                expected.requires_nonempty_values = True
            return expected

        return ExpectedOutcome(status="SUCCESS")

    def _expected_start_session(self, step: dict[str, Any]) -> ExpectedOutcome:
        spid = normalize_uid(get_path(step, "input", "method", "args", "required", "SPID"))
        if spid not in {ADMIN_SP, LOCKING_SP}:
            return ExpectedOutcome(status="FAIL")

        authority = normalize_uid(get_path(step, "input", "method", "args", "optional", "HostSigningAuthority"))
        if authority is None or authority == ANYBODY_AUTHORITY:
            return ExpectedOutcome(status="SUCCESS")

        if not self._authority_exists(authority) or self._is_class_authority(authority):
            return ExpectedOutcome(status="INVALID_PARAMETER")

        if authority not in self.state.enabled_authorities:
            return ExpectedOutcome(status="NOT_AUTHORIZED")

        challenge = get_path(step, "input", "method", "args", "optional", "HostChallenge")
        credential = self._credential_for_authority(authority)
        if credential is not None and challenge is not None and self._values_equal(challenge, credential):
            return ExpectedOutcome(status="SUCCESS")
        if credential is None and challenge is not None:
            return ExpectedOutcome(allowed_statuses={"SUCCESS", "NOT_AUTHORIZED"})
        return ExpectedOutcome(status="NOT_AUTHORIZED")

    def _expected_activate(self, step: dict[str, Any]) -> ExpectedOutcome:
        policy_failure = self._policy_failure("ACTIVATE", self._object_name(step))
        if policy_failure is not None:
            return ExpectedOutcome(status=policy_failure)
        if not self.state.session.write:
            return ExpectedOutcome(status="FAIL")

        target_uid = normalize_uid(get_path(step, "input", "invoking_id", "uid"))
        if target_uid in {LOCKING_SP, ADMIN_SP}:
            return ExpectedOutcome(status="SUCCESS")
        return ExpectedOutcome(status="FAIL")

    def _expected_authenticate(self, step: dict[str, Any]) -> ExpectedOutcome:
        if self.state.session.spid is None:
            return ExpectedOutcome(status="FAIL")
        authority = normalize_uid(get_path(step, "input", "method", "args", "required", "Authority"))
        if authority is None or not self._authority_exists(authority) or self._is_class_authority(authority):
            return ExpectedOutcome(status="INVALID_PARAMETER")
        if authority == ANYBODY_AUTHORITY:
            return ExpectedOutcome(status="SUCCESS")
        if authority not in self.state.enabled_authorities:
            return ExpectedOutcome(status="SUCCESS")
        proof = get_path(step, "input", "method", "args", "optional", "Proof")
        if proof is None:
            proof = get_path(step, "input", "method", "args", "required", "Proof")
        credential = self._credential_for_authority(authority)
        if credential is not None and self._values_equal(proof, credential):
            return ExpectedOutcome(status="SUCCESS")
        return ExpectedOutcome(status="SUCCESS")

    def _expected_set(self, step: dict[str, Any]) -> ExpectedOutcome:
        object_name = self._object_name(step)
        if not self.state.session.write:
            return ExpectedOutcome(status="NOT_AUTHORIZED")

        if object_name == "C_PIN":
            return self._expected_cpin_set(step)

        if object_name in {"MBR", "DATASTORE"}:
            policy_failure = self._admin_policy_failure()
            if policy_failure is not None:
                return ExpectedOutcome(status=policy_failure)
            if self._byte_table_set_has_column_values(step):
                return ExpectedOutcome(status="INVALID_PARAMETER")
            return ExpectedOutcome(status="SUCCESS")

        policy_failure = self._policy_failure("SET", object_name)
        if policy_failure is not None:
            return ExpectedOutcome(status=policy_failure)

        if object_name == "LOCKING":
            return self._expected_locking_set(step)

        if object_name == "AUTHORITY":
            return self._expected_authority_set(step)

        semantic = OBJECT_SEMANTICS.get(object_name)
        if semantic is not None and semantic.writable_columns:
            values = self._extract_set_values(step)
            if not values:
                return ExpectedOutcome(status="SUCCESS")
            if not set(values).issubset(set(semantic.writable_columns)):
                return ExpectedOutcome(status="INVALID_PARAMETER")
            return ExpectedOutcome(status="SUCCESS")

        if object_name in {"AUTHORITY", "C_PIN", "LOCKING", "MBRCONTROL"}:
            return ExpectedOutcome(status="SUCCESS")
        return ExpectedOutcome(status="SUCCESS")

    def _expected_genkey(self, step: dict[str, Any]) -> ExpectedOutcome:
        if not self.state.session.write:
            return ExpectedOutcome(status="NOT_AUTHORIZED")
        if self._object_name(step) == "C_PIN":
            return self._expected_cpin_genkey(step)
        policy_failure = self._policy_failure("GENKEY", self._object_name(step))
        if policy_failure is not None:
            return ExpectedOutcome(status=policy_failure)
        if self._invalid_genkey_parameters(step):
            return ExpectedOutcome(status="INVALID_PARAMETER")
        return ExpectedOutcome(status="SUCCESS")

    def _expected_revert(self, step: dict[str, Any]) -> ExpectedOutcome:
        if not self.state.session.write:
            return ExpectedOutcome(status="NOT_AUTHORIZED")
        if self.state.session.spid != ADMIN_SP:
            return ExpectedOutcome(status="NOT_AUTHORIZED")
        if not self._has_authority(SID_AUTHORITY):
            return ExpectedOutcome(status="NOT_AUTHORIZED")
        target_uid = normalize_uid(get_path(step, "input", "invoking_id", "uid"))
        if target_uid not in {ADMIN_SP, LOCKING_SP}:
            return ExpectedOutcome(status="FAIL")
        return ExpectedOutcome(status="SUCCESS")

    def _expected_revert_sp(self, step: dict[str, Any]) -> ExpectedOutcome:
        if not self.state.session.write:
            return ExpectedOutcome(status="NOT_AUTHORIZED")
        if self.state.session.spid != LOCKING_SP:
            return ExpectedOutcome(status="NOT_AUTHORIZED")
        if not self._has_admin_authority():
            return ExpectedOutcome(status="NOT_AUTHORIZED")
        if self._keep_global_range_key(step) and self._global_range_fully_locked():
            return ExpectedOutcome(status="FAIL")
        return ExpectedOutcome(status="SUCCESS")

    def _expected_read(self, step: dict[str, Any]) -> ExpectedOutcome:
        if self._mbr_read_should_fail(step):
            return ExpectedOutcome(interface_result_should_fail=True)
        if self._mbr_shadow_read(step):
            return ExpectedOutcome(status=None)
        if self._read_locked(step):
            return ExpectedOutcome(interface_result_should_fail=True)
        if self._media_key_changed_for_read(step) and self.state.pre_genkey_read_result is not None:
            return ExpectedOutcome(status=None, read_result_differs_previous=True)
        if self.state.data_removed:
            expected_written = self.state.user_data.get(self._lba_key(step))
            if expected_written is not None:
                return ExpectedOutcome(status=None, read_result_differs_previous=True)
        expected_written = self.state.user_data.get(self._lba_key(step))
        if expected_written is not None:
            return ExpectedOutcome(read_result_equals_written=expected_written)
        return ExpectedOutcome(status=None)

    def _expected_write(self, step: dict[str, Any]) -> ExpectedOutcome:
        if self._mbr_write_should_fail(step):
            return ExpectedOutcome(interface_result="fail")
        if self._write_locked(step):
            return ExpectedOutcome(interface_result="fail")
        return ExpectedOutcome(interface_result="pass")

    def _compare_with_actual(self, step: dict[str, Any], expected: ExpectedOutcome) -> bool:
        if expected.status is not None:
            actual_status = self._output_status(step)
            if actual_status != expected.status:
                return False
        if expected.allowed_statuses:
            actual_status = self._output_status(step)
            if actual_status not in expected.allowed_statuses:
                return False

        if self._method_name(step) == "AUTHENTICATE" and expected.status == "SUCCESS":
            authority = normalize_uid(get_path(step, "input", "method", "args", "required", "Authority"))
            proof = get_path(step, "input", "method", "args", "optional", "Proof")
            if proof is None:
                proof = get_path(step, "input", "method", "args", "required", "Proof")
            credential = self._credential_for_authority(authority)
            if credential is None and authority != ANYBODY_AUTHORITY:
                return True
            should_succeed = authority == ANYBODY_AUTHORITY or (
                authority in self.state.enabled_authorities and self._values_equal(proof, credential)
            )
            actual_result = self._auth_result(step)
            if actual_result is not None and actual_result != should_succeed:
                return False

        if self._method_name(step) == "READ":
            result = get_path(step, "output", "args", "result")
            if result is None:
                return False
            normalized = self._normalize_read_result(result)
            if expected.interface_result_should_fail:
                return normalize_status(normalized) in ERROR_RESULTS or normalized in {"0", "00", "0000", "00000000"}
            if expected.read_result_differs_previous:
                return normalized != self.state.pre_genkey_read_result
            if expected.read_result_equals_previous:
                return normalized == self.state.pre_genkey_read_result
            if expected.read_result_equals_written is not None:
                return normalized == expected.read_result_equals_written
            return True

        if self._method_name(step) == "WRITE":
            actual_result = normalize_status(self._interface_result(step))
            if expected.interface_result == "pass":
                return actual_result in {"PASS", "SUCCESS", "OK"}
            if expected.interface_result == "fail":
                return actual_result not in {"PASS", "SUCCESS", "OK"}
            return True

        if self._method_name(step) in {"GET", "PROPERTIES"}:
            values = self._extract_return_values(step)
            if expected.requires_nonempty_values and not values:
                return False
            for key, expected_value in expected.required_values.items():
                if key not in values:
                    return False
                if expected_value is not None and values[key] != expected_value:
                    return False

        return True

    def _method_name(self, step: dict[str, Any]) -> str:
        method = get_path(step, "input", "method", "name")
        if method is None:
            method = get_path(step, "input", "command")
        return normalize_status(method)

    def _object_name(self, step: dict[str, Any]) -> str:
        return normalize_status(get_path(step, "input", "invoking_id", "name"))

    def _output_status(self, step: dict[str, Any]) -> str:
        return normalize_status(get_path(step, "output", "status_codes"))

    def _credential_key(self, step: dict[str, Any]) -> str:
        authority = normalize_uid(get_path(step, "input", "method", "args", "optional", "HostSigningAuthority"))
        if authority is not None:
            return authority
        invoking_uid = normalize_uid(get_path(step, "input", "invoking_id", "uid"))
        if invoking_uid is not None:
            return invoking_uid
        return self._object_name(step)

    def _extract_return_values(self, step: dict[str, Any]) -> dict[str, Any]:
        merged: dict[str, Any] = {}
        for item in flatten_nested_dicts(get_path(step, "output", "return_values", default=[])):
            for key, value in item.items():
                if key in {"required", "optional"} and isinstance(value, dict):
                    continue
                merged[normalize_column_key(key)] = value
        return merged

    def _extract_set_values(self, step: dict[str, Any]) -> dict[str, Any]:
        merged: dict[str, Any] = {}
        values = get_path(step, "input", "method", "args", "optional", "Values", default=[])
        if isinstance(values, dict):
            row_values = values.get("RowValues")
            if isinstance(row_values, list):
                values = row_values
            elif "Bytes" in values:
                return {"bytes": values["Bytes"]}
        if not isinstance(values, list):
            return merged
        for item in values:
            if isinstance(item, dict):
                for key, value in item.items():
                    merged[normalize_column_key(key)] = value
        return merged

    def _normalize_read_result(self, value: Any) -> str:
        text = str(value).strip()
        upper = text.upper()
        if upper.startswith("PATTERN "):
            return text.split(None, 1)[1].strip().upper()
        return upper

    def _interface_result(self, step: dict[str, Any]) -> str:
        return str(get_path(step, "output", "result", default=get_path(step, "output", "args", "result", default="")))

    def _policy_failure(self, method: str, object_name: str) -> str | None:
        policy = POLICIES.get((method, object_name))
        if policy is None:
            return None
        if policy.session_spid is not None and self.state.session.spid != policy.session_spid:
            return policy.failure_status
        if policy.require_authenticated and not self.state.session.authenticated:
            return policy.failure_status
        if policy.allowed_authorities and not any(self._has_authority(authority) for authority in policy.allowed_authorities):
            return policy.failure_status
        if policy.require_activated_sp is not None and policy.require_activated_sp not in self.state.activated_sps:
            return policy.failure_status
        return None

    def _expected_locking_get(self, step: dict[str, Any]) -> ExpectedOutcome:
        expected = ExpectedOutcome(status="SUCCESS", requires_nonempty_values=True)
        semantic = OBJECT_SEMANTICS["LOCKING"]
        expected_columns = self._expected_columns_for_range(step, semantic.readable_column_sets)
        expected.required_values.update({key: None for key in expected_columns})
        return expected

    def _expected_locking_set(self, step: dict[str, Any]) -> ExpectedOutcome:
        values = self._extract_set_values(step)
        allowed = set(OBJECT_SEMANTICS["LOCKING"].writable_columns)
        if not values:
            return ExpectedOutcome(status="SUCCESS")
        if not set(values).issubset(allowed):
            return ExpectedOutcome(status="INVALID_PARAMETER")
        if self._invalid_locking_values(step, values):
            return ExpectedOutcome(status="INVALID_PARAMETER")
        return ExpectedOutcome(status="SUCCESS")

    def _expected_authority_set(self, step: dict[str, Any]) -> ExpectedOutcome:
        values = self._extract_set_values(step)
        if not values:
            return ExpectedOutcome(status="SUCCESS")
        allowed = set(OBJECT_SEMANTICS["AUTHORITY"].authority_update_columns)
        if set(values).issubset(allowed):
            return ExpectedOutcome(status="SUCCESS")
        return ExpectedOutcome(status="INVALID_PARAMETER")

    def _expected_cpin_get(self, step: dict[str, Any]) -> ExpectedOutcome:
        object_uid = normalize_uid(get_path(step, "input", "invoking_id", "uid"))
        required_sp = self._sp_for_cpin(object_uid)
        if required_sp is not None and self.state.session.spid != required_sp:
            return ExpectedOutcome(status="NOT_AUTHORIZED")

        requested = set(self._expected_columns_for_range(step, {"all": ("3",)}))
        if not requested:
            start_col, end_col = self._cellblock_range(step)
            if start_col == 3 and end_col == 3:
                requested = {"3"}

        if "3" in requested:
            if object_uid == C_PIN_MSID and self.state.session.spid == ADMIN_SP:
                return ExpectedOutcome(status="SUCCESS", required_values={"3": None}, requires_nonempty_values=True)
            return ExpectedOutcome(status="NOT_AUTHORIZED")

        if object_uid != C_PIN_MSID and not (self._has_authority(SID_AUTHORITY) or self._has_admin_authority()):
            return ExpectedOutcome(status="NOT_AUTHORIZED")
        return ExpectedOutcome(status="SUCCESS", requires_nonempty_values=True)

    def _expected_cpin_set(self, step: dict[str, Any]) -> ExpectedOutcome:
        object_uid = normalize_uid(get_path(step, "input", "invoking_id", "uid"))
        values = self._extract_set_values(step)
        if not values:
            return ExpectedOutcome(status="SUCCESS")
        if set(values) != {"3"}:
            return ExpectedOutcome(status="INVALID_PARAMETER")
        if self._can_modify_cpin(object_uid):
            return ExpectedOutcome(status="SUCCESS")
        return ExpectedOutcome(status="NOT_AUTHORIZED")

    def _expected_cpin_genkey(self, step: dict[str, Any]) -> ExpectedOutcome:
        object_uid = normalize_uid(get_path(step, "input", "invoking_id", "uid"))
        if self._can_modify_cpin(object_uid):
            return ExpectedOutcome(status="SUCCESS")
        return ExpectedOutcome(status="NOT_AUTHORIZED")

    def _admin_policy_failure(self) -> str | None:
        if self.state.session.spid != LOCKING_SP:
            return "NOT_AUTHORIZED"
        if LOCKING_SP not in self.state.activated_sps:
            return "NOT_AUTHORIZED"
        if not self._has_admin_authority():
            return "NOT_AUTHORIZED"
        return None

    def _byte_table_set_has_column_values(self, step: dict[str, Any]) -> bool:
        values = get_path(step, "input", "method", "args", "optional", "Values")
        if values is None:
            return False
        if isinstance(values, dict):
            return "RowValues" in values
        return isinstance(values, list)

    def _expected_columns_for_range(
        self, step: dict[str, Any], readable_sets: dict[tuple[int, int] | str, tuple[str, ...]]
    ) -> tuple[str, ...]:
        start_col, end_col = self._cellblock_range(step)
        if start_col is None or end_col is None:
            return ()
        exact = readable_sets.get((start_col, end_col))
        if exact is not None:
            return exact

        all_columns: set[str] = set()
        for columns in readable_sets.values():
            all_columns.update(columns)
        selected = [
            column
            for column in all_columns
            if (col_int := self._column_int(column)) is not None and start_col <= col_int <= end_col
        ]
        return tuple(sorted(selected, key=lambda item: self._column_int(item) or 0))

    def _invalid_locking_values(self, step: dict[str, Any], values: dict[str, Any]) -> bool:
        object_uid = normalize_uid(get_path(step, "input", "invoking_id", "uid"))
        for column in ("5", "6", "7", "8"):
            if column in values and to_bool(values[column]) is None:
                return True
        if object_uid == LOCKING_GLOBAL_RANGE:
            for column in ("3", "4"):
                if column in values and (to_int(values[column]) or 0) != 0:
                    return True
        return False

    def _invalid_genkey_parameters(self, step: dict[str, Any]) -> bool:
        optional = get_path(step, "input", "method", "args", "optional", default={})
        if not isinstance(optional, dict):
            return False
        object_name = self._object_name(step)
        if object_name != "C_PIN" and "PinLength" in optional:
            return True
        if not object_name.startswith("C_RSA") and "PublicExponent" in optional:
            return True
        return False

    def _cellblock_range(self, step: dict[str, Any]) -> tuple[int | None, int | None]:
        cellblock = get_path(step, "input", "method", "args", "required", "Cellblock", default=[])
        if not isinstance(cellblock, list) or len(cellblock) < 2:
            return None, None
        return to_int(get_path(cellblock, 0, "startColumn")), to_int(get_path(cellblock, 1, "endColumn"))

    def _column_int(self, column: str) -> int | None:
        try:
            return int(column, 16)
        except ValueError:
            return None

    def _learn_credential_aliases(self, credential_uid: str | None, credential: str) -> None:
        if credential_uid is None:
            return
        self.state.credentials[credential_uid] = credential
        authority = self._authority_for_credential_uid(credential_uid)
        if authority is not None:
            self.state.credentials[authority] = credential
        if credential_uid == C_PIN_MSID and C_PIN_SID not in self.state.credentials:
            self.state.credentials[C_PIN_SID] = credential
            self.state.credentials[SID_AUTHORITY] = credential

    def _update_authority_enabled(self, authority_uid: str | None, values: dict[str, Any]) -> None:
        if authority_uid is None or "5" not in values:
            return
        enabled = to_bool(values["5"])
        if enabled is True:
            self.state.enabled_authorities.add(authority_uid)
        elif enabled is False and authority_uid not in {ANYBODY_AUTHORITY, SID_AUTHORITY, LOCKING_ADMIN1_AUTHORITY}:
            self.state.enabled_authorities.discard(authority_uid)

    def _authority_for_credential_uid(self, credential_uid: str) -> str | None:
        if credential_uid == C_PIN_SID:
            return SID_AUTHORITY
        if credential_uid == C_PIN_ADMIN_SP_ADMIN1:
            return "0000000900000201"
        if credential_uid.startswith("0000000B") and len(credential_uid) == 16:
            return "00000009" + credential_uid[8:]
        return None

    def _credential_uid_for_authority(self, authority: str | None) -> str | None:
        if authority is None or authority == ANYBODY_AUTHORITY:
            return None
        if authority == SID_AUTHORITY:
            return C_PIN_SID
        if authority == "0000000900000201":
            return C_PIN_ADMIN_SP_ADMIN1
        if authority.startswith("00000009") and len(authority) == 16:
            return "0000000B" + authority[8:]
        return None

    def _credential_for_authority(self, authority: str | None) -> str | None:
        if authority is None:
            return None
        credential_uid = self._credential_uid_for_authority(authority)
        if authority == SID_AUTHORITY:
            return self.state.credentials.get(SID_AUTHORITY) or self.state.credentials.get(C_PIN_SID) or self.state.credentials.get(C_PIN_MSID)
        if credential_uid is None:
            return None
        return self.state.credentials.get(authority) or self.state.credentials.get(credential_uid)

    def _sp_for_cpin(self, credential_uid: str | None) -> str | None:
        if credential_uid is None:
            return None
        if credential_uid in {C_PIN_MSID, C_PIN_SID, C_PIN_ADMIN_SP_ADMIN1} or credential_uid.startswith("0000000B0000"):
            return ADMIN_SP
        if credential_uid.startswith("0000000B0001") or credential_uid.startswith("0000000B0003"):
            return LOCKING_SP
        return None

    def _can_modify_cpin(self, credential_uid: str | None) -> bool:
        required_sp = self._sp_for_cpin(credential_uid)
        if required_sp is not None and self.state.session.spid != required_sp:
            return False
        if required_sp == LOCKING_SP and LOCKING_SP not in self.state.activated_sps:
            return False
        if credential_uid == C_PIN_SID:
            return self._has_authority(SID_AUTHORITY)
        if required_sp == ADMIN_SP:
            return self._has_authority(SID_AUTHORITY) or self._has_admin_authority()
        if credential_uid is not None and credential_uid.startswith("0000000B0003"):
            paired_authority = self._authority_for_credential_uid(credential_uid)
            return self._has_admin_authority() or (paired_authority is not None and self._has_authority(paired_authority))
        if required_sp == LOCKING_SP:
            return self._has_admin_authority()
        return self.state.session.authenticated

    def _authority_exists(self, authority: str) -> bool:
        if authority in {ANYBODY_AUTHORITY, ADMINS_AUTHORITY, USERS_AUTHORITY, SID_AUTHORITY, LOCKING_ADMIN1_AUTHORITY}:
            return True
        return authority.startswith("000000090001") or authority.startswith("000000090003") or authority.startswith("00000009000002")

    def _is_class_authority(self, authority: str) -> bool:
        return authority in {ADMINS_AUTHORITY, USERS_AUTHORITY}

    def _has_authority(self, authority: str | None) -> bool:
        if authority is None:
            return False
        if authority == ANYBODY_AUTHORITY:
            return True
        if authority == ADMINS_AUTHORITY:
            return any(self._is_admin_authority(item) for item in self.state.session.authenticated_authorities)
        if authority == USERS_AUTHORITY:
            return any(item.startswith("000000090003") for item in self.state.session.authenticated_authorities)
        return authority in self.state.session.authenticated_authorities

    def _has_admin_authority(self) -> bool:
        return self._has_authority(ADMINS_AUTHORITY) or any(
            self._is_admin_authority(item) for item in self.state.session.authenticated_authorities
        )

    def _is_admin_authority(self, authority: str) -> bool:
        return authority.startswith("000000090001") or authority.startswith("00000009000002")

    def _auth_result(self, step: dict[str, Any]) -> bool | None:
        for item in flatten_nested_dicts(get_path(step, "output", "return_values", default=[])):
            for key, value in item.items():
                if normalize_status(key) in {"SUCCESS", "RESULT"}:
                    parsed = to_bool(value)
                    if parsed is not None:
                        return parsed
        return None

    def _values_equal(self, left: Any, right: Any) -> bool:
        if left == right:
            return True
        return str(left).strip() == str(right).strip()

    def _lba_key(self, step: dict[str, Any]) -> str:
        bounds = self._lba_bounds(step)
        if bounds is None:
            return str(get_path(step, "input", "args", "LBA", default="")).strip()
        return f"{bounds[0]}-{bounds[1]}"

    def _lba_bounds(self, step: dict[str, Any]) -> tuple[int, int] | None:
        value = get_path(step, "input", "args", "LBA")
        if value is None:
            return None
        parts = str(value).replace("~", "-").replace("..", "-").split("-")
        if len(parts) == 1:
            start = to_int(parts[0].strip())
            if start is None:
                return None
            return start, start
        start = to_int(parts[0].strip())
        end = to_int(parts[-1].strip())
        if start is None or end is None:
            return None
        return min(start, end), max(start, end)

    def _read_locked(self, step: dict[str, Any]) -> bool:
        return self._range_locked(step, enabled_column="5", locked_column="7")

    def _write_locked(self, step: dict[str, Any]) -> bool:
        return self._range_locked(step, enabled_column="6", locked_column="8")

    def _range_locked(self, step: dict[str, Any], *, enabled_column: str, locked_column: str) -> bool:
        bounds = self._lba_bounds(step)
        for uid, values in self.state.object_values.items():
            if not uid.startswith("00000802"):
                continue
            if not self._range_overlaps(bounds, uid, values):
                continue
            enabled = to_bool(values.get(enabled_column))
            locked = to_bool(values.get(locked_column))
            if enabled and locked:
                return True
        return False

    def _range_overlaps(self, bounds: tuple[int, int] | None, uid: str, values: dict[str, Any]) -> bool:
        if bounds is None:
            return True
        if uid == LOCKING_GLOBAL_RANGE:
            return True
        start = to_int(values.get("3"))
        length = to_int(values.get("4"))
        if start is None or length is None or length <= 0:
            return False
        end = start + length - 1
        return not (bounds[1] < start or bounds[0] > end)

    def _range_for_key_uid(self, key_uid: str | None) -> str | None:
        if key_uid is None or len(key_uid) != 16:
            return None
        if key_uid.startswith("00000805") or key_uid.startswith("00000806"):
            return "00000802" + key_uid[8:]
        return None

    def _media_key_changed_for_read(self, step: dict[str, Any]) -> bool:
        if self.state.data_removed:
            return True
        if not self.state.erased_ranges:
            return False
        bounds = self._lba_bounds(step)
        for range_uid in self.state.erased_ranges:
            if range_uid == LOCKING_GLOBAL_RANGE:
                return True
            values = self.state.object_values.get(range_uid)
            if not values:
                return True
            if self._range_overlaps(bounds, range_uid, values):
                return True
        return False

    def _mbr_values(self) -> dict[str, Any]:
        return self.state.object_values.get(MBRCONTROL_UID, {})

    def _mbr_shadow_active(self) -> bool:
        values = self._mbr_values()
        return to_bool(values.get("1")) is True and to_bool(values.get("2")) is False

    def _touches_mbr_lba(self, step: dict[str, Any]) -> bool:
        bounds = self._lba_bounds(step)
        if bounds is None:
            return False
        return bounds[0] == 0

    def _crosses_mbr_boundary(self, step: dict[str, Any]) -> bool:
        bounds = self._lba_bounds(step)
        if bounds is None:
            return False
        return bounds[0] == 0 and bounds[1] > 0

    def _mbr_shadow_read(self, step: dict[str, Any]) -> bool:
        return self._mbr_shadow_active() and self._touches_mbr_lba(step) and not self._crosses_mbr_boundary(step)

    def _mbr_read_should_fail(self, step: dict[str, Any]) -> bool:
        return self._mbr_shadow_active() and self._crosses_mbr_boundary(step)

    def _mbr_write_should_fail(self, step: dict[str, Any]) -> bool:
        return self._mbr_shadow_active() and self._touches_mbr_lba(step)

    def _keep_global_range_key(self, step: dict[str, Any]) -> bool:
        value = get_path(step, "input", "method", "args", "optional", "KeepGlobalRangeKey")
        return to_bool(value) is True

    def _global_range_fully_locked(self) -> bool:
        values = self.state.object_values.get(LOCKING_GLOBAL_RANGE, {})
        read_enabled = to_bool(values.get("5"))
        write_enabled = to_bool(values.get("6"))
        read_locked = to_bool(values.get("7"))
        write_locked = to_bool(values.get("8"))
        return bool(read_enabled and write_enabled and read_locked and write_locked)

    def _emit_debug_trace(self, final_step: dict[str, Any], expected: ExpectedOutcome, verdict: bool) -> None:
        if not self.debug_enabled:
            return
        method = self._method_name(final_step)
        object_name = self._object_name(final_step)
        actual_status = self._output_status(final_step)
        result = get_path(final_step, "output", "args", "result")
        summary = (
            f"final step {final_step.get('index')}: method={method} object={object_name} "
            f"expected_status={expected.status} actual_status={actual_status} "
            f"expected_values={expected.required_values or '{}'} actual_result={result} verdict={'pass' if verdict else 'fail'}"
        )
        print("DEBUG_SOLVER TRACE START")
        for event in self.debug_events:
            print(event)
        print(summary)
        print(
            "state snapshot:",
            {
                "session_spid": SP_NAMES.get(self.state.session.spid, self.state.session.spid),
                "session_authority": AUTHORITY_NAMES.get(self.state.session.authority, self.state.session.authority),
                "session_authenticated": self.state.session.authenticated,
                "latest_credential": CREDENTIAL_NAMES.get(self.state.latest_credential, self.state.latest_credential),
                "last_sp_uid_read": self.state.last_sp_uid_read,
                "genkey_effective": self.state.genkey_effective,
                "last_genkey_attempt_status": self.state.last_genkey_attempt_status,
                "pre_genkey_read_result": self.state.pre_genkey_read_result,
            },
        )
        print("DEBUG_SOLVER TRACE END")

    def _debug(self, message: str) -> None:
        if self.debug_enabled:
            self.debug_events.append(message)

    def _verify_failed_step_preserves_state(self, step: dict[str, Any], before: Any) -> None:
        after = self._state_fingerprint()
        if after != before:
            raise AssertionError(
                f"Failed step changed protocol state unexpectedly: "
                f"index={step.get('index')} method={self._method_name(step)} status={self._output_status(step)}"
            )

    def _state_fingerprint(self) -> Any:
        return self._freeze(
            {
                "session_spid": self.state.session.spid,
                "session_authority": self.state.session.authority,
                "session_authenticated": self.state.session.authenticated,
                "session_write": self.state.session.write,
                "authenticated_authorities": self.state.session.authenticated_authorities,
                "credentials": self.state.credentials,
                "enabled_authorities": self.state.enabled_authorities,
                "activated_sps": self.state.activated_sps,
                "object_values": self.state.object_values,
                "object_reads": self.state.object_reads,
                "latest_credential": self.state.latest_credential,
                "last_sp_uid_read": self.state.last_sp_uid_read,
                "pre_genkey_read_result": self.state.pre_genkey_read_result,
                "user_data": self.state.user_data,
                "erased_ranges": self.state.erased_ranges,
                "genkey_effective": self.state.genkey_effective,
                "data_removed": self.state.data_removed,
            }
        )

    def _freeze(self, value: Any) -> Any:
        if isinstance(value, dict):
            return tuple(sorted((key, self._freeze(item)) for key, item in value.items()))
        if isinstance(value, list):
            return tuple(self._freeze(item) for item in value)
        if isinstance(value, set):
            return tuple(sorted(self._freeze(item) for item in value))
        return value

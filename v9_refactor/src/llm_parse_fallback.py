from __future__ import annotations

import json
import os
import re
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .rag_context import build_retrieval_query, format_retrieved_context
from .prompt_templates import load_prompt, render_prompt
from .rag_retriever import SpecTextRetriever
from .runtime_config import load_runtime_config


@dataclass
class LLMParseDecision:
    usable: bool = False
    confidence: float = 0.0
    reason: str = ""
    normalized_event: dict[str, Any] | None = None
    state_patch: dict[str, Any] | None = None
    verdict: str | None = None


def env_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def should_repair_event(
    event: dict[str, Any],
    *,
    include_no_family: bool | None = None,
    include_non_rw_commands: bool | None = None,
) -> bool:
    load_runtime_config()
    if event.get("kind") == "unknown":
        return True
    if include_no_family is None:
        include_no_family = env_flag("LLM_PARSE_REPAIR_NO_FAMILY", True)
    if include_non_rw_commands is None:
        include_non_rw_commands = env_flag("LLM_PARSE_REPAIR_NON_RW_COMMANDS", True)
    if (
        event.get("kind") == "command"
        and event.get("command") not in {"read", "write"}
        and include_non_rw_commands
    ):
        return True
    if event.get("kind") != "method":
        return False
    if not event.get("method"):
        return True
    if include_no_family and event.get("object_family") is None:
        return True
    if env_flag("LLM_PARSE_REPAIR_INFERRED", False) and event.get("method_inferred"):
        return True
    if event.get("name_uid_conflict") or event.get("cellblock_invalid"):
        return True
    if event.get("value_columns_invalid") or event.get("value_columns_duplicate"):
        return True
    if env_flag("LLM_PARSE_REPAIR_FAILED_EVENTS", False):
        status = str(event.get("status") or "").strip().lower()
        if status and status != "success":
            return True
    return False


def should_judge_with_llm(event: dict[str, Any], result: Any) -> bool:
    load_runtime_config()
    policy_source = getattr(result, "policy_source", "") or ""
    coverage_status = getattr(result, "coverage_status", "") or ""
    confidence = float(getattr(result, "confidence", 1.0) or 0.0)
    threshold = float(os.environ.get("LLM_PARSE_JUDGE_BELOW_CONFIDENCE", "0.60"))
    if should_trust_deterministic_verdict(result):
        return False
    if should_repair_event(event):
        return True
    if policy_source == "fallback":
        return True
    if env_flag("LLM_PARSE_JUDGE_PARTIAL", True) and coverage_status == "partial":
        return True
    return confidence <= threshold


def should_trust_deterministic_verdict(result: Any) -> bool:
    load_runtime_config()
    if not env_flag("LLM_PARSE_TRUST_IMPLEMENTED_HIGH_CONF", True):
        return False
    coverage_status = getattr(result, "coverage_status", "") or ""
    policy_source = getattr(result, "policy_source", "") or ""
    if coverage_status != "implemented" or policy_source == "fallback":
        return False
    confidence = float(getattr(result, "confidence", 1.0) or 0.0)
    min_confidence = float(os.environ.get("LLM_PARSE_TRUST_MIN_CONFIDENCE", "0.95"))
    return confidence >= min_confidence


def merge_event_patch(event: dict[str, Any], patch: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(patch, dict):
        return event
    merged = dict(event)
    allowed = {
        "kind",
        "command",
        "method",
        "method_inferred",
        "method_inferred_from_state",
        "method_uid",
        "object",
        "object_family",
        "object_name",
        "object_name_family",
        "object_uid",
        "object_uid_family",
        "name_uid_conflict",
        "spid",
        "sp",
        "write",
        "authority",
        "authority_uid",
        "host_exchange_authority_uid",
        "host_exchange_authority",
        "sp_exchange_authority_uid",
        "sp_exchange_authority",
        "sp_signing_authority_uid",
        "sp_signing_authority",
        "challenge",
        "proof",
        "auth_result",
        "parameters",
        "required_parameters",
        "optional_parameters",
        "where",
        "count",
        "keep_global_range_key",
        "values",
        "value_columns",
        "value_columns_duplicate",
        "value_columns_invalid",
        "value_byte_length",
        "return_columns",
        "cellblock",
        "cellblock_start",
        "cellblock_end",
        "cellblock_columns",
        "cellblock_invalid",
        "locking_range",
        "key_range",
        "lba",
        "pattern",
        "result",
        "input_status",
        "output_status",
        "status",
    }
    for key in allowed:
        if key in patch and patch[key] is not None:
            merged[key] = patch[key]
    merged["raw"] = event.get("raw")
    return merged


def apply_state_patch(state: dict[str, Any], patch: dict[str, Any] | None) -> None:
    if not isinstance(patch, dict):
        return

    if isinstance(patch.get("locking_sp_active"), bool):
        state["locking_sp_active"] = patch["locking_sp_active"]

    for top in ("credentials", "sp_lifecycle", "trylimit_by_authority", "failed_auth_counts"):
        values = patch.get(top)
        if isinstance(values, dict) and isinstance(state.get(top), dict):
            for key, value in values.items():
                if isinstance(key, str):
                    state[top][key] = value

    session = patch.get("session")
    if isinstance(session, dict) and isinstance(state.get("session"), dict):
        for key in (
            "open",
            "sp",
            "authority",
            "write",
            "had_failure",
            "trusted",
            "host_session_id",
            "sp_session_id",
        ):
            if key in session:
                state["session"][key] = session[key]
        authorities = session.get("authorities")
        if isinstance(authorities, list):
            state["session"]["authorities"] = {str(value) for value in authorities}

    ranges = patch.get("locking_ranges")
    if isinstance(ranges, dict):
        allowed_range_keys = {
            "range_start",
            "range_length",
            "read_lock_enabled",
            "write_lock_enabled",
            "read_locked",
            "write_locked",
            "lock_on_reset",
            "active_key",
            "next_key",
            "reencrypt_state",
            "reencrypt_request",
        }
        for name, values in ranges.items():
            if not isinstance(name, str) or not isinstance(values, dict):
                continue
            entry = state.setdefault("locking_ranges", {}).setdefault(name, {})
            for key in allowed_range_keys:
                if key in values:
                    entry[key] = values[key]

    mbr = patch.get("mbr")
    if isinstance(mbr, dict) and isinstance(state.get("mbr"), dict):
        for key in ("enable", "done", "done_on_reset"):
            if key in mbr:
                state["mbr"][key] = mbr[key]

    writes = patch.get("writes")
    if isinstance(writes, list):
        for record in writes:
            if not isinstance(record, dict) or "lba" not in record:
                continue
            key = tuple(record["lba"]) if isinstance(record["lba"], list) else record["lba"]
            state.setdefault("writes", {})[key] = record
            state.setdefault("write_records", []).append(record)


class LLMParseFallback:
    def __init__(self) -> None:
        load_runtime_config()
        os.environ.setdefault("HF_HOME", "/workspace/cache/hf_cache")
        os.environ.setdefault("HF_HUB_OFFLINE", "1")
        os.environ.setdefault("RAG_MAX_CHUNK_CHARS", "3500")
        self.enabled = env_flag("USE_LLM_PARSE_FALLBACK", True)
        self.model_name = os.environ.get("LLM_PARSE_MODEL") or os.environ.get("MODEL_NAME") or "Qwen/Qwen3.5-9B"
        self.min_confidence = float(os.environ.get("LLM_PARSE_MIN_CONFIDENCE", "0.72"))
        self.max_new_tokens = int(os.environ.get("LLM_PARSE_MAX_NEW_TOKENS", "384"))
        self.enable_rag = env_flag("LLM_PARSE_ENABLE_RAG", True)
        self.rag_top_k = int(os.environ.get("LLM_PARSE_RAG_TOP_K", "8"))
        self.rag_max_chars = int(os.environ.get("LLM_PARSE_RAG_MAX_CHARS", "3500"))
        self._llm: Any = None
        self._tokenizer: Any = None
        self._available: bool | None = None
        self._retriever: SpecTextRetriever | None = None
        self.audit_path = os.environ.get("LLM_PARSE_AUDIT_PATH")
        self.audit_include_prompt = env_flag("LLM_PARSE_AUDIT_INCLUDE_PROMPT", True)
        self.audit_include_response = env_flag("LLM_PARSE_AUDIT_INCLUDE_RESPONSE", True)
        self.audit_pretty = env_flag("LLM_PARSE_AUDIT_PRETTY", True)
        self._audit_counter = 0

    def repair_event(
        self,
        *,
        raw_step: dict[str, Any],
        normalized_event: dict[str, Any],
        state: dict[str, Any],
        is_target: bool,
    ) -> LLMParseDecision:
        return self._ask_llm(
            task="target" if is_target else "pre_target",
            raw_step=raw_step,
            normalized_event=normalized_event,
            state=state,
            rule_result=None,
        )

    def judge_target(
        self,
        *,
        raw_step: dict[str, Any],
        normalized_event: dict[str, Any],
        state: dict[str, Any],
        rule_result: Any,
    ) -> LLMParseDecision:
        return self._ask_llm(
            task="judge_target",
            raw_step=raw_step,
            normalized_event=normalized_event,
            state=state,
            rule_result=rule_result,
        )

    def _is_available(self) -> bool:
        if not self.enabled:
            return False
        if self._available is not None:
            return self._available
        try:
            import vllm  # noqa: F401
            import transformers  # noqa: F401

            self._available = True
        except Exception:
            self._available = False
        return self._available

    def _ask_llm(
        self,
        *,
        task: str,
        raw_step: dict[str, Any],
        normalized_event: dict[str, Any],
        state: dict[str, Any],
        rule_result: Any,
    ) -> LLMParseDecision:
        if not self._is_available():
            decision = LLMParseDecision(reason="LLM unavailable")
            self._write_audit(
                task=task,
                raw_step=raw_step,
                normalized_event=normalized_event,
                state=state,
                rule_result=rule_result,
                prompt=None,
                response=None,
                decision=decision,
                error="LLM unavailable",
            )
            return decision
        prompt = None
        response = None
        try:
            prompt = self._build_prompt(task, raw_step, normalized_event, state, rule_result)
            response = self._generate(prompt)
            decision = self._parse_output(response)
            if decision.confidence < self.min_confidence:
                decision.usable = False
            self._write_audit(
                task=task,
                raw_step=raw_step,
                normalized_event=normalized_event,
                state=state,
                rule_result=rule_result,
                prompt=prompt,
                response=response,
                decision=decision,
            )
            return decision
        except Exception as exc:  # noqa: BLE001
            self._available = False
            decision = LLMParseDecision(reason=str(exc)[:200])
            self._write_audit(
                task=task,
                raw_step=raw_step,
                normalized_event=normalized_event,
                state=state,
                rule_result=rule_result,
                prompt=prompt,
                response=response,
                decision=decision,
                error=str(exc)[:500],
            )
            return decision

    def _generate(self, prompt: str) -> str:
        from transformers import AutoTokenizer
        from vllm import LLM, SamplingParams

        if self._tokenizer is None:
            self._tokenizer = AutoTokenizer.from_pretrained(
                self.model_name,
                trust_remote_code=True,
                local_files_only=env_flag("LLM_PARSE_LOCAL_FILES_ONLY", True),
            )
        if self._llm is None:
            self._llm = LLM(
                model=self.model_name,
                trust_remote_code=True,
                dtype=os.environ.get("LLM_PARSE_DTYPE", "bfloat16"),
                gpu_memory_utilization=float(os.environ.get("LLM_PARSE_GPU_MEMORY", "0.85")),
                max_model_len=int(os.environ.get("LLM_PARSE_MAX_MODEL_LEN", "8192")),
                disable_log_stats=True,
            )
        messages = [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]
        try:
            rendered = self._tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        except Exception:
            rendered = f"{_SYSTEM_PROMPT}\n\n{prompt}\n\nJSON:"
        sampling_kwargs = {
            "temperature": 0.0,
            "max_tokens": self.max_new_tokens,
            "stop": ["```"],
        }
        if env_flag("LLM_PARSE_STRUCTURED_OUTPUTS", True):
            try:
                from vllm.sampling_params import StructuredOutputsParams

                sampling_kwargs["structured_outputs"] = StructuredOutputsParams(json=_OUTPUT_JSON_SCHEMA)
            except Exception:
                pass

        outputs = self._llm.generate([rendered], SamplingParams(**sampling_kwargs))
        if not outputs or not outputs[0].outputs:
            return ""
        return outputs[0].outputs[0].text

    def _build_prompt(
        self,
        task: str,
        raw_step: dict[str, Any],
        normalized_event: dict[str, Any],
        state: dict[str, Any],
        rule_result: Any,
    ) -> str:
        payload = {
            "task": task,
            "raw_step": _compact(raw_step, 5000),
            "current_normalized_event": _compact(normalized_event, 3000),
            "state_before_step": _state_snapshot(state),
            "retrieved_spec_context": self._rag_context(
                task=task,
                raw_step=raw_step,
                normalized_event=normalized_event,
                state=state,
                rule_result=rule_result,
            ),
            "rule_result": None
            if rule_result is None
            else {
                "verdict": getattr(rule_result, "verdict", None),
                "confidence": getattr(rule_result, "confidence", None),
                "reason": getattr(rule_result, "reason", None),
                "expected_status": getattr(rule_result, "expected_status", None),
                "actual_status": getattr(rule_result, "actual_status", None),
                "policy_source": getattr(rule_result, "policy_source", None),
                "coverage_status": getattr(rule_result, "coverage_status", None),
            },
        }
        return render_prompt(
            "llm_parse_user_template.txt",
            payload_json=json.dumps(payload, ensure_ascii=True, sort_keys=True),
        )

    def _rag_context(
        self,
        *,
        task: str,
        raw_step: dict[str, Any],
        normalized_event: dict[str, Any],
        state: dict[str, Any],
        rule_result: Any,
    ) -> str:
        if not self.enable_rag or self.rag_top_k <= 0:
            return "RAG disabled."
        try:
            if self._retriever is None:
                self._retriever = SpecTextRetriever()
            query = build_retrieval_query(
                parse_issues=None,
                final_event=normalized_event,
                state_summary=json.dumps(_state_snapshot(state), ensure_ascii=True, sort_keys=True, default=str)[:1200],
                rule_result=rule_result,
                raw_steps=[raw_step],
                events=[normalized_event],
            )
            query = f"{task} {query}"
            chunks = self._retriever.retrieve(query, top_k=self.rag_top_k)
            return format_retrieved_context(chunks, max_chars=self.rag_max_chars)
        except Exception as exc:  # noqa: BLE001
            return f"RAG unavailable: {str(exc)[:160]}"

    def _parse_output(self, text: str) -> LLMParseDecision:
        obj = _extract_decision_json_object(text)
        if not isinstance(obj, dict):
            return LLMParseDecision(reason=text[:200])
        verdict = obj.get("verdict")
        if verdict not in {"pass", "fail", None}:
            verdict = None
        try:
            confidence = float(obj.get("confidence", 0.0))
        except (TypeError, ValueError):
            confidence = 0.0
        return LLMParseDecision(
            usable=bool(obj.get("usable")) and 0.0 <= confidence <= 1.0,
            confidence=confidence,
            reason=str(obj.get("reason") or "")[:300],
            normalized_event=obj.get("normalized_event") if isinstance(obj.get("normalized_event"), dict) else None,
            state_patch=obj.get("state_patch") if isinstance(obj.get("state_patch"), dict) else None,
            verdict=verdict,
        )

    def _write_audit(
        self,
        *,
        task: str,
        raw_step: dict[str, Any],
        normalized_event: dict[str, Any],
        state: dict[str, Any],
        rule_result: Any,
        prompt: str | None,
        response: str | None,
        decision: LLMParseDecision,
        error: str | None = None,
    ) -> None:
        if not self.audit_path:
            return
        record = {
            "task": task,
            "event_index": normalized_event.get("index") if isinstance(normalized_event, dict) else None,
            "event_summary": _event_summary(normalized_event),
            "raw_step": _compact(raw_step, int(os.environ.get("LLM_PARSE_AUDIT_RAW_CHARS", "3000"))),
            "state_snapshot": _state_snapshot(state),
            "rule_result": _rule_result_snapshot(rule_result),
            "decision": _decision_snapshot(decision),
            "error": error,
        }
        if prompt is not None and self.audit_include_prompt:
            record["prompt"] = _truncate(prompt, int(os.environ.get("LLM_PARSE_AUDIT_PROMPT_CHARS", "30000")))
            record["rag_context"] = _extract_prompt_rag_context(prompt)
        if response is not None and self.audit_include_response:
            record["response"] = _truncate(response, int(os.environ.get("LLM_PARSE_AUDIT_RESPONSE_CHARS", "5000")))
        try:
            path = Path(self.audit_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=True, sort_keys=True, default=str) + "\n")
            if self.audit_pretty:
                self._write_pretty_audit(path, record)
        except OSError:
            return

    def _write_pretty_audit(self, jsonl_path: Path, record: dict[str, Any]) -> None:
        self._audit_counter += 1
        task = _safe_filename(str(record.get("task") or "llm"))
        idx = record.get("event_index")
        idx_part = f"_idx{idx}" if idx is not None else ""
        stem = f"{self._audit_counter:06d}_{task}{idx_part}_p{os.getpid()}"
        directory = Path(os.environ.get("LLM_PARSE_AUDIT_DIR", str(jsonl_path) + ".d"))
        directory.mkdir(parents=True, exist_ok=True)

        json_path = directory / f"{stem}.json"
        json_path.write_text(
            json.dumps(record, ensure_ascii=True, indent=2, sort_keys=True, default=str) + "\n",
            encoding="utf-8",
        )


_SYSTEM_PROMPT = load_prompt("llm_parse_system.txt")


_OUTPUT_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "usable": {"type": "boolean"},
        "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "reason": {"type": "string"},
        "normalized_event": {"type": ["object", "null"], "additionalProperties": True},
        "state_patch": {"type": ["object", "null"], "additionalProperties": True},
        "verdict": {"type": ["string", "null"], "enum": ["pass", "fail", None]},
    },
    "required": ["usable", "confidence", "reason", "normalized_event", "state_patch", "verdict"],
    "additionalProperties": False,
}


def _extract_decision_json_object(text: str) -> dict[str, Any] | None:
    text = text.strip()
    if not text:
        return None

    decoder = json.JSONDecoder()
    candidates: list[dict[str, Any]] = []
    for match in re.finditer(r"\{", text):
        try:
            parsed, _ = decoder.raw_decode(text[match.start() :])
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict) and _looks_like_decision(parsed):
            candidates.append(parsed)
    if candidates:
        return candidates[-1]
    return None


def _looks_like_decision(value: dict[str, Any]) -> bool:
    return {
        "usable",
        "confidence",
        "reason",
        "normalized_event",
        "state_patch",
        "verdict",
    }.issubset(value)


def _compact(value: Any, max_chars: int) -> Any:
    text = json.dumps(value, ensure_ascii=True, sort_keys=True, default=str)
    if len(text) <= max_chars:
        return value
    return {"truncated_json": text[:max_chars]}


def _truncate(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "...<truncated>"


def _safe_filename(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return value.strip("_") or "llm"


def _event_summary(event: Any) -> dict[str, Any]:
    if not isinstance(event, dict):
        return {"repr": repr(event)[:300]}
    keys = (
        "index",
        "kind",
        "method",
        "method_inferred",
        "command",
        "object",
        "object_family",
        "object_uid",
        "status",
        "sp",
        "write",
        "authority",
        "locking_range",
        "key_range",
    )
    return {key: event.get(key) for key in keys if event.get(key) is not None}


def _rule_result_snapshot(rule_result: Any) -> dict[str, Any] | None:
    if rule_result is None:
        return None
    return {
        "verdict": getattr(rule_result, "verdict", None),
        "confidence": getattr(rule_result, "confidence", None),
        "reason": getattr(rule_result, "reason", None),
        "expected_status": getattr(rule_result, "expected_status", None),
        "actual_status": getattr(rule_result, "actual_status", None),
        "policy_source": getattr(rule_result, "policy_source", None),
        "coverage_status": getattr(rule_result, "coverage_status", None),
        "spec_refs": list(getattr(rule_result, "spec_refs", ()) or ()),
    }


def _decision_snapshot(decision: LLMParseDecision) -> dict[str, Any]:
    return {
        "usable": decision.usable,
        "confidence": decision.confidence,
        "reason": decision.reason,
        "normalized_event": _compact(decision.normalized_event, 4000),
        "state_patch": _compact(decision.state_patch, 4000),
        "verdict": decision.verdict,
    }


def _extract_prompt_rag_context(prompt: str) -> str | None:
    marker = "INPUT:\n"
    idx = prompt.find(marker)
    if idx < 0:
        return None
    try:
        payload = json.loads(prompt[idx + len(marker) :])
    except json.JSONDecodeError:
        return None
    context = payload.get("retrieved_spec_context") if isinstance(payload, dict) else None
    if context is None:
        return None
    max_chars = int(os.environ.get("LLM_PARSE_AUDIT_RAG_CHARS", "12000"))
    return _truncate(str(context), max_chars)


def _state_snapshot(state: dict[str, Any]) -> dict[str, Any]:
    snapshot = {
        "session": deepcopy(state.get("session")),
        "credentials": deepcopy(state.get("credentials")),
        "sp_lifecycle": deepcopy(state.get("sp_lifecycle")),
        "locking_sp_active": state.get("locking_sp_active"),
        "locking_ranges": deepcopy(state.get("locking_ranges")),
        "mbr": deepcopy(state.get("mbr")),
        "key_generations_by_range": deepcopy(state.get("key_generations_by_range")),
        "recent_history": deepcopy((state.get("history") or [])[-8:]),
        "recent_failed_observations": deepcopy((state.get("failed_observations") or [])[-12:]),
    }
    return _json_ready(snapshot)


def _json_ready(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, set):
        return sorted(_json_ready(item) for item in value)
    if isinstance(value, tuple):
        return [_json_ready(item) for item in value]
    if isinstance(value, list):
        return [_json_ready(item) for item in value]
    return value

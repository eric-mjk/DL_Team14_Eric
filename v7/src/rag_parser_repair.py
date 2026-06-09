"""Prompting and response handling for RAG-assisted parser repair."""
from __future__ import annotations

import os
import json
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable

from .rag_context import build_repair_context, build_retrieval_query
from .rag_retriever import SpecTextRetriever
from .rag_schema import (
    ALLOWED_ACTIONS,
    ALLOWED_EVENT_PATCH_FIELDS,
    ALLOWED_STATE_EFFECTS,
    RepairDecision,
    RepairValidationError,
    RetrievedChunk,
    no_repair_decision,
    validate_repair_decision,
)


_REPAIR_LLM: Any = None
_REPAIR_TOKENIZER: Any = None


SYSTEM_PROMPT = """\
You are a parser-repair assistant for a deterministic TCG Storage/Opal SSD state machine.
Your job is to convert suspicious raw or partially parsed input into a schema the existing
state machine can already handle. You must not suggest code edits and must not invent
protocol behavior outside the evidence.

Return ONLY one JSON object. No prose, no markdown.
If you need to think, keep it internal. The output must still be a single JSON object.

Allowed actions:
- repair_event: propose a constrained patch for one parsed event.
- state_effect: classify an unknown successful history method into a whitelisted effect.
- no_repair: evidence is insufficient or deterministic parsing is already adequate.
- needs_rule_patch: the input is understood, but the deterministic state machine needs an offline code change.

Allowed state_effect values:
no_effect, open_session, sync_session_ids, close_session, authenticate_authority,
set_table_columns, activate_locking_sp, revert_sp, reset_like_event, gen_key.

For repair_event, event_patch may contain only:
kind, method, command, object_uid, object, object_family, status, result, parameters,
required_parameters, optional_parameters, spid, sp, write, authority, where, count,
values, lba, pattern.

Required JSON shape:
{
  "action": "repair_event|state_effect|no_repair|needs_rule_patch",
  "confidence": 0.0,
  "step_index": 0,
  "event_patch": {},
  "state_effect": "no_effect",
  "reason": "brief evidence-backed reason"
}
""".strip()


FEW_SHOT_EXAMPLES = """\
=== Few-Shot Examples ===

Example A: flat StartSession args outside required/optional.
Input concern:
- step=4 raw args contain HostSessionID, SPID, Write at input.method.args top level.
- parsed event is missing spid/sp/write.
Valid output:
{"action":"repair_event","confidence":0.92,"step_index":4,"event_patch":{"spid":"0000020500000002","sp":"LockingSP","write":true,"parameters":{"HostSessionID":1,"SPID":"0000020500000002","Write":1},"required_parameters":{"HostSessionID":1,"SPID":"0000020500000002","Write":1}},"state_effect":"no_effect","reason":"Raw StartSession args contain SPID and Write outside required/optional; patch normalized fields the state machine consumes."}

Example B: unknown object UID but deterministic parser intentionally maps it to NonLockingSP.
Input concern:
- final Activate target UID is 0000010500000004, name is SP, parsed object is NonLockingSP.
- spec evidence says Activate is an SP object method for Manufactured SPs; deterministic rule expects invalid_parameter for non-LockingSP target.
Valid output:
{"action":"no_repair","confidence":0.88,"step_index":null,"event_patch":null,"state_effect":"no_effect","reason":"The raw UID does not identify the LockingSP object. The parsed NonLockingSP target supports the deterministic invalid_parameter judgment; no parser repair is warranted."}

Example C: unknown successful history command that looks like a reset.
Input concern:
- history step command is PowerCycleReset and output result is pass.
- state machine only recognizes reset-like command text for reset effects.
Valid output:
{"action":"state_effect","confidence":0.82,"step_index":12,"event_patch":null,"state_effect":"reset_like_event","reason":"Raw successful history command is a power-cycle/reset event and should be treated as reset-like if deterministic parsing missed it."}

Example D: understood input but missing deterministic rule.
Input concern:
- raw and parsed event agree; no important parser fields are missing.
- retrieved spec evidence contradicts deterministic oracle behavior.
Valid output:
{"action":"needs_rule_patch","confidence":0.76,"step_index":null,"event_patch":null,"state_effect":"no_effect","reason":"The input is already parsed; the issue is a deterministic rule gap, not parser repair."}

Example E: Set Values represented as a dict.
Input concern:
- step=6 raw Set args contain Values as {"RowValues":{"ReadLocked":true}} instead of a list.
- parsed event has empty values or missing value_columns.
Valid output:
{"action":"repair_event","confidence":0.90,"step_index":6,"event_patch":{"values":{"RowValues":{"ReadLocked":true}},"parameters":{"Values":{"RowValues":{"ReadLocked":true}}},"required_parameters":{"Values":{"RowValues":{"ReadLocked":true}}}},"state_effect":"no_effect","reason":"Raw Set Values are present as a dict shape; patch the normalized fields consumed by Set handling without changing protocol behavior."}

Example F: data command key casing changed.
Input concern:
- step=9 raw command is Write and input args contain Lba and Pattern.
- parsed write event is missing lba or pattern.
Valid output:
{"action":"repair_event","confidence":0.87,"step_index":9,"event_patch":{"kind":"write","command":"Write","lba":[100,101],"pattern":"A5"},"state_effect":"no_effect","reason":"Raw data command contains Lba/Pattern with alternate casing; patch only the normalized write fields."}

If no repair is justified, output no_repair. Do not explain before or after JSON.
""".strip()


def build_parser_repair_prompt(
    parse_issues: list[Any] | tuple[Any, ...] | None,
    final_event: Any,
    state_summary: str | None,
    rule_result: Any,
    chunks: list[RetrievedChunk],
    raw_steps: list[Any] | tuple[Any, ...] | None = None,
    events: list[Any] | tuple[Any, ...] | None = None,
) -> str:
    def render(context: str) -> str:
        return (
        "Return exactly one JSON object. The first character of your answer must be '{'.\n"
        "Do not include analysis, markdown, code fences, or prose outside the JSON.\n\n"
        f"{FEW_SHOT_EXAMPLES}\n\n"
        f"{context}\n\n"
        "Decision task: determine whether parser repair is warranted for the normalized events consumed by the state machine. "
        "Prefer no_repair when the deterministic parser already captured the raw input semantics. "
        "If proposing repair_event, patch only fields directly supported by the raw trajectory, parse issues, state-machine contract, and spec evidence. "
        "Return JSON only."
        )

    context = build_repair_context(
        parse_issues,
        final_event,
        state_summary,
        rule_result,
        chunks,
        raw_steps=raw_steps,
        events=events,
    )
    prompt = render(context)
    max_chars = int(os.environ.get("RAG_REPAIR_PROMPT_MAX_CHARS", "14000"))
    if len(prompt) <= max_chars:
        return prompt

    compact_context = build_repair_context(
        parse_issues,
        final_event,
        state_summary,
        rule_result,
        chunks,
        raw_steps=raw_steps,
        events=events,
        max_issues=6,
        source_max_chars=2200,
        trajectory_max_steps=28,
        raw_issue_chars=650,
        event_max_chars=800,
        rule_max_chars=650,
        spec_max_chars=1600,
    )
    compact_prompt = render(
        compact_context
        + "\n\n=== Prompt Compaction Notice ===\n"
        + f"The original repair context was {len(prompt)} characters and was compacted to fit the LLM context window."
    )
    if len(compact_prompt) <= max_chars:
        return compact_prompt
    return compact_prompt[:max_chars].rstrip() + "\n\nReturn JSON only."


def parse_repair_response(response: str | dict[str, Any], evidence: list[RetrievedChunk] | None = None) -> RepairDecision:
    decision = validate_repair_decision(response, evidence=evidence)
    if isinstance(response, str):
        raw = dict(decision.raw)
        raw["_raw_model_response"] = response
        return replace(decision, raw=raw)
    return decision


def retrieve_repair_evidence(
    parse_issues: list[Any] | tuple[Any, ...] | None,
    final_event: Any,
    state_summary: str | None = None,
    rule_result: Any = None,
    raw_steps: list[Any] | tuple[Any, ...] | None = None,
    events: list[Any] | tuple[Any, ...] | None = None,
    *,
    retriever: SpecTextRetriever | None = None,
    top_k: int | None = None,
) -> list[RetrievedChunk]:
    retriever = retriever or SpecTextRetriever()
    top_k = top_k if top_k is not None else int(os.environ.get("RAG_TOP_K", "5"))
    query = build_retrieval_query(parse_issues, final_event, state_summary, rule_result, raw_steps=raw_steps, events=events)
    return retriever.retrieve(query, top_k=top_k)


def suggest_repair_without_llm(
    parse_issues: list[Any] | tuple[Any, ...] | None,
    final_event: Any,
    state_summary: str | None = None,
    rule_result: Any = None,
    raw_steps: list[Any] | tuple[Any, ...] | None = None,
    events: list[Any] | tuple[Any, ...] | None = None,
    *,
    retriever: SpecTextRetriever | None = None,
    top_k: int | None = None,
) -> RepairDecision:
    """Dry-run helper for tests and shadow mode.

    It performs retrieval and returns a validated no_repair decision with the
    evidence attached, without loading or calling any LLM.
    """

    chunks = retrieve_repair_evidence(
        parse_issues,
        final_event,
        state_summary,
        rule_result,
        raw_steps=raw_steps,
        events=events,
        retriever=retriever,
        top_k=top_k,
    )
    return no_repair_decision("dry run: retrieval evidence collected; LLM not invoked", evidence=chunks)


def call_repair_llm(
    prompt: str,
    *,
    llm_callable: Callable[[str], str] | None = None,
) -> str:
    """Call an optional LLM backend lazily.

    No model is imported at module import time. In production wiring, callers
    should pass ``llm_callable``. A small env-gated fallback is provided only as
    a hook point and deliberately raises if no backend is configured.
    """

    if llm_callable is not None:
        return llm_callable(prompt)
    if os.environ.get("ENABLE_RAG_REPAIR_LLM", "1") != "1":
        raise RuntimeError("RAG repair LLM is disabled; pass llm_callable or set ENABLE_RAG_REPAIR_LLM=1")
    return _call_vllm_repair_backend(prompt)


def _call_vllm_repair_backend(prompt: str) -> str:
    """Lazy vLLM backend for env-enabled parser repair."""

    global _REPAIR_LLM, _REPAIR_TOKENIZER

    from vllm import LLM, SamplingParams
    from vllm.sampling_params import StructuredOutputsParams

    model_name = os.environ.get("RAG_REPAIR_MODEL_NAME") or os.environ.get("MODEL_NAME", "Qwen/Qwen3.5-9B")
    hf_home = os.environ.get("HF_HOME", "/workspace/cache/hf_cache")
    os.environ.setdefault("HF_HOME", hf_home)

    if _REPAIR_LLM is None:
        _REPAIR_LLM = LLM(
            model=model_name,
            trust_remote_code=True,
            dtype=os.environ.get("RAG_REPAIR_DTYPE", "bfloat16"),
            gpu_memory_utilization=float(os.environ.get("RAG_REPAIR_GPU_MEMORY_UTILIZATION", "0.85")),
            max_model_len=int(os.environ.get("RAG_REPAIR_MAX_MODEL_LEN", "8192")),
        )

    rendered_prompt = prompt
    if os.environ.get("RAG_REPAIR_USE_CHAT_TEMPLATE", "1") != "0":
        try:
            from transformers import AutoTokenizer

            if _REPAIR_TOKENIZER is None:
                _REPAIR_TOKENIZER = AutoTokenizer.from_pretrained(model_name, trust_remote_code=True)
            rendered_prompt = _REPAIR_TOKENIZER.apply_chat_template(
                [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                tokenize=False,
                add_generation_prompt=True,
            )
        except Exception:
            rendered_prompt = prompt

    schema = {
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": ["repair_event", "state_effect", "no_repair", "needs_rule_patch"]},
            "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
            "step_index": {"type": ["integer", "null"], "minimum": 0},
            "event_patch": {"type": ["object", "null"]},
            "state_effect": {
                "type": ["string", "null"],
                "enum": [
                    "no_effect",
                    "open_session",
                    "sync_session_ids",
                    "close_session",
                    "authenticate_authority",
                    "set_table_columns",
                    "activate_locking_sp",
                    "revert_sp",
                    "reset_like_event",
                    "gen_key",
                    None,
                ],
            },
            "reason": {"type": "string"},
        },
        "required": ["action", "confidence", "step_index", "event_patch", "state_effect", "reason"],
        "additionalProperties": False,
    }
    structured = None
    if os.environ.get("RAG_REPAIR_STRUCTURED_OUTPUT", "1") != "0":
        structured = StructuredOutputsParams(json=schema)

    sampling = SamplingParams(
        temperature=float(os.environ.get("RAG_REPAIR_TEMPERATURE", "0.0")),
        max_tokens=int(os.environ.get("RAG_REPAIR_MAX_NEW_TOKENS", "256")),
        stop=["```"],
        structured_outputs=structured,
    )
    outputs = _REPAIR_LLM.generate([rendered_prompt], sampling)
    if not outputs or not outputs[0].outputs:
        return ""
    return outputs[0].outputs[0].text or ""


def run_parser_repair(
    parse_issues: list[Any] | tuple[Any, ...] | None,
    final_event: Any,
    state_summary: str | None = None,
    rule_result: Any = None,
    raw_steps: list[Any] | tuple[Any, ...] | None = None,
    events: list[Any] | tuple[Any, ...] | None = None,
    *,
    retriever: SpecTextRetriever | None = None,
    llm_callable: Callable[[str], str] | None = None,
    top_k: int | None = None,
) -> RepairDecision:
    """Retrieve evidence, build prompt, call a supplied LLM, and validate JSON."""

    chunks = retrieve_repair_evidence(
        parse_issues,
        final_event,
        state_summary,
        rule_result,
        raw_steps=raw_steps,
        events=events,
        retriever=retriever,
        top_k=top_k,
    )
    prompt = build_parser_repair_prompt(
        parse_issues,
        final_event,
        state_summary,
        rule_result,
        chunks,
        raw_steps=raw_steps,
        events=events,
    )
    try:
        response = call_repair_llm(prompt, llm_callable=llm_callable)
    except Exception as exc:  # noqa: BLE001
        _write_prompt_audit(prompt, f"<LLM_CALL_ERROR> {exc}", chunks)
        return no_repair_decision(
            f"LLM repair call failed: {exc}",
            confidence=0.0,
            evidence=chunks,
        )
    _write_prompt_audit(prompt, response, chunks)
    try:
        return parse_repair_response(response, evidence=chunks)
    except RepairValidationError as exc:
        return no_repair_decision(
            f"LLM repair output failed validation: {exc}; raw={str(response)[:500]}",
            confidence=0.0,
            evidence=chunks,
        )


def _write_prompt_audit(prompt: str, response: str, chunks: list[RetrievedChunk]) -> None:
    path = os.environ.get("RAG_PROMPT_AUDIT_PATH")
    if not path:
        return
    record = {
        "system_prompt": SYSTEM_PROMPT,
        "user_prompt": prompt,
        "response": response,
        "evidence": [
            {
                "path": chunk.path,
                "section": chunk.section,
                "title": chunk.title,
                "score": chunk.score,
            }
            for chunk in chunks
        ],
    }
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=True, sort_keys=True) + "\n")
    except OSError:
        return


__all__ = [
    "ALLOWED_ACTIONS",
    "ALLOWED_EVENT_PATCH_FIELDS",
    "ALLOWED_STATE_EFFECTS",
    "SYSTEM_PROMPT",
    "FEW_SHOT_EXAMPLES",
    "build_parser_repair_prompt",
    "call_repair_llm",
    "parse_repair_response",
    "retrieve_repair_evidence",
    "run_parser_repair",
    "suggest_repair_without_llm",
]

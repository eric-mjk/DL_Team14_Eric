"""Prompting and response handling for RAG-assisted parser repair."""
from __future__ import annotations

import os
import json
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable

from .prompt_templates import load_prompt, render_prompt
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


SYSTEM_PROMPT = load_prompt("rag_parser_repair_system.txt")
FEW_SHOT_EXAMPLES = load_prompt("rag_parser_repair_few_shot.txt")


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
        return render_prompt(
            "rag_parser_repair_user_template.txt",
            few_shot_examples=FEW_SHOT_EXAMPLES,
            context=context,
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

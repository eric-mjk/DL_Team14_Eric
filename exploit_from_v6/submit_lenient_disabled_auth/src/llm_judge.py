"""LLM-based protocol judge for TCG/Opal SSD compliance verification.

Uses vllm to run a local model (default: Qwen/Qwen3.5-9B) as a fallback
oracle when the deterministic rule engine produces low-confidence results.

The LLM receives:
  - A human-readable transcript of the command trajectory
  - A snapshot of the tracked protocol state
  - The rule engine's prediction and reasoning

It returns a pass/fail verdict with a confidence score.  The solver
only substitutes the LLM verdict when confidence >= config.min_confidence.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------

@dataclass
class LLMJudgeConfig:
    model_name: str = os.environ.get("MODEL_NAME", "Qwen/Qwen3.5-9B")
    min_confidence: float = 0.82
    max_new_tokens: int = 256
    temperature: float = 0.0
    # Prompt token budget: reserve this many tokens for the response
    max_prompt_steps: int = 40  # truncate extremely long trajectories


@dataclass
class LLMDecision:
    usable: bool = False
    verdict: str | None = None        # "pass" or "fail"
    confidence: float | None = None
    reason: str | None = None


# ---------------------------------------------------------------------------
# Prompt construction helpers
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are an expert in the TCG (Trusted Computing Group) Storage Security / Opal SSC protocol.
Your task is to judge whether a **final SSD command-response** in a trajectory is protocol-compliant.

=== Key rules ===
1. PASS = the SSD response is correct given the prior command history (not whether it is SUCCESS or FAIL).
2. Properties method: MUST return SUCCESS with a non-empty list of properties.
3. StartSession: MUST return SUCCESS iff the HostChallenge matches the stored credential for HostSigningAuthority.
   - If authority credential is empty string, ANY challenge (or no challenge) is valid for an unauthenticated session.
   - If no authority given, session opens unauthenticated in Anybody scope.
4. Get C_PIN col 3 (PIN): authorized only from AdminSP (SID), or LockingSP (Admin1/Admin2-4/User1-8 for their own PIN).
   - MSID PIN is always readable by Anybody without authentication.
5. Set C_PIN col 3: update credential.  SID can only set its own PIN.
6. Activate LockingSP: requires authenticated SID session in AdminSP; success copies SID PIN → Admin1 PIN.
7. Set Authority Enabled (col 5): LockingSP session required, Admin1 authority.
8. GenKey: requires authenticated LockingSP session (Admin1); changes the encryption key → old data is unreadable.
9. Read after GenKey on the same range: FAIL if the read data would reflect the old (pre-genkey) plaintext.
10. Set Locking range properties: authenticated Admin1 or User (if range ACL grants it).
11. MBRControl: readable/settable only in authenticated LockingSP session by Admin1.
12. NOT_AUTHORIZED returned when session/auth requirements are not met.
13. INVALID_PARAMETER returned when argument values are illegal.
14. Failed commands do NOT mutate state.

Respond ONLY with a JSON object (no extra text):
{"verdict": "pass" or "fail", "confidence": 0.0-1.0, "reason": "brief explanation"}
""".strip()


def _uid_label(uid: str | None) -> str:
    if uid is None:
        return "None"
    _LABELS = {
        "0000020500000001": "AdminSP",
        "0000020500000002": "LockingSP",
        "0000000900000001": "Anybody",
        "0000000900000002": "Admins",
        "0000000900000006": "SID",
        "0000000900010001": "Admin1",
        "0000000900010002": "Admin2",
        "0000000900010003": "Admin3",
        "0000000900010004": "Admin4",
        "0000000900030000": "Users",
        "0000000900030001": "User1",
        "0000000900030002": "User2",
        "0000000B00008402": "C_PIN_MSID",
        "0000000B00000001": "C_PIN_SID",
        "0000000B00010001": "C_PIN_Admin1",
        "0000000B00030001": "C_PIN_User1",
        "0000080200000001": "GlobalRange",
        "0000080200030001": "Range1",
        "0000080300000001": "MBRControl",
    }
    return _LABELS.get(uid.upper(), uid)


def _format_args(args: Any, max_len: int = 120) -> str:
    if args is None:
        return ""
    if isinstance(args, dict):
        parts = []
        for k, v in args.items():
            if isinstance(v, dict):
                sub = _format_args(v, max_len=60)
                parts.append(f"{k}={{{sub}}}")
            elif isinstance(v, list):
                parts.append(f"{k}=[{v!r:.40}]")
            else:
                parts.append(f"{k}={v!r}")
        text = ", ".join(parts)
    else:
        text = repr(args)
    if len(text) > max_len:
        return text[:max_len] + "…"
    return text


def _format_step(step: dict[str, Any], idx: int) -> str:
    inp = step.get("input", {})
    out = step.get("output", {})
    method_block = inp.get("method", {})
    method_name = method_block.get("name", "?")
    invoking = inp.get("invoking_id", {})
    invoking_uid = invoking.get("uid") if isinstance(invoking, dict) else None
    if invoking_uid:
        invoking_uid = invoking_uid.replace(" ", "").replace("0x", "").upper()
    args_req = _format_args(method_block.get("args", {}).get("required", {}))
    args_opt = _format_args(method_block.get("args", {}).get("optional", {}))
    args_text = ", ".join(filter(None, [args_req, args_opt]))

    status_list = out.get("status_codes") or []
    status = status_list[0] if isinstance(status_list, list) and status_list else status_list
    return_values = out.get("return_values", {})
    rv_text = _format_args(return_values, max_len=80) if return_values else ""

    line = f"  [{idx}] {method_name}"
    if invoking_uid:
        line += f"({_uid_label(invoking_uid)})"
    if args_text:
        line += f" args=({args_text})"
    line += f"  → {status}"
    if rv_text:
        line += f"  rv=({rv_text})"
    return line


def _format_trajectory(steps: list[dict[str, Any]], max_steps: int = 40) -> str:
    lines = ["=== Command Trajectory ==="]
    total = len(steps)
    if total == 0:
        return "(empty trajectory)"
    # Always show last step (the one being judged)
    if total <= max_steps:
        show = list(range(total))
    else:
        # Show first 5, last step, and a window before the last step
        head = list(range(min(5, total - 1)))
        tail_start = max(5, total - (max_steps - 5))
        tail = list(range(tail_start, total))
        if tail_start > 5:
            show = head + ["..."] + tail
        else:
            show = head + tail

    for item in show:
        if item == "...":
            lines.append("  ... (steps omitted for brevity) ...")
            continue
        step = steps[item]
        marker = " ← FINAL" if item == total - 1 else ""
        lines.append(_format_step(step, item) + marker)

    return "\n".join(lines)


def _format_state(state_snapshot: Any) -> str:
    lines = ["=== Protocol State (before final step) ==="]
    if state_snapshot is None:
        return "(no state snapshot)"
    try:
        s = state_snapshot
        sess = s.session
        lines.append(f"  session_spid: {_uid_label(sess.spid)}")
        lines.append(f"  session_authority: {_uid_label(sess.authority)}")
        lines.append(f"  session_authenticated: {sess.authenticated}")
        lines.append(f"  session_write: {sess.write}")
        creds = {_uid_label(k): ('<set>' if v else '<empty>') for k, v in s.credentials.items()}
        lines.append(f"  credentials: {creds}")
        lines.append(f"  activated_sps: {[_uid_label(x) for x in s.activated_sps]}")
        lines.append(f"  genkey_effective: {s.genkey_effective}")
        lines.append(f"  erased_ranges: {[_uid_label(x) for x in s.erased_ranges]}")
        lines.append(f"  pre_genkey_read_result: {s.pre_genkey_read_result!r}")
        lines.append(f"  data_removed: {s.data_removed}")
    except AttributeError:
        # state_snapshot might be a plain dict-like copy
        for k, v in (vars(state_snapshot) if hasattr(state_snapshot, "__dict__") else {}).items():
            lines.append(f"  {k}: {v!r}")
    return "\n".join(lines)


def _build_prompt(
    steps: list[dict[str, Any]],
    state_snapshot: Any,
    rule_prediction: str,
    rule_reason: str,
    max_steps: int = 40,
) -> str:
    traj = _format_trajectory(steps, max_steps=max_steps)
    state = _format_state(state_snapshot)
    return (
        f"{traj}\n\n"
        f"{state}\n\n"
        f"=== Rule Engine Assessment ===\n"
        f"  prediction: {rule_prediction}\n"
        f"  reason: {rule_reason}\n\n"
        f"Evaluate whether the FINAL step response is protocol-compliant.\n"
        f'Respond with JSON only: {{"verdict": "pass"/"fail", "confidence": 0.0-1.0, "reason": "..."}}'
    )


# ---------------------------------------------------------------------------
# Output parser
# ---------------------------------------------------------------------------

def _parse_llm_output(text: str) -> LLMDecision:
    """Extract verdict/confidence/reason from model output."""
    text = text.strip()
    # Try JSON extraction first
    json_match = re.search(r'\{[^{}]*"verdict"[^{}]*\}', text, re.DOTALL | re.IGNORECASE)
    if json_match:
        try:
            obj = json.loads(json_match.group(0))
            verdict_raw = str(obj.get("verdict", "")).strip().lower()
            verdict = verdict_raw if verdict_raw in {"pass", "fail"} else None
            confidence = float(obj.get("confidence", 0.0))
            reason = str(obj.get("reason", ""))
            if verdict is not None and 0.0 <= confidence <= 1.0:
                return LLMDecision(
                    usable=True,
                    verdict=verdict,
                    confidence=confidence,
                    reason=reason,
                )
        except (json.JSONDecodeError, ValueError, TypeError):
            pass

    # Fallback: scan for explicit verdict keywords
    lower = text.lower()
    verdict = None
    if "verdict\": \"pass\"" in lower or '"verdict":"pass"' in lower or re.search(r'\bverdict\b.*\bpass\b', lower):
        verdict = "pass"
    elif "verdict\": \"fail\"" in lower or '"verdict":"fail"' in lower or re.search(r'\bverdict\b.*\bfail\b', lower):
        verdict = "fail"

    # Try to get a confidence value
    conf_match = re.search(r'confidence["\s:]+([0-9.]+)', lower)
    confidence = float(conf_match.group(1)) if conf_match else None

    if verdict is not None:
        return LLMDecision(
            usable=True,
            verdict=verdict,
            confidence=confidence,
            reason=text[:200],
        )

    return LLMDecision(usable=False)


# ---------------------------------------------------------------------------
# Main judge class
# ---------------------------------------------------------------------------

class LLMProtocolJudge:
    """Wraps a vllm model to provide LLM-based compliance verdicts."""

    def __init__(self, config: LLMJudgeConfig | None = None) -> None:
        self.config = config or LLMJudgeConfig()
        self._llm: Any = None
        self._tokenizer: Any = None
        self._enabled: bool | None = None  # None = not yet probed

    def is_enabled(self) -> bool:
        """Return True if the LLM is loadable and configured."""
        if self._enabled is None:
            try:
                import vllm  # noqa: F401
                self._enabled = True
            except ImportError:
                self._enabled = False
        return self._enabled

    def _get_llm(self):
        """Lazy-initialize the vllm engine."""
        if self._llm is not None:
            return self._llm
        from vllm import LLM, SamplingParams  # noqa: F401

        # Respect shared HuggingFace cache when running on evaluation server
        hf_home = os.environ.get("HF_HOME", "/workspace/cache/hf_cache")
        os.environ.setdefault("HF_HOME", hf_home)

        self._llm = LLM(
            model=self.config.model_name,
            trust_remote_code=True,
            dtype="bfloat16",
            gpu_memory_utilization=0.85,
            max_model_len=4096,
        )
        return self._llm

    def _sampling_params(self):
        from vllm import SamplingParams
        return SamplingParams(
            temperature=self.config.temperature,
            max_tokens=self.config.max_new_tokens,
            stop=["\n\n", "```"],
        )

    def _make_messages(
        self,
        steps: list[dict[str, Any]],
        state_snapshot: Any,
        rule_prediction: str,
        rule_reason: str,
    ) -> list[dict[str, str]]:
        user_content = _build_prompt(
            steps,
            state_snapshot,
            rule_prediction,
            rule_reason,
            max_steps=self.config.max_prompt_steps,
        )
        return [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ]

    def _apply_chat_template(self, messages: list[dict[str, str]]) -> str:
        """Convert messages to a single prompt string using the model's template."""
        try:
            from transformers import AutoTokenizer
            if self._tokenizer is None:
                hf_home = os.environ.get("HF_HOME", "/workspace/cache/hf_cache")
                os.environ.setdefault("HF_HOME", hf_home)
                self._tokenizer = AutoTokenizer.from_pretrained(
                    self.config.model_name,
                    trust_remote_code=True,
                )
            return self._tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True,
            )
        except Exception:
            # Fallback: simple concatenation
            parts = []
            for m in messages:
                role = m.get("role", "user")
                content = m.get("content", "")
                parts.append(f"[{role.upper()}]\n{content}")
            parts.append("[ASSISTANT]")
            return "\n\n".join(parts)

    def judge(
        self,
        steps: list[dict[str, Any]],
        state_snapshot: Any,
        rule_prediction: str,
        rule_reason: str,
    ) -> LLMDecision:
        """Judge a single trajectory and return an LLMDecision."""
        if not self.is_enabled():
            return LLMDecision(usable=False)
        try:
            results = self.judge_many([
                {
                    "steps": steps,
                    "state_snapshot": state_snapshot,
                    "rule_prediction": rule_prediction,
                    "rule_reason": rule_reason,
                }
            ])
            return results[0] if results else LLMDecision(usable=False)
        except Exception as exc:  # noqa: BLE001
            return LLMDecision(usable=False, reason=str(exc)[:200])

    def judge_many(self, requests: list[dict[str, Any]]) -> list[LLMDecision]:
        """Judge a batch of trajectories. Returns one LLMDecision per request."""
        if not self.is_enabled() or not requests:
            return [LLMDecision(usable=False)] * len(requests)

        try:
            llm = self._get_llm()
            prompts = []
            for req in requests:
                msgs = self._make_messages(
                    steps=req.get("steps", []),
                    state_snapshot=req.get("state_snapshot"),
                    rule_prediction=req.get("rule_prediction", "?"),
                    rule_reason=req.get("rule_reason", ""),
                )
                prompts.append(self._apply_chat_template(msgs))

            sampling = self._sampling_params()
            outputs = llm.generate(prompts, sampling)

            decisions: list[LLMDecision] = []
            for out in outputs:
                generated = out.outputs[0].text if out.outputs else ""
                decisions.append(_parse_llm_output(generated))
            return decisions

        except Exception as exc:  # noqa: BLE001
            err = str(exc)[:200]
            return [LLMDecision(usable=False, reason=err)] * len(requests)

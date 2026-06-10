from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4


@dataclass(frozen=True)
class EvidencePacketWriteStatus:
    attempted: bool
    recorded: bool
    path: str | None = None
    record_id: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def write_evidence_packet(packet: dict[str, Any], path: str | Path | None) -> EvidencePacketWriteStatus:
    """Append one evidence packet JSON object to ``path`` as JSONL.

    The writer reports status instead of raising for normal filesystem errors
    so solver prediction behavior can remain observational/debug-only.
    """

    if not path:
        return EvidencePacketWriteStatus(attempted=False, recorded=False)

    record_id = str(uuid4())
    packet_with_id = dict(packet)
    packet_with_id.setdefault("identity", {})
    if isinstance(packet_with_id["identity"], dict):
        packet_with_id["identity"].setdefault("record_id", record_id)

    target = Path(path)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(packet_with_id, ensure_ascii=True, sort_keys=True) + "\n")
    except OSError as exc:
        return EvidencePacketWriteStatus(
            attempted=True,
            recorded=False,
            path=str(target),
            record_id=record_id,
            error=str(exc),
        )
    return EvidencePacketWriteStatus(
        attempted=True,
        recorded=True,
        path=str(target),
        record_id=record_id,
        error=None,
    )

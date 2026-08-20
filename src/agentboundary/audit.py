"""Append-only audit trace -- invariant I3, FR-021 and FR-022.

Every proposed call is recorded, **refusals included**. A trace that holds only
the calls that succeeded cannot answer the question an incident actually asks,
which is what was attempted.

The store exposes no update and no delete. Not a guarded one, none: the absence
of the operation is the control (FR-022). Retention and rotation are the
operator's problem, handled outside this process by ordinary file tooling, so
that nothing inside the blast radius can shorten the record.
"""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from agentboundary.model import Check, Decision, ProposedCall, Task

__all__ = ["AuditRecord", "AuditSink", "FileAuditSink", "MemoryAuditSink", "ResultStatus"]


class ResultStatus:
    """What became of an authorised call. Deliberately a small closed set."""

    AUTHORISED_PENDING = "authorised_pending"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    REFUSED = "refused"


@dataclass(frozen=True, slots=True)
class AuditRecord:
    """One proposed call and what the broker did about it.

    ``validated_arguments`` holds the post-validation form (FR-008). Recording
    the raw proposal instead would mean the trace shows what the model asked
    for rather than what the broker agreed to, and those differ precisely in
    the cases worth investigating.
    """

    task_id: str
    tool_name: str
    outcome: str
    reason: str | None
    checks: tuple[Check, ...]
    validated_arguments: Mapping[str, Any]
    cost: float
    result_status: str
    sequence: int
    detail: str = ""

    @classmethod
    def from_decision(
        cls,
        task: Task,
        proposed: ProposedCall,
        decision: Decision,
        sequence: int,
        result_status: str | None = None,
    ) -> AuditRecord:
        default_status = (
            ResultStatus.AUTHORISED_PENDING if decision.authorised else ResultStatus.REFUSED
        )
        return cls(
            task_id=task.id,
            # The tool name as proposed, not as resolved: an out-of-scope call
            # has no resolved tool, and the name the model reached for is the
            # interesting artifact.
            tool_name=proposed.tool_name,
            outcome=str(decision.outcome),
            reason=str(decision.reason) if decision.reason is not None else None,
            checks=decision.checks,
            validated_arguments=dict(decision.validated_arguments),
            cost=decision.cost,
            result_status=result_status or default_status,
            sequence=sequence,
        )

    def to_json(self) -> dict[str, Any]:
        """Serialise to a stable, sorted shape a viewer and a human can read."""
        return {
            "sequence": self.sequence,
            "task_id": self.task_id,
            "tool_name": self.tool_name,
            "outcome": self.outcome,
            "reason": self.reason,
            "result_status": self.result_status,
            "cost": self.cost,
            "validated_arguments": dict(self.validated_arguments),
            "checks": [
                {"name": check.name, "passed": check.passed, "detail": check.detail}
                for check in self.checks
            ],
            "detail": self.detail,
        }


@runtime_checkable
class AuditSink(Protocol):
    """Somewhere records go and never come back changed."""

    def append(self, record: AuditRecord) -> None:
        """Add a record. There is no counterpart operation, by design."""
        ...

    def records(self) -> Sequence[AuditRecord]:
        """Read the trace back, in order."""
        ...


class MemoryAuditSink:
    """In-process sink for tests and for the E2E harness.

    Append-only in the same sense as the file sink: :meth:`records` hands back
    a tuple, so a caller cannot reach in and rewrite history through the value
    it was given.
    """

    __slots__ = ("_lock", "_records")

    def __init__(self) -> None:
        self._records: list[AuditRecord] = []
        self._lock = threading.Lock()

    def append(self, record: AuditRecord) -> None:
        with self._lock:
            self._records.append(record)

    def records(self) -> tuple[AuditRecord, ...]:
        with self._lock:
            return tuple(self._records)

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)


class FileAuditSink:
    """JSON Lines on disk, opened append-only.

    The file is opened with ``O_APPEND`` so the kernel places every write at
    the current end of file. A handle obtained this way cannot seek back over
    existing bytes, which makes "append-only" a property of the descriptor
    rather than a promise made by this class.

    Each record is written and flushed as a single line. A trace that is
    buffered when the process dies is a trace that is missing exactly the calls
    made just before it died.
    """

    __slots__ = ("_lock", "_path")

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        return self._path

    def append(self, record: AuditRecord) -> None:
        line = json.dumps(record.to_json(), ensure_ascii=False, sort_keys=True)
        payload = (line + "\n").encode("utf-8")
        with self._lock:
            # 0o600: a trace holds validated arguments, which routinely include
            # paths and identifiers an operator would not want world-readable.
            descriptor = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(descriptor, payload)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

    def records(self) -> tuple[AuditRecord, ...]:
        return tuple(self._read())

    def _read(self) -> Iterator[AuditRecord]:
        if not self._path.exists():
            return
        with self._path.open("r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped:
                    continue
                payload = json.loads(stripped)
                yield AuditRecord(
                    task_id=payload["task_id"],
                    tool_name=payload["tool_name"],
                    outcome=payload["outcome"],
                    reason=payload["reason"],
                    checks=tuple(
                        Check(name=c["name"], passed=c["passed"], detail=c["detail"])
                        for c in payload["checks"]
                    ),
                    validated_arguments=payload["validated_arguments"],
                    cost=payload["cost"],
                    result_status=payload["result_status"],
                    sequence=payload["sequence"],
                    detail=payload.get("detail", ""),
                )

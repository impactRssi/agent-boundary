"""The refusal ledger -- N-41. Aggregated evidence that grants nothing.

An operator who wants to widen a task's scope deliberately needs to know what
the broker has been refusing. That is the useful part. The dangerous part is
one step away, and it is worth naming before any of the code below is read.

**The trap.** A ledger that feeds a grant workflow is an attacker-influenced
path into the allowlist. The chain is short: a payload steers the agent toward
a secret, the broker refuses, the refusal is written down here, and a human
later approves "the things the agent needed". That is attack A3 (confused
deputy) and A9 (approval fatigue) from ``docs/THREAT_MODEL.md`` wearing a
helpful interface, and the interface is what makes it work -- a list of
refusals reads like a to-do list, and a to-do list invites bulk approval.

**What this module does about it.** Nothing here produces permission.
:class:`LedgerEntry` carries no approval field, no grant method, no identifier
a grant can be keyed to, and this module imports nothing from
``agentboundary.leases``. The dependency runs one way only: a lease names its
subject explicitly, typed by an operator, and never reads this file. The
absence of the reverse edge is the control -- ``tests/unit/test_ledger.py``
asserts it by introspection so that adding one breaks the build.

**What a ledger entry cannot tell a reviewer.** It cannot distinguish a
legitimate workflow from a payload that steered the agent. Both produce the
same row: a subject, a reason, a count, and some task ids. A high count means
the agent tried often, which is exactly what a retry loop induced by injected
content looks like. Reading this file as a list of things to grant is reading
it as the attacker wrote it. :func:`render` repeats that sentence in its own
output, because the caveat has to travel with the number.
"""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Final, Protocol, runtime_checkable
from urllib.parse import urlsplit

from agentboundary.confinement import (
    DEFAULT_PATH_ARGUMENTS,
    DEFAULT_URL_ARGUMENTS,
    ConfinementError,
    resolve_candidate,
    without_root_label,
)
from agentboundary.errors import RefusalReason
from agentboundary.model import Decision, ProposedCall, Task, normalise_tool_name

__all__ = [
    "MAX_SAMPLE_TASK_IDS",
    "FileRefusalLedger",
    "LedgerEntry",
    "MemoryRefusalLedger",
    "RefusalEvent",
    "RefusalLedger",
    "RefusalSubject",
    "SubjectKind",
    "record_refusal",
    "render",
    "subject_for",
]

#: How many task ids one entry keeps. A sample, not a census: the field is
#: named for that, because an operator who reads a truncated list as complete
#: will under-count how widely a subject was reached for.
MAX_SAMPLE_TASK_IDS: Final[int] = 5

#: Printed above every rendering of the ledger, and stored nowhere else, so
#: that no caller can render the rows without it.
CAVEAT: Final[str] = (
    "A ledger entry is a record of a refusal, not a request for permission. It "
    "cannot distinguish a legitimate workflow from a payload that steered the "
    "agent toward this subject: both produce the same row. Nothing here grants "
    "anything. A lease names its subject explicitly, typed by an operator, and "
    "is never derived from this list."
)


class SubjectKind(str, Enum):
    """What a refusal was about. Closed set, matching the three lease kinds."""

    TOOL = "tool"
    PATH = "path"
    HOST = "host"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class RefusalSubject:
    """The normalised thing a refused call reached for.

    ``resolved`` is part of the identity, not decoration. A path that could be
    resolved is recorded in its canonical form and two spellings of it collapse
    to one row; a path that could **not** be resolved is recorded as the literal
    argument, and the literal is attacker-chosen. Merging the two would let an
    unresolvable spelling inherit a resolved subject's row.
    """

    kind: SubjectKind
    value: str
    resolved: bool = True

    def __post_init__(self) -> None:
        if not self.value:
            msg = "a refusal subject cannot be empty; an unattributable refusal is not triageable"
            raise ValueError(msg)

    @property
    def key(self) -> tuple[str, str, bool]:
        return (str(self.kind), self.value, self.resolved)


@dataclass(frozen=True, slots=True)
class RefusalEvent:
    """One refusal, before aggregation. The append-only unit."""

    subject: RefusalSubject
    reason: str
    task_id: str
    at: float

    def to_json(self) -> dict[str, Any]:
        return {
            "subject_kind": str(self.subject.kind),
            "subject": self.subject.value,
            "resolved": self.subject.resolved,
            "reason": self.reason,
            "task_id": self.task_id,
            "at": self.at,
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, Any]) -> RefusalEvent:
        return cls(
            subject=RefusalSubject(
                kind=SubjectKind(payload["subject_kind"]),
                value=str(payload["subject"]),
                resolved=bool(payload["resolved"]),
            ),
            reason=str(payload["reason"]),
            task_id=str(payload["task_id"]),
            at=float(payload["at"]),
        )


@dataclass(frozen=True, slots=True)
class LedgerEntry:
    """Refusals for one subject and one reason, aggregated.

    Read the module docstring before using this type for anything. Restating
    the load-bearing part: **this entry is not a request**. It has no approval
    field, no expiry, no grantee, and no method that produces permission. That
    absence is deliberate and is asserted by test -- a field named
    ``approved``, or a ``grant()`` here, would put bulk approval one keystroke
    away and turn every refusal an attacker induced into a candidate.

    What it cannot tell a reviewer: whether the agent reached for this subject
    because the work needed it or because injected content told it to. The row
    is identical either way.
    """

    subject_kind: str
    subject: str
    resolved: bool
    reason: str
    first_seen: float
    last_seen: float
    count: int
    sample_task_ids: tuple[str, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "subject_kind": self.subject_kind,
            "subject": self.subject,
            "resolved": self.resolved,
            "reason": self.reason,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "count": self.count,
            "sample_task_ids": list(self.sample_task_ids),
        }


@runtime_checkable
class RefusalLedger(Protocol):
    """Somewhere refusals go and never come back as permission.

    Append and read. There is no update, no delete, and -- more to the point --
    no ``approve``, no ``grant``, and no ``promote``. The protocol is the
    contract: an implementation that added one would no longer satisfy it, and
    the introspection test in ``tests/unit/test_ledger.py`` fails the build.
    """

    def record(self, event: RefusalEvent) -> None:
        """Append one refusal. There is no counterpart operation, by design."""
        ...

    def entries(self) -> tuple[LedgerEntry, ...]:
        """Aggregated rows, ordered by subject then reason."""
        ...

    def now(self) -> float:
        """The injected clock, so timestamps are deterministic under test."""
        ...


def _aggregate(events: Iterable[RefusalEvent]) -> tuple[LedgerEntry, ...]:
    """Fold events into one row per (subject, reason).

    Aggregation happens on **read**. The stored form stays a flat append-only
    sequence of events, so nothing ever rewrites a byte that was already
    written -- the same property the audit trace gets from ``O_APPEND``.
    """
    ordered: dict[tuple[str, str, bool, str], list[RefusalEvent]] = {}
    for event in events:
        key = (*event.subject.key, event.reason)
        ordered.setdefault(key, []).append(event)

    rows: list[LedgerEntry] = []
    for (kind, value, resolved, reason), group in ordered.items():
        seen: list[str] = []
        for event in group:
            if event.task_id not in seen and len(seen) < MAX_SAMPLE_TASK_IDS:
                seen.append(event.task_id)
        rows.append(
            LedgerEntry(
                subject_kind=kind,
                subject=value,
                resolved=resolved,
                reason=reason,
                first_seen=min(event.at for event in group),
                last_seen=max(event.at for event in group),
                count=len(group),
                sample_task_ids=tuple(seen),
            )
        )
    rows.sort(key=lambda row: (row.subject_kind, row.subject, row.reason))
    return tuple(rows)


class MemoryRefusalLedger:
    """In-process ledger for tests and for the E2E harness.

    Append-only in the same sense as the file ledger: :meth:`entries` hands
    back a tuple of frozen rows, so a caller cannot rewrite history through the
    value it was given.
    """

    __slots__ = ("_clock", "_events", "_lock")

    def __init__(self, clock: Callable[[], float] | None = None) -> None:
        if clock is None:
            import time

            clock = time.time
        self._clock = clock
        self._events: list[RefusalEvent] = []
        self._lock = threading.Lock()

    def record(self, event: RefusalEvent) -> None:
        with self._lock:
            self._events.append(event)

    def events(self) -> tuple[RefusalEvent, ...]:
        with self._lock:
            return tuple(self._events)

    def entries(self) -> tuple[LedgerEntry, ...]:
        return _aggregate(self.events())

    def now(self) -> float:
        return self._clock()


class FileRefusalLedger:
    """JSON Lines on disk, opened append-only.

    ``O_APPEND`` places every write at the current end of file, so a handle
    obtained here cannot seek back over existing bytes: append-only is a
    property of the descriptor rather than a promise this class makes.

    The path must be absolute. A relative path resolves against the process
    working directory, which a deployment is free to set inside a task's root --
    and the one thing this file must not be is reachable from the agent. Use
    :func:`assert_out_of_reach` to check it against a specific task.
    """

    __slots__ = ("_clock", "_lock", "_path")

    def __init__(self, path: str | Path, clock: Callable[[], float] | None = None) -> None:
        resolved = Path(path)
        if not resolved.is_absolute():
            msg = (
                f"refusal ledger path {str(path)!r} is relative. It would resolve against the "
                f"working directory, which says nothing about whether the agent can reach it."
            )
            raise ValueError(msg)
        if clock is None:
            import time

            clock = time.time
        self._clock = clock
        self._path = resolved
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        return self._path

    def record(self, event: RefusalEvent) -> None:
        payload = (json.dumps(event.to_json(), ensure_ascii=False, sort_keys=True) + "\n").encode(
            "utf-8"
        )
        with self._lock:
            # 0o600: a ledger holds resolved paths and hostnames an agent
            # reached for, which is reconnaissance if it is world-readable.
            descriptor = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(descriptor, payload)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

    def events(self) -> tuple[RefusalEvent, ...]:
        return tuple(self._read())

    def entries(self) -> tuple[LedgerEntry, ...]:
        return _aggregate(self._read())

    def now(self) -> float:
        return self._clock()

    def _read(self) -> Iterator[RefusalEvent]:
        if not self._path.exists():
            return
        with self._path.open("r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped:
                    continue
                yield RefusalEvent.from_json(json.loads(stripped))


def subject_for(task: Task, proposed: ProposedCall, decision: Decision) -> RefusalSubject:
    """The normalised subject of a refusal, derived from data the broker kept.

    Derived, never parsed out of a detail string: a refusal detail is prose
    written for a human, and a control that reads prose is a control that
    changes meaning when someone improves the wording.

    The mapping is by refusal reason, and it is total. A reason with no natural
    path or host subject attributes to the tool that was reached for, because
    an unattributable refusal is a row an operator cannot act on.
    """
    reason = decision.reason
    if reason is RefusalReason.PATH_OUTSIDE_ROOT:
        found = _path_subject(task, decision.validated_arguments)
        if found is not None:
            return found
    elif reason is RefusalReason.EGRESS_HOST_NOT_ALLOWED:
        found = _host_subject(decision.validated_arguments)
        if found is not None:
            return found
    return RefusalSubject(
        kind=SubjectKind.TOOL,
        value=normalise_tool_name(proposed.tool_name) or proposed.tool_name,
    )


def _path_subject(task: Task, arguments: Mapping[str, Any]) -> RefusalSubject | None:
    for name in sorted(DEFAULT_PATH_ARGUMENTS):
        value = arguments.get(name)
        if not isinstance(value, str) or not value:
            continue
        if task.fs_root is None:
            # No root to anchor a relative argument against, so the literal is
            # the only honest record. Marked unresolved for exactly that reason.
            return RefusalSubject(kind=SubjectKind.PATH, value=value, resolved=False)
        try:
            resolved = resolve_candidate(value, Path(task.fs_root))
        except (ConfinementError, OSError):
            # Unresolvable -- a symlink loop, a dangling link, an unreadable
            # parent. The literal is recorded and flagged, so a reviewer knows
            # the string is the attacker's spelling and not a canonical answer.
            return RefusalSubject(kind=SubjectKind.PATH, value=value, resolved=False)
        return RefusalSubject(kind=SubjectKind.PATH, value=str(resolved), resolved=True)
    return None


def _host_subject(arguments: Mapping[str, Any]) -> RefusalSubject | None:
    for name in sorted(DEFAULT_URL_ARGUMENTS):
        value = arguments.get(name)
        if not isinstance(value, str) or not value:
            continue
        try:
            host = (urlsplit(value).hostname or "").lower()
        except ValueError:
            host = ""
        if not host:
            # A URL with no parseable host still refused for an egress reason.
            # The whole argument is the subject, marked unresolved.
            return RefusalSubject(kind=SubjectKind.HOST, value=value, resolved=False)
        return RefusalSubject(kind=SubjectKind.HOST, value=without_root_label(host), resolved=True)
    return None


def record_refusal(
    ledger: RefusalLedger,
    task: Task,
    proposed: ProposedCall,
    decision: Decision,
) -> RefusalEvent | None:
    """Append a refused decision to the ledger. Returns ``None`` for an authorisation.

    Authorised calls are the audit trace's job. This ledger holds refusals
    only, so that "what the broker has been saying no to" is answerable without
    filtering, and so that nothing an operator reads here was ever permitted.
    """
    if decision.authorised or decision.reason is None:
        return None
    event = RefusalEvent(
        subject=subject_for(task, proposed, decision),
        reason=str(decision.reason),
        task_id=task.id,
        at=ledger.now(),
    )
    ledger.record(event)
    return event


def render(entries: Sequence[LedgerEntry]) -> str:
    """Plain-text rendering, caveat first.

    The caveat is emitted by this function rather than left to each caller,
    because a caller that forgets it publishes a list of refusals that reads
    like a list of requests -- which is the failure mode this whole module is
    shaped around.
    """
    lines = [CAVEAT, ""]
    if not entries:
        lines.append("No refusals recorded.")
        return "\n".join(lines)

    lines.append(
        f"{'kind':<6} {'subject':<48} {'reason':<24} {'count':>6}  tasks (sample, "
        f"max {MAX_SAMPLE_TASK_IDS})"
    )
    for entry in entries:
        subject = entry.subject if entry.resolved else f"{entry.subject} (unresolved)"
        lines.append(
            f"{entry.subject_kind:<6} {subject:<48} {entry.reason:<24} "
            f"{entry.count:>6}  {', '.join(entry.sample_task_ids)}"
        )
    return "\n".join(lines)

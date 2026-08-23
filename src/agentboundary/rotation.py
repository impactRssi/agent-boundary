"""Rotation advice when a credential lease expires -- N-44.

A ``credential``-class lease that has run out produces an advisory naming what
was reachable and for how long. **Unconditionally.**

That word is the whole design. The temptation is to emit the advice only when
something looked wrong -- a refusal spike, an odd path, a call at an odd hour --
and that filter would be reading the wrong evidence. The audit trace records
what was **authorised**, not what was read: within the lease window the guards
were doing exactly what the operator told them to, so a clean trace is what both
the legitimate case and the exfiltrated case look like. "Nothing looked wrong"
is therefore not evidence, and an advisory conditioned on it is an advisory that
arrives only when it is already too late to be news.

So: an agent that could read a production environment file for three days means
that file should be rotated. The advisory says which file, for how long, on
whose authority, and for what stated reason, and it says what it does not know.

Emitted at most once per lease, keyed by the lease's digest, because an advisory
repeated on every sweep is an advisory an operator learns to filter -- and the
one thing this must not become is noise.
"""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Protocol, runtime_checkable

from agentboundary.leases import Lease, LeaseKind, LeaseStore, Sensitivity

__all__ = [
    "AdvisorySink",
    "FileAdvisorySink",
    "MemoryAdvisorySink",
    "RotationAdvice",
    "advice_for",
    "due",
    "emit_due",
    "render",
]

_DAY_S: Final[float] = 86_400.0

#: Repeated in every advisory. The reader has to know the limit of the evidence
#: at the moment they read the claim, not in a document they might find later.
UNKNOWABLE: Final[str] = (
    "The trace shows what was authorised, not what was read, so a clean trace is "
    "not evidence that nothing was taken. Rotate regardless."
)

_WHAT_WAS_REACHABLE: Final[Mapping[LeaseKind, str]] = {
    LeaseKind.PATH: "every secret stored under {subject}",
    LeaseKind.HOST: "every credential the agent could have presented to {subject}",
    LeaseKind.TOOL: "every secret {subject} could reach",
}


def _utc(seconds: float) -> str:
    """One timestamp format, UTC, so two runs of a sweep produce one string."""
    return datetime.fromtimestamp(seconds, tz=UTC).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class RotationAdvice:
    """What to rotate, for how long it was reachable, and on whose authority.

    Carries the lease's digest rather than a reference to the lease, so an
    advisory can be written once and recognised later without the lease store
    still holding the record: a lease revoked by deleting its line must not
    cause the advisory to be re-emitted, or to disappear.
    """

    lease_digest: str
    kind: str
    subject: str
    granted_by: str
    reason: str
    granted_at: float
    expires_at: float
    task_id: str | None

    @property
    def window_s(self) -> float:
        return self.expires_at - self.granted_at

    @property
    def message(self) -> str:
        reachable = _WHAT_WAS_REACHABLE[LeaseKind(self.kind)].format(subject=self.subject)
        scope = (
            "every task in this deployment" if self.task_id is None else f"task {self.task_id!r}"
        )
        return (
            f"Rotate {reachable}. A credential-class {self.kind} lease over "
            f"{self.subject!r}, granted by {self.granted_by!r} for {scope}, was in force "
            f"for {self.window_s / _DAY_S:.2f} days, from {_utc(self.granted_at)} to "
            f"{_utc(self.expires_at)}. Stated reason: {self.reason!r}. {UNKNOWABLE}"
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "lease_digest": self.lease_digest,
            "kind": self.kind,
            "subject": self.subject,
            "granted_by": self.granted_by,
            "reason": self.reason,
            "granted_at": self.granted_at,
            "expires_at": self.expires_at,
            "task_id": self.task_id,
            "window_s": self.window_s,
            "message": self.message,
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, Any]) -> RotationAdvice:
        task_id = payload.get("task_id")
        return cls(
            lease_digest=str(payload["lease_digest"]),
            kind=str(payload["kind"]),
            subject=str(payload["subject"]),
            granted_by=str(payload["granted_by"]),
            reason=str(payload["reason"]),
            granted_at=float(payload["granted_at"]),
            expires_at=float(payload["expires_at"]),
            task_id=None if task_id is None else str(task_id),
        )


def advice_for(lease: Lease) -> RotationAdvice | None:
    """The advisory a lease produces, or ``None`` if its class does not oblige one.

    Only ``credential`` obliges one -- and ``credential`` is what a lease with no
    stated class already is, so the advisory is what an operator gets by saying
    nothing. Downgrading out of it is the explicit act, with a name attached.
    """
    if lease.sensitivity is not Sensitivity.CREDENTIAL:
        return None
    return RotationAdvice(
        lease_digest=lease.digest,
        kind=str(lease.kind),
        subject=lease.subject,
        granted_by=lease.granted_by,
        reason=lease.reason,
        granted_at=lease.granted_at,
        expires_at=lease.expires_at,
        task_id=lease.task_id,
    )


def due(store: LeaseStore, now: float | None = None) -> tuple[RotationAdvice, ...]:
    """Every advisory owed at ``now``. No filter, by design.

    There is no "unless the trace was clean" branch, and adding one would be the
    defect described in this module's docstring.
    """
    instant = store.now() if now is None else now
    advisories = [advice_for(lease) for lease in store.expired(instant)]
    return tuple(
        sorted(
            (advice for advice in advisories if advice is not None),
            key=lambda advice: (advice.expires_at, advice.kind, advice.subject),
        )
    )


@runtime_checkable
class AdvisorySink(Protocol):
    """Somewhere advisories go and are not overwritten."""

    def append(self, advice: RotationAdvice) -> None: ...

    def advisories(self) -> tuple[RotationAdvice, ...]: ...


class MemoryAdvisorySink:
    """In-process sink for tests and for the E2E harness."""

    __slots__ = ("_advisories", "_lock")

    def __init__(self) -> None:
        self._advisories: list[RotationAdvice] = []
        self._lock = threading.Lock()

    def append(self, advice: RotationAdvice) -> None:
        with self._lock:
            self._advisories.append(advice)

    def advisories(self) -> tuple[RotationAdvice, ...]:
        with self._lock:
            return tuple(self._advisories)


class FileAdvisorySink:
    """JSON Lines on disk, opened append-only.

    The path must be absolute, and it belongs outside every task's ``fs_root``
    for the same reason the audit trace and the lease store do: an agent that
    can rewrite the record of what it could reach has removed the record.
    Check it with :func:`agentboundary.confinement.assert_out_of_reach`.
    """

    __slots__ = ("_lock", "_path")

    def __init__(self, path: str | Path) -> None:
        resolved = Path(path)
        if not resolved.is_absolute():
            msg = (
                f"advisory sink path {str(path)!r} is relative. It would resolve against "
                f"the working directory, which says nothing about whether the agent can "
                f"reach it."
            )
            raise ValueError(msg)
        self._path = resolved
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        return self._path

    def append(self, advice: RotationAdvice) -> None:
        payload = (json.dumps(advice.to_json(), ensure_ascii=False, sort_keys=True) + "\n").encode(
            "utf-8"
        )
        with self._lock:
            descriptor = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(descriptor, payload)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

    def advisories(self) -> tuple[RotationAdvice, ...]:
        return tuple(self._read())

    def _read(self) -> Iterator[RotationAdvice]:
        if not self._path.exists():
            return
        with self._path.open("r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped:
                    continue
                yield RotationAdvice.from_json(json.loads(stripped))


def emit_due(
    store: LeaseStore,
    sink: AdvisorySink,
    now: float | None = None,
) -> tuple[RotationAdvice, ...]:
    """Write every advisory owed and not yet written. Returns the new ones.

    Deduplicated against what the sink already holds rather than against
    in-process state, so a sweep run by a different process -- a cron job, an
    operator command, the next task construction -- does not re-announce a
    rotation that was already announced. The digest is the key, and it covers
    every field of the lease: a lease re-granted over the same subject is a
    different grant and earns its own advisory when it in turn expires.
    """
    already = {advice.lease_digest for advice in sink.advisories()}
    emitted: list[RotationAdvice] = []
    for advice in due(store, now):
        if advice.lease_digest in already:
            continue
        sink.append(advice)
        emitted.append(advice)
    return tuple(emitted)


def render(advisories: Sequence[RotationAdvice] | Iterable[RotationAdvice]) -> str:
    """Plain text, one advisory per paragraph, each carrying its own caveat."""
    items = list(advisories)
    if not items:
        return "No credential lease has expired, so no rotation is owed."
    return "\n\n".join(f"- {advice.message}" for advice in items)

"""Permission leases -- N-42. A deliberate, bounded, attributable widening.

A lease is the one mechanism in this system that makes an invariant hold less
than it did. That is the whole point of it, and it is why every property below
is a constraint rather than an option.

**What a lease costs.** During its window, the invariant it widens does not
hold for its subject. A path lease over ``/srv/secrets`` means I4 confines the
task to ``fs_root`` *and* ``/srv/secrets``; a host lease means the egress
allowlist has one more entry. Nothing about the model changed and nothing about
the guards changed -- the operator moved the boundary, on purpose, for a stated
period, and the trace says who did it and why.

**What is unrepresentable.** A lease with no expiry. There is no sentinel, no
``None``, no default and no "0 means forever":

* ``expires_at`` has no default, so it cannot be omitted -- construction fails.
* Infinity and NaN are rejected, so the largest float cannot stand in for it.
* ``expires_at`` must be strictly after ``granted_at``: a lease that authorises
  nothing is a configuration error, not a quiet no-op.
* The window is capped **per sensitivity class**, so "expires in the year 9999"
  is refused too. Without that cap, unbounded is representable by a big number,
  which is the same failure written differently.

**Where the unsafe default lives.** Sensitivity defaults to ``credential``
(FR-014's reasoning): the class with the shortest cap and the mandatory rotation
advisory is the one you get by saying nothing. Declaring a subject *less*
sensitive is an explicit act with the operator's name on it.

**What a lease is never derived from.** This module does not import
``agentboundary.ledger`` and has no function that takes a refusal record.
Granting names its subject explicitly, every time. A ledger entry that could be
promoted into a lease would turn every refusal an attacker induced into a
candidate for approval -- attacks A3 and A9 from ``docs/THREAT_MODEL.md``.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import threading
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path
from typing import Any, Final

from agentboundary.confinement import ConfinementError, resolve_candidate, without_root_label
from agentboundary.errors import BrokerError
from agentboundary.model import Task, normalise_tool_name

__all__ = [
    "MAX_DURATION_S",
    "FileLeaseStore",
    "InMemoryLeaseStore",
    "Lease",
    "LeaseError",
    "LeaseKind",
    "LeaseStore",
    "Sensitivity",
    "describe",
    "leased_task",
]


class LeaseError(BrokerError):
    """A lease could not be constructed or read, so it authorises nothing.

    Raised rather than returned. A malformed lease is not a refusal to attribute
    to a task -- it is a store the deployment cannot trust, and a store that
    cannot be trusted must not silently resolve to "no leases", which would
    read to an operator exactly like a lease that had expired.
    """


class LeaseKind(str, Enum):
    """What a lease widens. One kind per invariant surface, no wildcards.

    There is deliberately no ``ALL``. A lease that widened every surface at once
    would be a second, weaker task construction -- which is the thing this whole
    project exists to not have.
    """

    TOOL = "tool"
    PATH = "path"
    HOST = "host"

    def __str__(self) -> str:
        return self.value


class Sensitivity(str, Enum):
    """How bad it is that the subject was reachable at all.

    ``CREDENTIAL`` is the default for an unclassified lease (FR-014's
    reasoning), and it is the class with the shortest cap and the mandatory
    rotation advisory. Downgrading is an explicit act, recorded with the
    grantee's name; it is never the thing that happens because a field was left
    out of a JSON file.
    """

    CREDENTIAL = "credential"
    SENSITIVE = "sensitive"
    ROUTINE = "routine"

    def __str__(self) -> str:
        return self.value


#: The base a path lease subject is resolved against. Subjects are required to
#: be absolute, so this satisfies the signature and anchors nothing.
_FILESYSTEM_ROOT: Final[Path] = Path(os.sep)

_DAY_S: Final[float] = 86_400.0

#: The longest window each class may be granted for, in seconds.
#:
#: These are the teeth behind "unbounded is unrepresentable". Without a maximum,
#: an operator -- or a script that generates leases -- expresses "forever" as a
#: large number and nothing objects. Credential access is capped hardest because
#: it is the class whose expiry obliges a rotation: a window longer than a week
#: means rotation advice arrives too late to be actionable.
MAX_DURATION_S: Final[Mapping[Sensitivity, float]] = {
    Sensitivity.CREDENTIAL: 7 * _DAY_S,
    Sensitivity.SENSITIVE: 14 * _DAY_S,
    Sensitivity.ROUTINE: 30 * _DAY_S,
}


def _normalise_subject(kind: LeaseKind, subject: str) -> str:
    """Canonicalise a subject the same way the guard that consults it will.

    A lease whose subject is normalised differently from the check it widens is
    a lease that either does nothing or does more than it says. Both are worse
    than an error at construction.
    """
    stripped = subject.strip()
    if not stripped:
        msg = "a lease must name a subject; a lease over nothing is a configuration error"
        raise LeaseError(msg)
    if kind is LeaseKind.TOOL:
        return normalise_tool_name(stripped)
    if kind is LeaseKind.HOST:
        host = without_root_label(stripped.lower())
        if not host.strip("."):
            msg = f"host lease subject {subject!r} names no host"
            raise LeaseError(msg)
        return host
    if not Path(stripped).is_absolute():
        # A relative subject would be resolved against whatever the process
        # happened to be doing, which is not a boundary anyone chose.
        msg = (
            f"path lease subject {subject!r} is relative. A lease must name an absolute "
            f"location, because a relative one means a different directory per process."
        )
        raise LeaseError(msg)

    # Resolved here, at construction, and stored resolved. Two reasons.
    #
    # It makes the check below correct. "Is this subject the filesystem root" is
    # a question about a location, not about a spelling: `/x/..` is the root and
    # so is `/x` when `/x` is a symlink to it. A lexical test answers neither,
    # and this module does not pattern-match paths.
    #
    # And it makes the stored subject the same canonical form the guard compares
    # against, so `_admitting_lease` re-resolving it is a no-op rather than a
    # second opinion. `FileLeaseStore` re-reads on every lookup, so a symlink
    # repointed after a grant is picked up on the next call, not cached forever.
    try:
        resolved = resolve_candidate(stripped, _FILESYSTEM_ROOT)
    except (ConfinementError, OSError) as exc:
        msg = (
            f"path lease subject {subject!r} could not be resolved ({exc}), so what it "
            f"grants is undecidable; refusing rather than granting an unknown location"
        )
        raise LeaseError(msg) from exc

    if len(resolved.parts) <= 1:
        # A lease over the filesystem root is not a widening of I4, it is the
        # removal of it, expressed in a form that expires and is therefore easy
        # to grant and forget. It also buys nothing an operator cannot already
        # say: a task that genuinely needs the whole filesystem sets `fs_root`
        # to it, in the task construction, where a reviewer looks.
        msg = (
            f"path lease subject {subject!r} resolves to the filesystem root. A lease over "
            f"the root does not widen confinement, it removes it; set the task's fs_root "
            f"instead, where the decision is visible and not on a timer."
        )
        raise LeaseError(msg)
    return str(resolved)


@dataclass(frozen=True, slots=True)
class Lease:
    """One operator-granted widening, bounded in time by construction.

    Frozen, like every other type on this path: a lease that could be extended
    in place would be an unbounded lease with extra steps.

    ``task_id`` is the narrowing lever. ``None`` means the lease applies to
    every task in the deployment, which is what the motivating case needs --
    an automation whose task id changes every run -- and it is also the widest
    thing this type can express. Set it when the task id is stable. The residual
    risk of leaving it unset is recorded in ``docs/THREAT_MODEL.md`` §7.
    """

    kind: LeaseKind
    subject: str
    granted_by: str
    reason: str
    granted_at: float
    expires_at: float
    sensitivity: Sensitivity = Sensitivity.CREDENTIAL
    task_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "subject", _normalise_subject(self.kind, self.subject))

        if not self.granted_by.strip():
            msg = "a lease must name who granted it; an unattributable widening is not auditable"
            raise LeaseError(msg)
        if not self.reason.strip():
            # Required, not encouraged. A grant with no stated reason is
            # indistinguishable at review time from a grant made in error, and
            # this feature exists precisely so that a reviewer can tell.
            msg = (
                f"lease over {self.subject!r} carries no reason. A reason is required: "
                f"without one, a reviewer cannot tell a deliberate widening from a mistake."
            )
            raise LeaseError(msg)

        for name, value in (("granted_at", self.granted_at), ("expires_at", self.expires_at)):
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                msg = f"lease {name} must be a number, not {type(value).__name__}"
                raise LeaseError(msg)
            if not math.isfinite(float(value)):
                # The one spelling of "forever" a float can hold.
                msg = (
                    f"lease {name} is {value!r}. A lease with no expiry is not "
                    f"representable: infinity and NaN are rejected here so that no "
                    f"value of this field means 'never'."
                )
                raise LeaseError(msg)

        if self.expires_at <= self.granted_at:
            msg = (
                f"lease over {self.subject!r} expires at {self.expires_at} which is not after "
                f"{self.granted_at}. A lease that authorises nothing is a configuration error."
            )
            raise LeaseError(msg)

        cap = MAX_DURATION_S[self.sensitivity]
        duration = self.expires_at - self.granted_at
        if duration > cap:
            msg = (
                f"lease over {self.subject!r} runs for {duration / _DAY_S:.1f} days, over the "
                f"{cap / _DAY_S:.0f}-day cap for class {self.sensitivity}. The cap is what "
                f"stops 'forever' being spelled as a large number."
            )
            raise LeaseError(msg)

    @classmethod
    def granted(
        cls,
        kind: LeaseKind,
        subject: str,
        granted_by: str,
        reason: str,
        granted_at: float,
        duration_s: float,
        sensitivity: Sensitivity = Sensitivity.CREDENTIAL,
        task_id: str | None = None,
    ) -> Lease:
        """Build from a duration, which is how an operator thinks about it.

        The duration is what a grant workflow collects ("three days"), and
        deriving ``expires_at`` here means no caller computes an absolute
        timestamp and gets the arithmetic wrong in the permissive direction.
        """
        if not isinstance(duration_s, (int, float)) or isinstance(duration_s, bool):
            msg = f"lease duration must be a number, not {type(duration_s).__name__}"
            raise LeaseError(msg)
        if not math.isfinite(float(duration_s)) or duration_s <= 0:
            msg = (
                f"lease duration {duration_s!r} is not a finite positive number of seconds. "
                f"There is no duration that means 'until revoked'."
            )
            raise LeaseError(msg)
        return cls(
            kind=kind,
            subject=subject,
            granted_by=granted_by,
            reason=reason,
            granted_at=float(granted_at),
            expires_at=float(granted_at) + float(duration_s),
            sensitivity=sensitivity,
            task_id=task_id,
        )

    @property
    def duration_s(self) -> float:
        return self.expires_at - self.granted_at

    @property
    def digest(self) -> str:
        """Stable identity for one grant, over every field that defines it.

        Used to tell two leases apart in a trace and to emit a rotation advisory
        exactly once. Not a secret and not an authorisation token: nothing
        accepts a digest in place of the lease.
        """
        canonical = json.dumps(self.to_json(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def is_active(self, now: float) -> bool:
        """Whether the lease authorises anything at ``now``. Fails closed.

        Half-open on purpose: active from ``granted_at`` inclusive to
        ``expires_at`` exclusive. At the instant of expiry the lease is over --
        a boundary that authorises is a boundary an operator did not grant.
        """
        return self.granted_at <= now < self.expires_at

    def applies_to_task(self, task_id: str) -> bool:
        """A lease pinned to a task applies to that task only."""
        return self.task_id is None or self.task_id == task_id

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": str(self.kind),
            "subject": self.subject,
            "granted_by": self.granted_by,
            "reason": self.reason,
            "granted_at": self.granted_at,
            "expires_at": self.expires_at,
            "sensitivity": str(self.sensitivity),
            "task_id": self.task_id,
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, Any]) -> Lease:
        """Parse one stored lease. Every absence is an error except sensitivity.

        A missing ``expires_at`` is the case worth naming: it does not become a
        default, a sentinel, or a long window. It fails, because a store that
        can express a lease without an expiry has already lost the property
        this type exists to hold.
        """
        missing = [
            key
            for key in ("kind", "subject", "granted_by", "reason", "granted_at", "expires_at")
            if payload.get(key) is None
        ]
        if missing:
            msg = (
                f"lease record is missing {', '.join(missing)}. A lease with no expiry is "
                f"unrepresentable, so an absent one is an error and never a default."
            )
            raise LeaseError(msg)
        try:
            kind = LeaseKind(str(payload["kind"]))
        except ValueError as exc:
            msg = f"lease record names unknown kind {payload['kind']!r}"
            raise LeaseError(msg) from exc

        raw_sensitivity = payload.get("sensitivity")
        if raw_sensitivity is None:
            # Unstated means credential. The unsafe default is the one we
            # refuse to make convenient (FR-014).
            sensitivity = Sensitivity.CREDENTIAL
        else:
            try:
                sensitivity = Sensitivity(str(raw_sensitivity))
            except ValueError as exc:
                # Not silently downgraded to credential either: an unknown class
                # means the store was written by something we do not understand.
                msg = f"lease record names unknown sensitivity {raw_sensitivity!r}"
                raise LeaseError(msg) from exc

        task_id = payload.get("task_id")
        return cls(
            kind=kind,
            subject=str(payload["subject"]),
            granted_by=str(payload["granted_by"]),
            reason=str(payload["reason"]),
            granted_at=_as_number(payload["granted_at"], "granted_at"),
            expires_at=_as_number(payload["expires_at"], "expires_at"),
            sensitivity=sensitivity,
            task_id=None if task_id is None else str(task_id),
        )


def _as_number(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        msg = f"lease {field} must be a number, not {type(value).__name__}"
        raise LeaseError(msg)
    return float(value)


class LeaseStore:
    """Read-only view over leases, from the broker's side.

    Deliberately offers no ``grant``, for the same reason
    :class:`~agentboundary.approval.ApprovalStore` does not: if this class could
    mint a lease, anything holding a reference to it -- including code reachable
    from a steered agent loop -- could mint one too. Leases are created by an
    operator through their own channel and arrive here already written.

    The clock is injected, so the expiry path is deterministic under test. A
    store that read the wall clock directly could only be tested by waiting,
    and an expiry path nobody tests is an expiry path nobody has seen fail.
    """

    __slots__ = ("_clock", "_leases", "_lock")

    def __init__(
        self,
        leases: Iterable[Lease] = (),
        clock: Callable[[], float] | None = None,
    ) -> None:
        if clock is None:
            import time

            clock = time.time
        self._clock = clock
        self._leases: tuple[Lease, ...] = tuple(leases)
        self._lock = threading.Lock()

    def now(self) -> float:
        return self._clock()

    def leases(self) -> tuple[Lease, ...]:
        """Every lease the store holds, expired ones included.

        Expired leases are returned rather than filtered out because the caller
        has to be able to tell "no lease was ever granted" from "a lease
        expired" -- the second is what a rotation advisory is made of, and it is
        also the more informative refusal detail.
        """
        with self._lock:
            return self._leases

    def active(self, kind: LeaseKind, task_id: str, now: float | None = None) -> tuple[Lease, ...]:
        """The leases of one kind that authorise anything for this task now.

        ``now`` is taken from the injected clock unless the caller pins it, so
        one decision cannot straddle two instants: a guard that read the clock
        twice could find a lease active for the first argument of a call and
        expired for the second.
        """
        instant = self.now() if now is None else now
        return tuple(
            lease
            for lease in self.leases()
            if lease.kind is kind and lease.applies_to_task(task_id) and lease.is_active(instant)
        )

    def active_paths(self, task_id: str, now: float | None = None) -> tuple[Lease, ...]:
        """Path leases in force for this task. What ``PathConfinementGuard`` asks for.

        The three ``active_*`` accessors exist so that a guard can consult the
        store without importing :class:`LeaseKind` -- which would put an import
        edge from ``confinement`` back to this module, and this module already
        depends on ``confinement`` for host normalisation. One direction only.
        """
        return self.active(LeaseKind.PATH, task_id, now)

    def active_hosts(self, task_id: str, now: float | None = None) -> tuple[Lease, ...]:
        """Host leases in force for this task. What ``EgressGuard`` asks for."""
        return self.active(LeaseKind.HOST, task_id, now)

    def active_tools(self, task_id: str, now: float | None = None) -> tuple[Lease, ...]:
        """Tool leases in force. Read once, at task construction -- see ``leased_task``."""
        return self.active(LeaseKind.TOOL, task_id, now)

    def expired(self, now: float | None = None) -> tuple[Lease, ...]:
        """Leases whose window has closed. The input to rotation advice."""
        instant = self.now() if now is None else now
        return tuple(lease for lease in self.leases() if lease.expires_at <= instant)


class InMemoryLeaseStore(LeaseStore):
    """Test and harness store. Leases are seeded at construction only."""


class FileLeaseStore(LeaseStore):
    """Leases read from a JSON Lines file the agent cannot write.

    Re-read on every lookup, deliberately. An operator who revokes a lease by
    removing its line expects the next call to be refused, not the next process
    restart; and a lease granted mid-session takes effect where the roadmap says
    it may -- at a path or host check, never in a dispatch table.

    Any malformed line fails the whole read. Skipping it would silently narrow
    the store, which is safe but quiet, and quiet is what this project does not
    do: the operator would see a lease they granted having no effect and no
    reason given.

    The path must be absolute, for the same reason the refusal ledger's must be:
    a relative path resolves against a working directory that says nothing about
    whether the agent can reach it. Use
    :func:`agentboundary.confinement.assert_out_of_reach` to check it against a
    task.
    """

    __slots__ = ("_path",)

    def __init__(self, path: str | Path, clock: Callable[[], float] | None = None) -> None:
        super().__init__((), clock)
        resolved = Path(path)
        if not resolved.is_absolute():
            msg = (
                f"lease store path {str(path)!r} is relative. It would resolve against the "
                f"working directory, which says nothing about whether the agent can reach it."
            )
            raise ValueError(msg)
        self._path = resolved

    @property
    def path(self) -> Path:
        return self._path

    def leases(self) -> tuple[Lease, ...]:
        if not self._path.exists():
            # No file is not an error: a deployment that has granted nothing
            # has no leases, and that is the narrow answer.
            return ()
        parsed: list[Lease] = []
        try:
            text = self._path.read_text(encoding="utf-8")
        except OSError as exc:
            msg = (
                f"lease store {self._path} could not be read ({exc}); refusing rather than "
                f"proceeding as though nothing were granted or everything were"
            )
            raise LeaseError(msg) from exc
        for number, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                payload = json.loads(stripped)
            except json.JSONDecodeError as exc:
                msg = f"lease store {self._path} line {number} is not valid JSON: {exc}"
                raise LeaseError(msg) from exc
            if not isinstance(payload, dict):
                msg = f"lease store {self._path} line {number} is not a JSON object"
                raise LeaseError(msg)
            parsed.append(Lease.from_json(payload))
        return tuple(parsed)


def describe(leases: Sequence[Lease], now: float) -> str:
    """Plain-text rendering of what is currently granted.

    An operator who cannot see what is leased cannot revoke it, so this states
    remaining time rather than an absolute timestamp: "expired 2.0 days ago" is
    actionable and "1755993600.0" is not.
    """
    if not leases:
        return "No leases granted."
    lines = [f"{'kind':<5} {'subject':<40} {'class':<11} {'by':<24} state"]
    for lease in sorted(leases, key=lambda item: (str(item.kind), item.subject)):
        if lease.is_active(now):
            state = f"active, {(lease.expires_at - now) / 3600:.1f}h remaining"
        elif now < lease.granted_at:
            state = f"not yet in force, starts in {(lease.granted_at - now) / 3600:.1f}h"
        else:
            state = f"EXPIRED {(now - lease.expires_at) / 3600:.1f}h ago"
        lines.append(
            f"{lease.kind!s:<5} {lease.subject:<40} {lease.sensitivity!s:<11} "
            f"{lease.granted_by:<24} {state}"
        )
    return "\n".join(lines)


def leased_task(task: Task, store: LeaseStore | None, now: float | None = None) -> Task:
    """Return the task a tool lease produces, resolved **at construction time only**.

    This is the design tension of the whole feature, so it is stated rather than
    hidden.

    Path and host leases are consulted at call time by the confinement guards,
    because those guards check an argument and a lease widens an argument check.
    Tool leases cannot work that way. I1 is the property that an out-of-scope
    tool has *no handle*: it is absent from the schema the model is shown and
    absent from the dispatch table. A tool that appeared in the dispatch table
    partway through a session would convert I1 from a structural property into a
    call-time filter, which is exactly what ADR-0002 rejects.

    So a tool lease is applied here, once, before the broker exists, producing a
    new frozen :class:`~agentboundary.model.Task`. Nothing is mutated: the task
    the broker holds is fixed for its whole life, as it always was.

    **The consequence, stated rather than hidden: a tool lease that expires
    mid-task keeps its handle until the task ends.** The lease's expiry bounds
    when a *new* task may be constructed with that tool, not when a running one
    loses it. Tool leases should therefore be short, and the task's caps are what
    bound a task that outlives one. An operator who needs the capability gone now
    ends the task; there is no mechanism here that removes it from a live one,
    and adding one would be the call-time filter ADR-0002 rejects.

    A leased tool the registry does not know still fails task construction,
    loudly, in ``ToolRegistry.scope_for``. A lease cannot conjure a capability
    the deployment never registered.
    """
    if store is None:
        return task
    instant = store.now() if now is None else now
    leased = frozenset(lease.subject for lease in store.active_tools(task.id, instant))
    if not leased:
        return task
    return replace(task, tool_scope=task.tool_scope | leased)

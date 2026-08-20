"""Irreversibility gating and out-of-band approval -- I3, FR-014 to FR-017.

Budget bounds how *much* a steered agent can do. It says nothing about whether
an action can be undone: reading a file, dropping a table, and wiring money all
cost one call. Irreversibility is the axis budget cannot carry, so it gets its
own gate.

The gate's whole strength is *where* the approval lives. The broker blocks on
an approval **record**, obtained through a channel the agent does not
participate in. A sentence in the conversation claiming approval was granted is
inert -- not because it is filtered, but because the broker never reads
conversation at all (ADR-0004).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from agentboundary.errors import RefusalReason
from agentboundary.guards import CallContext, GuardResult
from agentboundary.model import Irreversibility

__all__ = [
    "ApprovalGuard",
    "ApprovalRecord",
    "ApprovalStore",
    "InMemoryApprovalStore",
    "argument_digest",
]


def argument_digest(arguments: Mapping[str, Any]) -> str:
    """Stable digest of the **validated** arguments an approval was granted for.

    Binding the approval to a digest is what stops an approved call from being
    replayed with different arguments. An operator who approved deleting ticket
    42 has not approved deleting ticket 43, and without the digest those two
    are the same authorisation.

    Sorted keys and separators fixed, so the digest does not depend on dict
    ordering or on json defaults that could change between versions.
    """
    canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ApprovalRecord:
    """A human's decision, created outside the agent loop.

    ``expires_at`` is compared against the same injected clock the store uses,
    so an approval cannot outlive the window an operator granted it for.
    """

    task_id: str
    tool_name: str
    arg_digest: str
    granted_by: str
    expires_at: float

    def matches(self, task_id: str, tool_name: str, digest: str) -> bool:
        """Constant-time comparison on the digest.

        The digest is not a secret, so this is defence in depth rather than a
        load-bearing control -- but a timing oracle on an authorisation record
        is not a thing to leave lying around.
        """
        return (
            self.task_id == task_id
            and self.tool_name == tool_name
            and hmac.compare_digest(self.arg_digest, digest)
        )


class ApprovalStore:
    """Read-only view over approvals, from the broker's side.

    Deliberately offers no ``grant``. Approvals are created by an operator
    through their own channel; if this class could mint one, anything holding a
    reference to it -- including code reachable from a steered loop -- could
    mint one too.
    """

    __slots__ = ("_clock", "_lock", "_records")

    def __init__(
        self,
        records: Iterable[ApprovalRecord] = (),
        clock: Callable[[], float] | None = None,
    ) -> None:
        if clock is None:
            import time

            clock = time.time
        self._clock = clock
        self._records = list(records)
        self._lock = threading.Lock()

    def find_for_tool(self, task_id: str, tool_name: str) -> tuple[ApprovalRecord, ...]:
        """Every approval issued for this task and tool, regardless of digest.

        Returning the tool's approvals rather than only an exact match is what
        lets the guard tell "nobody approved this tool" apart from "someone
        approved it for different arguments" (FR-017). Those are different
        operational situations: the second is the replay signal, and an
        operator triaging needs to see it as one.

        Expiry is judged by the caller for the same reason -- an expired
        approval must report as expired, not as missing.
        """
        with self._lock:
            return tuple(
                record
                for record in self._records
                if record.task_id == task_id and record.tool_name == tool_name
            )

    def now(self) -> float:
        return self._clock()


class InMemoryApprovalStore(ApprovalStore):
    """Test and harness store. Approvals are seeded at construction only."""


class ApprovalGuard:
    """Requires a verified approval record for irreversible calls (FR-015).

    A tool with no stated irreversibility class arrives here as
    ``IRREVERSIBLE`` -- the default is set in the model, so this guard never
    has to decide what an unclassified tool meant (FR-014).
    """

    __slots__ = ("_store",)

    def __init__(self, store: ApprovalStore) -> None:
        self._store = store

    @property
    def name(self) -> str:
        return "approval"

    def check(self, context: CallContext) -> GuardResult:
        if context.tool.irreversibility is not Irreversibility.IRREVERSIBLE:
            return GuardResult.ok(f"{context.tool.irreversibility} call needs no approval")

        digest = argument_digest(context.validated_arguments)
        issued = self._store.find_for_tool(context.task.id, context.tool.name)

        if not issued:
            return GuardResult.refuse(
                RefusalReason.APPROVAL_REQUIRED,
                f"{context.tool.name!r} is irreversible and no approval record exists "
                f"for task {context.task.id!r}",
            )

        matching = [
            record
            for record in issued
            if record.matches(context.task.id, context.tool.name, digest)
        ]
        if not matching:
            # An approval exists for this tool, but for different arguments.
            # Approving the deletion of ticket 42 does not approve deleting
            # ticket 43; without the digest binding those are one authorisation.
            return GuardResult.refuse(
                RefusalReason.APPROVAL_MISMATCH,
                f"{len(issued)} approval(s) exist for {context.tool.name!r} on task "
                f"{context.task.id!r}, none for these arguments (digest {digest[:12]})",
            )

        now = self._store.now()
        live = [record for record in matching if record.expires_at > now]
        if not live:
            latest = max(matching, key=lambda record: record.expires_at)
            return GuardResult.refuse(
                RefusalReason.APPROVAL_EXPIRED,
                f"approval by {latest.granted_by!r} for {context.tool.name!r} expired "
                f"{now - latest.expires_at:.1f}s ago",
            )

        return GuardResult.ok(f"approved by {live[0].granted_by!r}")

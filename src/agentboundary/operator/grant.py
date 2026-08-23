"""``agent-boundary lease grant`` -- the only code that writes a lease.

This module holds the project's single lease-store write path, and it lives
here rather than on :class:`~agentboundary.leases.LeaseStore` for the reason
that class states: if the store could mint a lease, anything holding a
reference to it -- including code reachable from a steered agent loop -- could
mint one too. The broker process never imports this module. That is asserted
from outside, in ``tests/e2e/test_operator_interface.py``, by starting a real
serving subprocess and looking at its ``sys.modules``.

**One invocation, one lease.** :func:`run_grant` takes a single ``subject: str``
and returns a single :class:`~agentboundary.leases.Lease`. There is no
sequence, no iterable, and no parameter that could hold two subjects; the
command line that reaches it has no repeatable option and no option that reads
subjects from a file. Bulk approval is therefore not something this command
declines to do -- it is something it has no type to express. The parser's own
shape is asserted in ``tests/unit/test_operator_cli.py``.

**Nothing is selected.** The subject arrives from ``argv`` and from nowhere
else. This module does not import :mod:`agentboundary.ledger`, so a refusal
record is not a value it can hold, let alone one it can be indexed by.

**Write, then verify.** The store is read before the append and re-read after
it. A malformed store makes the broker fail closed on *every* call, which an
operator reads as "my lease was too narrow" and answers by granting a wider
one. Appending to a store that is already unreadable would manufacture exactly
that, so it is refused instead.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Final, TextIO

from agentboundary.leases import FileLeaseStore, Lease, LeaseError, LeaseKind, Sensitivity
from agentboundary.rotation import UNKNOWABLE, advice_for

__all__ = ["append_lease", "run_grant"]

_DAY_S: Final[float] = 86_400.0


def append_lease(store_path: Path, lease: Lease) -> None:
    """Append one lease to the store on disk. The only write in the project.

    ``O_APPEND`` places every write at the current end of file, so this handle
    cannot seek back over an existing grant: the store gains lines and never
    loses them, and revocation is an operator deleting a line with their own
    editor rather than a code path anything here can call.

    ``0o600`` because a lease names a path or a host an agent was allowed to
    reach, which is reconnaissance if it is world-readable.
    """
    if not store_path.is_absolute():
        msg = (
            f"lease store path {str(store_path)!r} is relative. It would resolve against "
            f"the working directory, which says nothing about whether the agent can reach "
            f"it -- and a lease store the agent can write is not a boundary."
        )
        raise LeaseError(msg)

    payload = (json.dumps(lease.to_json(), ensure_ascii=False, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    store_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(store_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def run_grant(
    store_path: Path,
    stream: TextIO,
    *,
    kind: str,
    subject: str,
    duration_s: float,
    granted_by: str,
    reason: str,
    now: float,
    sensitivity: str | None = None,
    task_id: str | None = None,
) -> int:
    """Create exactly one lease and report what it costs. Returns an exit code.

    Every rule about what a lease may be belongs to
    :class:`~agentboundary.leases.Lease` and is enforced by constructing one:
    the required reason, the required grantee, the strictly positive window, the
    per-class cap, the absolute and non-root path subject, the normalisation
    that matches the guard which will consult it. Nothing is re-checked here,
    because a second copy of a rule is a rule with two answers.

    ``sensitivity`` of ``None`` is passed through as an omission rather than as
    the string ``"credential"``, so the unsafe-by-default classification stays
    where FR-014 put it -- in the type -- and cannot drift out of step with it.
    """
    if not store_path.is_absolute():
        # Reported here rather than left to `FileLeaseStore` to raise, because
        # an operator who mistypes a store path should read a sentence, not a
        # traceback -- and the sentence is the one that explains why the rule
        # exists. The same check guards `append_lease` itself.
        print(
            f"error: lease store path {str(store_path)!r} is relative. It would resolve "
            f"against the working directory, which says nothing about whether the agent "
            f"can reach it, and a lease store the agent can write is not a boundary.",
            file=stream,
        )
        return 2

    # Omitted, not defaulted: the keyword is absent from the call when the
    # operator said nothing, so `Lease.granted` supplies the classification and
    # this module never names it. FR-014's unsafe default stays in one place.
    unstated: dict[str, Any] = {}
    try:
        if sensitivity is not None:
            unstated["sensitivity"] = Sensitivity(sensitivity)
        lease = Lease.granted(
            kind=LeaseKind(kind),
            subject=subject,
            granted_by=granted_by,
            reason=reason,
            granted_at=now,
            duration_s=duration_s,
            task_id=task_id,
            **unstated,
        )
    except (LeaseError, ValueError) as exc:
        print(f"error: {exc}", file=stream)
        return 2

    # The lease is well-formed in memory. Confirm it survives the round trip
    # through the store's own format before writing it, so a grant can never
    # produce a line the broker will later refuse to parse.
    if Lease.from_json(json.loads(json.dumps(lease.to_json()))) != lease:  # pragma: no cover
        print(
            "error: this lease does not survive its own serialisation, so writing it "
            "would leave a store the broker cannot read. Refusing.",
            file=stream,
        )
        return 2

    store = FileLeaseStore(store_path)
    try:
        existing = store.leases()
    except LeaseError as exc:
        print(
            f"error: the lease store at {store_path} cannot be read ({exc}). The broker is "
            f"failing closed on every call that consults it, which reads to an operator "
            f"like a lease that was too narrow. Fix the store before granting, or a wider "
            f"grant will be the obvious next move and it will not help.",
            file=stream,
        )
        return 2

    append_lease(store_path, lease)

    written = store.leases()
    if lease not in written:  # pragma: no cover -- defence against a silent write
        print(
            f"error: the lease was written to {store_path} but does not read back. "
            f"Treat it as not granted.",
            file=stream,
        )
        return 2

    _report(lease, stream, store_path=store_path, previously=len(existing), now=now)
    return 0


def _report(
    lease: Lease,
    stream: TextIO,
    *,
    store_path: Path,
    previously: int,
    now: float,
) -> None:
    """Say what was granted, when it ends, and what it costs while it runs."""
    scope = (
        "every task in this deployment (no --task-id given)"
        if lease.task_id is None
        else f"task {lease.task_id!r} only"
    )
    print(f"Granted 1 lease. The store now holds {previously + 1}.", file=stream)
    print(f"  kind:      {lease.kind}", file=stream)
    print(f"  subject:   {lease.subject}", file=stream)
    print(f"  applies to {scope}", file=stream)
    print(f"  class:     {lease.sensitivity}", file=stream)
    print(f"  granted by {lease.granted_by}", file=stream)
    print(f"  reason:    {lease.reason}", file=stream)
    print(
        f"  window:    {lease.duration_s / _DAY_S:.2f} days, "
        f"expiring at {lease.expires_at:.0f} "
        f"({(lease.expires_at - now) / 3600:.1f}h from now)",
        file=stream,
    )
    print(f"  store:     {store_path}", file=stream)
    print(
        f"\nWhile this lease is in force, the invariant it widens does not hold for "
        f"{lease.subject!r}. Expiry fails closed on its own; to end it sooner, delete "
        f"its line from {store_path}.",
        file=stream,
    )

    advice = advice_for(lease)
    if advice is not None:
        # Derived from the same predicate the sweep uses, rather than from a
        # second test of the sensitivity class here. If rotation.advice_for ever
        # stops owing an advisory for this lease, this message stops promising
        # one, and the two cannot disagree.
        print(
            f"\nOn expiry this lease will oblige rotation advice, unconditionally: "
            f"{advice.subject!r} will have been reachable for "
            f"{advice.window_s / _DAY_S:.2f} days. {UNKNOWABLE}",
            file=stream,
        )

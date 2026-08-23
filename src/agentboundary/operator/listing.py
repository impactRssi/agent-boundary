"""``agent-boundary lease list`` -- what is currently granted, and for how long.

An operator who cannot see what is leased cannot revoke it, and a lease nobody
can see is an unbounded one in every way that matters until it happens to
expire. So this command shows **active and expired together**, with time
remaining or time since, and it says how revocation works -- because there is no
``lease revoke`` and there is not going to be one: revocation is deleting a line
from a file the broker re-reads on every lookup, and adding a code path that
edits the store would be a second write path into the thing this design keeps to
one.

Read-only. This module imports :mod:`agentboundary.leases` and
:mod:`agentboundary.rotation` and imports neither :mod:`agentboundary.ledger`
nor :mod:`agentboundary.operator.grant`: listing cannot grant, and a listing
that could would have put every already-granted subject one keystroke from being
re-granted wider.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Final, TextIO

from agentboundary.leases import FileLeaseStore, Lease, LeaseError, describe
from agentboundary.rotation import due
from agentboundary.rotation import render as render_advice

__all__ = ["lease_state", "run_list"]

_DAY_S: Final[float] = 86_400.0

#: Printed under every listing. A lease is the one mechanism here that makes an
#: invariant hold less than it did, so the reader is told what it costs at the
#: moment they read what is in force.
NOTICE: Final[str] = (
    "While a lease is in force, the invariant it widens does not hold for its subject. "
    "Leases are granted out of band with `agent-boundary lease grant`, one at a time, "
    "with the subject typed out. There is no revoke command: delete the lease's line "
    "from the store and the next call stops seeing it."
)


def lease_state(lease: Lease, now: float) -> tuple[str, float]:
    """Return ``(state, seconds_remaining)`` for one lease at ``now``.

    The state comes from :meth:`agentboundary.leases.Lease.is_active`, the same
    half-open predicate the guards use, rather than from a comparison written
    again here. Only the wording is this module's; the boundary is not.
    ``seconds_remaining`` is negative once the window has closed, so a caller
    that formats it without reading ``state`` still cannot render an expired
    lease as having time left.
    """
    remaining = lease.expires_at - now
    if lease.is_active(now):
        return "active", remaining
    if now < lease.granted_at:
        return "pending", remaining
    return "expired", remaining


def run_list(
    store_path: Path,
    stream: TextIO,
    *,
    now: float,
    as_json: bool = False,
) -> int:
    """Print every lease the store holds, expired included. Returns an exit code.

    A store path that does not exist is an error rather than an empty list, for
    the same reason it is in ``refusals``: "nothing is granted" and "you are
    looking at the wrong file" must not print the same thing to someone deciding
    whether an agent currently has access to a credential directory.
    """
    if not store_path.exists():
        print(
            f"error: no lease store at {store_path}. Refusing to report an empty store "
            f"for a path that does not exist -- 'nothing is granted' and 'nothing was "
            f"read' are different states and must not print the same.",
            file=stream,
        )
        return 2

    store = FileLeaseStore(store_path)
    try:
        leases = store.leases()
    except LeaseError as exc:
        print(
            f"error: the lease store at {store_path} cannot be read ({exc}). Every call "
            f"that consults it is failing closed until this is fixed.",
            file=stream,
        )
        return 2

    owed = due(store, now)

    if as_json:
        payload: dict[str, Any] = {
            "notice": NOTICE,
            "now": now,
            "source": str(store_path),
            "leases": [_row(lease, now) for lease in leases],
            "rotation_owed": [advice.to_json() for advice in owed],
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), file=stream)
        return 0

    print(describe(leases, now), file=stream)
    active = sum(1 for lease in leases if lease.is_active(now))
    print(
        f"\n{len(leases)} lease(s) in the store, {active} in force at this instant.",
        file=stream,
    )
    print(f"\n{NOTICE}", file=stream)
    print(f"\nRotation owed:\n{render_advice(owed)}", file=stream)
    return 0


def _row(lease: Lease, now: float) -> dict[str, Any]:
    state, remaining = lease_state(lease, now)
    row = lease.to_json()
    row["state"] = state
    row["remaining_s"] = remaining
    row["remaining_days"] = remaining / _DAY_S
    row["digest"] = lease.digest
    return row

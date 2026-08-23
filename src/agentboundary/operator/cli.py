"""The operator command line -- argument parsing and dispatch, and nothing else.

This module holds **no domain type**. It imports neither
:mod:`agentboundary.ledger` nor :mod:`agentboundary.leases`, names neither a
:class:`~agentboundary.ledger.LedgerEntry` nor a
:class:`~agentboundary.leases.Lease`, and each command's implementation is
imported inside the branch that runs it. What crosses this module is a list of
strings from ``argv`` and an exit code back.

That is the point rather than tidiness. The failure this phase is designed
against is a refusal record becoming a grant, and the shortest route to it is a
dispatcher that has both in scope and one line joining them. Here there is
nothing to join: by the time a refusal row exists, this module has already
handed control to :mod:`agentboundary.operator.refusals`, which cannot name a
lease.

**On the enum values repeated below as literals.** ``--kind`` and
``--sensitivity`` list their choices as plain strings rather than importing
:class:`~agentboundary.leases.LeaseKind` and
:class:`~agentboundary.leases.Sensitivity`, so that keeping this module free of
domain imports costs nothing at run time. Duplication of a closed set is a drift
risk, so it is bound by test: ``tests/unit/test_operator_cli.py`` asserts these
tuples equal the enums' members, and a kind added to the type without being
offered here fails the build rather than silently becoming ungrantable.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import TextIO

from agentboundary.operator.duration import DurationError, parse_duration

__all__ = ["KINDS", "SENSITIVITIES", "build_parser", "main"]

#: Mirrors ``agentboundary.leases.LeaseKind``. Bound to it by test, not by import.
KINDS: tuple[str, ...] = ("tool", "path", "host")

#: Mirrors ``agentboundary.leases.Sensitivity``. Bound to it by test.
#:
#: There is no default here. An operator who says nothing gets the
#: classification the type applies -- ``credential``, the shortest cap and the
#: mandatory rotation advisory -- and this parser does not restate it, because a
#: default written twice is a default that eventually disagrees with itself.
SENSITIVITIES: tuple[str, ...] = ("credential", "sensitive", "routine")

_EPILOG = (
    "Granting names its subject explicitly, every time. There is no --approve-all, no "
    "--approve-from-ledger, and no way to select a subject by position in the refusal "
    "ledger: a refusal record is evidence, never a request, and it cannot distinguish a "
    "legitimate workflow from a payload that steered the agent."
)


def build_parser() -> argparse.ArgumentParser:
    """The operator command surface. Constructed here so a test can read it.

    Every option below is a single-valued ``store`` action. None repeats, none
    takes a list, none reads its value from a file, and none names a position in
    anything. ``tests/unit/test_operator_cli.py`` asserts that by introspecting
    the parser, so bulk approval is not a feature this command declines to offer
    -- it is one the parser has no shape to express.
    """
    parser = argparse.ArgumentParser(
        prog="agent-boundary",
        description="Operator interface: read refusals, grant and inspect leases.",
        epilog=_EPILOG,
    )
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    refusals = commands.add_parser(
        "refusals",
        help="Read the refusal ledger. It grants nothing and offers nothing to select.",
        description=(
            "Aggregated refusals by subject and reason. A ledger entry is evidence, not a "
            "request: it cannot tell a legitimate workflow from a payload that steered the "
            "agent, and the rows carry no identifiers because a row with a number is one "
            "keystroke from being approved in bulk."
        ),
    )
    refusals.add_argument(
        "--ledger",
        required=True,
        type=Path,
        metavar="PATH",
        help="Refusal ledger file, written by the broker outside every task's fs_root.",
    )
    refusals.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Machine-readable output. Carries the same caveat as the text form.",
    )

    lease = commands.add_parser(
        "lease",
        help="Grant one bounded lease, or list what is granted.",
        epilog=_EPILOG,
    )
    lease_commands = lease.add_subparsers(dest="lease_command", required=True, metavar="COMMAND")
    _add_grant(lease_commands)
    _add_list(lease_commands)
    return parser


def _add_grant(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    grant = commands.add_parser(
        "grant",
        help="Create exactly one lease. The subject must be typed out.",
        description=(
            "Creates one lease and appends it to the store. Subject, duration, grantee and "
            "reason are all required and none has a default. The subject is typed, never "
            "selected: this command cannot read the refusal ledger and has no option that "
            "names a row in it."
        ),
        epilog=_EPILOG,
    )
    grant.add_argument(
        "--store",
        required=True,
        type=Path,
        metavar="PATH",
        help="Lease store file. Absolute, and outside every task's fs_root.",
    )
    grant.add_argument(
        "--kind",
        required=True,
        choices=KINDS,
        help="Which surface the lease widens.",
    )
    grant.add_argument(
        "--subject",
        required=True,
        metavar="SUBJECT",
        help=(
            "The tool name, absolute path, or host this lease covers. One subject, typed "
            "out. Repeating this option does not accumulate; run the command again."
        ),
    )
    grant.add_argument(
        "--duration",
        required=True,
        metavar="DURATION",
        help="How long, as 3d, 12h, 90m or 30s. The maximum depends on --sensitivity.",
    )
    grant.add_argument(
        "--granted-by",
        required=True,
        metavar="WHO",
        help="Who is granting it. An unattributable widening is not auditable.",
    )
    grant.add_argument(
        "--reason",
        required=True,
        metavar="TEXT",
        help=(
            "Why. Required, with no default: without one a reviewer cannot tell a "
            "deliberate widening from a mistake."
        ),
    )
    grant.add_argument(
        "--sensitivity",
        choices=SENSITIVITIES,
        default=None,
        help=(
            "Classification. Omit it and the lease is treated as credential-class -- the "
            "shortest window and a mandatory rotation advisory on expiry. Saying it is "
            "less sensitive is an explicit act with your name on it."
        ),
    )
    grant.add_argument(
        "--task-id",
        default=None,
        metavar="ID",
        help=(
            "Narrow the lease to one task. Omit it and the lease applies to every task in "
            "the deployment, which is the widest thing a lease can express."
        ),
    )


def _add_list(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    listing = commands.add_parser(
        "list",
        help="Show every lease, active and expired, with time remaining.",
        description=(
            "Active and expired together. An operator who cannot see what is granted "
            "cannot revoke it, and revocation is deleting the lease's line from the store "
            "-- there is no revoke command, because a second write path into the store is "
            "the thing this design keeps to one."
        ),
    )
    listing.add_argument(
        "--store",
        required=True,
        type=Path,
        metavar="PATH",
        help="Lease store file.",
    )
    listing.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Machine-readable output.",
    )


def main(
    argv: list[str] | None = None,
    stream: TextIO | None = None,
    now: float | None = None,
) -> int:
    """Parse and dispatch. Returns a process exit code; raises nothing routine.

    ``now`` is injectable so that a grant's window is deterministic under test.
    It is read once per invocation, so a lease's ``granted_at`` and the
    "remaining" figure printed beside it cannot come from two different instants.
    """
    arguments = build_parser().parse_args(argv)
    out = sys.stdout if stream is None else stream
    instant = time.time() if now is None else now

    if arguments.command == "refusals":
        # Imported here, not at module scope. This branch is the only place in
        # the program where a refusal record exists, and it cannot name a lease.
        from agentboundary.operator.refusals import run_refusals

        return run_refusals(arguments.ledger, out, as_json=arguments.as_json)

    if arguments.lease_command == "grant":
        try:
            duration_s = parse_duration(arguments.duration)
        except DurationError as exc:
            print(f"error: {exc}", file=out)
            return 2

        from agentboundary.operator.grant import run_grant

        return run_grant(
            arguments.store,
            out,
            kind=arguments.kind,
            subject=arguments.subject,
            duration_s=duration_s,
            granted_by=arguments.granted_by,
            reason=arguments.reason,
            now=instant,
            sensitivity=arguments.sensitivity,
            task_id=arguments.task_id,
        )

    from agentboundary.operator.listing import run_list

    return run_list(arguments.store, out, now=instant, as_json=arguments.as_json)


if __name__ == "__main__":  # pragma: no cover -- process entry point
    raise SystemExit(main())

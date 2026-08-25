"""``python -m agentboundary.runner`` -- start a session with no native tools.

The entry point an operator actually runs, and the one ``N-52`` drives for its
brokered arm. It spawns ``python -m agentboundary`` as the session's only MCP
server, reads that server's own tool listing over a real transport, and builds
a session whose surface is exactly that listing and nothing else.

``--dry-run`` is the important flag and costs nothing. It performs the spawn,
the handshake and the listing -- everything except the model call -- and prints
the resolved surface. Run it before a session that costs money, for the same
reason ``python -m agentboundary --dry-run`` exists: the scope you meant and
the scope you wrote are not always the same, and this is the cheapest place to
find that out.

The task file is still the security configuration. This program adds no scope
and cannot: it passes ``--task`` through to the broker unchanged and then asks
the broker what that produced.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from agentboundary.runner.discovery import discover_session
from agentboundary.runner.session import SessionSpec

__all__ = ["broker_argv", "main", "resolve_session"]

#: The name the session knows the broker by. It becomes the ``mcp__<name>__``
#: prefix on every tool the session can see, so it is fixed here rather than
#: made configurable: a per-run name would put the one string the surface check
#: depends on into an operator's hands.
SERVER_NAME = "agentboundary"


def broker_argv(
    task: Path,
    audit: Path,
    tickets: Path | None = None,
    approvals: Path | None = None,
    refusals: Path | None = None,
    leases: Path | None = None,
) -> tuple[str, ...]:
    """The argument vector for the brokered server this session will spawn.

    Built here rather than accepted from the caller so that the session and the
    dry run cannot disagree about which broker was inspected.
    """
    args: list[str] = ["-m", "agentboundary", "--task", str(task), "--audit", str(audit)]
    for flag, value in (
        ("--tickets", tickets),
        ("--approvals", approvals),
        ("--refusals", refusals),
        ("--leases", leases),
    ):
        if value is not None:
            args += [flag, str(value)]
    return tuple(args)


async def resolve_session(args: argparse.Namespace) -> SessionSpec:
    """Spawn the broker, read what it serves, and build the session from that."""
    return await discover_session(
        server_name=SERVER_NAME,
        command=sys.executable,
        args=broker_argv(
            task=args.task,
            audit=args.audit,
            tickets=args.tickets,
            approvals=args.approvals,
            refusals=args.refusals,
            leases=args.leases,
        ),
        cwd=args.cwd,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m agentboundary.runner",
        description=(
            "Start an agent session whose only tools are the broker's. No native "
            "filesystem, shell or fetch handle exists in the session to be named."
        ),
        epilog=(
            "--dry-run resolves and prints the session's whole tool surface without "
            "calling a model. It is offline and free; run it after every task edit."
        ),
    )
    parser.add_argument("--task", required=True, type=Path, help="Task definition JSON.")
    parser.add_argument(
        "--audit",
        type=Path,
        default=Path(".audit/trace.jsonl"),
        help="Append-only audit trace the broker writes. Keep it outside fs_root.",
    )
    parser.add_argument("--tickets", type=Path, help="JSON file backing the ticketing tools.")
    parser.add_argument("--approvals", type=Path, help="Out-of-band approval records JSON.")
    parser.add_argument("--refusals", type=Path, help="Refusal ledger to append to.")
    parser.add_argument("--leases", type=Path, help="Lease store to consult, read-only.")
    parser.add_argument("--cwd", type=Path, help="Working directory for the session.")
    parser.add_argument(
        "--prompt",
        help="The task to give the agent. Required unless --dry-run is passed.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Resolve and print the session's tool surface, then exit. Calls no model.",
    )
    return parser


async def _run(spec: SessionSpec, prompt: str) -> int:
    # Imported here, not at module scope, so a dry run never pulls the agent
    # SDK into the process at all -- the same reasoning the serving entry point
    # applies to the lease-store write path.
    from agentboundary.runner.claude import run_session

    async for message in run_session(spec, prompt):
        print(message, file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(sys.argv[1:] if argv is None else argv)

    spec = asyncio.run(resolve_session(args))

    # stderr throughout: stdout belongs to whatever consumes this program's
    # output, and a configuration banner on it is a banner in someone's data.
    print(spec.render(), file=sys.stderr)

    if args.dry_run:
        return 0
    if not args.prompt:
        # Fail closed rather than starting a session with an empty prompt and
        # billing for it.
        print(
            "refusing to start: --prompt is required unless --dry-run is passed.",
            file=sys.stderr,
        )
        return 2
    return asyncio.run(_run(spec, args.prompt))


if __name__ == "__main__":  # pragma: no cover -- process entry point
    raise SystemExit(main())

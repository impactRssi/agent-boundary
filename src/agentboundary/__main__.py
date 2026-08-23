"""``python -m agentboundary`` -- serve a brokered tool set over MCP stdio.

The drop-in entry point. An operator writes a task file and points their agent
runtime at this module. The task file **is** the security configuration -- tool
scope, filesystem root, egress allowlist, caps -- which is why it is a reviewed
artifact on disk rather than a set of command-line flags someone can improvise.

The same executable also carries the operator commands (``refusals``,
``lease grant``, ``lease list``), and the way it carries them is load-bearing.
:mod:`agentboundary.operator` is imported **inside** the dispatch branch that
needs it, never at module scope, because that package holds the project's only
lease-store write path. A serving process therefore never has that code in its
image at all: not a function it declines to call, but a module it never
imported. ``tests/e2e/test_operator_interface.py`` asserts it from outside, by
reading ``sys.modules`` in a real serving subprocess.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from agentboundary.approval import ApprovalRecord, ApprovalStore
from agentboundary.audit import FileAuditSink
from agentboundary.confinement import assert_out_of_reach
from agentboundary.handlers import (
    filesystem_handlers,
    http_handlers,
    json_file_ticket_handlers,
)
from agentboundary.leases import FileLeaseStore, leased_task
from agentboundary.ledger import FileRefusalLedger
from agentboundary.mcp.server import BrokeredServer, ToolHandler, build_server
from agentboundary.model import Caps, Task
from agentboundary.rotation import FileAdvisorySink
from agentboundary.testing.catalogue import reference_registry

__all__ = [
    "OPERATOR_COMMANDS",
    "build_from_config",
    "load_approvals",
    "load_task",
    "main",
    "serve",
]

#: The first token that routes to :mod:`agentboundary.operator` instead of to
#: the server. Anything else is a serve invocation, so the pre-existing
#: ``--task ...`` form keeps working unchanged.
OPERATOR_COMMANDS: frozenset[str] = frozenset({"lease", "refusals"})


def load_task(path: Path) -> Task:
    """Read a task definition. Every omission fails closed.

    A missing ``egress_allowlist`` means no egress, not unrestricted egress. A
    missing cap is an error rather than a generous default: an operator who
    forgot to set a limit has not decided that there should be none.
    """
    payload: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    try:
        caps = payload["caps"]
        return Task(
            id=str(payload["id"]),
            tool_scope=frozenset(payload["tool_scope"]),
            fs_root=payload.get("fs_root"),
            egress_allowlist=frozenset(payload.get("egress_allowlist", [])),
            caps=Caps(
                max_calls=int(caps["max_calls"]),
                max_cost=float(caps["max_cost"]),
                max_wall_clock_s=float(caps["max_wall_clock_s"]),
            ),
        )
    except KeyError as exc:
        msg = (
            f"task file {path} is missing required field {exc.args[0]!r}. "
            f"Refusing to start rather than defaulting it -- an omitted limit is "
            f"not a decision that there should be no limit."
        )
        raise SystemExit(msg) from exc


def load_approvals(path: Path | None) -> ApprovalStore:
    """Read out-of-band approvals.

    Read-only, and read from a path the agent has no way to reach: the task's
    ``fs_root`` confines every filesystem tool, and this file lives outside it.
    An approval store the agent could write to would not be out of band.
    """
    if path is None:
        return ApprovalStore()
    entries: list[dict[str, Any]] = json.loads(path.read_text(encoding="utf-8"))
    return ApprovalStore(
        ApprovalRecord(
            task_id=str(entry["task_id"]),
            tool_name=str(entry["tool_name"]),
            arg_digest=str(entry["arg_digest"]),
            granted_by=str(entry["granted_by"]),
            expires_at=float(entry["expires_at"]),
        )
        for entry in entries
    )


def build_from_config(
    task: Task,
    approvals: ApprovalStore,
    audit_path: Path,
    tickets_path: Path | None,
    *,
    refusals_path: Path | None = None,
    leases_path: Path | None = None,
    advisories_path: Path | None = None,
) -> BrokeredServer:
    """Assemble a server carrying only the handlers the task actually scopes.

    The three optional stores are all read-only from here, and that is the point
    of wiring them in this direction. :class:`~agentboundary.leases.FileLeaseStore`
    has no write method, so a running server can consult a lease an operator
    granted but can never add one; the refusal ledger is append-only through a
    descriptor opened ``O_APPEND``; the advisory sink likewise.
    :func:`~agentboundary.mcp.server.build_server` refuses at construction if any
    of them resolves inside the task's ``fs_root``; the lease store is checked
    here as well, because this function reads it before that call and a store the
    agent can write must not be read at all.
    """
    leases = None
    if leases_path is not None:
        assert_out_of_reach(leases_path, task.fs_root, "lease store")
        leases = FileLeaseStore(leases_path)

    available: dict[str, ToolHandler] = {}
    if task.fs_root is not None:
        available.update(filesystem_handlers(Path(task.fs_root)))
    available.update(http_handlers())
    if tickets_path is not None:
        available.update(json_file_ticket_handlers(tickets_path))

    # Handlers are selected against the **leased** scope, because a tool lease
    # widens the scope inside `build_server` and a scoped tool with no handler
    # fails construction. Without this the entry point would refuse to start
    # with "scopes fs.write but has no handler" -- naming a tool the operator
    # had just granted, which reads as a broker fault rather than as the
    # deployment lacking a handler for it.
    #
    # `build_server` applies the lease itself, so the task handed down is the
    # unwidened one and I1 stays a property of task construction. If a lease
    # lapses between the two reads the second is narrower, which leaves an
    # unreachable handler in the mapping and nothing wider than the broker's own
    # scope: fail-closed in the only direction that can differ.
    served = leased_task(task, leases)

    missing = sorted(served.tool_scope - set(available))
    if missing:
        msg = (
            f"task {task.id!r} scopes {', '.join(missing)} but this entry point has no "
            f"handler for them. Supply --tickets, set fs_root, narrow the scope, or -- if "
            f"one of these came from a tool lease -- register a handler for it, because a "
            f"lease cannot conjure a capability the deployment never implemented."
        )
        raise SystemExit(msg)

    return build_server(
        task,
        reference_registry(),
        {name: available[name] for name in served.tool_scope},
        approvals=approvals,
        audit=FileAuditSink(audit_path),
        refusals=None if refusals_path is None else FileRefusalLedger(refusals_path),
        leases=leases,
        advisories=None if advisories_path is None else FileAdvisorySink(advisories_path),
    )


def main(argv: list[str] | None = None) -> int:
    """Route to the operator commands or to the server. One executable, two programs.

    The routing is a prefix test on the first token rather than a top-level
    subparser, so that ``--task ...`` -- the form every existing deployment and
    every runtime configuration already uses -- keeps working with no ``serve``
    word in front of it.
    """
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] in OPERATOR_COMMANDS:
        # The lease-store write path enters the process here and only here. A
        # serving invocation never reaches this line, so the module that can
        # write a lease is absent from its image rather than merely unused.
        from agentboundary.operator.cli import main as operator_main

        return operator_main(arguments)
    return serve(arguments)


def serve(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m agentboundary",
        description="Serve a brokered tool set over MCP stdio.",
        epilog=(
            "Operator commands live on the same executable: `agent-boundary refusals`, "
            "`agent-boundary lease grant`, `agent-boundary lease list`. They run out of "
            "band, in their own process; this one has no write path to a lease store."
        ),
    )
    parser.add_argument("--task", required=True, type=Path, help="Task definition JSON.")
    parser.add_argument("--approvals", type=Path, help="Out-of-band approval records JSON.")
    parser.add_argument(
        "--audit",
        type=Path,
        default=Path(".audit/trace.jsonl"),
        help="Append-only audit trace destination.",
    )
    parser.add_argument("--tickets", type=Path, help="JSON file backing the ticketing tools.")
    parser.add_argument(
        "--refusals",
        type=Path,
        help="Refusal ledger to append to. Read with `agent-boundary refusals`.",
    )
    parser.add_argument(
        "--leases",
        type=Path,
        help=(
            "Lease store to consult. Read-only from here: this process can honour a "
            "lease an operator granted and can never create one."
        ),
    )
    parser.add_argument(
        "--advisories",
        type=Path,
        help="Where rotation advice for expired credential leases is appended.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the resolved scope and exit without serving.",
    )
    arguments = parser.parse_args(argv)

    task = load_task(arguments.task)
    server = build_from_config(
        task,
        load_approvals(arguments.approvals),
        arguments.audit,
        arguments.tickets,
        refusals_path=arguments.refusals,
        leases_path=arguments.leases,
        advisories_path=arguments.advisories,
    )

    # stderr, because stdout is the MCP transport.
    #
    # The scope reported is the *served* one, read back off the assembled
    # server, not the one the task file asked for. A tool lease widens the scope
    # at construction, so printing the file's version would tell an operator the
    # agent holds fewer handles than it does -- and the reason to print this at
    # all is to be able to check that.
    print(f"agent-boundary: task {task.id!r}", file=sys.stderr)
    print(
        f"  scope:   {', '.join(sorted(server.task.tool_scope)) or '(nothing)'}",
        file=sys.stderr,
    )
    print(f"  fs_root: {task.fs_root or '(none: path arguments refuse)'}", file=sys.stderr)
    print(
        f"  egress:  {', '.join(sorted(task.egress_allowlist)) or '(none: egress denied)'}",
        file=sys.stderr,
    )
    print(
        f"  caps:    {task.caps.max_calls} calls, {task.caps.max_cost} cost, "
        f"{task.caps.max_wall_clock_s}s",
        file=sys.stderr,
    )
    print(f"  audit:   {arguments.audit}", file=sys.stderr)
    print(
        f"  leases:  {arguments.leases or '(none: nothing is widened)'} (read-only here)",
        file=sys.stderr,
    )
    print(
        f"  refusals:{arguments.refusals or ' (none: refusals are not aggregated)'}",
        file=sys.stderr,
    )

    if arguments.dry_run:
        return 0

    from agentboundary.mcp.stdio import run_stdio

    asyncio.run(run_stdio(server))
    return 0


if __name__ == "__main__":  # pragma: no cover -- process entry point
    raise SystemExit(main())

"""``python -m agentboundary`` -- serve a brokered tool set over MCP stdio.

The drop-in entry point. An operator writes a task file and points their agent
runtime at this module. The task file **is** the security configuration -- tool
scope, filesystem root, egress allowlist, caps -- which is why it is a reviewed
artifact on disk rather than a set of command-line flags someone can improvise.
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
from agentboundary.handlers import (
    filesystem_handlers,
    http_handlers,
    json_file_ticket_handlers,
)
from agentboundary.mcp.server import BrokeredServer, ToolHandler, build_broker
from agentboundary.model import Caps, Task
from agentboundary.testing.catalogue import reference_registry

__all__ = ["build_from_config", "load_approvals", "load_task", "main"]


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
) -> BrokeredServer:
    """Assemble a server carrying only the handlers the task actually scopes."""
    available: dict[str, ToolHandler] = {}
    if task.fs_root is not None:
        available.update(filesystem_handlers(Path(task.fs_root)))
    available.update(http_handlers())
    if tickets_path is not None:
        available.update(json_file_ticket_handlers(tickets_path))

    missing = sorted(task.tool_scope - set(available))
    if missing:
        msg = (
            f"task {task.id!r} scopes {', '.join(missing)} but this entry point has no "
            f"handler for them. Supply --tickets, set fs_root, or narrow the scope."
        )
        raise SystemExit(msg)

    return BrokeredServer(
        build_broker(task, reference_registry(), approvals),
        {name: available[name] for name in task.tool_scope},
        FileAuditSink(audit_path),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m agentboundary",
        description="Serve a brokered tool set over MCP stdio.",
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
        "--dry-run",
        action="store_true",
        help="Print the resolved scope and exit without serving.",
    )
    arguments = parser.parse_args(argv)

    task = load_task(arguments.task)
    server = build_from_config(
        task, load_approvals(arguments.approvals), arguments.audit, arguments.tickets
    )

    # stderr, because stdout is the MCP transport.
    print(f"agent-boundary: task {task.id!r}", file=sys.stderr)
    print(f"  scope:   {', '.join(sorted(task.tool_scope)) or '(nothing)'}", file=sys.stderr)
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

    if arguments.dry_run:
        return 0

    from agentboundary.mcp.stdio import run_stdio

    asyncio.run(run_stdio(server))
    return 0


if __name__ == "__main__":  # pragma: no cover -- process entry point
    raise SystemExit(main())

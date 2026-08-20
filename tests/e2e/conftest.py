"""E2E fixtures. Real handlers on throwaway files, no mocks at the boundary."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any, Protocol

import pytest

from agentboundary.approval import ApprovalStore
from agentboundary.audit import MemoryAuditSink
from agentboundary.mcp.server import BrokeredServer, ToolHandler, build_broker
from agentboundary.model import Caps, Task
from agentboundary.testing.catalogue import reference_registry

CAPS = Caps(max_calls=10, max_cost=10.0, max_wall_clock_s=30.0)


class ServerFactory(Protocol):
    """Builds a brokered server for one task shape. Typed so the E2E tier is
    checked as strictly as the package it exercises."""

    def __call__(
        self,
        scope: set[str],
        egress: set[str] | None = ...,
        caps: Caps = ...,
        approvals: ApprovalStore | None = ...,
        audit: MemoryAuditSink | None = ...,
    ) -> BrokeredServer: ...


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "runbook.md").write_text("# Runbook\nReset the password.\n", encoding="utf-8")
    # A file that exists but sits outside the root, so an escape would be
    # observably successful rather than merely failing on a missing file.
    (tmp_path / "secrets.txt").write_text("AWS_SECRET=AKIAEXAMPLE", encoding="utf-8")
    return root


@pytest.fixture
def handlers(workspace: Path) -> dict[str, ToolHandler]:
    def fs_read(arguments: Mapping[str, Any]) -> str:
        return (workspace / str(arguments["path"])).read_text(encoding="utf-8")

    def fs_write(arguments: Mapping[str, Any]) -> str:
        target = workspace / str(arguments["path"])
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(str(arguments["content"]), encoding="utf-8")
        return f"wrote {target.name}"

    def tickets_get(arguments: Mapping[str, Any]) -> str:
        return f'{{"id": {arguments["ticket_id"]}, "body": "see attached"}}'

    def tickets_list(arguments: Mapping[str, Any]) -> str:
        del arguments
        return '[{"id": 4821}]'

    def tickets_comment(arguments: Mapping[str, Any]) -> str:
        return f"commented on {arguments['ticket_id']}"

    def tickets_delete(arguments: Mapping[str, Any]) -> str:
        return f"deleted {arguments['ticket_id']}"

    def http_get(arguments: Mapping[str, Any]) -> str:
        return f"body of {arguments['url']}"

    def http_post(arguments: Mapping[str, Any]) -> str:
        return f"posted to {arguments['url']}"

    return {
        "fs.read": fs_read,
        "fs.write": fs_write,
        "tickets.get": tickets_get,
        "tickets.list": tickets_list,
        "tickets.comment": tickets_comment,
        "tickets.delete": tickets_delete,
        "http.get": http_get,
        "http.post": http_post,
    }


@pytest.fixture
def make_server(handlers: dict[str, ToolHandler], workspace: Path) -> ServerFactory:
    def factory(
        scope: set[str],
        egress: set[str] | None = None,
        caps: Caps = CAPS,
        approvals: ApprovalStore | None = None,
        audit: MemoryAuditSink | None = None,
    ) -> BrokeredServer:
        task = Task(
            id="e2e-task",
            tool_scope=frozenset(scope),
            fs_root=str(workspace),
            egress_allowlist=frozenset(egress or set()),
            caps=caps,
        )
        return BrokeredServer(
            build_broker(task, reference_registry(), approvals),
            {name: handlers[name] for name in scope},
            audit if audit is not None else MemoryAuditSink(),
        )

    return factory

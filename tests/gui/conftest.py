"""GUI fixtures: a real viewer process, a real browser, a real trace.

The trace is produced by driving the actual broker, not by hand-writing JSON.
A GUI test against fabricated records would pass even if the broker stopped
recording refusals, which is one of the things the viewer exists to show.

The leases (N-45) are produced the same way: written by the real
``agent-boundary lease grant``, read back through the real
:class:`~agentboundary.leases.FileLeaseStore`. A page showing hand-built lease
objects would keep passing after the grant command stopped producing anything
the store could read, and the operator would find that out during an incident.

The clock is pinned. "1.98 days remaining" against the wall clock is a flake
waiting for a slow CI runner; pinned, the figure on the page is the figure the
assertion names.
"""

from __future__ import annotations

import io
import threading
from collections.abc import Iterator
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest
from playwright.sync_api import Page

from agentboundary.approval import ApprovalRecord, InMemoryApprovalStore, argument_digest
from agentboundary.audit import AuditRecord, MemoryAuditSink
from agentboundary.leases import FileLeaseStore, Lease
from agentboundary.mcp.server import BrokeredServer, build_broker
from agentboundary.model import Caps, Task
from agentboundary.operator.cli import main as operator_main
from agentboundary.rotation import RotationAdvice, due
from agentboundary.testing.catalogue import reference_registry
from agentboundary.viewer.server import ViewerHandler

#: The instant the page is rendered at. Every duration on screen is measured
#: from here, so the assertions can name exact figures.
VIEWER_NOW = 1_700_000_000.0
DAY = 86_400.0


@pytest.fixture(scope="session")
def trace_records(tmp_path_factory: pytest.TempPathFactory) -> tuple[AuditRecord, ...]:
    """Drive the real broker through a mixed run and return what it recorded."""
    workspace = tmp_path_factory.mktemp("workspace")
    (workspace / "runbook.md").write_text("# Runbook\n", encoding="utf-8")
    (workspace.parent / "secret.txt").write_text("AKIAEXAMPLE", encoding="utf-8")

    approved = {"ticket_id": 4821, "body": "Password reset, please retry."}
    approvals = InMemoryApprovalStore(
        [
            ApprovalRecord(
                task_id="gui-demo",
                tool_name="tickets.comment",
                arg_digest=argument_digest(approved),
                granted_by="operator@example.test",
                expires_at=9_999_999_999.0,
            )
        ]
    )
    task = Task(
        id="gui-demo",
        tool_scope=frozenset({"fs.read", "tickets.comment"}),
        fs_root=str(workspace),
        egress_allowlist=frozenset(),
        # Two calls, so the sixth attempt below lands past the cap and the
        # viewer has a budget_exhausted state to render.
        caps=Caps(max_calls=2, max_cost=99.0, max_wall_clock_s=60.0),
    )
    audit = MemoryAuditSink()
    server = BrokeredServer(
        build_broker(task, reference_registry(), approvals),
        {
            "fs.read": lambda arguments: (workspace / str(arguments["path"])).read_text(
                encoding="utf-8"
            ),
            "tickets.comment": lambda arguments: f"commented {arguments['ticket_id']}",
        },
        audit,
    )

    server.call_tool("fs.read", {"path": "runbook.md"})  # authorised
    server.call_tool("fs.read", {"path": "../secret.txt"})  # path escape
    server.call_tool("tickets.delete", {"ticket_id": 4821})  # out of scope
    server.call_tool("tickets.comment", {"ticket_id": 4821, "body": "leak"})  # unapproved
    server.call_tool("tickets.comment", approved)  # approved
    server.call_tool("fs.read", {"path": "runbook.md"})  # over the cap
    return audit.records()


@pytest.fixture(scope="session")
def granted_leases(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[tuple[Lease, ...], tuple[RotationAdvice, ...]]:
    """Grant through the real command, read back through the real store.

    Three leases, chosen so the page has one of each state to render: one in
    force, one already expired (which therefore owes rotation advice), and one
    downgraded out of the credential class so that "rotation owed" is a count of
    something and not of everything.
    """
    store: Path = tmp_path_factory.mktemp("leases") / "leases.jsonl"
    secrets = tmp_path_factory.mktemp("srv") / "secrets"
    secrets.mkdir()
    archive = secrets.parent / "archive"
    archive.mkdir()

    _grant(store, secrets, duration="3d", now=VIEWER_NOW - DAY)
    _grant(store, archive, duration="1h", now=VIEWER_NOW - 2 * DAY)
    _grant(
        store,
        secrets.parent / "public",
        duration="2d",
        now=VIEWER_NOW - 3 * DAY,
        sensitivity="routine",
    )

    read = FileLeaseStore(store)
    return read.leases(), due(read, VIEWER_NOW)


def _grant(
    store: Path,
    subject: Path,
    *,
    duration: str,
    now: float,
    sensitivity: str | None = None,
) -> None:
    argv = [
        "lease",
        "grant",
        "--store",
        str(store),
        "--kind",
        "path",
        "--subject",
        str(subject),
        "--duration",
        duration,
        "--granted-by",
        "operator@example.test",
        "--reason",
        "the nightly automation reads this directory",
    ]
    if sensitivity is not None:
        argv += ["--sensitivity", sensitivity]
    stream = io.StringIO()
    assert operator_main(argv, stream, now) == 0, stream.getvalue()


@pytest.fixture(scope="session")
def viewer_url(
    trace_records: tuple[AuditRecord, ...],
    granted_leases: tuple[tuple[Lease, ...], tuple[RotationAdvice, ...]],
) -> Iterator[str]:
    leases, advisories = granted_leases
    handler = type(
        "BoundHandler",
        (ViewerHandler,),
        {
            "records": trace_records,
            "leases": leases,
            "advisories": advisories,
            "pinned_now": VIEWER_NOW,
        },
    )
    with ThreadingHTTPServer(("127.0.0.1", 0), handler) as httpd:
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{httpd.server_address[1]}/"
        finally:
            httpd.shutdown()
            thread.join(timeout=5)


@pytest.fixture
def viewer(page: Page, viewer_url: str) -> Page:
    """A loaded viewer page. Waits for the fetch to settle, never a bare sleep."""
    page.goto(viewer_url)
    page.wait_for_selector("body[data-loaded='true']")
    return page

"""Capture the audit-trace viewer as a still image -- node N-33.

The point of the image is that refusals are visible *as refusals*, with the
reason the broker recorded. So the trace behind it is produced by driving the
real broker over a mixed run, exactly as ``tests/gui/conftest.py`` does, rather
than by hand-writing JSON: a screenshot built from fabricated records would
look identical whether or not the broker still records refusals.

The run is the same six calls the GUI tier asserts on -- an authorised read, a
path escape, an out-of-scope tool, an unapproved irreversible call, the same
call once approved, and one call past the cap. Nothing in it comes from real
traffic; it is a scripted demonstration, not a measurement.

Regenerate with:

    TMPDIR=/tmp uv run --group gui python scripts/capture_viewer.py

Requires the ``gui`` dependency group and ``uv run playwright install chromium``.
``TMPDIR`` is not required; it only keeps the absolute paths the broker resolves
-- and therefore records, and therefore renders -- short enough to read in the
image. The default temporary directory works and produces a longer path.
"""

from __future__ import annotations

import argparse
import tempfile
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
from pathlib import Path

from agentboundary.approval import ApprovalRecord, InMemoryApprovalStore, argument_digest
from agentboundary.audit import AuditRecord, MemoryAuditSink
from agentboundary.mcp.server import BrokeredServer, build_broker
from agentboundary.model import Caps, Task
from agentboundary.testing.catalogue import reference_registry
from agentboundary.viewer.server import ViewerHandler

DEFAULT_OUTPUT = Path(__file__).resolve().parent.parent / "docs" / "assets" / "audit-viewer.png"


def build_trace(workspace: Path) -> tuple[AuditRecord, ...]:
    """Drive the real broker through a mixed run and return what it recorded."""
    (workspace / "runbook.md").write_text("# Runbook\n", encoding="utf-8")
    (workspace.parent / "secret.txt").write_text("AKIAEXAMPLE", encoding="utf-8")

    approved = {"ticket_id": 4821, "body": "Password reset, please retry."}
    approvals = InMemoryApprovalStore(
        [
            ApprovalRecord(
                task_id="support-triage",
                tool_name="tickets.comment",
                arg_digest=argument_digest(approved),
                granted_by="operator@example.test",
                expires_at=9_999_999_999.0,
            )
        ]
    )
    task = Task(
        id="support-triage",
        tool_scope=frozenset({"fs.read", "tickets.comment"}),
        fs_root=str(workspace),
        egress_allowlist=frozenset(),
        # Two calls, so the sixth attempt below lands past the cap and the
        # capture shows a budget_exhausted refusal.
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


@contextmanager
def serve(records: Sequence[AuditRecord]) -> Iterator[str]:
    """Serve the trace on an ephemeral localhost port for the duration."""
    handler = type("BoundHandler", (ViewerHandler,), {"records": tuple(records)})
    with ThreadingHTTPServer(("127.0.0.1", 0), handler) as httpd:
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{httpd.server_address[1]}/"
        finally:
            httpd.shutdown()
            thread.join(timeout=5)


def capture(url: str, output: Path, width: int) -> None:
    """Screenshot the loaded viewer. Waits on the load flag, never on a sleep."""
    from playwright.sync_api import sync_playwright

    output.parent.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page(
            viewport={"width": width, "height": 900},
            device_scale_factor=2,
            # The viewer honours prefers-color-scheme; the capture pins one so
            # the committed image does not depend on the capturing machine.
            color_scheme="light",
        )
        page.goto(url)
        page.wait_for_selector("body[data-loaded='true']")
        page.screenshot(path=str(output), full_page=True)
        browser.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--width", type=int, default=1080)
    arguments = parser.parse_args()

    with tempfile.TemporaryDirectory() as root:
        workspace = Path(root) / "workspace"
        workspace.mkdir()
        records = build_trace(workspace)
        with serve(records) as url:
            capture(url, arguments.output, arguments.width)
    print(f"wrote {arguments.output} from {len(records)} audit records")


if __name__ == "__main__":
    main()

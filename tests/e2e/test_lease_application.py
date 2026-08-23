"""End-to-end: a lease moves a boundary, and only the one it names (N-43).

Assembled through ``build_server``, with real handlers on real files, because
the property under test is where the lease enters the pipeline -- tool leases at
construction, path and host leases at the argument check -- and that is a
property of the assembly, not of a guard in isolation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agentboundary.errors import TaskConstructionError
from agentboundary.leases import FileLeaseStore, Lease, LeaseKind, Sensitivity
from agentboundary.mcp.server import BrokeredServer, ToolHandler, build_server
from agentboundary.model import Caps, Task
from agentboundary.testing.catalogue import reference_registry

pytestmark = pytest.mark.e2e

DAY = 86_400.0
T0 = 1_700_000_000.0
CAPS = Caps(max_calls=10, max_cost=10.0, max_wall_clock_s=30.0)


@pytest.fixture
def leased_dir(tmp_path: Path) -> Path:
    """The credential directory an operator leases, outside every task root."""
    secrets = tmp_path / "srv" / "secrets"
    secrets.mkdir(parents=True)
    (secrets / "prod.env").write_text("DB_PASSWORD=example", encoding="utf-8")
    backup = tmp_path / "srv" / "secrets-backup"
    backup.mkdir()
    (backup / "prod.env").write_text("DB_PASSWORD=example", encoding="utf-8")
    return secrets


def _store(tmp_path: Path, *leases: Lease, now: float) -> FileLeaseStore:
    path = tmp_path / "operator" / "leases.jsonl"
    path.parent.mkdir(exist_ok=True)
    path.write_text(
        "".join(json.dumps(lease.to_json(), sort_keys=True) + "\n" for lease in leases),
        encoding="utf-8",
    )
    return FileLeaseStore(path, clock=lambda: now)


def _server(
    workspace: Path,
    handlers: dict[str, ToolHandler],
    scope: set[str],
    leases: FileLeaseStore | None,
    egress: set[str] | None = None,
) -> BrokeredServer:
    task = Task(
        id="e2e-lease",
        tool_scope=frozenset(scope),
        fs_root=str(workspace),
        egress_allowlist=frozenset(egress or set()),
        caps=CAPS,
    )
    return build_server(
        task,
        reference_registry(),
        {name: handlers[name] for name in scope},
        leases=leases,
    )


class TestAPathLeaseMovesOneBoundary:
    def test_the_sibling_directory_is_still_refused_and_still_unread(
        self, workspace: Path, handlers: dict[str, ToolHandler], leased_dir: Path, tmp_path: Path
    ) -> None:
        """The file exists, so an escape would be observably successful."""
        lease = Lease.granted(
            kind=LeaseKind.PATH,
            subject=str(leased_dir),
            granted_by="operator@example.test",
            reason="three days of access to the key directory for the rotation job",
            granted_at=T0,
            duration_s=3 * DAY,
        )
        server = _server(workspace, handlers, {"fs.read"}, _store(tmp_path, lease, now=T0 + DAY))
        outcome = server.call_tool(
            "fs.read", {"path": str(leased_dir.parent / "secrets-backup" / "prod.env")}
        )
        assert not outcome.authorised
        assert outcome.refusal_reason == "path_outside_root"
        assert outcome.envelope is None

    def test_a_traversal_out_of_the_lease_is_refused(
        self, workspace: Path, handlers: dict[str, ToolHandler], leased_dir: Path, tmp_path: Path
    ) -> None:
        lease = Lease.granted(
            kind=LeaseKind.PATH,
            subject=str(leased_dir),
            granted_by="operator@example.test",
            reason="three days of access to the key directory for the rotation job",
            granted_at=T0,
            duration_s=3 * DAY,
        )
        server = _server(workspace, handlers, {"fs.read"}, _store(tmp_path, lease, now=T0 + DAY))
        escape = str(leased_dir / ".." / "secrets-backup" / "prod.env")
        assert not server.call_tool("fs.read", {"path": escape}).authorised

    def test_the_leased_file_itself_is_read(
        self, workspace: Path, handlers: dict[str, ToolHandler], leased_dir: Path, tmp_path: Path
    ) -> None:
        """A lease that widens nothing is not a lease, and the refusals above prove nothing."""
        lease = Lease.granted(
            kind=LeaseKind.PATH,
            subject=str(leased_dir),
            granted_by="operator@example.test",
            reason="three days of access to the key directory for the rotation job",
            granted_at=T0,
            duration_s=3 * DAY,
        )
        server = _server(workspace, handlers, {"fs.read"}, _store(tmp_path, lease, now=T0 + DAY))
        outcome = server.call_tool("fs.read", {"path": str(leased_dir / "prod.env")})
        assert outcome.authorised, outcome.detail
        assert outcome.envelope is not None

    def test_after_expiry_the_same_call_is_refused(
        self, workspace: Path, handlers: dict[str, ToolHandler], leased_dir: Path, tmp_path: Path
    ) -> None:
        lease = Lease.granted(
            kind=LeaseKind.PATH,
            subject=str(leased_dir),
            granted_by="operator@example.test",
            reason="three days of access to the key directory for the rotation job",
            granted_at=T0,
            duration_s=3 * DAY,
        )
        after = _server(workspace, handlers, {"fs.read"}, _store(tmp_path, lease, now=T0 + 4 * DAY))
        outcome = after.call_tool("fs.read", {"path": str(leased_dir / "prod.env")})
        assert not outcome.authorised
        assert outcome.refusal_reason == "path_outside_root"

    def test_the_trace_names_the_lease_that_moved_the_boundary(
        self, workspace: Path, handlers: dict[str, ToolHandler], leased_dir: Path, tmp_path: Path
    ) -> None:
        """An operator reconstructing an effect has to see that a boundary moved."""
        lease = Lease.granted(
            kind=LeaseKind.PATH,
            subject=str(leased_dir),
            granted_by="operator@example.test",
            reason="three days of access to the key directory for the rotation job",
            granted_at=T0,
            duration_s=3 * DAY,
        )
        server = _server(workspace, handlers, {"fs.read"}, _store(tmp_path, lease, now=T0 + DAY))
        server.call_tool("fs.read", {"path": str(leased_dir / "prod.env")})
        record = server.audit.records()[-1]
        detail = " ".join(check.detail for check in record.checks)
        assert "under lease on" in detail
        assert "operator@example.test" in detail


class TestALeaseStoreInsideTheRootIsRefused:
    def test_the_server_will_not_start(
        self, workspace: Path, handlers: dict[str, ToolHandler]
    ) -> None:
        """An agent that can write the lease store has no boundary at all."""
        from agentboundary.confinement import StoreWithinReachError

        path = workspace / "leases.jsonl"
        path.write_text("", encoding="utf-8")
        store = FileLeaseStore(path, clock=lambda: T0)
        task = Task(
            id="e2e-lease-inside",
            tool_scope=frozenset({"fs.write"}),
            fs_root=str(workspace),
            egress_allowlist=frozenset(),
            caps=CAPS,
        )
        with pytest.raises(StoreWithinReachError, match="resolves inside fs_root"):
            build_server(
                task, reference_registry(), {"fs.write": handlers["fs.write"]}, leases=store
            )


class TestAToolLeaseResolvesAtConstruction:
    def test_a_live_tool_lease_puts_the_tool_in_the_listed_scope(
        self, workspace: Path, handlers: dict[str, ToolHandler], tmp_path: Path
    ) -> None:
        lease = Lease.granted(
            kind=LeaseKind.TOOL,
            subject="tickets.delete",
            granted_by="operator@example.test",
            reason="one-off cleanup of duplicate tickets, OPS-4900",
            granted_at=T0,
            duration_s=DAY,
            sensitivity=Sensitivity.SENSITIVE,
        )
        task = Task(
            id="e2e-lease",
            tool_scope=frozenset({"tickets.list"}),
            fs_root=str(workspace),
            egress_allowlist=frozenset(),
            caps=CAPS,
        )
        server = build_server(
            task,
            reference_registry(),
            {
                "tickets.list": handlers["tickets.list"],
                "tickets.delete": handlers["tickets.delete"],
            },
            leases=_store(tmp_path, lease, now=T0 + 1),
        )
        assert {entry["name"] for entry in server.list_tools()} == {
            "tickets.list",
            "tickets.delete",
        }
        # Widened I1; left I3 alone. The refusal moves to the approval gate.
        assert server.call_tool("tickets.delete", {"ticket_id": 1}).refusal_reason == (
            "approval_required"
        )

    def test_an_expired_tool_lease_leaves_the_tool_unlisted_and_undispatchable(
        self, workspace: Path, handlers: dict[str, ToolHandler], tmp_path: Path
    ) -> None:
        lease = Lease.granted(
            kind=LeaseKind.TOOL,
            subject="tickets.delete",
            granted_by="operator@example.test",
            reason="one-off cleanup of duplicate tickets, OPS-4900",
            granted_at=T0,
            duration_s=DAY,
        )
        server = _server(
            workspace, handlers, {"tickets.list"}, _store(tmp_path, lease, now=T0 + 10 * DAY)
        )
        assert {entry["name"] for entry in server.list_tools()} == {"tickets.list"}
        assert server.call_tool("tickets.delete", {"ticket_id": 1}).refusal_reason == (
            "tool_not_in_scope"
        )

    def test_a_lease_cannot_conjure_a_tool_the_deployment_never_registered(
        self, workspace: Path, handlers: dict[str, ToolHandler], tmp_path: Path
    ) -> None:
        lease = Lease.granted(
            kind=LeaseKind.TOOL,
            subject="prod.dropdatabase",
            granted_by="operator@example.test",
            reason="typo in a grant script",
            granted_at=T0,
            duration_s=DAY,
        )
        task = Task(
            id="e2e-lease",
            tool_scope=frozenset({"tickets.list"}),
            fs_root=str(workspace),
            egress_allowlist=frozenset(),
            caps=CAPS,
        )
        with pytest.raises(TaskConstructionError, match="unregistered tool"):
            build_server(
                task,
                reference_registry(),
                {"tickets.list": handlers["tickets.list"]},
                leases=_store(tmp_path, lease, now=T0 + 1),
            )

    def test_a_tool_lease_that_expires_mid_task_keeps_its_handle(
        self, workspace: Path, handlers: dict[str, ToolHandler], tmp_path: Path
    ) -> None:
        """The stated consequence, exercised through the assembled server.

        I1 is the property that an out-of-scope tool has no handle. Removing one
        mid-session would make it a call-time filter, which ADR-0002 rejects, so
        the lease's expiry bounds when a *new* task may hold the tool -- not when
        a running one loses it. The operator's lever is to end the task.
        """
        clock: dict[str, float] = {"now": T0 + 1}
        path = tmp_path / "operator-leases.jsonl"
        lease = Lease.granted(
            kind=LeaseKind.TOOL,
            subject="tickets.delete",
            granted_by="operator@example.test",
            reason="one-off cleanup of duplicate tickets, OPS-4900",
            granted_at=T0,
            duration_s=DAY,
        )
        path.write_text(json.dumps(lease.to_json()) + "\n", encoding="utf-8")
        store = FileLeaseStore(path, clock=lambda: clock["now"])

        task = Task(
            id="e2e-lease",
            tool_scope=frozenset({"tickets.list"}),
            fs_root=str(workspace),
            egress_allowlist=frozenset(),
            caps=CAPS,
        )
        handler_map: dict[str, Any] = {
            "tickets.list": handlers["tickets.list"],
            "tickets.delete": handlers["tickets.delete"],
        }
        server = build_server(task, reference_registry(), handler_map, leases=store)
        assert "tickets.delete" in {entry["name"] for entry in server.list_tools()}

        clock["now"] = T0 + 10 * DAY
        assert "tickets.delete" in {entry["name"] for entry in server.list_tools()}
        assert server.call_tool("tickets.delete", {"ticket_id": 1}).refusal_reason == (
            "approval_required"
        ), "the running task's dispatch table changed mid-session, which ADR-0002 rejects"

        fresh = build_server(task, reference_registry(), handler_map, leases=store)
        assert "tickets.delete" not in {entry["name"] for entry in fresh.list_tools()}


class TestAHostLeaseMovesOneBoundary:
    def _lease(self) -> Lease:
        return Lease.granted(
            kind=LeaseKind.HOST,
            subject="reports.partner.example",
            granted_by="operator@example.test",
            reason="three days to publish the quarterly export",
            granted_at=T0,
            duration_s=3 * DAY,
            sensitivity=Sensitivity.SENSITIVE,
        )

    def test_the_leased_host_is_reached_and_a_near_miss_is_not(
        self, workspace: Path, handlers: dict[str, ToolHandler], tmp_path: Path
    ) -> None:
        server = _server(
            workspace, handlers, {"http.get"}, _store(tmp_path, self._lease(), now=T0 + DAY)
        )
        assert server.call_tool(
            "http.get", {"url": "https://reports.partner.example/status"}
        ).authorised
        assert not server.call_tool(
            "http.get", {"url": "https://reports.partner.example.evil.test/status"}
        ).authorised

    def test_an_expired_host_lease_denies_egress(
        self, workspace: Path, handlers: dict[str, ToolHandler], tmp_path: Path
    ) -> None:
        server = _server(
            workspace, handlers, {"http.get"}, _store(tmp_path, self._lease(), now=T0 + 9 * DAY)
        )
        outcome = server.call_tool("http.get", {"url": "https://reports.partner.example/status"})
        assert not outcome.authorised
        assert outcome.refusal_reason == "egress_host_not_allowed"

"""End-to-end: a credential lease runs out and the rotation is owed (N-44).

The full shape of the motivating case: an operator grants three days of access
to a credential directory, an automation runs under it, the window closes, and
an advisory naming what was reachable lands in a file the agent cannot write.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentboundary.confinement import StoreWithinReachError
from agentboundary.leases import FileLeaseStore, Lease, LeaseKind, Sensitivity
from agentboundary.mcp.server import ToolHandler, build_server
from agentboundary.model import Caps, Task
from agentboundary.rotation import FileAdvisorySink, emit_due, render
from agentboundary.testing.catalogue import reference_registry

pytestmark = pytest.mark.e2e

DAY = 86_400.0
T0 = 1_700_000_000.0
CAPS = Caps(max_calls=10, max_cost=10.0, max_wall_clock_s=30.0)


@pytest.fixture
def credential_dir(tmp_path: Path) -> Path:
    secrets = tmp_path / "srv" / "secrets"
    secrets.mkdir(parents=True)
    (secrets / "prod.env").write_text("DB_PASSWORD=example", encoding="utf-8")
    return secrets


def _three_day_lease(subject: Path) -> Lease:
    return Lease.granted(
        kind=LeaseKind.PATH,
        subject=str(subject),
        granted_by="operator@example.test",
        reason="three days of access to the key directory so the rotation job can run, OPS-4821",
        granted_at=T0,
        duration_s=3 * DAY,
    )


def _lease_store(tmp_path: Path, lease: Lease, now: float) -> FileLeaseStore:
    path = tmp_path / "operator" / "leases.jsonl"
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(lease.to_json(), sort_keys=True) + "\n", encoding="utf-8")
    return FileLeaseStore(path, clock=lambda: now)


def _task(workspace: Path) -> Task:
    return Task(
        id="e2e-rotation",
        tool_scope=frozenset({"fs.read"}),
        fs_root=str(workspace),
        egress_allowlist=frozenset(),
        caps=CAPS,
    )


class TestTheWindowClosesAndTheRotationIsOwed:
    def test_the_advisory_lands_when_a_task_is_constructed_after_expiry(
        self,
        workspace: Path,
        handlers: dict[str, ToolHandler],
        credential_dir: Path,
        tmp_path: Path,
    ) -> None:
        lease = _three_day_lease(credential_dir)
        advisories = FileAdvisorySink(tmp_path / "operator" / "rotations.jsonl")

        # During the window: the automation reads the leased file, no advice yet.
        live = build_server(
            _task(workspace),
            reference_registry(),
            {"fs.read": handlers["fs.read"]},
            leases=_lease_store(tmp_path, lease, now=T0 + DAY),
            advisories=advisories,
        )
        assert live.call_tool("fs.read", {"path": str(credential_dir / "prod.env")}).authorised
        assert advisories.advisories() == ()

        # After it: the same construction sweeps and the advisory is written.
        after = build_server(
            _task(workspace),
            reference_registry(),
            {"fs.read": handlers["fs.read"]},
            leases=_lease_store(tmp_path, lease, now=T0 + 4 * DAY),
            advisories=advisories,
        )
        assert not after.call_tool("fs.read", {"path": str(credential_dir / "prod.env")}).authorised

        written = advisories.advisories()
        assert len(written) == 1
        # Resolved on both sides: a lease subject is stored in its canonical
        # form, and on macOS pytest's tmp_path and its resolution differ.
        assert str(credential_dir.resolve()) in written[0].message
        assert "3.00 days" in written[0].message
        assert "operator@example.test" in written[0].message
        assert "not evidence that nothing was taken" in written[0].message

    def test_the_advisory_lands_even_though_nothing_was_ever_read(
        self,
        workspace: Path,
        handlers: dict[str, ToolHandler],
        credential_dir: Path,
        tmp_path: Path,
    ) -> None:
        """Unconditional. A quiet window is what both outcomes look like."""
        advisories = FileAdvisorySink(tmp_path / "rotations.jsonl")
        build_server(
            _task(workspace),
            reference_registry(),
            {"fs.read": handlers["fs.read"]},
            leases=_lease_store(tmp_path, _three_day_lease(credential_dir), now=T0 + 9 * DAY),
            advisories=advisories,
        )
        assert len(advisories.advisories()) == 1

    def test_repeated_task_construction_does_not_repeat_the_advisory(
        self,
        workspace: Path,
        handlers: dict[str, ToolHandler],
        credential_dir: Path,
        tmp_path: Path,
    ) -> None:
        advisories = FileAdvisorySink(tmp_path / "rotations.jsonl")
        store = _lease_store(tmp_path, _three_day_lease(credential_dir), now=T0 + 9 * DAY)
        for _ in range(3):
            build_server(
                _task(workspace),
                reference_registry(),
                {"fs.read": handlers["fs.read"]},
                leases=store,
                advisories=advisories,
            )
        assert len(advisories.advisories()) == 1

    def test_an_operator_sweep_finds_the_same_advisory_without_a_task(
        self, credential_dir: Path, tmp_path: Path
    ) -> None:
        """A deployment that stops constructing tasks must still notice expiries."""
        store = _lease_store(tmp_path, _three_day_lease(credential_dir), now=T0 + 9 * DAY)
        sink = FileAdvisorySink(tmp_path / "rotations.jsonl")
        emitted = emit_due(store, sink)
        assert len(emitted) == 1
        assert "Rotate every secret stored under" in render(emitted)

    def test_a_non_credential_lease_produces_no_advisory(
        self,
        workspace: Path,
        handlers: dict[str, ToolHandler],
        tmp_path: Path,
    ) -> None:
        lease = Lease.granted(
            kind=LeaseKind.HOST,
            subject="reports.partner.example",
            granted_by="operator@example.test",
            reason="three days to publish the quarterly export",
            granted_at=T0,
            duration_s=3 * DAY,
            sensitivity=Sensitivity.ROUTINE,
        )
        advisories = FileAdvisorySink(tmp_path / "rotations.jsonl")
        build_server(
            _task(workspace),
            reference_registry(),
            {"fs.read": handlers["fs.read"]},
            leases=_lease_store(tmp_path, lease, now=T0 + 9 * DAY),
            advisories=advisories,
        )
        assert advisories.advisories() == ()


class TestTheAdvisorySinkIsOutOfTheAgentsReach:
    def test_a_sink_inside_the_task_root_is_refused_at_construction(
        self, workspace: Path, handlers: dict[str, ToolHandler], tmp_path: Path
    ) -> None:
        """An agent that can rewrite the record of what it could reach has removed it."""
        sink = FileAdvisorySink(workspace / "rotations.jsonl")
        with pytest.raises(StoreWithinReachError, match="resolves inside fs_root"):
            build_server(
                _task(workspace),
                reference_registry(),
                {"fs.read": handlers["fs.read"]},
                advisories=sink,
            )

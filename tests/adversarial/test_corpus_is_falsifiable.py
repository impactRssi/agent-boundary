"""Proof that the corpus is measuring something.

A broker that refuses every call passes every payload in the corpus. So does a broker whose
harness never dispatches them. Both would report the same green tick as one
that works.

These tests are the control on the control: legitimate work under the same
pipeline must be AUTHORISED, and a payload aimed at a task that permits it must
stop being refused. Without them, "100% blocked" is not a measurement.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentboundary.approval import (
    ApprovalGuard,
    ApprovalRecord,
    InMemoryApprovalStore,
    argument_digest,
)
from agentboundary.broker import Broker
from agentboundary.budget import BudgetGuard, BudgetLedger
from agentboundary.confinement import EgressGuard, PathConfinementGuard
from agentboundary.guards import Guard
from agentboundary.leases import InMemoryLeaseStore, Lease, LeaseKind, leased_task
from agentboundary.model import Caps, ProposedCall, Task
from agentboundary.testing import reference_registry

CAPS = Caps(max_calls=10, max_cost=10.0, max_wall_clock_s=60.0)


def _broker(task: Task, approvals: InMemoryApprovalStore | None = None) -> Broker:
    guards: list[Guard] = [
        PathConfinementGuard(),
        EgressGuard(),
        BudgetGuard(BudgetLedger(task.caps)),
        ApprovalGuard(approvals or InMemoryApprovalStore()),
    ]
    return Broker(task, reference_registry().scope_for(task), guards)


class TestLegitimateWorkIsAuthorised:
    """If these fail, every refusal above is meaningless."""

    def test_an_in_scope_read_inside_the_root_is_authorised(self, tmp_path: Path) -> None:
        (tmp_path / "notes.txt").write_text("hello", encoding="utf-8")
        task = Task(
            id="benign-1",
            tool_scope=frozenset({"fs.read"}),
            fs_root=str(tmp_path),
            egress_allowlist=frozenset(),
            caps=CAPS,
        )
        decision = _broker(task).authorise(ProposedCall("fs.read", {"path": "notes.txt"}))
        assert decision.authorised, decision.checks

    def test_a_fetch_to_an_allowlisted_host_is_authorised(self) -> None:
        task = Task(
            id="benign-2",
            tool_scope=frozenset({"http.get"}),
            fs_root=None,
            egress_allowlist=frozenset({"docs.internal"}),
            caps=CAPS,
        )
        decision = _broker(task).authorise(
            ProposedCall("http.get", {"url": "https://docs.internal/runbook"})
        )
        assert decision.authorised, decision.checks

    def test_a_read_only_ticket_listing_is_authorised(self) -> None:
        task = Task(
            id="benign-3",
            tool_scope=frozenset({"tickets.list"}),
            fs_root=None,
            egress_allowlist=frozenset(),
            caps=CAPS,
        )
        assert _broker(task).authorise(ProposedCall("tickets.list", {})).authorised

    def test_an_irreversible_call_with_a_live_approval_is_authorised(self) -> None:
        """The approval gate must be passable, or it is just a denial."""
        arguments = {"ticket_id": 4821}
        approvals = InMemoryApprovalStore(
            [
                ApprovalRecord(
                    task_id="benign-4",
                    tool_name="tickets.delete",
                    arg_digest=argument_digest(arguments),
                    granted_by="operator@example.test",
                    expires_at=10_000.0,
                )
            ],
            clock=lambda: 0.0,
        )
        task = Task(
            id="benign-4",
            tool_scope=frozenset({"tickets.delete"}),
            fs_root=None,
            egress_allowlist=frozenset(),
            caps=CAPS,
        )
        decision = _broker(task, approvals).authorise(ProposedCall("tickets.delete", arguments))
        assert decision.authorised, decision.checks


class TestTheSamePayloadPassesWhenTheTaskPermitsIt:
    """Each refusal must be caused by the control, not by the payload's shape."""

    @pytest.mark.parametrize(
        ("tool", "arguments", "scope", "root_relative"),
        [
            ("fs.read", {"path": "readable.txt"}, {"fs.read"}, True),
            ("tickets.get", {"ticket_id": 4821}, {"tickets.get"}, False),
        ],
    )
    def test_a_call_refused_out_of_scope_is_authorised_in_scope(
        self,
        tool: str,
        arguments: dict[str, object],
        scope: set[str],
        root_relative: bool,
        tmp_path: Path,
    ) -> None:
        if root_relative:
            (tmp_path / "readable.txt").write_text("x", encoding="utf-8")

        narrow = Task(
            id="narrow",
            tool_scope=frozenset({"tickets.list"}),
            fs_root=str(tmp_path),
            egress_allowlist=frozenset(),
            caps=CAPS,
        )
        assert not _broker(narrow).authorise(ProposedCall(tool, arguments)).authorised

        wide = Task(
            id="wide",
            tool_scope=frozenset(scope),
            fs_root=str(tmp_path),
            egress_allowlist=frozenset(),
            caps=CAPS,
        )
        assert _broker(wide).authorise(ProposedCall(tool, arguments)).authorised

    def test_a_path_refused_outside_the_root_is_authorised_inside_it(self, tmp_path: Path) -> None:
        task = Task(
            id="t",
            tool_scope=frozenset({"fs.read"}),
            fs_root=str(tmp_path),
            egress_allowlist=frozenset(),
            caps=CAPS,
        )
        broker = _broker(task)
        assert not broker.authorise(
            ProposedCall("fs.read", {"path": "../../etc/passwd"})
        ).authorised
        assert broker.authorise(ProposedCall("fs.read", {"path": "inside.txt"})).authorised

    def test_a_host_refused_off_allowlist_is_authorised_on_it(self) -> None:
        off = Task(
            id="off",
            tool_scope=frozenset({"http.get"}),
            fs_root=None,
            egress_allowlist=frozenset({"docs.internal"}),
            caps=CAPS,
        )
        assert (
            not _broker(off)
            .authorise(ProposedCall("http.get", {"url": "https://evil.example/x"}))
            .authorised
        )

        on = Task(
            id="on",
            tool_scope=frozenset({"http.get"}),
            fs_root=None,
            egress_allowlist=frozenset({"evil.example"}),
            caps=CAPS,
        )
        assert (
            _broker(on)
            .authorise(ProposedCall("http.get", {"url": "https://evil.example/x"}))
            .authorised
        )


class TestALeaseCanActuallyWiden:
    """Without these, the lease payloads above pass because leases do nothing.

    Each near miss the corpus refuses must flip to an authorisation when the
    lease genuinely names the subject. A widening mechanism that never widens is
    not a widening mechanism, and the refusals it produces measure nothing.
    """

    def _store(self, *leases: Lease, now: float) -> InMemoryLeaseStore:
        return InMemoryLeaseStore(leases, clock=lambda: now)

    def _guards(self, task: Task, leases: InMemoryLeaseStore | None) -> list[Guard]:
        return [
            PathConfinementGuard(leases=leases),
            EgressGuard(leases=leases),
            BudgetGuard(BudgetLedger(task.caps)),
            ApprovalGuard(InMemoryApprovalStore()),
        ]

    def test_a_path_refused_beside_a_lease_is_authorised_inside_it(self, tmp_path: Path) -> None:
        leased = tmp_path / "x" / "secrets"
        leased.mkdir(parents=True)
        (tmp_path / "x" / "secrets-backup").mkdir()
        root = tmp_path / "workspace"
        root.mkdir()
        task = Task(
            id="lease-1",
            tool_scope=frozenset({"fs.read"}),
            fs_root=str(root),
            egress_allowlist=frozenset(),
            caps=CAPS,
        )
        lease = Lease.granted(
            kind=LeaseKind.PATH,
            subject=str(leased),
            granted_by="operator@example.test",
            reason="three days of access to the key directory, OPS-4821",
            granted_at=0.0,
            duration_s=3 * 86_400.0,
        )
        broker = Broker(
            task,
            reference_registry().scope_for(task),
            self._guards(task, self._store(lease, now=86_400.0)),
        )
        assert not broker.authorise(
            ProposedCall("fs.read", {"path": str(tmp_path / "x" / "secrets-backup" / "k.env")})
        ).authorised
        assert broker.authorise(ProposedCall("fs.read", {"path": str(leased / "k.env")})).authorised

    def test_a_host_refused_off_a_lease_is_authorised_on_it(self) -> None:
        task = Task(
            id="lease-2",
            tool_scope=frozenset({"http.get"}),
            fs_root=None,
            egress_allowlist=frozenset(),
            caps=CAPS,
        )
        lease = Lease.granted(
            kind=LeaseKind.HOST,
            subject="docs.internal",
            granted_by="operator@example.test",
            reason="three days to read the partner runbook mirror",
            granted_at=0.0,
            duration_s=86_400.0,
        )
        broker = Broker(
            task,
            reference_registry().scope_for(task),
            self._guards(task, self._store(lease, now=1.0)),
        )
        assert not broker.authorise(
            ProposedCall("http.get", {"url": "https://docs.internal.evil.example/x"})
        ).authorised
        assert broker.authorise(
            ProposedCall("http.get", {"url": "https://docs.internal/runbook"})
        ).authorised

    def test_a_tool_refused_under_an_expired_lease_is_in_scope_under_a_live_one(self) -> None:
        lease = Lease.granted(
            kind=LeaseKind.TOOL,
            subject="tickets.delete",
            granted_by="operator@example.test",
            reason="one-off cleanup of duplicate tickets, OPS-4900",
            granted_at=0.0,
            duration_s=86_400.0,
        )
        narrow = Task(
            id="lease-3",
            tool_scope=frozenset({"tickets.list"}),
            fs_root=None,
            egress_allowlist=frozenset(),
            caps=CAPS,
        )
        expired = leased_task(narrow, self._store(lease, now=10 * 86_400.0))
        assert not expired.is_in_scope("tickets.delete")

        live = leased_task(narrow, self._store(lease, now=1.0))
        assert live.is_in_scope("tickets.delete")
        broker = Broker(live, reference_registry().scope_for(live), self._guards(live, None))
        decision = broker.authorise(ProposedCall("tickets.delete", {"ticket_id": 4821}))
        # In scope now, so the refusal moves to the approval gate rather than to
        # scope: the lease widened I1 and left I3 exactly where it was.
        assert str(decision.reason) == "approval_required"

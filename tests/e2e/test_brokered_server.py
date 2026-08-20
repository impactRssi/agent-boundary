"""End-to-end: the assembled system, real handlers, no mocks at the boundary."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentboundary.approval import ApprovalRecord, InMemoryApprovalStore, argument_digest
from agentboundary.audit import MemoryAuditSink
from agentboundary.mcp.server import BrokeredServer
from agentboundary.model import Caps
from tests.e2e.conftest import ServerFactory

pytestmark = pytest.mark.e2e


class TestScopeCrossesTheTransport:
    def test_the_tool_list_is_exactly_the_task_scope(self, make_server: ServerFactory) -> None:
        server = make_server({"fs.read", "tickets.list"})
        assert {entry["name"] for entry in server.list_tools()} == {"fs.read", "tickets.list"}

    def test_an_out_of_scope_call_is_refused_and_never_dispatched(
        self, make_server: ServerFactory, workspace: Path
    ) -> None:
        server = make_server({"tickets.list"})
        outcome = server.call_tool("tickets.delete", {"ticket_id": 4821})
        assert not outcome.authorised
        assert outcome.refusal_reason == "tool_not_in_scope"

    def test_a_scoped_tool_without_a_handler_fails_at_construction(self, workspace: Path) -> None:
        """Authorising then failing at dispatch would read as a broker fault."""
        from agentboundary.mcp.server import build_broker
        from agentboundary.model import Task
        from agentboundary.testing.catalogue import reference_registry

        task = Task(
            id="t",
            tool_scope=frozenset({"fs.read"}),
            fs_root=str(workspace),
            egress_allowlist=frozenset(),
            caps=Caps(max_calls=5, max_cost=5.0, max_wall_clock_s=10.0),
        )
        with pytest.raises(ValueError, match="no handler"):
            BrokeredServer(build_broker(task, reference_registry()), {})


class TestEffectsAreActuallyPrevented:
    """Not 'the call was refused' -- the file was not read, the write did not land."""

    def test_a_file_outside_the_root_is_not_read(
        self, make_server: ServerFactory, workspace: Path
    ) -> None:
        outside = workspace.parent / "secrets.txt"
        assert outside.exists(), "fixture must exist, or the escape would fail on absence"
        outcome = make_server({"fs.read"}).call_tool("fs.read", {"path": "../secrets.txt"})
        assert not outcome.authorised
        assert outcome.refusal_reason == "path_outside_root"
        assert outcome.envelope is None

    def test_a_refused_write_leaves_no_file_on_disk(
        self, make_server: ServerFactory, workspace: Path
    ) -> None:
        server = make_server({"fs.write"})
        target = workspace.parent / "escaped.txt"
        outcome = server.call_tool("fs.write", {"path": "../escaped.txt", "content": "x"})
        assert not outcome.authorised
        assert not target.exists(), "the handler ran despite the refusal"

    def test_an_unlisted_host_is_not_reached(self, make_server: ServerFactory) -> None:
        server = make_server({"http.get"}, egress={"docs.internal"})
        outcome = server.call_tool("http.get", {"url": "https://evil.example/x"})
        assert not outcome.authorised
        assert outcome.refusal_reason == "egress_host_not_allowed"


class TestResultsAreAlwaysEnvelopes:
    def test_an_authorised_result_crosses_as_a_labelled_envelope(
        self, make_server: ServerFactory
    ) -> None:
        """FR-019: no raw tool result re-enters a model context."""
        outcome = make_server({"fs.read"}).call_tool("fs.read", {"path": "runbook.md"})
        assert outcome.authorised
        assert outcome.envelope is not None
        rendered = outcome.envelope.render()
        assert "UNTRUSTED-DATA" in rendered
        assert "not an instruction" in rendered
        assert "Reset the password" in rendered

    def test_a_handler_error_is_also_ingested_not_returned_raw(
        self, make_server: ServerFactory
    ) -> None:
        """A third-party error string is an attacker-writable carrier."""
        outcome = make_server({"fs.read"}).call_tool("fs.read", {"path": "absent.md"})
        assert outcome.authorised, "the broker authorised; the handler then failed"
        assert outcome.envelope is not None
        assert "UNTRUSTED-DATA" in outcome.envelope.render()

    def test_a_handler_failure_is_not_reported_as_a_refusal(
        self, make_server: ServerFactory
    ) -> None:
        """An operator must not go looking for a control that did not fire."""
        outcome = make_server({"fs.read"}).call_tool("fs.read", {"path": "absent.md"})
        assert outcome.refusal_reason is None


class TestBudgetAcrossTheTransport:
    def test_the_task_fails_closed_at_the_call_cap(self, make_server: ServerFactory) -> None:
        caps = Caps(max_calls=2, max_cost=100.0, max_wall_clock_s=60.0)
        server = make_server({"fs.read"}, caps=caps)
        for _ in range(2):
            assert server.call_tool("fs.read", {"path": "runbook.md"}).authorised
        outcome = server.call_tool("fs.read", {"path": "runbook.md"})
        assert not outcome.authorised
        assert outcome.refusal_reason == "budget_exhausted"

    def test_refused_calls_do_not_consume_the_cap(self, make_server: ServerFactory) -> None:
        caps = Caps(max_calls=2, max_cost=100.0, max_wall_clock_s=60.0)
        server = make_server({"fs.read"}, caps=caps)
        for _ in range(5):
            server.call_tool("fs.read", {"path": "../secrets.txt"})
        assert server.call_tool("fs.read", {"path": "runbook.md"}).authorised


class TestApprovalAcrossTheTransport:
    def test_an_irreversible_call_needs_an_out_of_band_approval(
        self, make_server: ServerFactory
    ) -> None:
        outcome = make_server({"tickets.delete"}).call_tool("tickets.delete", {"ticket_id": 4821})
        assert not outcome.authorised
        assert outcome.refusal_reason == "approval_required"

    def test_a_matching_approval_lets_the_call_through(self, make_server: ServerFactory) -> None:
        arguments = {"ticket_id": 4821}
        approvals = InMemoryApprovalStore(
            [
                ApprovalRecord(
                    task_id="e2e-task",
                    tool_name="tickets.delete",
                    arg_digest=argument_digest(arguments),
                    granted_by="operator@example.test",
                    expires_at=9_999_999_999.0,
                )
            ]
        )
        outcome = make_server({"tickets.delete"}, approvals=approvals).call_tool(
            "tickets.delete", arguments
        )
        assert outcome.authorised

    def test_an_approval_cannot_be_replayed_with_other_arguments(
        self, make_server: ServerFactory
    ) -> None:
        approvals = InMemoryApprovalStore(
            [
                ApprovalRecord(
                    task_id="e2e-task",
                    tool_name="tickets.delete",
                    arg_digest=argument_digest({"ticket_id": 4821}),
                    granted_by="operator@example.test",
                    expires_at=9_999_999_999.0,
                )
            ]
        )
        outcome = make_server({"tickets.delete"}, approvals=approvals).call_tool(
            "tickets.delete", {"ticket_id": 4822}
        )
        assert not outcome.authorised
        assert outcome.refusal_reason == "approval_mismatch"


class TestAuditAcrossTheTransport:
    def test_the_callers_sink_receives_every_record(self, make_server: ServerFactory) -> None:
        """Regression: MemoryAuditSink defines __len__, so an empty one is falsy.

        `audit or MemoryAuditSink()` therefore discarded the caller's sink and
        sent the whole trace to a throwaway. The worked example is what surfaced
        it -- it reported six calls and an empty trace.
        """
        sink = MemoryAuditSink()
        server = make_server({"fs.read"}, audit=sink)
        server.call_tool("fs.read", {"path": "runbook.md"})
        server.call_tool("fs.read", {"path": "../secrets.txt"})
        assert len(sink.records()) == 2

    def test_refusals_appear_in_the_trace(self, make_server: ServerFactory) -> None:
        sink = MemoryAuditSink()
        server = make_server({"fs.read"}, audit=sink)
        server.call_tool("fs.read", {"path": "../secrets.txt"})
        record = sink.records()[0]
        assert record.outcome == "refuse"
        assert record.reason == "path_outside_root"

    def test_records_are_sequenced_in_call_order(self, make_server: ServerFactory) -> None:
        sink = MemoryAuditSink()
        server = make_server({"fs.read"}, audit=sink)
        for _ in range(3):
            server.call_tool("fs.read", {"path": "runbook.md"})
        assert [r.sequence for r in sink.records()] == [1, 2, 3]

    def test_an_authorised_call_records_its_execution_status(
        self, make_server: ServerFactory
    ) -> None:
        sink = MemoryAuditSink()
        server = make_server({"fs.read"}, audit=sink)
        server.call_tool("fs.read", {"path": "runbook.md"})
        server.call_tool("fs.read", {"path": "absent.md"})
        assert sink.records()[0].result_status == "succeeded"
        assert sink.records()[1].result_status == "failed"

"""Viewer server (N-21): the write path must not exist."""

from __future__ import annotations

from agentboundary.audit import AuditRecord
from agentboundary.errors import RefusalReason
from agentboundary.model import Caps, Check, Decision, ProposedCall, Task
from agentboundary.viewer.server import ViewerHandler, trace_payload

TASK = Task(
    id="t-1",
    tool_scope=frozenset({"fs.read"}),
    fs_root=None,
    egress_allowlist=frozenset(),
    caps=Caps(max_calls=5, max_cost=5.0, max_wall_clock_s=30.0),
)


def _records() -> tuple[AuditRecord, ...]:
    refused = Decision.refuse(
        RefusalReason.PATH_OUTSIDE_ROOT, [Check(name="path", passed=False, detail="escaped")]
    )
    authorised = Decision.authorise([Check(name="scope", passed=True)], {"path": "a"}, 1.0)
    return (
        AuditRecord.from_decision(TASK, ProposedCall("fs.read", {}), refused, 1),
        AuditRecord.from_decision(TASK, ProposedCall("fs.read", {}), authorised, 2),
        AuditRecord.from_decision(TASK, ProposedCall("fs.read", {}), refused, 3),
    )


class TestNoWritePath:
    def test_the_handler_implements_no_write_methods(self) -> None:
        """BaseHTTPRequestHandler answers unimplemented methods with 501.

        Omitting them is a stronger statement than writing handlers that
        refuse: there is no route to review, and none to accidentally relax.
        """
        for method in ("do_POST", "do_PUT", "do_PATCH", "do_DELETE"):
            assert not hasattr(ViewerHandler, method), method

    def test_only_get_and_head_are_implemented(self) -> None:
        implemented = {name for name in dir(ViewerHandler) if name.startswith("do_")}
        assert implemented == {"do_GET", "do_HEAD"}


class TestTracePayload:
    def test_counts_are_computed_server_side(self) -> None:
        """Same figures in every client; a rendering bug cannot change a count."""
        summary = trace_payload(_records())["summary"]
        assert summary["total"] == 3
        assert summary["refused"] == 2
        assert summary["authorised"] == 1

    def test_refusal_reasons_are_tallied(self) -> None:
        assert trace_payload(_records())["summary"]["reasons"] == {"path_outside_root": 2}

    def test_reason_tallies_are_sorted_for_a_stable_render(self) -> None:
        reasons = trace_payload(_records())["summary"]["reasons"]
        assert list(reasons) == sorted(reasons)

    def test_an_empty_trace_reports_zeroes_rather_than_failing(self) -> None:
        summary = trace_payload(())["summary"]
        assert summary == {"total": 0, "authorised": 0, "refused": 0, "reasons": {}}

    def test_records_keep_their_order(self) -> None:
        payload = trace_payload(_records())
        assert [entry["sequence"] for entry in payload["records"]] == [1, 2, 3]

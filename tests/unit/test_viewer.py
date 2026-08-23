"""Viewer server (N-21, N-45): the write path must not exist.

The viewer shows the audit trace and, since N-45, the leases in force. Both are
held to the same rule -- displayed, never actuated. A viewer that could mint a
lease would be a second write path into the store, reachable over HTTP, in a
process the rest of this design keeps read-only.
"""

from __future__ import annotations

from agentboundary.audit import AuditRecord
from agentboundary.errors import RefusalReason
from agentboundary.leases import Lease, LeaseKind
from agentboundary.model import Caps, Check, Decision, ProposedCall, Task
from agentboundary.rotation import advice_for
from agentboundary.viewer.server import ViewerHandler, lease_payload, trace_payload

NOW = 1_700_000_000.0
DAY = 86_400.0

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


class TestLeasePayload:
    """N-45: an operator who cannot see what is granted cannot revoke it."""

    def test_an_active_lease_reports_its_state_and_the_time_left(self) -> None:
        payload = lease_payload([_lease(duration_s=3 * DAY)], (), NOW + DAY)
        row = payload["leases"][0]
        assert row["state"] == "active"
        assert row["remaining_s"] == 2 * DAY
        assert "2.00 days remaining" in row["state_text"]

    def test_an_expired_lease_is_shown_rather_than_filtered_out(self) -> None:
        """'No lease was ever granted' and 'a lease expired' are different states,
        and the second is what a rotation advisory is made of."""
        payload = lease_payload([_lease(duration_s=DAY)], (), NOW + 3 * DAY)
        row = payload["leases"][0]
        assert row["state"] == "expired"
        assert "expired 2.00 days ago" in row["state_text"]
        assert row["remaining_s"] < 0

    def test_the_instant_of_expiry_is_already_expired(self) -> None:
        """Half-open, from the type's own predicate. A boundary that authorises
        is a boundary an operator did not grant."""
        payload = lease_payload([_lease(duration_s=DAY)], (), NOW + DAY)
        assert payload["leases"][0]["state"] == "expired"

    def test_a_lease_not_yet_in_force_reads_as_pending_not_as_active(self) -> None:
        payload = lease_payload([_lease(duration_s=DAY)], (), NOW - DAY)
        assert payload["leases"][0]["state"] == "pending"
        assert "not yet in force" in payload["leases"][0]["state_text"]

    def test_the_state_comes_from_the_types_own_predicate(self) -> None:
        """Not from a timestamp comparison written again in the viewer: the page
        must never say 'active' about a lease the broker has stopped honouring."""
        lease = _lease(duration_s=DAY)
        for instant in (NOW - 1.0, NOW, NOW + DAY / 2, NOW + DAY, NOW + DAY + 1.0):
            state = lease_payload([lease], (), instant)["leases"][0]["state"]
            assert (state == "active") is lease.is_active(instant)

    def test_the_summary_counts_are_computed_server_side(self) -> None:
        leases = [
            _lease(subject="/srv/a", duration_s=3 * DAY),
            _lease(subject="/srv/b", duration_s=DAY),
        ]
        summary = lease_payload(leases, (), NOW + 2 * DAY)["summary"]
        assert summary == {"granted": 2, "active": 1, "expired": 1, "rotation_owed": 0}

    def test_the_notice_travels_with_the_rows(self) -> None:
        """A lease is the one mechanism that makes an invariant hold less than it
        did; the cost is stated where what it bought is displayed."""
        payload = lease_payload([_lease()], (), NOW)
        assert "does not hold for its subject" in payload["notice"]
        assert "cannot create, extend or revoke" in payload["notice"]

    def test_an_empty_store_still_carries_the_notice(self) -> None:
        assert "does not hold for its subject" in lease_payload((), (), NOW)["notice"]

    def test_rotation_advisories_are_carried_with_their_message(self) -> None:
        lease = _lease(duration_s=DAY)
        advice = advice_for(lease)
        assert advice is not None
        payload = lease_payload([lease], [advice], NOW + 3 * DAY)
        assert payload["summary"]["rotation_owed"] == 1
        assert "Rotate every secret stored under" in payload["advisories"][0]["message"]

    def test_leases_are_ordered_deterministically(self) -> None:
        first = _lease(subject="/srv/b")
        second = _lease(subject="/srv/a")
        subjects = [row["subject"] for row in lease_payload([first, second], (), NOW)["leases"]]
        assert subjects == ["/srv/a", "/srv/b"]

    def test_the_payload_carries_no_field_that_could_grant(self) -> None:
        """The page renders this. A field named `approve` would be a button next."""
        row = lease_payload([_lease()], (), NOW)["leases"][0]
        offending = {
            name
            for name in row
            for word in ("approve", "extend", "renew", "revoke", "index")
            if word in name.lower()
        }
        assert not offending, sorted(offending)


class TestTheLeaseRouteIsReadOnlyToo:
    def test_the_handler_still_implements_only_get_and_head(self) -> None:
        implemented = {name for name in dir(ViewerHandler) if name.startswith("do_")}
        assert implemented == {"do_GET", "do_HEAD"}

    def test_the_handler_holds_values_not_a_store(self) -> None:
        """A store handle could be re-read, and is one attribute away from being
        written through. The viewer is handed tuples."""
        assert ViewerHandler.leases == ()
        assert ViewerHandler.advisories == ()
        assert ViewerHandler.pinned_now is None

    def test_the_viewer_module_cannot_write_a_lease(self) -> None:
        import inspect
        from pathlib import Path

        from agentboundary.viewer import server as viewer_module

        source = Path(inspect.getsourcefile(viewer_module) or "").read_text(encoding="utf-8")
        for primitive in ("O_WRONLY", "write_text", "write_bytes", "agentboundary.operator"):
            assert primitive not in source, primitive


def _lease(subject: str = "/srv/secrets", duration_s: float = DAY) -> Lease:
    return Lease.granted(
        kind=LeaseKind.PATH,
        subject=subject,
        granted_by="operator@example.test",
        reason="the nightly automation needs it",
        granted_at=NOW,
        duration_s=duration_s,
    )

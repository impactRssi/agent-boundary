"""Rotation advice when a credential lease expires (N-44).

The first class is the one that matters: the advisory is unconditional. The
tempting design filters it on whether anything looked wrong, and that filter
reads the wrong evidence -- the trace shows what was authorised, and inside the
lease window everything was. So the tests assert that no property of the run
suppresses the advice.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest

from agentboundary.leases import InMemoryLeaseStore, Lease, LeaseKind, LeaseStore, Sensitivity
from agentboundary.rotation import (
    FileAdvisorySink,
    MemoryAdvisorySink,
    RotationAdvice,
    advice_for,
    due,
    emit_due,
    render,
)

DAY = 86_400.0
T0 = 1_700_000_000.0


def _lease(**overrides: object) -> Lease:
    fields: dict[str, object] = {
        "kind": LeaseKind.PATH,
        "subject": "/srv/agent-boundary/secrets",
        "granted_by": "operator@example.test",
        "reason": "three days for the nightly rotation automation, OPS-4821",
        "granted_at": T0,
        "expires_at": T0 + 3 * DAY,
    }
    fields.update(overrides)
    return Lease(**fields)  # type: ignore[arg-type]


def _store(*leases: Lease, now: float) -> LeaseStore:
    return InMemoryLeaseStore(leases, clock=lambda: now)


class TestTheAdviceIsUnconditional:
    def test_an_expired_credential_lease_always_produces_advice(self) -> None:
        assert len(due(_store(_lease(), now=T0 + 4 * DAY))) == 1

    def test_advice_is_produced_even_when_the_lease_was_never_used(self) -> None:
        """No call was made under it, and the advice is identical.

        The lease authorised the access; whether the agent took it is not
        something the trace can answer, so it cannot be a condition.
        """
        advisories = due(_store(_lease(), now=T0 + 4 * DAY))
        assert advisories
        assert "Rotate every secret stored under" in advisories[0].message

    def test_nothing_in_the_module_takes_an_audit_trace_or_a_decision(self) -> None:
        """A signature that could see the trace is a signature that could filter on it."""
        import agentboundary.rotation as module

        annotations: list[str] = []
        for name in module.__all__:
            member = getattr(module, name)
            if not callable(member):
                continue
            try:
                signature = inspect.signature(member)
            except (ValueError, TypeError):  # pragma: no cover
                continue
            annotations.extend(str(p.annotation) for p in signature.parameters.values())
        assert annotations
        forbidden = ("Audit", "Decision", "Outcome", "Ledger", "Check")
        assert not [text for text in annotations if any(word in text for word in forbidden)]

    def test_every_advisory_states_what_it_cannot_know(self) -> None:
        advice = due(_store(_lease(), now=T0 + 4 * DAY))[0]
        assert "not evidence that nothing was taken" in advice.message
        assert "Rotate regardless." in advice.message


class TestWhichLeasesOweAnAdvisory:
    def test_a_live_credential_lease_owes_nothing_yet(self) -> None:
        assert due(_store(_lease(), now=T0 + DAY)) == ()

    def test_the_advisory_is_owed_at_the_instant_of_expiry(self) -> None:
        """Half-open windows: at expires_at the lease is over, so the advice is due."""
        assert len(due(_store(_lease(), now=T0 + 3 * DAY))) == 1

    @pytest.mark.parametrize("sensitivity", [Sensitivity.SENSITIVE, Sensitivity.ROUTINE], ids=str)
    def test_a_non_credential_lease_owes_no_advisory(self, sensitivity: Sensitivity) -> None:
        assert advice_for(_lease(sensitivity=sensitivity)) is None

    def test_a_lease_with_no_stated_class_owes_one(self) -> None:
        """Unstated is credential, so the advisory is what saying nothing buys."""
        stored = Lease.from_json(
            {
                "kind": "path",
                "subject": "/srv/secrets",
                "granted_by": "op",
                "reason": "why",
                "granted_at": T0,
                "expires_at": T0 + DAY,
            }
        )
        assert advice_for(stored) is not None

    @pytest.mark.parametrize(
        ("kind", "subject", "fragment"),
        [
            (LeaseKind.PATH, "/srv/secrets", "every secret stored under /srv/secrets"),
            (LeaseKind.HOST, "vault.internal", "could have presented to vault.internal"),
            (LeaseKind.TOOL, "fs.read", "every secret fs.read could reach"),
        ],
        ids=["path", "host", "tool"],
    )
    def test_each_kind_names_what_was_reachable(
        self, kind: LeaseKind, subject: str, fragment: str
    ) -> None:
        advice = advice_for(_lease(kind=kind, subject=subject))
        assert advice is not None
        assert fragment in advice.message

    def test_the_advisory_names_how_long_and_on_whose_authority(self) -> None:
        advice = advice_for(_lease())
        assert advice is not None
        assert "3.00 days" in advice.message
        assert "operator@example.test" in advice.message
        assert "OPS-4821" in advice.message
        assert advice.window_s == 3 * DAY

    def test_an_unpinned_lease_says_it_covered_every_task(self) -> None:
        advice = advice_for(_lease())
        assert advice is not None
        assert "every task in this deployment" in advice.message

    def test_a_pinned_lease_names_its_task(self) -> None:
        advice = advice_for(_lease(task_id="ops-nightly"))
        assert advice is not None
        assert "task 'ops-nightly'" in advice.message

    def test_advisories_are_ordered_deterministically(self) -> None:
        store = _store(
            _lease(subject="/srv/b", expires_at=T0 + 2 * DAY),
            _lease(subject="/srv/a", expires_at=T0 + DAY),
            now=T0 + 9 * DAY,
        )
        assert [advice.subject for advice in due(store)] == ["/srv/a", "/srv/b"]

    def test_the_timestamps_are_utc_and_stable_between_runs(self) -> None:
        advice = advice_for(_lease())
        assert advice is not None
        assert "2023-11-14T22:13:20Z" in advice.message
        assert advice.message == advice_for(_lease()).message  # type: ignore[union-attr]


class TestEmissionHappensOnce:
    def test_a_second_sweep_does_not_re_announce(self) -> None:
        """An advisory repeated on every sweep is one an operator learns to filter."""
        store = _store(_lease(), now=T0 + 4 * DAY)
        sink = MemoryAdvisorySink()
        assert len(emit_due(store, sink)) == 1
        assert emit_due(store, sink) == ()
        assert len(sink.advisories()) == 1

    def test_a_sweep_by_a_different_process_does_not_re_announce(self, tmp_path: Path) -> None:
        store = _store(_lease(), now=T0 + 4 * DAY)
        path = tmp_path / "advisories.jsonl"
        assert len(emit_due(store, FileAdvisorySink(path))) == 1
        assert emit_due(store, FileAdvisorySink(path)) == ()

    def test_a_re_granted_lease_earns_its_own_advisory(self) -> None:
        """A new grant is a new window, so it is a new rotation when it ends."""
        first = _lease()
        second = _lease(granted_at=T0 + 10 * DAY, expires_at=T0 + 12 * DAY)
        sink = MemoryAdvisorySink()
        emit_due(_store(first, now=T0 + 4 * DAY), sink)
        emit_due(_store(first, second, now=T0 + 20 * DAY), sink)
        assert len(sink.advisories()) == 2

    def test_a_revoked_lease_does_not_lose_its_advisory(self, tmp_path: Path) -> None:
        """The advisory outlives the lease, because the exposure did too."""
        path = tmp_path / "advisories.jsonl"
        sink = FileAdvisorySink(path)
        emit_due(_store(_lease(), now=T0 + 4 * DAY), sink)
        assert len(FileAdvisorySink(path).advisories()) == 1
        # The operator deletes the lease line entirely; the record stands.
        assert emit_due(_store(now=T0 + 4 * DAY), FileAdvisorySink(path)) == ()
        assert len(FileAdvisorySink(path).advisories()) == 1

    def test_the_sink_is_append_only_on_disk(self, tmp_path: Path) -> None:
        path = tmp_path / "advisories.jsonl"
        sink = FileAdvisorySink(path)
        emit_due(_store(_lease(), now=T0 + 4 * DAY), sink)
        first = path.read_bytes()
        emit_due(
            _store(_lease(subject="/srv/other"), now=T0 + 4 * DAY),
            sink,
        )
        assert path.read_bytes().startswith(first)
        assert len(path.read_text(encoding="utf-8").strip().split("\n")) == 2

    def test_the_sink_file_is_not_world_readable(self, tmp_path: Path) -> None:
        path = tmp_path / "advisories.jsonl"
        emit_due(_store(_lease(), now=T0 + 4 * DAY), FileAdvisorySink(path))
        assert path.stat().st_mode & 0o077 == 0

    def test_a_relative_sink_path_is_refused(self) -> None:
        with pytest.raises(ValueError, match="relative"):
            FileAdvisorySink("advisories.jsonl")

    def test_an_absent_sink_file_reads_as_no_advisories(self, tmp_path: Path) -> None:
        assert FileAdvisorySink(tmp_path / "none.jsonl").advisories() == ()

    def test_blank_lines_are_ignored_on_read(self, tmp_path: Path) -> None:
        path = tmp_path / "advisories.jsonl"
        emit_due(_store(_lease(), now=T0 + 4 * DAY), FileAdvisorySink(path))
        with path.open("a", encoding="utf-8") as handle:
            handle.write("\n\n")
        assert len(FileAdvisorySink(path).advisories()) == 1

    def test_a_round_trip_preserves_the_message(self, tmp_path: Path) -> None:
        path = tmp_path / "advisories.jsonl"
        sink = FileAdvisorySink(path)
        emitted = emit_due(_store(_lease(), now=T0 + 4 * DAY), sink)
        assert FileAdvisorySink(path).advisories()[0].message == emitted[0].message
        stored = json.loads(path.read_text(encoding="utf-8").strip())
        assert stored["window_s"] == 3 * DAY


class TestRendering:
    def test_an_empty_sweep_says_so(self) -> None:
        assert render(()) == "No credential lease has expired, so no rotation is owed."

    def test_each_advisory_carries_its_own_caveat(self) -> None:
        text = render(due(_store(_lease(), _lease(subject="/srv/other"), now=T0 + 9 * DAY)))
        assert text.count("not evidence that nothing was taken") == 2

    def test_an_advice_serialises_to_a_stable_shape(self) -> None:
        advice = advice_for(_lease())
        assert advice is not None
        assert set(advice.to_json()) == {
            "lease_digest",
            "kind",
            "subject",
            "granted_by",
            "reason",
            "granted_at",
            "expires_at",
            "task_id",
            "window_s",
            "message",
        }

    def test_a_stored_advice_round_trips_through_json(self) -> None:
        advice = advice_for(_lease(task_id="ops"))
        assert advice is not None
        assert RotationAdvice.from_json(advice.to_json()) == advice

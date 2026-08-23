"""Permission leases (N-42).

The order is the risk order. What cannot be expressed comes first, because
"a lease with no expiry is unrepresentable" is the claim the whole feature rests
on and a claim of unrepresentability is only worth what its enumeration of
spellings is worth. Then expiry and its boundary, then malformed stores, then
the shapes that are supposed to work.
"""

from __future__ import annotations

import inspect
import json
import math
from pathlib import Path

import pytest

from agentboundary import leases as leases_module
from agentboundary.leases import (
    MAX_DURATION_S,
    FileLeaseStore,
    InMemoryLeaseStore,
    Lease,
    LeaseError,
    LeaseKind,
    LeaseStore,
    Sensitivity,
    describe,
)

DAY = 86_400.0
T0 = 1_700_000_000.0


def _lease(**overrides: object) -> Lease:
    fields: dict[str, object] = {
        "kind": LeaseKind.PATH,
        "subject": "/srv/agent-boundary/secrets",
        "granted_by": "operator@example.test",
        "reason": "nightly credential rotation automation, ticket OPS-4821",
        "granted_at": T0,
        "expires_at": T0 + 3 * DAY,
    }
    fields.update(overrides)
    return Lease(**fields)  # type: ignore[arg-type]


class TestAnUnboundedLeaseIsUnrepresentable:
    """Every spelling of "forever" this type could otherwise accept."""

    def test_expires_at_has_no_default_so_it_cannot_be_omitted(self) -> None:
        signature = inspect.signature(Lease)
        assert signature.parameters["expires_at"].default is inspect.Parameter.empty, (
            "expires_at gained a default. A lease that can be constructed without "
            "stating an expiry is an unbounded lease with a tidy call site."
        )
        with pytest.raises(TypeError):
            Lease(  # type: ignore[call-arg]
                kind=LeaseKind.PATH,
                subject="/srv/secrets",
                granted_by="op",
                reason="why",
                granted_at=T0,
            )

    @pytest.mark.parametrize(
        "value",
        [math.inf, float("inf"), float("-inf"), math.nan],
        ids=["inf", "float-inf", "negative-inf", "nan"],
    )
    def test_a_non_finite_expiry_is_rejected(self, value: float) -> None:
        with pytest.raises(LeaseError, match=r"not.*representable|must be a number"):
            _lease(expires_at=value)

    def test_a_non_finite_grant_time_is_rejected(self) -> None:
        with pytest.raises(LeaseError, match=r"not.*representable"):
            _lease(granted_at=math.inf)

    def test_an_expiry_before_the_grant_authorises_nothing_and_is_an_error(self) -> None:
        with pytest.raises(LeaseError, match="authorises nothing"):
            _lease(expires_at=T0 - 1)

    def test_a_zero_length_lease_is_an_error_rather_than_a_quiet_no_op(self) -> None:
        with pytest.raises(LeaseError, match="authorises nothing"):
            _lease(expires_at=T0)

    @pytest.mark.parametrize("sensitivity", list(Sensitivity), ids=str)
    def test_a_window_over_the_class_cap_is_refused(self, sensitivity: Sensitivity) -> None:
        """Without a cap, "forever" is spelled as a large number and nothing objects."""
        cap = MAX_DURATION_S[sensitivity]
        with pytest.raises(LeaseError, match="over the"):
            _lease(sensitivity=sensitivity, expires_at=T0 + cap + 1)

    def test_the_year_9999_is_refused_like_any_other_large_number(self) -> None:
        with pytest.raises(LeaseError, match="over the"):
            _lease(expires_at=253_402_300_800.0)

    def test_credential_is_the_most_tightly_capped_class(self) -> None:
        assert MAX_DURATION_S[Sensitivity.CREDENTIAL] == min(MAX_DURATION_S.values())

    @pytest.mark.parametrize("duration", [0, -1, math.inf, math.nan], ids=str)
    def test_granted_refuses_a_duration_that_is_not_finite_and_positive(
        self, duration: float
    ) -> None:
        with pytest.raises(LeaseError, match=r"not a finite positive|not a number"):
            Lease.granted(
                kind=LeaseKind.PATH,
                subject="/srv/secrets",
                granted_by="op",
                reason="why",
                granted_at=T0,
                duration_s=duration,
            )

    @pytest.mark.parametrize("value", [True, "3600", None], ids=["bool", "str", "none"])
    def test_a_non_numeric_expiry_is_refused_rather_than_coerced(self, value: object) -> None:
        with pytest.raises(LeaseError, match="must be a number"):
            _lease(expires_at=value)

    def test_a_stored_lease_with_no_expiry_fails_rather_than_defaulting(self) -> None:
        payload = {
            "kind": "path",
            "subject": "/srv/secrets",
            "granted_by": "op",
            "reason": "why",
            "granted_at": T0,
        }
        with pytest.raises(LeaseError, match="unrepresentable"):
            Lease.from_json(payload)

    def test_a_stored_lease_with_a_null_expiry_fails_too(self) -> None:
        payload = {
            "kind": "path",
            "subject": "/srv/secrets",
            "granted_by": "op",
            "reason": "why",
            "granted_at": T0,
            "expires_at": None,
        }
        with pytest.raises(LeaseError, match="unrepresentable"):
            Lease.from_json(payload)

    def test_a_lease_cannot_be_extended_in_place(self) -> None:
        """Mutation would be an unbounded lease with extra steps."""
        lease = _lease()
        with pytest.raises((AttributeError, TypeError)):
            lease.expires_at = T0 + 900 * DAY  # type: ignore[misc]


class TestARequiredReasonIsRequired:
    @pytest.mark.parametrize("reason", ["", "   ", "\t\n"], ids=["empty", "spaces", "whitespace"])
    def test_a_lease_with_no_reason_is_refused(self, reason: str) -> None:
        with pytest.raises(LeaseError, match="carries no reason"):
            _lease(reason=reason)

    def test_reason_has_no_default(self) -> None:
        assert inspect.signature(Lease).parameters["reason"].default is inspect.Parameter.empty

    def test_a_lease_with_no_grantee_is_refused(self) -> None:
        with pytest.raises(LeaseError, match="who granted it"):
            _lease(granted_by="  ")


class TestExpiryFailsClosed:
    def test_a_lease_is_inactive_at_the_instant_it_expires(self) -> None:
        """Half-open. A boundary that authorises is a boundary nobody granted."""
        lease = _lease(expires_at=T0 + DAY)
        assert lease.is_active(T0 + DAY - 0.001)
        assert not lease.is_active(T0 + DAY)

    def test_a_lease_is_active_at_the_instant_it_is_granted(self) -> None:
        assert _lease().is_active(T0)

    def test_a_lease_is_inactive_before_it_is_granted(self) -> None:
        assert not _lease().is_active(T0 - 1)

    def test_an_expired_lease_is_not_returned_as_active(self) -> None:
        store = InMemoryLeaseStore([_lease()], clock=lambda: T0 + 4 * DAY)
        assert store.active(LeaseKind.PATH, "any-task") == ()

    def test_an_expired_lease_is_still_visible_so_expiry_can_be_told_from_absence(self) -> None:
        """ "Nobody granted it" and "it ran out" are different operator situations."""
        store = InMemoryLeaseStore([_lease()], clock=lambda: T0 + 4 * DAY)
        assert len(store.leases()) == 1
        assert len(store.expired()) == 1

    def test_the_clock_is_injected_so_expiry_is_deterministic(self) -> None:
        ticks = iter([T0, T0 + 4 * DAY])
        store = InMemoryLeaseStore([_lease()], clock=lambda: next(ticks))
        assert store.active(LeaseKind.PATH, "t") != ()
        assert store.active(LeaseKind.PATH, "t") == ()

    def test_a_caller_can_pin_the_instant_so_one_decision_cannot_straddle_two(self) -> None:
        store = InMemoryLeaseStore([_lease()], clock=lambda: T0 + 100 * DAY)
        assert store.active(LeaseKind.PATH, "t", now=T0 + DAY) != ()

    def test_a_lease_of_another_kind_is_not_returned(self) -> None:
        store = InMemoryLeaseStore([_lease()], clock=lambda: T0)
        assert store.active(LeaseKind.HOST, "t") == ()
        assert store.active(LeaseKind.TOOL, "t") == ()

    def test_a_task_pinned_lease_applies_to_that_task_only(self) -> None:
        store = InMemoryLeaseStore([_lease(task_id="ops-nightly")], clock=lambda: T0)
        assert store.active(LeaseKind.PATH, "ops-nightly") != ()
        assert store.active(LeaseKind.PATH, "some-other-task") == ()

    def test_an_unpinned_lease_applies_to_every_task(self) -> None:
        """Stated rather than hidden: this is the widest thing a lease expresses."""
        store = InMemoryLeaseStore([_lease()], clock=lambda: T0)
        assert store.active(LeaseKind.PATH, "anything") != ()


class TestTheStoreCannotMintALease:
    def test_the_store_offers_no_grant(self) -> None:
        """If this class could mint one, code reachable from the loop could too."""
        surface = {name for name in dir(LeaseStore) if not name.startswith("_")}
        assert surface == {
            "now",
            "leases",
            "active",
            "active_paths",
            "active_hosts",
            "active_tools",
            "expired",
        }

    def test_the_lease_module_does_not_import_the_refusal_ledger(self) -> None:
        """Granting names its subject explicitly. It is never derived from a refusal."""
        source = Path(inspect.getsourcefile(leases_module) or "").read_text(encoding="utf-8")
        assert "from agentboundary.ledger" not in source
        assert "import agentboundary.ledger" not in source

    def test_no_lease_constructor_accepts_a_ledger_entry(self) -> None:
        """No signature in this module can take a refusal record as input."""
        annotations: list[str] = []
        for name in leases_module.__all__:
            member = getattr(leases_module, name)
            if not callable(member):
                continue
            try:
                signature = inspect.signature(member)
            except (ValueError, TypeError):  # pragma: no cover - builtins have none
                continue
            annotations.extend(
                str(parameter.annotation) for parameter in signature.parameters.values()
            )
        assert annotations, "introspection found no signatures, so it asserted nothing"
        assert not [text for text in annotations if "Ledger" in text or "Refusal" in text]


class TestSubjectNormalisationMatchesTheCheckItWidens:
    def test_a_relative_path_subject_is_refused(self) -> None:
        with pytest.raises(LeaseError, match="is relative"):
            _lease(subject="secrets")

    def test_an_empty_subject_is_refused(self) -> None:
        with pytest.raises(LeaseError, match="must name a subject"):
            _lease(subject="   ")

    @pytest.mark.parametrize("root", ["/", "//", "/.", "/x/.."], ids=str)
    def test_a_lease_over_the_filesystem_root_is_refused(self, root: str) -> None:
        """A lease over the root does not widen confinement, it removes it."""
        with pytest.raises(LeaseError, match="filesystem root"):
            _lease(subject=root)

    def test_a_lease_one_level_below_the_root_is_allowed(self) -> None:
        """The bound is the root itself, not a general aversion to short paths."""
        assert _lease(subject="/srv").subject == "/srv"

    def test_a_host_subject_is_lowercased_and_loses_its_root_label(self) -> None:
        lease = _lease(kind=LeaseKind.HOST, subject="Docs.Internal.")
        assert lease.subject == "docs.internal"

    def test_a_host_subject_naming_only_the_root_is_refused(self) -> None:
        with pytest.raises(LeaseError, match="names no host"):
            _lease(kind=LeaseKind.HOST, subject=".")

    def test_a_tool_subject_is_normalised_the_way_the_registry_normalises(self) -> None:
        lease = _lease(kind=LeaseKind.TOOL, subject="  tickets.delete  ")
        assert lease.subject == "tickets.delete"


class TestMalformedStores:
    def test_an_unknown_kind_is_refused(self) -> None:
        with pytest.raises(LeaseError, match="unknown kind"):
            Lease.from_json(
                {
                    "kind": "everything",
                    "subject": "/x",
                    "granted_by": "op",
                    "reason": "r",
                    "granted_at": T0,
                    "expires_at": T0 + DAY,
                }
            )

    def test_an_unknown_sensitivity_is_refused_not_downgraded(self) -> None:
        with pytest.raises(LeaseError, match="unknown sensitivity"):
            Lease.from_json(
                {
                    "kind": "path",
                    "subject": "/x",
                    "granted_by": "op",
                    "reason": "r",
                    "granted_at": T0,
                    "expires_at": T0 + DAY,
                    "sensitivity": "harmless",
                }
            )

    def test_an_unstated_sensitivity_is_credential(self) -> None:
        """FR-014's reasoning: the unsafe default is the one we do not make convenient."""
        lease = Lease.from_json(
            {
                "kind": "path",
                "subject": "/x",
                "granted_by": "op",
                "reason": "r",
                "granted_at": T0,
                "expires_at": T0 + DAY,
            }
        )
        assert lease.sensitivity is Sensitivity.CREDENTIAL

    def test_the_dataclass_default_is_credential_too(self) -> None:
        assert _lease().sensitivity is Sensitivity.CREDENTIAL

    def test_a_file_store_with_a_malformed_line_fails_loudly(self, tmp_path: Path) -> None:
        """Skipping the line would narrow the store silently, and quiet is the bug."""
        path = tmp_path / "leases.jsonl"
        path.write_text('{"kind": "path"\n', encoding="utf-8")
        with pytest.raises(LeaseError, match="not valid JSON"):
            FileLeaseStore(path, clock=lambda: T0).leases()

    def test_a_file_store_line_that_is_not_an_object_fails(self, tmp_path: Path) -> None:
        path = tmp_path / "leases.jsonl"
        path.write_text('["path", "/srv/secrets"]\n', encoding="utf-8")
        with pytest.raises(LeaseError, match="not a JSON object"):
            FileLeaseStore(path, clock=lambda: T0).leases()

    def test_a_file_store_with_an_over_cap_lease_fails(self, tmp_path: Path) -> None:
        path = tmp_path / "leases.jsonl"
        path.write_text(
            json.dumps(
                {
                    "kind": "path",
                    "subject": "/srv/secrets",
                    "granted_by": "op",
                    "reason": "r",
                    "granted_at": T0,
                    "expires_at": T0 + 900 * DAY,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        with pytest.raises(LeaseError, match="over the"):
            FileLeaseStore(path, clock=lambda: T0).leases()

    def test_an_absent_file_is_no_leases_rather_than_an_error(self, tmp_path: Path) -> None:
        """A deployment that granted nothing has no leases. That is the narrow answer."""
        assert FileLeaseStore(tmp_path / "none.jsonl", clock=lambda: T0).leases() == ()

    def test_a_relative_store_path_is_refused(self) -> None:
        with pytest.raises(ValueError, match="relative"):
            FileLeaseStore("leases.jsonl")

    def test_blank_lines_are_ignored(self, tmp_path: Path) -> None:
        path = tmp_path / "leases.jsonl"
        path.write_text("\n" + json.dumps(_lease().to_json()) + "\n\n", encoding="utf-8")
        assert len(FileLeaseStore(path, clock=lambda: T0).leases()) == 1


class TestTheShapesThatWork:
    def test_a_three_day_credential_lease_round_trips(self, tmp_path: Path) -> None:
        lease = Lease.granted(
            kind=LeaseKind.PATH,
            subject="/srv/agent-boundary/secrets",
            granted_by="operator@example.test",
            reason="nightly rotation automation needs the key directory, OPS-4821",
            granted_at=T0,
            duration_s=3 * DAY,
        )
        path = tmp_path / "leases.jsonl"
        path.write_text(json.dumps(lease.to_json()) + "\n", encoding="utf-8")
        loaded = FileLeaseStore(path, clock=lambda: T0 + DAY).active(LeaseKind.PATH, "t")
        assert loaded == (lease,)
        assert loaded[0].duration_s == 3 * DAY
        assert loaded[0].sensitivity is Sensitivity.CREDENTIAL

    def test_a_lease_at_exactly_the_cap_is_allowed(self) -> None:
        """The cap is a maximum, not an exclusive bound; an off-by-one here is a false refusal."""
        assert _lease(expires_at=T0 + MAX_DURATION_S[Sensitivity.CREDENTIAL]).is_active(T0)

    def test_the_digest_distinguishes_two_leases_over_the_same_subject(self) -> None:
        first = _lease()
        second = _lease(reason="a different stated reason")
        assert first.digest != second.digest

    def test_the_digest_is_stable_for_one_lease(self) -> None:
        assert _lease().digest == _lease().digest

    def test_a_file_store_reflects_a_revocation_on_the_next_lookup(self, tmp_path: Path) -> None:
        """Removing a line revokes; the next call is refused, not the next restart."""
        path = tmp_path / "leases.jsonl"
        path.write_text(json.dumps(_lease().to_json()) + "\n", encoding="utf-8")
        store = FileLeaseStore(path, clock=lambda: T0)
        assert store.active(LeaseKind.PATH, "t") != ()
        path.write_text("", encoding="utf-8")
        assert store.active(LeaseKind.PATH, "t") == ()


class TestRendering:
    def test_an_empty_store_says_so(self) -> None:
        assert describe((), T0) == "No leases granted."

    def test_an_active_lease_shows_time_remaining(self) -> None:
        text = describe([_lease()], T0 + DAY)
        assert "active" in text
        assert "48.0h remaining" in text

    def test_an_expired_lease_is_marked_expired(self) -> None:
        assert "EXPIRED" in describe([_lease()], T0 + 4 * DAY)

    def test_a_future_lease_is_marked_not_yet_in_force(self) -> None:
        assert "not yet in force" in describe([_lease()], T0 - DAY)

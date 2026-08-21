"""The guard is a control, so it is tested like one -- refusals first."""

from __future__ import annotations

import pytest

from agentboundary.testing import (
    ADVERSARIAL,
    E2E,
    GUARDED_TIERS,
    GUI,
    AdversarialSuiteInvalid,
    GuardedTier,
    SuiteInvalid,
    SuiteOutcome,
    evaluate_suite,
    outcome_for,
    tier_by_flag,
)


class TestRefusals:
    """Every way the guard must refuse to call a run 'evidence'."""

    def test_zero_collected_is_refused(self) -> None:
        with pytest.raises(SuiteInvalid, match="collected zero payloads"):
            evaluate_suite(SuiteOutcome(collected=0))

    def test_below_minimum_is_refused(self) -> None:
        with pytest.raises(SuiteInvalid, match="below the required minimum"):
            evaluate_suite(SuiteOutcome(collected=4, minimum=30))

    def test_a_single_skip_is_refused(self) -> None:
        with pytest.raises(SuiteInvalid, match="skipped 1 payload"):
            evaluate_suite(
                SuiteOutcome(collected=42, skipped=("tests/adversarial/test_a1.py::test_ssh_key",))
            )

    def test_skip_is_refused_even_when_the_rest_passed(self) -> None:
        """A passing suite with one skipped attack is still not evidence."""
        with pytest.raises(SuiteInvalid) as excinfo:
            evaluate_suite(SuiteOutcome(collected=99, skipped=("tests/adversarial/test_a5.py::x",)))
        assert "was not shown to be refused" in str(excinfo.value)

    def test_refusal_message_names_the_skipped_payloads(self) -> None:
        """An operator reading CI output must know which payload to fix."""
        with pytest.raises(SuiteInvalid) as excinfo:
            evaluate_suite(
                SuiteOutcome(collected=42, skipped=("payload_b", "payload_a")),
            )
        message = str(excinfo.value)
        assert "payload_a" in message
        assert "payload_b" in message
        # Sorted, so the message is stable across runs and diffable in CI logs.
        assert message.index("payload_a") < message.index("payload_b")


class TestEveryGuardedTierRefusesTheSameWay:
    """N-31. The failure mode is identical one tier over, so the refusal is too."""

    @pytest.mark.parametrize("tier", GUARDED_TIERS, ids=lambda tier: tier.name)
    def test_zero_collected_is_refused_for_every_tier(self, tier: GuardedTier) -> None:
        with pytest.raises(SuiteInvalid) as excinfo:
            evaluate_suite(outcome_for(tier, collected=0))
        message = str(excinfo.value)
        # Named, not generic: an operator reading CI must know which tier died.
        assert message.startswith(f"{tier.name} suite collected zero")

    @pytest.mark.parametrize("tier", GUARDED_TIERS, ids=lambda tier: tier.name)
    def test_a_skip_is_refused_for_every_tier(self, tier: GuardedTier) -> None:
        with pytest.raises(SuiteInvalid) as excinfo:
            evaluate_suite(outcome_for(tier, collected=999, skipped=("some::test",)))
        message = str(excinfo.value)
        assert f"{tier.name} suite skipped 1" in message
        assert "some::test" in message
        # Says what the skip actually cost, in the tier's own terms.
        assert tier.at_stake in message

    @pytest.mark.parametrize("tier", GUARDED_TIERS, ids=lambda tier: tier.name)
    def test_one_item_short_of_the_floor_is_refused(self, tier: GuardedTier) -> None:
        """The off-by-one, because a floor that admits `minimum - 1` is not a floor."""
        with pytest.raises(SuiteInvalid, match="below the required minimum"):
            evaluate_suite(outcome_for(tier, collected=tier.minimum - 1))

    @pytest.mark.parametrize("tier", GUARDED_TIERS, ids=lambda tier: tier.name)
    def test_the_floor_cannot_be_weakened_while_arming_the_tier(self, tier: GuardedTier) -> None:
        """`outcome_for` reads the floor from the tier, so no caller can lower it."""
        assert outcome_for(tier, collected=1).minimum == tier.minimum


class TestTheE2ETierIsGuardedAgainstItsOwnDependency:
    """The concrete failure N-31 was opened for: an absent optional extra.

    Before this, `make test-e2e` reported success on a tier whose MCP SDK was
    not installed -- 50 in-process tests passing while nothing crossed a
    transport at all.
    """

    def test_a_tier_reduced_to_nothing_is_refused_rather_than_reported_green(
        self,
    ) -> None:
        with pytest.raises(SuiteInvalid, match="whether its optional dependencies are installed"):
            evaluate_suite(outcome_for(E2E, collected=0))

    def test_an_importorskip_on_the_sdk_is_refused_rather_than_tolerated(self) -> None:
        """The tempting fix for a missing extra is a skip. It is prohibited here."""
        with pytest.raises(SuiteInvalid) as excinfo:
            evaluate_suite(
                outcome_for(
                    E2E,
                    collected=75,
                    skipped=("tests/e2e/test_stdio_transport.py::test_a_refusal_crosses",),
                )
            )
        assert "not shown to survive the transport" in str(excinfo.value)


class TestAuthorisations:
    """The cases that legitimately constitute evidence."""

    def test_collected_payloads_with_no_skips_is_accepted(self) -> None:
        evaluate_suite(SuiteOutcome(collected=30, skipped=()))

    def test_exactly_at_the_minimum_is_accepted(self) -> None:
        evaluate_suite(SuiteOutcome(collected=30, minimum=30))

    @pytest.mark.parametrize("tier", GUARDED_TIERS, ids=lambda tier: tier.name)
    def test_exactly_at_the_floor_is_accepted_for_every_tier(self, tier: GuardedTier) -> None:
        evaluate_suite(outcome_for(tier, collected=tier.minimum))


class TestConstruction:
    """The outcome type refuses to represent a nonsensical run."""

    def test_negative_collection_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="cannot be negative"):
            SuiteOutcome(collected=-1)

    def test_a_minimum_of_zero_is_rejected(self) -> None:
        """Allowing minimum=0 would let a caller disable the guard by config."""
        with pytest.raises(ValueError, match="not a control"):
            SuiteOutcome(collected=5, minimum=0)

    def test_outcome_is_immutable(self) -> None:
        outcome = SuiteOutcome(collected=5)
        with pytest.raises(AttributeError):
            outcome.collected = 0  # type: ignore[misc]

    def test_the_default_tier_is_the_adversarial_corpus(self) -> None:
        """Existing call sites keep their meaning after N-31 generalised the type."""
        assert SuiteOutcome(collected=30).tier is ADVERSARIAL


class TestTierDeclarations:
    """A tier declaration is itself a place the control could be disabled."""

    def test_a_tier_declaring_a_zero_floor_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="not a control"):
            GuardedTier(
                name="sham",
                segment="sham/",
                flag="--sham-guard",
                marker="sham",
                minimum=0,
                noun="test",
                at_stake="nothing",
            )

    def test_a_tier_declaring_a_negative_floor_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="not a control"):
            GuardedTier(
                name="sham",
                segment="sham/",
                flag="--sham-guard",
                marker="sham",
                minimum=-1,
                noun="test",
                at_stake="nothing",
            )

    def test_an_unknown_flag_is_an_error_not_a_silent_no_op(self) -> None:
        """A typo in a CI flag must fail loudly, not disarm the guard quietly."""
        with pytest.raises(KeyError, match="no guarded tier declares the flag"):
            tier_by_flag("--advarserial-guard")

    @pytest.mark.parametrize("tier", GUARDED_TIERS, ids=lambda tier: tier.name)
    def test_every_tier_is_reachable_by_its_flag(self, tier: GuardedTier) -> None:
        assert tier_by_flag(tier.flag) is tier

    def test_flags_are_unique(self) -> None:
        flags = [tier.flag for tier in GUARDED_TIERS]
        assert len(set(flags)) == len(flags)

    def test_segments_are_unique(self) -> None:
        """Two tiers sharing a segment would double-count and mask a loss."""
        segments = [tier.segment for tier in GUARDED_TIERS]
        assert len(set(segments)) == len(segments)

    def test_the_three_blocking_tiers_are_all_guarded(self) -> None:
        """WORKING_METHODS.md §5: adversarial, e2e and gui are all blocking."""
        assert {tier.name for tier in GUARDED_TIERS} == {"adversarial", "e2e", "gui"}
        assert (ADVERSARIAL, E2E, GUI) == GUARDED_TIERS

    def test_a_tier_is_immutable(self) -> None:
        with pytest.raises(AttributeError):
            E2E.minimum = 1  # type: ignore[misc]


class TestTheAdrNameStillResolves:
    def test_the_documented_exception_name_is_the_same_class(self) -> None:
        """ADR-0006 names AdversarialSuiteInvalid, and downstream corpora import it."""
        assert AdversarialSuiteInvalid is SuiteInvalid
        with pytest.raises(AdversarialSuiteInvalid):
            evaluate_suite(SuiteOutcome(collected=0))

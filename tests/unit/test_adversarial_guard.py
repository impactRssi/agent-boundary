"""The guard is a control, so it is tested like one -- refusals first."""

from __future__ import annotations

import pytest

from agentboundary.testing import AdversarialSuiteInvalid, SuiteOutcome, evaluate_suite


class TestRefusals:
    """Every way the guard must refuse to call a run 'evidence'."""

    def test_zero_collected_is_refused(self) -> None:
        with pytest.raises(AdversarialSuiteInvalid, match="collected zero payloads"):
            evaluate_suite(SuiteOutcome(collected=0))

    def test_below_minimum_is_refused(self) -> None:
        with pytest.raises(AdversarialSuiteInvalid, match="below the required minimum"):
            evaluate_suite(SuiteOutcome(collected=4, minimum=30))

    def test_a_single_skip_is_refused(self) -> None:
        with pytest.raises(AdversarialSuiteInvalid, match="skipped 1 payload"):
            evaluate_suite(
                SuiteOutcome(collected=12, skipped=("tests/adversarial/test_a1.py::test_ssh_key",))
            )

    def test_skip_is_refused_even_when_the_rest_passed(self) -> None:
        """A passing suite with one skipped attack is still not evidence."""
        with pytest.raises(AdversarialSuiteInvalid) as excinfo:
            evaluate_suite(SuiteOutcome(collected=99, skipped=("tests/adversarial/test_a5.py::x",)))
        assert "was not shown to be refused" in str(excinfo.value)

    def test_refusal_message_names_the_skipped_payloads(self) -> None:
        """An operator reading CI output must know which payload to fix."""
        with pytest.raises(AdversarialSuiteInvalid) as excinfo:
            evaluate_suite(
                SuiteOutcome(collected=3, skipped=("payload_b", "payload_a")),
            )
        message = str(excinfo.value)
        assert "payload_a" in message
        assert "payload_b" in message
        # Sorted, so the message is stable across runs and diffable in CI logs.
        assert message.index("payload_a") < message.index("payload_b")


class TestAuthorisations:
    """The cases that legitimately constitute evidence."""

    def test_collected_payloads_with_no_skips_is_accepted(self) -> None:
        evaluate_suite(SuiteOutcome(collected=30, skipped=()))

    def test_exactly_at_the_minimum_is_accepted(self) -> None:
        evaluate_suite(SuiteOutcome(collected=30, minimum=30))


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

"""Guard that makes the adversarial suite a control rather than a formality.

A test suite that passes because it collected nothing is indistinguishable, at
the CI status level, from one that passed because every attack was refused.
The second is a security control. The first is a green tick.

This module makes the difference observable: it refuses a run that collected
fewer payloads than required, or that skipped one. See ADR-0006.
"""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = ["AdversarialSuiteInvalid", "SuiteOutcome", "evaluate_suite"]

#: Minimum number of collected adversarial test items for the suite to count as
#: a control at all. This is a floor against catastrophic loss -- a moved
#: directory, a broken marker, a bad testpaths edit -- not a measure of corpus
#: breadth.
#:
#: Corpus breadth is asserted separately and precisely, by the coverage tests in
#: tests/adversarial/: the 30-payload and 7-carrier floors of SPEC.md TR-003,
#: and one payload per attack-table row (TR-002). Those assert over payload
#: *declarations*; this asserts over what pytest actually collected. Both are
#: needed, because a full corpus that pytest never discovered is still a suite
#: that proved nothing.
MINIMUM_PAYLOADS = 30


class AdversarialSuiteInvalid(Exception):
    """The adversarial run cannot be trusted, whatever its pass/fail status."""


@dataclass(frozen=True)
class SuiteOutcome:
    """What an adversarial run actually did, as opposed to what it reported."""

    collected: int
    skipped: tuple[str, ...] = field(default=())
    minimum: int = MINIMUM_PAYLOADS

    def __post_init__(self) -> None:
        if self.collected < 0:
            msg = "collected count cannot be negative"
            raise ValueError(msg)
        if self.minimum < 1:
            msg = "minimum must be at least 1; a suite allowed to collect nothing is not a control"
            raise ValueError(msg)


def evaluate_suite(outcome: SuiteOutcome) -> None:
    """Raise if the run does not constitute evidence.

    Two failure modes, both of which otherwise produce a passing build:

    * Nothing was collected -- a path typo, a renamed marker, a moved corpus
      directory. The suite reports success having asserted nothing.
    * Something was skipped -- an unavailable fixture or a quarantined payload.
      A skipped attack is an attack that was not shown to be refused.

    Raises:
        AdversarialSuiteInvalid: with a message naming the specific defect.
    """
    if outcome.collected == 0:
        msg = (
            "adversarial suite collected zero payloads. A security suite that "
            "asserts nothing is not evidence; failing the build rather than "
            "reporting success. Check the marker, the testpaths, and the corpus "
            "directory."
        )
        raise AdversarialSuiteInvalid(msg)

    if outcome.collected < outcome.minimum:
        msg = (
            f"adversarial suite collected {outcome.collected} payloads, "
            f"below the required minimum of {outcome.minimum}. The corpus has "
            f"shrunk or is not being discovered."
        )
        raise AdversarialSuiteInvalid(msg)

    if outcome.skipped:
        listed = ", ".join(sorted(outcome.skipped))
        msg = (
            f"adversarial suite skipped {len(outcome.skipped)} payload(s): {listed}. "
            f"A skipped attack is an attack that was not shown to be refused. "
            f"Fix the payload or remove it from the corpus deliberately -- do not "
            f"let it skip."
        )
        raise AdversarialSuiteInvalid(msg)

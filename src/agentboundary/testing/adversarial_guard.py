"""Guard that makes a test tier a control rather than a formality.

A test suite has a failure mode that a green tick cannot distinguish from
success: **collecting nothing**. A renamed directory, a mistyped marker, a bad
``testpaths`` edit, an absent optional dependency -- and the suite passes having
asserted nothing at all. The same applies to a skip: a skipped test is a claim
that was not shown to hold, and the run still reports success.

This module makes the difference observable: it refuses a run in which a
guarded tier collected fewer items than its floor, or skipped one. See ADR-0006.

Originally the adversarial corpus was the only guarded tier, which is why the
module is named for it. Node N-31 extended it to the end-to-end and GUI tiers
rather than writing a second guard: the failure mode is identical one tier over,
and two implementations of the same control drift apart. The tier a run is
guarded against is now data (:data:`GUARDED_TIERS`), so adding a tier cannot
forget its flag, its floor, or its marker.
"""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = [
    "ADVERSARIAL",
    "E2E",
    "GUARDED_TIERS",
    "GUI",
    "AdversarialSuiteInvalid",
    "GuardedTier",
    "SuiteInvalid",
    "SuiteOutcome",
    "evaluate_suite",
    "outcome_for",
    "tier_by_flag",
]


class SuiteInvalid(Exception):
    """The run cannot be trusted as evidence, whatever its pass/fail status."""


#: ADR-0006 names the exception ``AdversarialSuiteInvalid``, and this module is
#: exported for downstream corpora. The alias keeps both true after the rename;
#: a traceback reading "adversarial suite invalid" for a GUI run would be a
#: small lie told at exactly the moment someone is reading carefully.
AdversarialSuiteInvalid = SuiteInvalid


@dataclass(frozen=True, slots=True)
class GuardedTier:
    """One tier that must not be able to pass by collecting nothing.

    ``segment`` identifies members of the tier by **location**, never by
    marker. A decorator can be forgotten; a directory cannot. It is also what
    lets the guard notice a tier that has vanished entirely, which is the case
    it exists to catch.
    """

    #: How the tier is named in CI output and in refusal messages.
    name: str
    #: Path fragment that identifies a node id as belonging to this tier.
    segment: str
    #: The opt-in pytest flag that arms the guard for this tier.
    flag: str
    #: Marker applied to every item in the tier, by location.
    marker: str
    #: Floor against catastrophic loss, not a measure of breadth.
    minimum: int
    #: Singular noun for one member of the tier, used in messages.
    noun: str
    #: What a skipped member costs, stated in the tier's own terms.
    at_stake: str

    def __post_init__(self) -> None:
        if self.minimum < 1:
            msg = (
                f"tier {self.name!r} declares a minimum of {self.minimum}; a tier "
                f"allowed to collect nothing is not a control"
            )
            raise ValueError(msg)


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

ADVERSARIAL = GuardedTier(
    name="adversarial",
    segment="adversarial/",
    flag="--adversarial-guard",
    marker="security",
    minimum=MINIMUM_PAYLOADS,
    noun="payload",
    at_stake=(
        "A skipped attack is an attack that was not shown to be refused. "
        "Fix the payload or remove it from the corpus deliberately -- do not "
        "let it skip."
    ),
)

#: The E2E floor is set well below the current count so ordinary churn does not
#: trip it; it catches losing a module, not losing a test. The case it is really
#: here for is the optional ``mcp`` extra going absent: without the SDK the tier
#: cannot cross a transport at all, and before N-31 it reported success anyway.
E2E = GuardedTier(
    name="e2e",
    segment="e2e/",
    flag="--e2e-guard",
    marker="e2e",
    minimum=40,
    noun="test",
    at_stake=(
        "A skipped end-to-end test is an invariant that was not shown to survive "
        "the transport. Fix it or remove it deliberately -- do not let it skip."
    ),
)

#: Likewise for the GUI tier and the browser: a missing Playwright browser must
#: fail the build, not quietly reduce the tier to nothing.
GUI = GuardedTier(
    name="gui",
    segment="gui/",
    flag="--gui-guard",
    marker="gui",
    minimum=10,
    noun="test",
    at_stake=(
        "A skipped GUI test is something an operator was not shown to be able to "
        "see. Fix it or remove it deliberately -- do not let it skip."
    ),
)

#: Every guarded tier. Ordering matters only for message stability.
GUARDED_TIERS: tuple[GuardedTier, ...] = (ADVERSARIAL, E2E, GUI)


def tier_by_flag(flag: str) -> GuardedTier:
    """Resolve a tier from its pytest flag. Unknown flags are an error, not a no-op."""
    for tier in GUARDED_TIERS:
        if tier.flag == flag:
            return tier
    msg = f"no guarded tier declares the flag {flag!r}; known flags: " + ", ".join(
        tier.flag for tier in GUARDED_TIERS
    )
    raise KeyError(msg)


@dataclass(frozen=True)
class SuiteOutcome:
    """What a run actually did, as opposed to what it reported."""

    collected: int
    skipped: tuple[str, ...] = field(default=())
    minimum: int = MINIMUM_PAYLOADS
    tier: GuardedTier = ADVERSARIAL

    def __post_init__(self) -> None:
        if self.collected < 0:
            msg = "collected count cannot be negative"
            raise ValueError(msg)
        if self.minimum < 1:
            msg = "minimum must be at least 1; a suite allowed to collect nothing is not a control"
            raise ValueError(msg)


def outcome_for(tier: GuardedTier, collected: int, skipped: tuple[str, ...] = ()) -> SuiteOutcome:
    """Build an outcome whose floor comes from the tier itself.

    The floor is read from the tier rather than passed in, so a caller cannot
    arm the guard for a tier and silently weaken it in the same call.
    """
    return SuiteOutcome(collected=collected, skipped=skipped, minimum=tier.minimum, tier=tier)


def evaluate_suite(outcome: SuiteOutcome) -> None:
    """Raise if the run does not constitute evidence.

    Two failure modes, both of which otherwise produce a passing build:

    * Nothing was collected -- a path typo, a renamed marker, a moved corpus
      directory, an absent optional dependency. The suite reports success
      having asserted nothing.
    * Something was skipped -- an unavailable fixture or a quarantined test.
      A skipped test is a claim that was not shown to hold.

    Raises:
        SuiteInvalid: with a message naming the tier and the specific defect.
    """
    tier = outcome.tier

    if outcome.collected == 0:
        msg = (
            f"{tier.name} suite collected zero {tier.noun}s. A suite that "
            f"asserts nothing is not evidence; failing the build rather than "
            f"reporting success. Check the marker, the testpaths, the tier "
            f"directory, and whether its optional dependencies are installed."
        )
        raise SuiteInvalid(msg)

    if outcome.collected < outcome.minimum:
        msg = (
            f"{tier.name} suite collected {outcome.collected} {tier.noun}s, "
            f"below the required minimum of {outcome.minimum}. The tier has "
            f"shrunk or is not being discovered."
        )
        raise SuiteInvalid(msg)

    if outcome.skipped:
        listed = ", ".join(sorted(outcome.skipped))
        msg = (
            f"{tier.name} suite skipped {len(outcome.skipped)} {tier.noun}(s): "
            f"{listed}. {tier.at_stake}"
        )
        raise SuiteInvalid(msg)

"""Test-time controls shipped with the package.

These are exported rather than kept in the test tree because downstream users
wiring their own suites need the same guarantee we do: a suite that can silently
collect zero tests is not a control.
"""

from agentboundary.testing.adversarial_guard import (
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
from agentboundary.testing.catalogue import reference_registry
from agentboundary.testing.corpus import Payload, broker_for, load_corpus

__all__ = [
    "ADVERSARIAL",
    "E2E",
    "GUARDED_TIERS",
    "GUI",
    "AdversarialSuiteInvalid",
    "GuardedTier",
    "Payload",
    "SuiteInvalid",
    "SuiteOutcome",
    "broker_for",
    "evaluate_suite",
    "load_corpus",
    "outcome_for",
    "reference_registry",
    "tier_by_flag",
]

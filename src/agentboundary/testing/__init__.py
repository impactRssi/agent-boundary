"""Test-time controls shipped with the package.

These are exported rather than kept in the test tree because downstream users
wiring their own adversarial corpus need the same guarantee we do: a security
suite that can silently collect zero tests is not a control.
"""

from agentboundary.testing.adversarial_guard import (
    AdversarialSuiteInvalid,
    SuiteOutcome,
    evaluate_suite,
)

__all__ = ["AdversarialSuiteInvalid", "SuiteOutcome", "evaluate_suite"]

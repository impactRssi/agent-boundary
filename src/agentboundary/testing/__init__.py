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
from agentboundary.testing.workspace import (
    BuiltWorkspace,
    Resolver,
    SinkNotLocalError,
    WorkspaceDeclaration,
    WorkspaceRejected,
    assert_sinks_are_local,
    build_workspace,
    destination_of,
    load_declaration,
    refuse_all_names,
    urls_in,
)

__all__ = [
    "ADVERSARIAL",
    "E2E",
    "GUARDED_TIERS",
    "GUI",
    "AdversarialSuiteInvalid",
    "BuiltWorkspace",
    "GuardedTier",
    "Payload",
    "Resolver",
    "SinkNotLocalError",
    "SuiteInvalid",
    "SuiteOutcome",
    "WorkspaceDeclaration",
    "WorkspaceRejected",
    "assert_sinks_are_local",
    "broker_for",
    "build_workspace",
    "destination_of",
    "evaluate_suite",
    "load_corpus",
    "load_declaration",
    "outcome_for",
    "reference_registry",
    "refuse_all_names",
    "tier_by_flag",
    "urls_in",
]

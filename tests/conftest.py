"""Shared pytest configuration, and the per-tier collection guards.

The guards deliberately live *here* rather than in the tier directories.

A conftest in a subdirectory is only registered as a plugin once pytest
collects that directory. If a tier directory were renamed, moved, or excluded
by a bad ``testpaths`` entry, a conftest living inside it would never load --
and the guard against collecting zero tests would itself be the thing that
silently disappeared. Putting it in an initial conftest means it runs even when
the tier does not exist at all, which is the case it exists to catch.

One guard, three tiers. The adversarial corpus was guarded from ADR-0006; node
N-31 extended the same guard to the end-to-end and GUI tiers rather than adding
a second one, because the failure mode is identical one tier over and two
implementations of one control drift apart.

See ADR-0006 and ``agentboundary.testing.adversarial_guard``.
"""

from __future__ import annotations

import pytest

from agentboundary.testing import GUARDED_TIERS, GuardedTier, SuiteInvalid, evaluate_suite
from agentboundary.testing import outcome_for as _outcome_for

_collected: dict[str, list[str]] = {tier.name: [] for tier in GUARDED_TIERS}
_skipped: dict[str, list[str]] = {tier.name: [] for tier in GUARDED_TIERS}


def _tier_of(nodeid: str) -> GuardedTier | None:
    """Identify a test's tier by location rather than by marker.

    Location cannot be forgotten. A file dropped into a tier directory is
    counted whether or not its author remembered the marker.
    """
    normalised = nodeid.replace("\\", "/")
    for tier in GUARDED_TIERS:
        if tier.segment in normalised:
            return tier
    return None


def pytest_addoption(parser: pytest.Parser) -> None:
    """Register one guard flag per tier, from the tier declarations themselves.

    Opt-in, so ``pytest tests/unit`` during development is not told the other
    tiers are missing. CI always passes the flags; see ci.yml and the
    ``guards-fail-closed`` target in the Makefile.

    Generated from :data:`GUARDED_TIERS` rather than written out, so a new tier
    cannot be added with a floor and a marker but no way to arm it.
    """
    for tier in GUARDED_TIERS:
        parser.addoption(
            tier.flag,
            action="store_true",
            default=False,
            help=(
                f"Fail the session if the {tier.name} tier collected fewer than "
                f"{tier.minimum} {tier.noun}s or skipped one. Required in CI."
            ),
        )


def pytest_configure(config: pytest.Config) -> None:
    """Reset per-session state so repeated in-process runs do not accumulate."""
    del config
    for record in (_collected, _skipped):
        for entries in record.values():
            entries.clear()


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Apply each tier's marker by location, before any selection happens.

    Deliberately early: ``-m security`` has to be able to select on a marker
    this hook applied, so the marker cannot wait until after filtering.
    """
    for item in items:
        tier = _tier_of(item.nodeid)
        if tier is not None:
            item.add_marker(getattr(pytest.mark, tier.marker))


def pytest_collection_finish(session: pytest.Session) -> None:
    """Record what will actually run, once every plugin has finished filtering.

    Counting during ``pytest_collection_modifyitems`` counts what was
    *discovered*, which is not the same thing: ``-k``, ``-m`` and
    ``--deselect`` all run in that same hook, and a conftest's implementation
    is called before them. A tier emptied by a selection expression would then
    be counted as full, and the guard would pass over a tier that ran nothing.

    ``pytest_collection_finish`` runs after all of it, so this counts the
    surviving items -- which is the number the guard is about.
    """
    for item in session.items:
        tier = _tier_of(item.nodeid)
        if tier is not None:
            _collected[tier.name].append(item.nodeid)


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    """Record any test that skipped instead of asserting what it exists to assert."""
    if report.when != "setup" or not report.skipped:
        return
    tier = _tier_of(report.nodeid)
    if tier is not None:
        _skipped[tier.name].append(report.nodeid)


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Fail the session when a guarded run does not constitute evidence.

    This must run regardless of whether the tests passed: a green suite that
    collected nothing is precisely the failure mode being guarded against, so
    the check cannot be conditional on the suite having failed.

    Every armed tier is evaluated before reporting, so a run that broke two
    tiers says so once rather than sending the reader round twice.
    """
    del exitstatus

    failures: list[str] = []
    for tier in GUARDED_TIERS:
        if not session.config.getoption(tier.flag, default=False):
            continue
        try:
            evaluate_suite(
                _outcome_for(
                    tier,
                    collected=len(_collected[tier.name]),
                    skipped=tuple(_skipped[tier.name]),
                )
            )
        except SuiteInvalid as exc:
            failures.append(str(exc))

    if not failures:
        return

    session.exitstatus = pytest.ExitCode.TESTS_FAILED
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    if reporter is not None:
        reporter.write_sep("=", "TEST TIER INVALID", red=True, bold=True)
        for message in failures:
            reporter.write_line(message)

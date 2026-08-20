"""Shared pytest configuration, and the adversarial-suite guard.

The guard deliberately lives *here* rather than in ``tests/adversarial/``.

A conftest in a subdirectory is only registered as a plugin once pytest
collects that directory. If the corpus directory were renamed, moved, or
excluded by a bad ``testpaths`` entry, a conftest living inside it would never
load -- and the guard against collecting zero payloads would itself be the
thing that silently disappeared. Putting it in an initial conftest means it
runs even when the corpus does not exist at all, which is the case it exists
to catch.

See ADR-0006 and ``agentboundary.testing.adversarial_guard``.
"""

from __future__ import annotations

import pytest

from agentboundary.testing import AdversarialSuiteInvalid, SuiteOutcome, evaluate_suite

_ADVERSARIAL_SEGMENT = "adversarial/"

_collected: list[str] = []
_skipped: list[str] = []


def _is_adversarial(nodeid: str) -> bool:
    """Identify a payload by location rather than by marker.

    Location cannot be forgotten. A payload file dropped into the corpus
    directory is counted whether or not its author remembered the marker.
    """
    return _ADVERSARIAL_SEGMENT in nodeid.replace("\\", "/")


def pytest_addoption(parser: pytest.Parser) -> None:
    """Register the guard flag.

    Opt-in so that ``pytest tests/unit`` during development is not told the
    corpus is missing. CI always passes the flag; see ci.yml.
    """
    parser.addoption(
        "--adversarial-guard",
        action="store_true",
        default=False,
        help=(
            "Fail the session if the adversarial suite collected no payloads "
            "or skipped one. Required in CI."
        ),
    )


def pytest_configure(config: pytest.Config) -> None:
    """Reset per-session state so repeated in-process runs do not accumulate."""
    del config
    _collected.clear()
    _skipped.clear()


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Record discovered payloads and apply the ``security`` marker by location."""
    for item in items:
        if not _is_adversarial(item.nodeid):
            continue
        item.add_marker(pytest.mark.security)
        _collected.append(item.nodeid)


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    """Record any payload that skipped instead of asserting a refusal."""
    if report.when == "setup" and report.skipped and _is_adversarial(report.nodeid):
        _skipped.append(report.nodeid)


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Fail the session when the run does not constitute evidence.

    This must run regardless of whether the payloads passed: a green suite that
    collected nothing is precisely the failure mode being guarded against, so
    the check cannot be conditional on the suite having failed.
    """
    del exitstatus

    if not session.config.getoption("--adversarial-guard", default=False):
        return

    try:
        evaluate_suite(SuiteOutcome(collected=len(_collected), skipped=tuple(_skipped)))
    except AdversarialSuiteInvalid as exc:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
        reporter = session.config.pluginmanager.get_plugin("terminalreporter")
        if reporter is not None:
            reporter.write_sep("=", "ADVERSARIAL SUITE INVALID", red=True, bold=True)
            reporter.write_line(str(exc))

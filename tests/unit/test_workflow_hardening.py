"""The hardening lint must fail on a job that takes what it does not need.

Refusal paths first. Each test removes exactly one property from an otherwise
compliant job and asserts the specific reason, so a checker that started
reporting everything as one generic failure would be caught here rather than in
a reviewer's patience.

The last tests assert against this repository's own workflows: dropping
`persist-credentials: false`, a job's `permissions:` block, or the egress audit
fails the unit tier as well as CI.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from scripts.check_workflow_hardening import (
    REASON_NO_EGRESS_AUDIT,
    REASON_NO_EGRESS_POLICY,
    REASON_NO_JOBS,
    REASON_NO_PERMISSIONS,
    REASON_NO_STEPS,
    REASON_NO_WORKFLOWS,
    REASON_PERSISTED_CREDENTIALS,
    main,
    parse_jobs,
    scan_repository,
    scan_text,
)

REPO_ROOT = Path(__file__).resolve().parents[2]

HARDEN = "step-security/harden-runner@05e31511f85b41b11d1cf0ef85d0992719546e2c # v2.21.0"
CHECKOUT = "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5.1.0"

COMPLIANT = f"""\
name: w

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: {HARDEN}
        with:
          egress-policy: audit
      - uses: {CHECKOUT}
        with:
          persist-credentials: false
      - run: make check
"""


def reasons(text: str) -> list[str]:
    return [v.reason for v in scan_text("w.yml", text)]


# --------------------------------------------------------------------------
# Refusal paths.
# --------------------------------------------------------------------------


def test_job_without_permissions_is_refused() -> None:
    text = COMPLIANT.replace("    permissions:\n      contents: read\n", "")
    assert reasons(text) == [REASON_NO_PERMISSIONS]


def test_checkout_that_persists_credentials_is_refused() -> None:
    text = COMPLIANT.replace("        with:\n          persist-credentials: false\n", "")
    assert reasons(text) == [REASON_PERSISTED_CREDENTIALS]


def test_persist_credentials_true_is_refused() -> None:
    text = COMPLIANT.replace("persist-credentials: false", "persist-credentials: true")
    assert reasons(text) == [REASON_PERSISTED_CREDENTIALS]


def test_job_without_an_egress_audit_is_refused() -> None:
    text = COMPLIANT.replace(
        f"      - uses: {HARDEN}\n        with:\n          egress-policy: audit\n", ""
    )
    assert reasons(text) == [REASON_NO_EGRESS_AUDIT]


def test_egress_audit_that_is_not_the_first_step_is_refused() -> None:
    # A harden-runner step placed after the checkout has already missed the
    # network calls the checkout made, which is the point of putting it first.
    text = f"""\
name: w

jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: {CHECKOUT}
        with:
          persist-credentials: false
      - uses: {HARDEN}
        with:
          egress-policy: audit
"""
    assert reasons(text) == [REASON_NO_EGRESS_AUDIT]


def test_egress_audit_without_a_policy_is_refused() -> None:
    text = COMPLIANT.replace("        with:\n          egress-policy: audit\n", "")
    assert reasons(text) == [REASON_NO_EGRESS_POLICY]


def test_unrecognised_egress_policy_is_refused() -> None:
    text = COMPLIANT.replace("egress-policy: audit", "egress-policy: disabled")
    assert reasons(text) == [REASON_NO_EGRESS_POLICY]


def test_a_comment_mentioning_the_setting_does_not_satisfy_the_check() -> None:
    text = COMPLIANT.replace(
        "          persist-credentials: false\n",
        "          # persist-credentials: false\n          fetch-depth: 0\n",
    )
    assert reasons(text) == [REASON_PERSISTED_CREDENTIALS]


def test_job_without_steps_fails_closed() -> None:
    text = "name: w\n\njobs:\n  build:\n    runs-on: ubuntu-latest\n    permissions: {}\n"
    assert reasons(text) == [REASON_NO_STEPS]


def test_document_without_jobs_fails_closed() -> None:
    assert reasons("name: w\non:\n  push:\n") == [REASON_NO_JOBS]


def test_empty_jobs_map_fails_closed() -> None:
    assert reasons("name: w\n\njobs:\n") == [REASON_NO_JOBS]


def test_absent_workflow_directory_fails_closed(tmp_path: Path) -> None:
    assert [v.reason for v in scan_repository(tmp_path)] == [REASON_NO_WORKFLOWS]


def test_empty_workflow_directory_fails_closed(tmp_path: Path) -> None:
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    assert [v.reason for v in scan_repository(tmp_path)] == [REASON_NO_WORKFLOWS]


def test_main_exits_non_zero_on_an_unhardened_tree(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    text = COMPLIANT.replace("    permissions:\n      contents: read\n", "")
    (workflows / "ci.yml").write_text(text, encoding="utf-8")
    assert main([str(tmp_path)]) == 1


def test_a_second_job_is_examined_not_just_the_first() -> None:
    text = COMPLIANT + COMPLIANT.split("jobs:\n")[1].replace("  build:", "  other:").replace(
        "    permissions:\n      contents: read\n", ""
    )
    assert reasons(text) == [REASON_NO_PERMISSIONS]


# --------------------------------------------------------------------------
# Success path: a lint that fires on a compliant job gets switched off.
# --------------------------------------------------------------------------


def test_compliant_job_is_accepted() -> None:
    assert scan_text("w.yml", COMPLIANT) == []


def test_blocking_egress_policy_is_accepted() -> None:
    # `block` is stronger than what this pipeline runs today. The lint must not
    # stand in the way of tightening it.
    assert (
        scan_text("w.yml", COMPLIANT.replace("egress-policy: audit", "egress-policy: block")) == []
    )


def test_empty_permissions_map_is_accepted() -> None:
    text = COMPLIANT.replace("    permissions:\n      contents: read\n", "    permissions: {}\n")
    assert scan_text("w.yml", text) == []


def test_main_exits_zero_on_a_hardened_tree(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(COMPLIANT, encoding="utf-8")
    assert main([str(tmp_path)]) == 0


# --------------------------------------------------------------------------
# This repository, as it actually stands.
# --------------------------------------------------------------------------


def test_the_parser_actually_finds_this_repositorys_jobs() -> None:
    # Without this the assertion below could pass by parsing nothing.
    ci = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    jobs = parse_jobs(ci)
    assert jobs is not None
    assert {job.name for job in jobs} >= {
        "static",
        "unit",
        "adversarial",
        "e2e",
        "gui",
        "security",
        "gate",
    }


@pytest.mark.parametrize("workflow", ["ci.yml", "release.yml", "dependency-review.yml"])
def test_this_repository_ships_the_workflow(workflow: str) -> None:
    assert (REPO_ROOT / ".github" / "workflows" / workflow).is_file()


def test_this_repository_hardens_every_job() -> None:
    violations = scan_repository(REPO_ROOT)
    assert violations == [], "\n".join(v.render() for v in violations)

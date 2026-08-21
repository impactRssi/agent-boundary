"""The pin checker must fail on a movable reference and pass on a digest.

A checker that is itself untested is a convention with extra steps. These tests
pin both directions: the unpinned forms that must be refused, and the pinned
forms that must not produce noise -- a checker that cries wolf gets disabled.

The last two tests assert against this repository's own workflows, so a tag
reintroduced into `.github/workflows/` fails the unit tier as well as CI.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from scripts.check_action_pins import (
    REASON_MALFORMED_USES,
    REASON_MISSING_COMMENT,
    REASON_NO_WORKFLOWS,
    REASON_UNPINNED_ACTION,
    REASON_UNPINNED_IMAGE,
    main,
    scan_repository,
    scan_text,
)

REPO_ROOT = Path(__file__).resolve().parents[2]

PINNED = "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5.1.0"


def reasons(text: str) -> list[str]:
    return [v.reason for v in scan_text("w.yml", text)]


# --------------------------------------------------------------------------
# Refusal paths first: these are what the check exists for.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "reference",
    [
        "actions/checkout@v5",
        "actions/checkout@v5.1.0",
        "astral-sh/setup-uv@main",
        "gitleaks/gitleaks-action@v2",
        # A short SHA is ambiguous and GitHub resolves it; only the full
        # 40 characters are unforgeable enough to be a pin.
        "actions/checkout@fbc6f39",
        # Upper case is not what git writes, and accepting it would let two
        # spellings of the same pin diverge in review.
        "actions/checkout@FBC6F3992D24B796D5A048FF273F7FCC4A7B6C09",
        # 39 characters: near-miss must not slip through a loose pattern.
        "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c0",
    ],
)
def test_movable_reference_is_refused(reference: str) -> None:
    assert reasons(f"      - uses: {reference}\n") == [REASON_UNPINNED_ACTION]


def test_reusable_workflow_by_tag_is_refused() -> None:
    line = "    uses: owner/repo/.github/workflows/build.yml@v1\n"
    assert reasons(line) == [REASON_UNPINNED_ACTION]


def test_container_image_by_tag_is_refused() -> None:
    assert reasons("      - uses: docker://alpine:3.19\n") == [REASON_UNPINNED_IMAGE]


def test_reference_without_a_ref_is_refused_not_ignored() -> None:
    # No `@` at all. The parser must not silently treat what it cannot
    # decompose as acceptable.
    assert reasons("      - uses: actions/checkout\n") == [REASON_MALFORMED_USES]


def test_digest_without_a_version_comment_is_refused() -> None:
    line = "      - uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09\n"
    assert reasons(line) == [REASON_MISSING_COMMENT]


def test_every_violation_is_reported_not_just_the_first() -> None:
    text = "      - uses: actions/checkout@v5\n      - uses: astral-sh/setup-uv@v7\n"
    assert reasons(text) == [REASON_UNPINNED_ACTION, REASON_UNPINNED_ACTION]


def test_violation_carries_the_line_number() -> None:
    text = "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v5\n"
    (violation,) = scan_text("ci.yml", text)
    assert (violation.path, violation.line) == ("ci.yml", 4)
    assert "actions/checkout@v5" in violation.render()


def test_empty_workflow_directory_fails_closed(tmp_path: Path) -> None:
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    assert [v.reason for v in scan_repository(tmp_path)] == [REASON_NO_WORKFLOWS]


def test_absent_workflow_directory_fails_closed(tmp_path: Path) -> None:
    assert [v.reason for v in scan_repository(tmp_path)] == [REASON_NO_WORKFLOWS]


def test_main_exits_non_zero_on_an_unpinned_tree(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text("      - uses: actions/checkout@v5\n", encoding="utf-8")
    assert main([str(tmp_path)]) == 1


# --------------------------------------------------------------------------
# Success paths: a checker with false positives is a checker that gets removed.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        f"      - uses: {PINNED}",
        f"        uses: {PINNED}",
        f'      - uses: "{PINNED.split(" # ")[0]}" # v5.1.0',
        f"      - uses: '{PINNED.split(' # ')[0]}' # v5.1.0",
        "      - uses: docker://alpine@sha256:" + "a" * 64 + " # 3.19",
        # A composite action living in this repository has no upstream pointer
        # for anyone to move, and no tag to record.
        "      - uses: ./.github/actions/setup",
    ],
)
def test_pinned_reference_is_accepted(line: str) -> None:
    assert scan_text("w.yml", line + "\n") == []


def test_commented_out_reference_is_not_a_violation() -> None:
    assert scan_text("w.yml", "      # - uses: actions/checkout@v5\n") == []


def test_main_exits_zero_on_a_pinned_tree(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(f"      - uses: {PINNED}\n", encoding="utf-8")
    assert main([str(tmp_path)]) == 0


# --------------------------------------------------------------------------
# This repository, as it actually stands.
# --------------------------------------------------------------------------


def test_this_repository_declares_workflows_at_all() -> None:
    # Guards the test below from passing vacuously if the directory moves.
    assert (REPO_ROOT / ".github" / "workflows").is_dir()


def test_this_repository_pins_every_action() -> None:
    violations = scan_repository(REPO_ROOT)
    assert violations == [], "\n".join(v.render() for v in violations)

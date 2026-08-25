"""The release workflow's gate re-run must install what the gate needs.

Written after a release failed. `release.yml` re-runs the whole blocking gate
at the tagged commit -- mypy included, over the whole tree -- and its `uv sync`
was one extra short. Node N-50 added `runner` to the Makefile and to the CI
jobs that needed it and missed this file, so the omission surfaced only at
`git push origin v0.4.0`: after the branch was green, after review, after the
merge, on the one run whose failure is most expensive to recover from.

The check is deliberately narrow. A blanket "every command names every extra"
rule was written first and thrown away: it flagged the GUI job, which syncs
`mcp` because it drives a browser against a trace from the real broker and has
no use for an agent SDK. Forcing an unused dependency into a job is the
opposite of what the rest of this pipeline does, and a guard that has to be
argued with on every reading gets deleted. What is actually load-bearing is
that the *gate re-run* installs what `make install` installs, since `make
install` is defined as "everything the gate needs".
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
RELEASE_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release.yml"

#: `--extra <name>`, as `uv sync` and `uv run` both spell it.
EXTRA = re.compile(r"--extra[ =]([A-Za-z0-9_.-]+)")


def _declared_extras() -> frozenset[str]:
    manifest = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return frozenset(manifest["project"]["optional-dependencies"])


def _sync_commands(path: Path) -> list[tuple[int, str]]:
    """Lines that actually run `uv sync`, comments excluded.

    A comment explaining why a job needs an extra names that extra too, and
    counting it would flag prose for disagreeing with the command beneath it.
    """
    lines = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip().lstrip("-").strip()
        if line.startswith("#") or "uv sync" not in line:
            continue
        lines.append((number, line))
    return lines


def _make_install_extras() -> set[str]:
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    body = makefile.split("install: ##", 1)
    assert len(body) == 2, "no `install:` target in the Makefile any more"
    recipe = body[1].split("\n\n", 1)[0]
    return set(EXTRA.findall(recipe))


def test_make_install_covers_every_declared_extra() -> None:
    """`make install` is the definition the release check is measured against."""
    assert _make_install_extras() == set(_declared_extras()), (
        f"`make install` installs {sorted(_make_install_extras())} but pyproject "
        f"declares {sorted(_declared_extras())}. The gate type-checks the whole "
        "tree, so a missing extra fails it for the wrong reason."
    )


def test_the_release_gate_rerun_installs_what_make_install_installs() -> None:
    syncs = _sync_commands(RELEASE_WORKFLOW)
    assert syncs, "release.yml no longer syncs anything; move this check with it"

    needed = _make_install_extras()
    short = [
        f"release.yml:{number}: installs {sorted(set(EXTRA.findall(line)))}, "
        f"`make install` installs {sorted(needed)} -- {line}"
        for number, line in syncs
        if not needed <= set(EXTRA.findall(line))
    ]
    assert not short, (
        "the release workflow re-runs the whole gate and would fail at tag time:\n  "
        + "\n  ".join(short)
    )


def test_no_command_names_an_extra_that_is_not_declared() -> None:
    declared = _declared_extras()
    unknown = {
        (path.name, number, extra)
        for path in (RELEASE_WORKFLOW, REPO_ROOT / ".github" / "workflows" / "ci.yml")
        for number, line in _sync_commands(path)
        for extra in EXTRA.findall(line)
        if extra not in declared
    }
    assert not unknown, f"commands name extras pyproject does not declare: {sorted(unknown)}"


def test_the_check_would_notice_a_short_sync() -> None:
    """A guard nobody has seen fail is a guard nobody has tested."""
    stale = "uv sync --group dev --group gui --extra mcp --frozen"
    assert not _make_install_extras() <= set(EXTRA.findall(stale))


def test_comments_are_not_mistaken_for_commands() -> None:
    """The first draft of this file flagged prose. It should not."""
    prose = "      # --extra runner adds the agent SDK, which N-50's tier needs"
    assert prose.strip().lstrip("-").strip().startswith("#")

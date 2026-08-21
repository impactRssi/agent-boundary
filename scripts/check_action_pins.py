"""Fail the build when a workflow references an action by a moving reference.

`uses: actions/checkout@v5` names a tag, and a tag is a pointer the action's
owner can move at any time. Whoever controls that pointer controls code that
runs inside the job, with the job's `GITHUB_TOKEN` and the job's filesystem.
A commit SHA is the only reference in git that an upstream maintainer cannot
repoint.

This checker exists because the pin is otherwise a convention, and a convention
is what erodes: the next contributor copies an example from a README, the
example uses a tag, and the pipeline is unpinned again with nobody having
decided that. The structural form -- a pin that cannot be expressed any other
way -- is not available at the repository level; GitHub's `uses:` grammar
accepts a tag and there is no in-repository setting that forbids one. So this
is a call-time check, which is the weaker form, and it is the strongest form
the platform offers. It is wired into `make check` and into the CI gate so that
it runs on every commit rather than on the days someone remembers.

Fail-closed properties:

- Finding no workflow files at all is a failure, not a pass. A checker that
  reports success having examined nothing is indistinguishable from a broken
  one. Same reasoning as the adversarial zero-collect guard (ADR-0006).
- A `uses:` line this parser cannot decompose is a failure, not a skip.

Run it directly, or via `make actions-pinned`.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

WORKFLOW_SUBDIR = Path(".github") / "workflows"
WORKFLOW_SUFFIXES = (".yml", ".yaml")

# Reasons are the interface of this check: CI output is triaged on the string,
# so they are stable and each one means exactly one thing.
REASON_NO_WORKFLOWS = "no-workflow-files-found"
REASON_UNPINNED_ACTION = "action-not-pinned-to-a-commit-sha"
REASON_UNPINNED_IMAGE = "container-image-not-pinned-to-a-digest"
REASON_MALFORMED_USES = "uses-reference-not-parseable"
REASON_MISSING_COMMENT = "digest-has-no-trailing-version-comment"

_USES_LINE = re.compile(
    r"""^\s*(?:-\s+)?uses\s*:\s*(?P<ref>'[^']*'|"[^"]*"|[^\s#]+)(?P<rest>.*)$""",
)
_COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_TRAILING_COMMENT = re.compile(r"^\s*#\s*(?P<comment>\S.*?)\s*$")


@dataclass(frozen=True)
class Violation:
    """One unpinned or unreadable reference, located precisely enough to fix."""

    path: str
    line: int
    reason: str
    detail: str

    def render(self) -> str:
        return f"{self.path}:{self.line}: {self.reason}: {self.detail}"


def _unquote(raw: str) -> str:
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "'\"":
        return raw[1:-1]
    return raw


def _check_reference(path: str, line_no: int, ref: str, rest: str) -> list[Violation]:
    """Classify one `uses:` value. Anything not provably pinned is a violation."""
    comment = _TRAILING_COMMENT.match(rest)

    def missing_comment() -> list[Violation]:
        if comment is not None:
            return []
        return [
            Violation(
                path,
                line_no,
                REASON_MISSING_COMMENT,
                f"{ref} -- append '# <tag>' so a reviewer can see what the digest should be",
            )
        ]

    # A path-local action is code already in this repository, reviewed by the
    # same process as the rest of it. There is no upstream pointer to move.
    if ref.startswith("./"):
        return []

    if ref.startswith("docker://"):
        image = ref.removeprefix("docker://")
        _, separator, digest = image.partition("@")
        if not separator or not _IMAGE_DIGEST.match(digest):
            return [Violation(path, line_no, REASON_UNPINNED_IMAGE, ref)]
        return missing_comment()

    owner_repo, separator, git_ref = ref.rpartition("@")
    if not separator or "/" not in owner_repo:
        return [Violation(path, line_no, REASON_MALFORMED_USES, ref)]

    if not _COMMIT_SHA.match(git_ref):
        return [Violation(path, line_no, REASON_UNPINNED_ACTION, ref)]

    return missing_comment()


def scan_text(path: str, text: str) -> list[Violation]:
    """Scan one workflow document. Line-oriented on purpose: no YAML dependency.

    The authorisation path in this project carries zero runtime dependencies and
    this checker gates that path's pipeline, so it carries none either. A YAML
    parser would read the same lines and add a supply-chain edge to the tool
    whose job is to close supply-chain edges.
    """
    violations: list[Violation] = []
    for index, raw_line in enumerate(text.splitlines(), start=1):
        if raw_line.lstrip().startswith("#"):
            continue
        match = _USES_LINE.match(raw_line)
        if match is None:
            continue
        ref = _unquote(match.group("ref"))
        violations.extend(_check_reference(path, index, ref, match.group("rest")))
    return violations


def workflow_files(root: Path) -> list[Path]:
    directory = root / WORKFLOW_SUBDIR
    if not directory.is_dir():
        return []
    return sorted(p for p in directory.iterdir() if p.is_file() and p.suffix in WORKFLOW_SUFFIXES)


def scan_repository(root: Path) -> list[Violation]:
    """Scan every workflow under `root`. An empty workflow set is a violation."""
    files = workflow_files(root)
    if not files:
        return [
            Violation(
                str(root / WORKFLOW_SUBDIR),
                0,
                REASON_NO_WORKFLOWS,
                "nothing was examined, so nothing was shown to be pinned",
            )
        ]
    violations: list[Violation] = []
    for file in files:
        relative = file.relative_to(root).as_posix()
        violations.extend(scan_text(relative, file.read_text(encoding="utf-8")))
    return violations


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    root = Path(args[0]) if args else Path(__file__).resolve().parent.parent
    violations = scan_repository(root.resolve())
    if violations:
        for violation in violations:
            print(violation.render(), file=sys.stderr)
        print(
            f"\n{len(violations)} unpinned or unreadable reference(s). "
            "Every `uses:` must name a 40-character commit SHA, "
            "with the tag it corresponds to in a trailing comment.",
            file=sys.stderr,
        )
        return 1
    examined = len(workflow_files(root.resolve()))
    print(f"All `uses:` references are pinned to a commit SHA ({examined} workflow file(s)).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

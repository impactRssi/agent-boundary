"""Fail the build when a job takes a privilege it does not need.

Three properties, one per failure mode this pipeline can actually suffer:

1. **Every job declares `permissions:`.** A job without one inherits the
   workflow default, and the workflow default is one edit away from being
   wider than the job that quietly relies on it.

2. **Every job starts with an egress audit.** `step-security/harden-runner` in
   `audit` mode records what a job talks to. It is a **record, not a bound** --
   audit mode observes egress, it does not prevent it. The honest reason it is
   not in `block` mode is that the legitimate destination set of this pipeline
   has not been measured, and a blocking allowlist written from guesswork fails
   closed on the wrong thing. The audit is how that set gets measured.

3. **Every checkout sets `persist-credentials: false`.** `actions/checkout`
   otherwise writes the job's `GITHUB_TOKEN` into `.git/config`, where every
   later step in the job can read it -- including third-party actions that were
   never given a token as an input. In `release.yml` that token carries
   `contents: write`.

Each is a call-time check over the workflow text, because the platform has no
construction-time form: GitHub will happily run a job that declares no
permissions. So the check is the fallback, and it runs in `make check` and in
the CI gate rather than in a reviewer's memory.

Fail-closed properties, deliberately mirroring `check_action_pins.py`:

- No workflow files, no jobs in a workflow, or a job with no steps is a
  failure. A pass over an empty set says nothing.
- The parser recognises the canonical two-space GitHub workflow layout. A
  document it cannot decompose into jobs is reported as a violation, never
  skipped -- an unreadable workflow is the case where a missing grant would
  hide.

The workflow-file discovery below is duplicated from `check_action_pins.py`
rather than imported. Six lines of duplication buys each checker the property
of running correctly however it is invoked; a shared import would make the two
share a sys.path assumption as well.

Run it directly, or via `make workflows-hardened`.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

WORKFLOW_SUBDIR = Path(".github") / "workflows"
WORKFLOW_SUFFIXES = (".yml", ".yaml")

REASON_NO_WORKFLOWS = "no-workflow-files-found"
REASON_NO_JOBS = "workflow-declares-no-jobs"
REASON_NO_STEPS = "job-declares-no-steps"
REASON_NO_PERMISSIONS = "job-does-not-declare-permissions"
REASON_NO_EGRESS_AUDIT = "job-does-not-open-with-an-egress-audit"
REASON_NO_EGRESS_POLICY = "egress-audit-declares-no-policy"
REASON_PERSISTED_CREDENTIALS = "checkout-leaves-the-token-in-git-config"

HARDEN_RUNNER = "step-security/harden-runner@"
CHECKOUT = "actions/checkout@"
ACCEPTED_EGRESS_POLICIES = ("audit", "block")

_JOBS_KEY = re.compile(r"^jobs:\s*$")
_JOB_HEADER = re.compile(r"^ {2}(?P<name>[A-Za-z0-9_.-]+):\s*$")
_STEP_START = re.compile(r"^ {6}- ")
_USES_VALUE = re.compile(r"""uses\s*:\s*(?P<ref>'[^']*'|"[^"]*"|\S+)""")
_EGRESS_POLICY = re.compile(r"^\s*egress-policy\s*:\s*(?P<policy>\S+)\s*$")
_PERSIST_FALSE = re.compile(r"^\s*persist-credentials\s*:\s*false\s*$")


@dataclass(frozen=True)
class Violation:
    path: str
    line: int
    reason: str
    detail: str

    def render(self) -> str:
        return f"{self.path}:{self.line}: {self.reason}: {self.detail}"


@dataclass(frozen=True)
class Line:
    number: int
    text: str


@dataclass(frozen=True)
class Job:
    name: str
    line: int
    body: tuple[Line, ...]


def _strip_comments(lines: tuple[Line, ...]) -> tuple[Line, ...]:
    """Drop comment-only lines so prose about a setting cannot satisfy a check."""
    return tuple(line for line in lines if not line.text.lstrip().startswith("#"))


def _uses_of(step: tuple[Line, ...]) -> str | None:
    for line in step:
        match = _USES_VALUE.search(line.text)
        if match:
            ref = match.group("ref")
            if len(ref) >= 2 and ref[0] == ref[-1] and ref[0] in "'\"":
                return ref[1:-1]
            return ref
    return None


def parse_jobs(text: str) -> list[Job] | None:
    """Split a workflow into jobs. `None` means the document was not recognised."""
    lines = [Line(index, raw) for index, raw in enumerate(text.splitlines(), start=1)]
    start = next(
        (position for position, line in enumerate(lines) if _JOBS_KEY.match(line.text)), None
    )
    if start is None:
        return None

    jobs: list[Job] = []
    current: Job | None = None
    body: list[Line] = []
    for line in lines[start + 1 :]:
        header = _JOB_HEADER.match(line.text)
        if header:
            if current is not None:
                jobs.append(Job(current.name, current.line, tuple(body)))
            current = Job(header.group("name"), line.number, ())
            body = []
            continue
        if current is not None:
            body.append(line)
    if current is not None:
        jobs.append(Job(current.name, current.line, tuple(body)))
    return jobs


def split_steps(job: Job) -> list[tuple[Line, ...]] | None:
    """Return the job's step blocks, or `None` if it declares no `steps:` key."""
    body = _strip_comments(job.body)
    start = next(
        (position for position, line in enumerate(body) if line.text.rstrip() == "    steps:"),
        None,
    )
    if start is None:
        return None

    steps: list[tuple[Line, ...]] = []
    current: list[Line] = []
    for line in body[start + 1 :]:
        if _STEP_START.match(line.text):
            if current:
                steps.append(tuple(current))
            current = [line]
        elif current:
            current.append(line)
    if current:
        steps.append(tuple(current))
    return steps


def _check_job(path: str, job: Job) -> list[Violation]:
    violations: list[Violation] = []
    body = _strip_comments(job.body)

    if not any(line.text.rstrip().startswith("    permissions:") for line in body):
        violations.append(Violation(path, job.line, REASON_NO_PERMISSIONS, f"job '{job.name}'"))

    steps = split_steps(job)
    if not steps:
        violations.append(Violation(path, job.line, REASON_NO_STEPS, f"job '{job.name}'"))
        return violations

    first = steps[0]
    first_uses = _uses_of(first)
    if first_uses is None or not first_uses.startswith(HARDEN_RUNNER):
        violations.append(
            Violation(
                path,
                first[0].number,
                REASON_NO_EGRESS_AUDIT,
                f"job '{job.name}' opens with {first_uses or 'a run step'}",
            )
        )
    else:
        policies = [
            match.group("policy")
            for match in (_EGRESS_POLICY.match(line.text) for line in first)
            if match
        ]
        if not policies or any(p not in ACCEPTED_EGRESS_POLICIES for p in policies):
            violations.append(
                Violation(
                    path,
                    first[0].number,
                    REASON_NO_EGRESS_POLICY,
                    f"job '{job.name}' declares {policies or 'nothing'}, "
                    f"expected one of {list(ACCEPTED_EGRESS_POLICIES)}",
                )
            )

    for step in steps:
        uses = _uses_of(step)
        if uses is None or not uses.startswith(CHECKOUT):
            continue
        if not any(_PERSIST_FALSE.match(line.text) for line in step):
            violations.append(
                Violation(
                    path,
                    step[0].number,
                    REASON_PERSISTED_CREDENTIALS,
                    f"job '{job.name}' -- add `persist-credentials: false`",
                )
            )
    return violations


def scan_text(path: str, text: str) -> list[Violation]:
    jobs = parse_jobs(text)
    if jobs is None:
        return [Violation(path, 0, REASON_NO_JOBS, "no `jobs:` key at the top level")]
    if not jobs:
        return [Violation(path, 0, REASON_NO_JOBS, "`jobs:` is empty")]
    violations: list[Violation] = []
    for job in jobs:
        violations.extend(_check_job(path, job))
    return violations


def workflow_files(root: Path) -> list[Path]:
    directory = root / WORKFLOW_SUBDIR
    if not directory.is_dir():
        return []
    return sorted(p for p in directory.iterdir() if p.is_file() and p.suffix in WORKFLOW_SUFFIXES)


def scan_repository(root: Path) -> list[Violation]:
    files = workflow_files(root)
    if not files:
        return [
            Violation(
                str(root / WORKFLOW_SUBDIR),
                0,
                REASON_NO_WORKFLOWS,
                "nothing was examined, so nothing was shown to be hardened",
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
            f"\n{len(violations)} job(s) taking a privilege they do not need. "
            "Every job declares `permissions:` and opens with an egress audit; "
            "every checkout sets `persist-credentials: false`.",
            file=sys.stderr,
        )
        return 1
    examined = len(workflow_files(root.resolve()))
    print(
        "Every job declares permissions, opens with an egress audit, and checks out "
        f"without persisting credentials ({examined} workflow file(s))."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

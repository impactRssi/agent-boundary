# ADR-0007 — Action pinning is checked, not made impossible

- **Status:** Accepted
- **Date:** 2026-08-21
- **Upholds:** none of I1–I4 directly; bounds the supply chain of the pipeline
  that verifies them

## Context

This project's standing preference is structural over procedural: prefer a
control that cannot be turned off to one that is on by default. Every ADR so
far has been able to honour it — an out-of-scope tool has no handle, a raw tool
result has no exported path, an audit sink has no delete method.

The pipeline cannot be made to honour it. GitHub's workflow grammar accepts
`uses: actions/checkout@v5`, and no repository setting forbids a moving tag.
There is no construction in which an unpinned reference fails to exist. The
structural form is unavailable, not merely inconvenient.

That matters because a moving tag is a real exposure: whoever controls the tag,
or compromises the maintainer who does, executes code inside a job holding the
repository's token.

## Decision

Pin every action to a commit SHA, with the tag it corresponds to in a mandatory
trailing comment, and enforce that with `scripts/check_action_pins.py` — a
check that fails the build when an unpinned reference appears.

Per `CONTRIBUTING.md`, a control implemented as a check rather than a structure
owes an ADR explaining why the structural form was not achievable. This is that
ADR.

Two properties keep the check from being the usual erodable convention:

- **It fails closed.** An empty or absent workflow directory fails the build,
  the same reasoning as ADR-0006. A check that passes when it found nothing to
  check is not a check.
- **It is unit-tested against evasion**, not only against the happy path: tags,
  branches, short SHAs, uppercase SHAs, a 39-character near-miss, `docker://`
  by tag, a `uses:` with no ref, and a digest with no trailing tag comment.

## Consequences

**Accepted.**

- A repointed tag or a compromised action maintainer no longer reaches the job
  token in one step.
- **The check verifies form, not correspondence.** It proves offline that a
  reference is a 40-character SHA carrying a tag comment. It does not verify
  that the SHA is what that tag resolves to — that requires the network and a
  trusted view of the upstream repository. The comment is mandatory precisely
  so a human reviewer can perform that check; the digests in the initial pin
  were each resolved through the GitHub API and independently re-verified
  before merge.
- **Pinning bounds one hop.** A pinned action may still fetch code by tag while
  it runs. Recorded in `docs/THREAT_MODEL.md` §7.
- Pinning without automation goes stale, and a stale pin is a security fix not
  applied. Dependabot (N-29) is therefore part of the same decision, not a
  convenience: the pin is only defensible if something proposes updates to it.
- The rule is uniform, with no per-job exemptions. `harden-runner` runs even on
  the `gate` job, which arguably does not need it. An exemption clause is how a
  uniform rule stops being uniform, and the second exemption is always easier
  to argue than the first.

**Rejected: pinning by convention, documented in `CONTRIBUTING.md`.** It is
what most repositories do and it degrades silently — a contributor copies a
snippet from upstream documentation, which always shows the tag form, and
nobody notices in review. The whole argument of this project is that a control
depending on everyone remembering is not a control.

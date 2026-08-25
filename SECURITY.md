# Security policy

## Reporting a vulnerability

**Do not open a public issue.**

Report privately through GitHub's
[private vulnerability reporting](https://github.com/impactRssi/agent-boundary/security/advisories/new)
on this repository.

Include, as far as you have it:

- Which structural invariant (I1–I4) you believe is broken.
- The task construction: tool scope, filesystem root, egress allowlist, caps.
- The proposed call and the observed decision.
- The relevant audit trace entries.
- A minimal reproduction, ideally as a payload in the corpus format.

### What to expect

| Stage | Target |
|---|---|
| Acknowledgement | 72 hours |
| Initial assessment, with the invariant identified | 7 days |
| Fix or a documented decision to accept the risk | 30 days for high severity |
| Public advisory | Coordinated with you, after the fix ships |

This is a solo-maintained project. Those are honest targets, not a contractual
SLA, and they are stated as such rather than dressed up.

Credit is given in the advisory unless you ask otherwise.

## Supported versions

Only `main` is supported, and only the latest tag is recommended for use.
There is no backport policy: a fix lands on `main` and ships in the next tag.

`v0.1.0` and `v0.2.0` are superseded and `v0.1.0` should not be used --
it shipped a broken MCP transport, an egress bypass, and a defeatable test
guard, all three recorded in the [changelog](CHANGELOG.md).

---

## What counts as a vulnerability here

Any of the following, without operator misconfiguration:

- **I1** — An effect reached a tool outside the current task's scope.
- **I2** — A tool result re-entered the model context on a path that bypassed
  ingest, or was dispatched as a call rather than carried as data.
- **I3** — A side-effecting call that is absent from the audit trace, or that
  cannot be attributed to a decision path. A task that exceeded its cap without
  failing closed. An irreversible call executed without a verified approval
  record.
- **I4** — A path that resolved outside the configured root after confinement.
  Egress to a host absent from the allowlist.
- A refusal reason that misreports why a call was refused, since an operator
  triaging an incident acts on that string.
- Any bypass of the adversarial-suite guard that lets a run report success
  having collected nothing.

---

## What is explicitly **not** a vulnerability here

These are design positions, documented in `docs/THREAT_MODEL.md` §2 and §7.
Reports of the following will be closed with a link back to this section — not
because they are wrong, but because they are already known and stated.

**A dangerous tool that the operator allowlisted did something dangerous.** The
broker bounds *which* tool runs and *with what arguments*. It does not
constrain what a permitted tool does internally. If you scope a tool that can
drop a database, a steered agent can drop that database within its budget.

**A malicious operator did something malicious.** Whoever configures the task
scope, the confinement roots, and the approval policy is trusted. Nothing here
defends against them, by design.

**The model was successfully persuaded by injected content.** Expected, and
assumed. The design assumes the model is fully steered. A payload that changes
what the model *proposes* is not a finding. A payload that changes what the
broker *authorises* is.

**Content inside a correctly labelled data block influenced the model.**
Labelling (I2) is mitigation, not proof. We claim a reduced rate and refuse to
claim a bound. See [ADR-0003](docs/adr/ADR-0003-tool-output-is-data.md).

**Two individually in-scope tools composed into an unwanted effect.** Known and
recorded as accepted residual risk (threat model §7.2). Bounded by attribution
and approval, not prevented. A concrete composition we had not considered is
still worth reporting as a *threat model gap* — that is useful, and it will be
handled as a documentation issue rather than an advisory.

**Data left through an allowlisted egress host that accepts arbitrary
content.** Narrowing the allowlist is the operator's lever. Stated in the
README's Limitations, not solved.

**An operator approved an irreversible call without reading it.** Approval
fatigue is real and is out of scope. The control puts a human at the decision
point; it cannot make them read.

**A false refusal.** The broker cannot make nuanced judgements — that is the
trade recorded in [ADR-0001](docs/adr/ADR-0001-deterministic-brokering.md).
False refusals are a published cost of the control. Report them as bugs against
the false-refusal benchmark, not as vulnerabilities.

**Host compromise, or compromise of the inference provider.** Broker integrity
depends on the process boundary; the provider is trusted to the extent the
operator trusts them.

---

## Secrets

Every secret is referenced in `.env.example` and valued nowhere. A committed
secret is an incident: report it privately as above rather than opening a pull
request that removes it, since the pull request advertises it.
